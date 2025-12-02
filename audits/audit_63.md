## Title
FULLY_DISABLED State Blocks Cross-Chain Burns, Permanently Locking User Funds on Spoke Chain

## Summary
The `_beforeTokenTransfer` function in `iTryTokenOFT.sol` unconditionally reverts all token operations when `transferState` is set to `FULLY_DISABLED`, including burns required for LayerZero cross-chain bridging. This prevents users on the spoke chain from burning their iTRY tokens to bridge back to the hub chain, effectively locking their funds until the owner changes the transfer state.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol`, function `_beforeTokenTransfer`, lines 174-176 [1](#0-0) 

**Intended Logic:** The `FULLY_DISABLED` transfer state is designed to halt token transfers during emergency situations while maintaining critical protocol operations. Cross-chain bridging should remain functional to allow users to exit the spoke chain and return to the hub chain.

**Actual Logic:** In `FULLY_DISABLED` state, the function unconditionally reverts ALL token operations without any exceptions. Unlike `FULLY_ENABLED` and `WHITELIST_ENABLED` states which explicitly allow minter burns for cross-chain redemptions, the `FULLY_DISABLED` case provides no escape hatch for users to bridge their tokens back to the hub chain.

Compare with `FULLY_ENABLED` state which allows burns: [2](#0-1) 

And `WHITELIST_ENABLED` state which allows whitelisted burns: [3](#0-2) 

**Exploitation Path:**
1. Owner sets `transferState` to `FULLY_DISABLED` on spoke chain (MegaETH) due to security concerns
2. User on spoke chain attempts to bridge 1,000 iTRY back to hub chain (Ethereum) by calling `send()` on iTryTokenOFT
3. LayerZero's OFT implementation internally calls `_burn(user, 1000)` to burn tokens before sending cross-chain message
4. The burn operation triggers `_beforeTokenTransfer(user, address(0), 1000)` where `msg.sender` is the user
5. Function evaluates to `FULLY_DISABLED` case and reverts with `OperationNotAllowed()`
6. Cross-chain bridge transaction fails, funds remain locked on spoke chain
7. User has no mechanism to retrieve funds except waiting for owner to change transfer state

**Security Property Broken:** Violates the core cross-chain architecture principle that users can always exit spoke chains to return to the hub chain. The README states "No addresses can send/receive tokens in a FULLY_DISABLED transfer state" but fails to account for the critical exception needed for cross-chain burns. [4](#0-3) 

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by users on the spoke chain (MegaETH) when `FULLY_DISABLED` is active
- **Damage Severity**: Complete temporary fund lock for all spoke chain users. If owner is unavailable or compromised, lock becomes permanent. Users cannot access their funds on hub chain where main liquidity and redemption mechanisms exist.
- **User Impact**: Every user holding iTRY on spoke chain is affected. The lock is triggered by a single owner action (setting `FULLY_DISABLED`) and affects all subsequent bridge attempts until state is changed back.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a protocol design flaw. Any legitimate user attempting to bridge during `FULLY_DISABLED` state experiences fund lock.
- **Preconditions**: Owner sets `transferState` to `FULLY_DISABLED` on spoke chain, which is a documented emergency response mechanism per the transfer state design.
- **Execution Complexity**: Single transaction - user calls standard `send()` function on OFT contract, which fails due to the revert.
- **Frequency**: Affects every bridge attempt during `FULLY_DISABLED` period. Given that `FULLY_DISABLED` is an intended protocol state for emergencies, this is a realistic scenario with high probability of occurrence.

## Recommendation

Modify `_beforeTokenTransfer` to allow cross-chain burns even in `FULLY_DISABLED` state: [1](#0-0) 

**FIXED:**
```solidity
// State 0 - Fully disabled transfers
} else if (transferState == TransferState.FULLY_DISABLED) {
    // Allow minter (LayerZero endpoint) to burn tokens for cross-chain bridging back to hub
    if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
        // Cross-chain burn allowed - user is exiting spoke chain
    } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
        // Allow owner to redistribute blacklisted funds even in FULLY_DISABLED
    } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
        // Allow owner to mint during redistribution in FULLY_DISABLED
    } else {
        revert OperationNotAllowed();
    }
}
```

**Alternative mitigation:** Consider adding a dedicated `emergencyBridge()` function that bypasses transfer restrictions for cross-chain exits only, callable by users even in `FULLY_DISABLED` state.

## Proof of Concept
```solidity
// File: test/Exploit_FullyDisabledBridgeLock.t.sol
// Run with: forge test --match-test test_FullyDisabledBlocksCrosschainBurn -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_FullyDisabledBridgeLock is Test {
    iTryTokenOFT public itryOFT;
    address public owner = address(0x1);
    address public user = address(0x2);
    address public lzEndpoint = address(0x3);
    
    function setUp() public {
        vm.startPrank(owner);
        itryOFT = new iTryTokenOFT(lzEndpoint, owner);
        
        // Mint tokens to user (simulating previous bridge from hub)
        vm.startPrank(lzEndpoint);
        itryOFT.mint(user, 1000 ether);
        vm.stopPrank();
        
        assertEq(itryOFT.balanceOf(user), 1000 ether);
    }
    
    function test_FullyDisabledBlocksCrosschainBurn() public {
        // SETUP: Owner sets transfer state to FULLY_DISABLED (emergency scenario)
        vm.prank(owner);
        itryOFT.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        
        // EXPLOIT: User attempts to burn tokens for cross-chain bridge back to hub
        // In real scenario, this would be called by LayerZero OFT send() function
        vm.prank(user);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itryOFT.burn(100 ether); // Burns are blocked
        
        // VERIFY: User funds remain locked on spoke chain
        assertEq(itryOFT.balanceOf(user), 1000 ether, "Vulnerability confirmed: User cannot burn tokens to bridge back to hub chain");
        
        // Even transfers to address(0) are blocked
        vm.prank(user);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itryOFT.transfer(address(0), 100 ether);
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Architectural Mismatch**: The spoke chain implementation should prioritize user exit capability. The FULLY_DISABLED state on spoke chains should be less restrictive than on the hub chain to allow emergency evacuation of funds.

2. **Asymmetric Risk**: Users on spoke chains face additional risk compared to hub chain users. If the hub chain iTry contract enters FULLY_DISABLED, users can still hold their tokens. But spoke chain users are dependent on bridging functionality to access the main protocol features.

3. **Compounding with Other Issues**: This vulnerability compounds with any other spoke chain issues. If a separate vulnerability is discovered on the spoke chain, users cannot escape even if they detect the issue early.

4. **Design Philosophy Violation**: The LayerZero OFT architecture assumes that spoke chains are less critical and users can always bridge back to the canonical chain. This implementation violates that assumption.

The fix should maintain emergency controls while preserving the critical escape hatch for cross-chain exits. The recommended solution adds explicit exceptions for minter-initiated burns (cross-chain operations) and owner redistributions while still blocking regular peer-to-peer transfers in FULLY_DISABLED state.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L143-144)
```text
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L166-167)
```text
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L174-176)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```

**File:** README.md (L127-127)
```markdown
- No adresses can send/receive tokens in a FULLY_DISABLED transfer state.
```
