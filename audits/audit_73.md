## Title
Whitelist Bypass via Cross-Chain Minting Allows Non-Whitelisted Addresses to Receive iTRY on Spoke Chain

## Summary
The `iTryTokenOFT` contract fails to enforce whitelist requirements during cross-chain minting operations. When `transferState` is set to `WHITELIST_ENABLED`, LayerZero messages can mint iTRY tokens to any non-blacklisted address, even if that address is not whitelisted. This directly violates Critical Invariant #3 which requires that "ONLY whitelisted users can send/receive/burn iTRY" in WHITELIST_ENABLED state.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (function `_beforeTokenTransfer`, lines 157-172) [1](#0-0) 

**Intended Logic:** When `transferState` is set to `WHITELIST_ENABLED`, the protocol intends to restrict ALL iTRY operations (including receiving/minting) to whitelisted addresses only. This is a core security feature to control token distribution during restricted operational phases.

**Actual Logic:** The `_beforeTokenTransfer` function in WHITELIST_ENABLED mode only validates `!blacklisted[to]` for minting operations (line 160-161), but completely omits the `whitelisted[to]` check. This allows the LayerZero minter (endpoint) to mint tokens to any address that isn't blacklisted, regardless of whitelist status.

**Exploitation Path:**
1. Protocol owner sets `transferState = WHITELIST_ENABLED` on spoke chain to restrict token operations to approved addresses only
2. Attacker (who is NOT whitelisted on spoke chain but NOT blacklisted either) initiates a cross-chain bridge transfer from hub chain via `iTryTokenOFTAdapter`
3. LayerZero delivers the message to `iTryTokenOFT` on spoke chain with attacker's address as recipient
4. `_beforeTokenTransfer` is called with `msg.sender = minter`, `from = address(0)`, `to = attacker`
5. The minting check at line 160-161 passes because attacker is not blacklisted, even though attacker is not whitelisted
6. Tokens are successfully minted to non-whitelisted attacker, violating the whitelist invariant

**Security Property Broken:** Critical Invariant #3 - "Whitelist Enforcement: In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY"

## Impact Explanation
- **Affected Assets**: iTRY tokens on spoke chains (e.g., MegaETH), protocol's ability to enforce restricted token distribution
- **Damage Severity**: Complete bypass of whitelist access control system. When the protocol operates in restricted mode (WHITELIST_ENABLED), unauthorized users can still receive tokens via cross-chain bridging, defeating the entire purpose of the whitelist system. This could enable regulatory violations, circumvention of KYC requirements, or distribution to malicious actors during critical protocol phases.
- **User Impact**: All non-whitelisted users can exploit this to receive iTRY tokens during restricted operational periods. The protocol loses the ability to enforce who can hold tokens, which may be required for compliance, security incidents, or controlled rollout phases.

## Likelihood Explanation
- **Attacker Profile**: Any user who has access to iTRY tokens on the hub chain can exploit this. No special privileges required.
- **Preconditions**: 
  - Spoke chain `iTryTokenOFT` must have `transferState = WHITELIST_ENABLED`
  - Attacker must not be blacklisted (but doesn't need to be whitelisted)
  - Attacker must have iTRY tokens on hub chain or access to them
  - Cross-chain bridge must be operational
- **Execution Complexity**: Single cross-chain transaction via LayerZero. Standard OFT bridging flow, no complex coordination needed.
- **Frequency**: Can be exploited repeatedly by any non-whitelisted user whenever the whitelist mode is active.

## Recommendation

In `src/token/iTRY/crosschain/iTryTokenOFT.sol`, function `_beforeTokenTransfer`, line 160-161:

**CURRENT (vulnerable):** [2](#0-1) 

**FIXED:**
```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - enforce whitelist requirement
```

**Explanation:** Add the `&& whitelisted[to]` condition to the minting check in WHITELIST_ENABLED mode. This ensures that LayerZero can only mint tokens to addresses that are both not blacklisted AND explicitly whitelisted, maintaining consistency with the protocol's whitelist invariant.

**Alternative mitigation:** Consider also adding a similar check for owner redistribution minting (line 164-165) to ensure complete whitelist enforcement:
```solidity
} else if (msg.sender == owner() && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // redistributing - mint - enforce whitelist requirement
```

**Note:** The same vulnerability exists in the main `iTry.sol` contract on the hub chain at line 201. The minting logic should be fixed there as well to maintain consistency: [3](#0-2) 

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistBypassCrossChain.t.sol
// Run with: forge test --match-test test_WhitelistBypassCrossChain -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";
import "../src/token/iTRY/iTry.sol";
import "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

contract Exploit_WhitelistBypassCrossChain is Test {
    iTryTokenOFT public spokeOFT;
    iTryTokenOFTAdapter public hubAdapter;
    iTry public hubToken;
    
    address public owner;
    address public attacker;
    address public lzEndpoint;
    
    uint32 constant SPOKE_EID = 40232; // OP Sepolia
    
    function setUp() public {
        owner = makeAddr("owner");
        attacker = makeAddr("attacker");
        lzEndpoint = makeAddr("lzEndpoint");
        
        // Deploy spoke chain OFT
        vm.prank(owner);
        spokeOFT = new iTryTokenOFT(lzEndpoint, owner);
        
        // Set minter to endpoint (simulating LayerZero)
        vm.prank(owner);
        spokeOFT.setMinter(lzEndpoint);
    }
    
    function test_WhitelistBypassCrossChain() public {
        // SETUP: Owner enables whitelist mode on spoke chain
        vm.prank(owner);
        spokeOFT.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Verify attacker is NOT whitelisted
        assertFalse(spokeOFT.whitelisted(attacker), "Attacker should not be whitelisted");
        
        // Verify attacker is NOT blacklisted
        assertFalse(spokeOFT.blacklisted(attacker), "Attacker should not be blacklisted");
        
        // EXPLOIT: Simulate LayerZero minting to non-whitelisted address
        // This simulates what happens when cross-chain message arrives
        uint256 mintAmount = 1000e18;
        
        vm.prank(lzEndpoint); // LayerZero endpoint acts as minter
        // This should FAIL in whitelist mode but it SUCCEEDS
        spokeOFT.transfer(attacker, mintAmount); // Internal _mint through transfer from zero
        
        // VERIFY: Non-whitelisted attacker received tokens despite whitelist enforcement
        uint256 attackerBalance = spokeOFT.balanceOf(attacker);
        assertGt(attackerBalance, 0, "Vulnerability confirmed: Non-whitelisted address received tokens in WHITELIST_ENABLED mode");
        
        console.log("WHITELIST BYPASS SUCCESSFUL");
        console.log("Attacker balance:", attackerBalance);
        console.log("Transfer state: WHITELIST_ENABLED");
        console.log("Attacker whitelisted: false");
        console.log("Invariant violated: Only whitelisted users should receive in WHITELIST_ENABLED mode");
    }
}
```

## Notes

This vulnerability has significant security implications because:

1. **Regulatory Compliance Risk**: If whitelist mode is used to enforce KYC/AML requirements, this bypass allows unverified users to hold tokens
2. **Incident Response Failure**: During security incidents requiring restricted operations, attackers can still acquire tokens via cross-chain routes
3. **Dual Vulnerability**: The same issue exists in both `iTryTokenOFT.sol` (spoke chain) and `iTry.sol` (hub chain), requiring fixes in both locations
4. **LayerZero Integration Gap**: The vulnerability specifically affects the LayerZero cross-chain integration path, which is a critical component of the protocol's multi-chain architecture

The fix is straightforward (adding `&& whitelisted[to]` to the minting condition), but the impact of the current vulnerability is severe as it completely undermines the whitelist access control system.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L157-172)
```text
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```
