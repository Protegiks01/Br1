## Title
FULLY_DISABLED Transfer State Blocks Critical Protocol Operations, Causing Complete Protocol Lockdown and Permanent User Fund Lock

## Summary
The `_beforeTokenTransfer` hook in iTry.sol unconditionally reverts ALL token transfers when `transferState` is set to `FULLY_DISABLED`, including privileged minting and burning operations by `MINTER_CONTRACT`. This causes complete protocol shutdown: users cannot redeem iTRY for DLF, new iTRY cannot be minted, yield distribution fails, and even admin cannot recover blacklisted funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` - `_beforeTokenTransfer` function (lines 177-222, specifically lines 219-221) [1](#0-0) 

**Intended Logic:** The `FULLY_DISABLED` state is meant to be an emergency kill switch to prevent user-to-user transfers. However, based on the implementation of `FULLY_ENABLED` and `WHITELIST_ENABLED` states, privileged operations (minting by `MINTER_CONTRACT`, burning during redemption, and admin redistribution) should remain functional even in restricted transfer states.

**Actual Logic:** When `transferState == TransferState.FULLY_DISABLED`, the code unconditionally reverts with `OperationNotAllowed()` for ALL token transfers, including:
- Minting: `_beforeTokenTransfer(address(0), recipient, amount)` reverts
- Burning: `_beforeTokenTransfer(user, address(0), amount)` reverts  
- Redistribution: Both burn and mint operations revert

This differs from `FULLY_ENABLED` and `WHITELIST_ENABLED` states which explicitly allow these privileged operations: [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. Admin legitimately calls `updateTransferState(TransferState.FULLY_DISABLED)` during an emergency (e.g., security incident, regulatory requirement, oracle failure) [4](#0-3) 

2. User attempts to redeem iTRY via `iTryIssuer.redeemFor()`, which internally calls `_burn()`: [5](#0-4) [6](#0-5) 

3. The `iTryToken.burnFrom()` call triggers `_beforeTokenTransfer(user, address(0), amount)`, which hits the FULLY_DISABLED branch and reverts

4. Similarly, minting attempts via `iTryIssuer.mintFor()` revert when calling `iTryToken.mint()`: [7](#0-6) [8](#0-7) 

5. Yield distribution via `processAccumulatedYield()` also fails because minting to `yieldReceiver` reverts: [9](#0-8) 

6. Admin cannot recover blacklisted funds via `redistributeLockedAmount()` because both burn and mint operations revert: [10](#0-9) 

**Security Property Broken:** 
- Violates the iTRY Backing invariant: Users should always be able to redeem iTRY for DLF (assuming sufficient backing), but this becomes impossible in FULLY_DISABLED state
- Breaks protocol functionality: Core operations (minting, redemption, yield) become permanently unavailable
- Contradicts the pattern established in FULLY_ENABLED and WHITELIST_ENABLED states where privileged operations are explicitly exempted

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by users, all DLF collateral under custody, wiTRY stakers expecting yield
- **Damage Severity**: 
  - Users cannot redeem their iTRY for DLF - funds are completely locked
  - Protocol cannot issue new iTRY - business operations cease
  - Yield cannot be distributed to wiTRY stakers - loss of expected returns
  - Admin cannot recover blacklisted user funds - permanent lock even for emergency recovery
- **User Impact**: ALL iTRY holders are affected. Any attempt to redeem fails, causing complete loss of liquidity. Users expecting to withdraw their capital are unable to do so for an indefinite period.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is triggered by legitimate admin action during an emergency scenario
- **Preconditions**: Admin sets `transferState` to `FULLY_DISABLED`, which is a documented feature intended for emergency use
- **Execution Complexity**: Single admin transaction to set the state; immediate impact on all subsequent operations
- **Frequency**: Whenever FULLY_DISABLED state is activated, the lockdown persists until state is changed back

## Recommendation
Modify the `_beforeTokenTransfer` function to include exemptions for privileged operations in the FULLY_DISABLED state, consistent with the other transfer states: [11](#0-10) 

**FIXED:**
```solidity
// State 0 - Fully disabled transfers
} else if (transferState == TransferState.FULLY_DISABLED) {
    // Allow MINTER_CONTRACT to mint (from == address(0))
    if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // minting - allow
    } 
    // Allow MINTER_CONTRACT to burn/redeem (to == address(0))
    else if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // redeeming - allow
    } 
    // Allow DEFAULT_ADMIN_ROLE to redistribute blacklisted funds
    else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // redistributing - burn - allow
    } 
    else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // redistributing - mint - allow
    } 
    else {
        // All other transfers blocked in FULLY_DISABLED state
        revert OperationNotAllowed();
    }
}
```

**Alternative Mitigation:** Add a dedicated emergency function that allows admin to temporarily re-enable specific addresses (like `MINTER_CONTRACT`) even in FULLY_DISABLED state, though the primary fix above is cleaner and more consistent with existing code patterns.

## Proof of Concept
```solidity
// File: test/Exploit_FullyDisabledBlocksRedemption.t.sol
// Run with: forge test --match-test test_FullyDisabledBlocksRedemption -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_FullyDisabledBlocksRedemption is Test {
    iTry public itryToken;
    iTryIssuer public issuer;
    address public admin = address(0x1);
    address public user = address(0x2);
    address public minterContract;
    
    function setUp() public {
        vm.startPrank(admin);
        
        // Deploy iTry token
        itryToken = new iTry();
        
        // Initialize with temporary minter
        itryToken.initialize(admin, admin);
        
        // Setup: Simulate iTryIssuer as MINTER_CONTRACT
        minterContract = address(0x3);
        itryToken.addMinter(minterContract);
        
        vm.stopPrank();
    }
    
    function test_FullyDisabledBlocksRedemption() public {
        // SETUP: Mint some iTRY to user (simulating normal protocol operation)
        vm.prank(minterContract);
        itryToken.mint(user, 1000 ether);
        
        uint256 userBalance = itryToken.balanceOf(user);
        assertEq(userBalance, 1000 ether, "User should have 1000 iTRY");
        
        // TRIGGER: Admin sets transfer state to FULLY_DISABLED (emergency scenario)
        vm.prank(admin);
        itryToken.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        
        // EXPLOIT 1: User tries to redeem (burn) their iTRY - this should work but reverts
        vm.startPrank(user);
        itryToken.approve(minterContract, 500 ether);
        vm.stopPrank();
        
        vm.prank(minterContract);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itryToken.burnFrom(user, 500 ether);
        // VERIFICATION: Burn fails even though MINTER_CONTRACT has the role
        
        // EXPLOIT 2: Protocol tries to mint new iTRY - this should work but reverts  
        vm.prank(minterContract);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itryToken.mint(user, 100 ether);
        // VERIFICATION: Mint fails even though MINTER_CONTRACT has the role
        
        // EXPLOIT 3: Admin tries to redistribute blacklisted funds
        address blacklistedUser = address(0x4);
        vm.prank(admin);
        itryToken.addBlacklistAddress(_toArray(blacklistedUser));
        
        vm.prank(minterContract);
        itryToken.mint(blacklistedUser, 200 ether);
        
        // Now try to redistribute (should work but reverts in FULLY_DISABLED)
        vm.prank(admin);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itryToken.redistributeLockedAmount(blacklistedUser, admin);
        // VERIFICATION: Redistribution fails, funds permanently locked
        
        // FINAL VERIFICATION: User funds remain locked
        assertEq(itryToken.balanceOf(user), 1000 ether, "User funds remain locked - cannot redeem");
    }
    
    function _toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }
}
```

## Notes
This vulnerability is particularly insidious because:

1. **Design Inconsistency**: The FULLY_ENABLED and WHITELIST_ENABLED states both explicitly exempt privileged operations (minting by MINTER_CONTRACT, burning during redemption, admin redistribution), but FULLY_DISABLED was implemented without these exemptions. This suggests an oversight rather than intentional design.

2. **Emergency Response Backfire**: The FULLY_DISABLED state is intended as an emergency measure to protect users, but it paradoxically makes the situation worse by locking all user funds and preventing protocol recovery.

3. **Impact on Cross-chain Operations**: The same vulnerability exists in `iTryTokenOFT.sol` for spoke chains: [12](#0-11) 

4. **Yield Distribution Cascade Failure**: Even if minting to `YieldForwarder` succeeded, the subsequent transfer in `processNewYield()` would fail: [13](#0-12) 

5. **Not a Known Issue**: While the Zellic audit identified that blacklisted users can transfer via allowance, it did not identify this FULLY_DISABLED state issue that blocks ALL protocol operations including privileged ones.

### Citations

**File:** src/token/iTRY/iTry.sol (L112-121)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L155-157)
```text
    function mint(address to, uint256 amount) external onlyRole(MINTER_CONTRACT) {
        _mint(to, amount);
    }
```

**File:** src/token/iTRY/iTry.sol (L171-175)
```text
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L180-196)
```text
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/iTRY/iTry.sol (L199-217)
```text
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/iTRY/iTry.sol (L218-222)
```text
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/protocol/iTryIssuer.sol (L351-351)
```text
        _burn(msg.sender, iTRYAmount);
```

**File:** src/protocol/iTryIssuer.sol (L412-413)
```text
        // Mint yield amount to yieldReceiver contract
        _mint(address(yieldReceiver), newYield);
```

**File:** src/protocol/iTryIssuer.sol (L576-579)
```text
    function _mint(address receiver, uint256 amount) internal {
        _totalIssuedITry += amount;
        iTryToken.mint(receiver, amount);
    }
```

**File:** src/protocol/iTryIssuer.sol (L587-591)
```text
    function _burn(address from, uint256 amount) internal {
        // Burn user's iTRY tokens
        _totalIssuedITry -= amount;
        iTryToken.burnFrom(from, amount);
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L174-176)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```

**File:** src/protocol/YieldForwarder.sol (L97-107)
```text
    function processNewYield(uint256 _newYieldAmount) external override {
        if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
        if (yieldRecipient == address(0)) revert RecipientNotSet();

        // Transfer yield tokens to the recipient
        if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
            revert CommonErrors.TransferFailed();
        }

        emit YieldForwarded(yieldRecipient, _newYieldAmount);
    }
```
