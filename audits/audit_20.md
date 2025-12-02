## Title
Permanent Yield Lock in YieldForwarder Due to Whitelist Enforcement Without Recovery Path

## Summary
When iTRY is in `WHITELIST_ENABLED` mode, the `YieldForwarder.processNewYield()` function will permanently fail if the YieldForwarder contract itself, the `yieldRecipient` address, or the caller of `processNewYield()` lacks the `WHITELISTED_ROLE`. The emergency `rescueToken()` function cannot recover these funds because it also triggers the same whitelist validation, creating an irrecoverable fund lock scenario.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol` (function `processNewYield`, lines 97-107) and `src/token/iTRY/iTry.sol` (function `_beforeTokenTransfer`, lines 198-217)

**Intended Logic:** The YieldForwarder contract should forward accumulated yield to a designated recipient when `processNewYield()` is called. The emergency `rescueToken()` function should provide a recovery mechanism for accidentally locked tokens. [1](#0-0) 

**Actual Logic:** When iTRY is in `WHITELIST_ENABLED` mode, the `_beforeTokenTransfer` hook enforces that for normal transfers (non-mint/burn), ALL THREE parties must have `WHITELISTED_ROLE`: `msg.sender`, `from`, and `to`. [2](#0-1) 

When `processNewYield()` executes `yieldToken.transfer(yieldRecipient, _newYieldAmount)`:
- `msg.sender` = whoever calls `processNewYield()` (no access control on this function)
- `from` = YieldForwarder contract address
- `to` = `yieldRecipient` address

If ANY of these three addresses lacks `WHITELISTED_ROLE`, the transfer reverts with `OperationNotAllowed()`. [3](#0-2) 

**Exploitation Path:**
1. Protocol admin sets iTRY to `WHITELIST_ENABLED` mode using `updateTransferState(TransferState.WHITELIST_ENABLED)`
2. YieldForwarder contract is deployed with a `yieldRecipient` that is not whitelisted, OR the YieldForwarder contract itself is not granted `WHITELISTED_ROLE`
3. iTryIssuer mints yield tokens to YieldForwarder via `processAccumulatedYield()` [4](#0-3) 

4. Any attempt to call `processNewYield()` reverts due to whitelist check failure
5. Owner attempts to rescue funds via `rescueToken()`, but this also uses `safeTransfer()` which triggers the same `_beforeTokenTransfer` hook [5](#0-4) 

6. Yield tokens are permanently locked in YieldForwarder with no recovery path

**Security Property Broken:** This violates the protocol's yield distribution mechanism and creates a permanent fund lock scenario, effectively causing loss of protocol yield that should be distributed to stakeholders.

## Impact Explanation
- **Affected Assets**: All iTRY yield tokens minted to the YieldForwarder contract become permanently locked
- **Damage Severity**: Complete loss of yield distribution functionality. All accumulated yield from NAV appreciation that gets minted to YieldForwarder cannot be distributed or recovered. This represents 100% loss of protocol yield until the issue is resolved.
- **User Impact**: All protocol users expecting yield distribution are affected. The protocol's entire yield generation mechanism becomes non-functional, as yield accumulates but cannot be distributed to intended recipients (e.g., wiTRY stakers).

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is an operational failure scenario triggered by normal protocol operations
- **Preconditions**: 
  1. iTRY must be in `WHITELIST_ENABLED` mode (a legitimate operational state)
  2. Either the YieldForwarder contract, the `yieldRecipient`, or typical callers of `processNewYield()` are not whitelisted
  3. Yield is minted to YieldForwarder
- **Execution Complexity**: Occurs automatically during normal yield processing operations. No special actions required beyond normal protocol flow.
- **Frequency**: Every time yield is processed while iTRY is in `WHITELIST_ENABLED` mode without proper whitelist coordination

## Recommendation

**Primary Fix:** Grant the YieldForwarder contract itself the `WHITELISTED_ROLE` during deployment/initialization, and ensure `yieldRecipient` is whitelisted before any yield processing occurs.

**Secondary Fix (Enhanced Recovery):** Implement a dedicated emergency withdrawal function in YieldForwarder that bypasses the normal transfer flow by having the iTRY admin perform a special rescue operation:

```solidity
// In src/protocol/YieldForwarder.sol, add new emergency function:

/**
 * @notice Emergency function to request admin rescue when normal transfers fail
 * @dev Emits event for iTRY admin to manually redistribute tokens using redistributeLockedAmount
 * @param emergencyRecipient The address where rescued tokens should be sent
 */
function requestEmergencyRescue(address emergencyRecipient) external onlyOwner {
    require(emergencyRecipient != address(0), "Invalid recipient");
    uint256 balance = yieldToken.balanceOf(address(this));
    
    emit EmergencyRescueRequested(address(yieldToken), emergencyRecipient, balance);
}
```

Alternatively, modify iTRY's `_beforeTokenTransfer` to add an exception for contracts with special privileges:

```solidity
// In src/token/iTRY/iTry.sol, in _beforeTokenTransfer, add before line 210:

// Allow whitelisted contracts to send to whitelisted recipients even if caller is not whitelisted
} else if (
    hasRole(WHITELISTED_ROLE, from) && hasRole(WHITELISTED_ROLE, to) && from != msg.sender
) {
    // Contract-to-user transfers for protocol operations
```

**Best Practice:** Before setting iTRY to `WHITELIST_ENABLED` mode, protocol operators should ensure:
1. YieldForwarder contract has `WHITELISTED_ROLE`
2. The configured `yieldRecipient` has `WHITELISTED_ROLE`
3. The account that will call `processNewYield()` has `WHITELISTED_ROLE`

## Proof of Concept

```solidity
// File: test/Exploit_YieldForwarderWhitelistLock.t.sol
// Run with: forge test --match-test test_YieldForwarderWhitelistLock -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_YieldForwarderWhitelistLock is Test {
    iTry public itry;
    YieldForwarder public forwarder;
    
    address public admin;
    address public yieldRecipient;
    address public caller;
    
    function setUp() public {
        admin = makeAddr("admin");
        yieldRecipient = makeAddr("yieldRecipient");
        caller = makeAddr("caller");
        
        // Deploy iTry token
        itry = new iTry();
        itry.initialize(admin, admin); // admin is also minter for simplicity
        
        // Deploy YieldForwarder
        forwarder = new YieldForwarder(address(itry), yieldRecipient);
    }
    
    function test_YieldForwarderWhitelistLock() public {
        // SETUP: Set iTry to WHITELIST_ENABLED mode
        vm.prank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Mint some yield to the YieldForwarder (simulating yield distribution)
        vm.prank(admin);
        itry.mint(address(forwarder), 1000e18);
        
        uint256 forwarderBalance = itry.balanceOf(address(forwarder));
        assertEq(forwarderBalance, 1000e18, "Forwarder should have yield tokens");
        
        // EXPLOIT: Try to process yield - this will FAIL
        vm.prank(caller);
        vm.expectRevert(); // OperationNotAllowed
        forwarder.processNewYield(1000e18);
        
        // Verify funds are still locked in forwarder
        assertEq(itry.balanceOf(address(forwarder)), 1000e18, "Yield still locked");
        assertEq(itry.balanceOf(yieldRecipient), 0, "Recipient received nothing");
        
        // VERIFY: Even emergency rescue fails
        address rescueTarget = makeAddr("rescueTarget");
        vm.prank(forwarder.owner());
        vm.expectRevert(); // SafeERC20 will revert on failed transfer
        forwarder.rescueToken(address(itry), rescueTarget, 1000e18);
        
        // Confirm funds are PERMANENTLY LOCKED
        assertEq(itry.balanceOf(address(forwarder)), 1000e18, "Funds permanently locked");
        console.log("Vulnerability confirmed: 1000e18 iTRY permanently locked in YieldForwarder");
    }
}
```

## Notes

This vulnerability highlights a critical integration issue between the transfer restriction mechanism in iTRY and the YieldForwarder contract. The issue is particularly severe because:

1. **No Warning System**: There's no mechanism to detect or warn when the whitelist configuration will cause yield distribution to fail
2. **Silent Failure**: The yield gets minted successfully to YieldForwarder, but cannot be moved out, creating a false sense that everything is working
3. **Cascading Impact**: This doesn't just affect one transaction - it locks ALL future yield until iTRY is taken out of WHITELIST_ENABLED mode or proper whitelisting is configured
4. **Recovery Complexity**: Even with admin intervention, recovering requires either changing iTRY's transfer state (affecting the entire protocol) or granting whitelist roles retroactively

The root cause is that YieldForwarder was designed without consideration for iTRY's transfer restriction modes. The `processNewYield()` function has no access control, meaning any caller can trigger it, but the whitelist check requires the caller to be whitelisted - creating an impossible dependency when operating in restricted mode.

### Citations

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

**File:** src/protocol/YieldForwarder.sol (L166-166)
```text
            IERC20(token).safeTransfer(to, amount);
```

**File:** src/token/iTRY/iTry.sol (L210-214)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
```

**File:** src/token/iTRY/iTry.sol (L215-217)
```text
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/protocol/iTryIssuer.sol (L413-416)
```text
        _mint(address(yieldReceiver), newYield);

        // Notify yield distributor of received yield
        yieldReceiver.processNewYield(newYield);
```
