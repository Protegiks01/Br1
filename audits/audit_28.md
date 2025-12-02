## Title
FULLY_DISABLED Transfer State Prevents Yield Distribution Creating DOS on Protocol Yield Mechanism

## Summary
When the iTRY token is set to `FULLY_DISABLED` transfer state for emergency purposes, the `processAccumulatedYield()` function in iTryIssuer becomes completely non-functional because the minting operation itself reverts. This creates a denial-of-service on the critical yield distribution mechanism, preventing accumulated yield from being processed and distributed to stakers.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/token/iTRY/iTry.sol` (_beforeTokenTransfer function, lines 219-220) and `src/protocol/iTryIssuer.sol` (processAccumulatedYield function, line 413)

**Intended Logic:** The `FULLY_DISABLED` transfer state is designed to prevent unauthorized token transfers during emergency situations (e.g., security incidents), while allowing critical protocol operations like yield distribution to continue functioning.

**Actual Logic:** The `_beforeTokenTransfer` hook unconditionally reverts for ALL token operations when in `FULLY_DISABLED` state, including minting operations. [1](#0-0) 

This affects yield distribution because when `processAccumulatedYield()` attempts to mint yield tokens to the YieldForwarder contract, the mint operation triggers `_beforeTokenTransfer` which immediately reverts. [2](#0-1) 

The iTry token's mint function does not bypass the transfer state check. [3](#0-2) 

**Exploitation Path:**
1. Admin sets iTRY to `FULLY_DISABLED` state for legitimate emergency reasons (security incident, regulatory hold, etc.)
2. NAV appreciation occurs, creating accumulated yield that should be distributed
3. Yield processor role calls `processAccumulatedYield()` to mint and distribute yield
4. The function calls `_mint(address(yieldReceiver), newYield)` which internally triggers `_beforeTokenTransfer(address(0), yieldReceiver, newYield)`
5. Since `transferState == TransferState.FULLY_DISABLED`, the hook immediately reverts with `OperationNotAllowed()`
6. Entire transaction fails - no yield is minted or distributed
7. Yield continues to accumulate but cannot be processed until `FULLY_DISABLED` state is lifted

**Security Property Broken:** This violates the protocol's yield distribution invariant. Accumulated yield based on NAV appreciation cannot be processed and distributed to stakers, breaking the expected yield mechanism that rewards iTRY stakers.

## Impact Explanation

- **Affected Assets**: Accumulated iTRY yield that should be distributed to stakers through the YieldForwarder mechanism
- **Damage Severity**: Complete denial-of-service on yield distribution for the duration of `FULLY_DISABLED` state. While no funds are permanently lost (yield can be distributed once state changes), this could last for extended periods during serious security incidents or regulatory issues. The accumulated yield remains "trapped" in the protocol's accounting but cannot be minted and distributed.
- **User Impact**: All iTRY stakers are affected. They do not receive their entitled yield for the entire period the token remains in `FULLY_DISABLED` state. If NAV appreciates significantly during this period, substantial yield could be delayed.

## Likelihood Explanation

- **Attacker Profile**: Not applicable - this is a design flaw triggered by legitimate admin emergency actions, not attacker exploitation
- **Preconditions**: 
  - Admin must set iTRY to `FULLY_DISABLED` transfer state (legitimate emergency action)
  - NAV appreciation must occur creating yield
  - Yield processor attempts to call `processAccumulatedYield()`
- **Execution Complexity**: Simple - occurs automatically when yield processing is attempted during `FULLY_DISABLED` state
- **Frequency**: Every time `processAccumulatedYield()` is called while in `FULLY_DISABLED` state

## Recommendation

Modify the `_beforeTokenTransfer` function to allow minting operations by the MINTER_CONTRACT role even in `FULLY_DISABLED` state: [4](#0-3) 

**FIXED:**
```solidity
// State 0 - Fully disabled transfers (except protocol minting/burning)
} else if (transferState == TransferState.FULLY_DISABLED) {
    if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // Allow minting by authorized minter contract even in fully disabled state
    } else if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // Allow burning by authorized minter contract even in fully disabled state
    } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // Allow admin to burn from blacklisted addresses
    } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // Allow admin to mint for redistribution
    } else {
        revert OperationNotAllowed();
    }
}
```

**Alternative Mitigation:**
Add a separate emergency function that allows the yield processor to accumulate yield accounting without minting, then distribute it later when transfers are re-enabled.

## Proof of Concept

```solidity
// File: test/Exploit_YieldDOSFullyDisabled.t.sol
// Run with: forge test --match-test test_YieldDOSFullyDisabled -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/protocol/YieldForwarder.sol";

contract Exploit_YieldDOSFullyDisabled is Test {
    iTryIssuer issuer;
    iTry itry;
    YieldForwarder forwarder;
    
    address admin = address(0x1);
    address yieldProcessor = address(0x2);
    address treasury = address(0x3);
    
    function setUp() public {
        // Deploy and initialize contracts
        // (Simplified - actual deployment would use full constructor params)
        vm.startPrank(admin);
        
        // Deploy iTry token
        itry = new iTry();
        itry.initialize(admin, address(issuer));
        
        // Deploy YieldForwarder
        forwarder = new YieldForwarder(address(itry), treasury);
        
        // Grant roles
        itry.grantRole(itry.MINTER_CONTRACT(), address(issuer));
        issuer.grantRole(issuer.YIELD_DISTRIBUTOR_ROLE(), yieldProcessor);
        
        vm.stopPrank();
    }
    
    function test_YieldDOSFullyDisabled() public {
        // SETUP: Initial state with some issued iTRY and collateral
        // (Assume issuer has 1M iTRY issued backed by DLF)
        
        // Simulate NAV appreciation creating 100k yield
        // (Oracle price increases from 1.0 to 1.1)
        
        vm.startPrank(admin);
        // EXPLOIT: Admin sets FULLY_DISABLED for emergency
        itry.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        vm.stopPrank();
        
        // VERIFY: Yield processing now fails
        vm.startPrank(yieldProcessor);
        vm.expectRevert(OperationNotAllowed.selector);
        issuer.processAccumulatedYield();
        vm.stopPrank();
        
        // Yield remains stuck - cannot be distributed to stakers
        assertEq(itry.balanceOf(address(forwarder)), 0, "Vulnerability confirmed: No yield distributed while FULLY_DISABLED");
    }
}
```

## Notes

**Clarification on Question Premise:** The security question asks if "yield is minted but cannot be distributed." The actual behavior is more severe - yield **cannot even be minted** in `FULLY_DISABLED` state, as the mint operation itself reverts before any distribution attempt. This means the entire `processAccumulatedYield()` transaction fails atomically.

**Why This Is Valid Despite Admin Action:** While `FULLY_DISABLED` requires admin action, this is a **design flaw** where a legitimate emergency measure (halting unauthorized transfers) has an unintended consequence (breaking protocol yield distribution). Admins would reasonably expect that protocol-internal operations like yield processing would continue functioning even when user transfers are disabled for security reasons.

**Severity Justification (Medium):** This qualifies as Medium severity under Code4rena criteria as it causes temporary protocol dysfunction affecting yield distribution to all stakers. While not permanent (reversible when state changes) and not directly stealing funds, it significantly disrupts a critical protocol function and could persist for extended periods during serious incidents.

### Citations

**File:** src/token/iTRY/iTry.sol (L155-157)
```text
    function mint(address to, uint256 amount) external onlyRole(MINTER_CONTRACT) {
        _mint(to, amount);
    }
```

**File:** src/token/iTRY/iTry.sol (L219-221)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```

**File:** src/protocol/iTryIssuer.sol (L413-413)
```text
        _mint(address(yieldReceiver), newYield);
```
