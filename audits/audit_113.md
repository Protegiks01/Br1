## Title
ERC20Permit Bypass of FULLY_DISABLED Transfer State Enables Allowance Preparation During Emergency Pause

## Summary
The `iTry.sol` contract inherits `ERC20PermitUpgradeable` but does not override or restrict the `permit()` function to respect the `transferState` variable. This allows users to grant token allowances even when `transferState` is set to `FULLY_DISABLED`, creating a partial bypass of the emergency pause mechanism. When the state changes back to `FULLY_ENABLED`, these pre-approved allowances immediately become active and usable.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/token/iTRY/iTry.sol` [1](#0-0) 

**Intended Logic:** 
When `transferState` is set to `FULLY_DISABLED` (value 0), the protocol intends to freeze ALL token operations as an emergency pause mechanism. The `updateTransferState()` function allows the admin to "disable all transfers" according to the function comment. [2](#0-1) 

The `_beforeTokenTransfer()` hook enforces this by reverting all transfers when in FULLY_DISABLED state: [3](#0-2) 

**Actual Logic:** 
The contract inherits `ERC20PermitUpgradeable` (line 4, 17) but does NOT override the `permit()` function. OpenZeppelin's standard `permit()` implementation only calls `_approve()` internally, which does NOT trigger the `_beforeTokenTransfer()` hook. Therefore, users can successfully call `permit()` to grant allowances even when `transferState = FULLY_DISABLED`.

**Exploitation Path:**

1. **Emergency State Activated**: Protocol admin sets `transferState = FULLY_DISABLED` (e.g., due to detected vulnerability, regulatory requirement, or emergency pause)

2. **Allowance Preparation**: Attacker (or any user) calls `permit()` with valid EIP-2612 signatures to grant token allowances. These calls succeed because `permit()` bypasses the transfer state check.

3. **Social Engineering Window**: Users may be more willing to sign permit messages during FULLY_DISABLED state, believing "nothing can happen" since transfers are frozen. Attackers can collect multiple permit signatures during this period.

4. **State Re-enabled**: Admin changes `transferState` back to `FULLY_ENABLED` after resolving the issue.

5. **Immediate Exploitation**: All pre-approved allowances from step 2 immediately become active. Attacker can call `transferFrom()` to drain funds using the collected permits, gaining first-mover advantage over users who waited for the pause to lift.

**Security Property Broken:** 
Invariant #4 states: "FULLY_DISABLED: NO addresses can transfer". While `permit()` itself doesn't transfer tokens, it creates approved allowances that enable immediate transfers the instant the state changes. This violates the spirit of the FULLY_DISABLED emergency pause, which should prevent all token-related operations from progressing.

## Impact Explanation

- **Affected Assets**: All iTRY tokens held by users who sign permit messages during FULLY_DISABLED state
- **Damage Severity**: Attackers can prepare complex multi-address transfer operations during an emergency pause. When the pause lifts, they can immediately execute these transfers, potentially front-running legitimate users or exploiting vulnerabilities the pause was meant to prevent. The social engineering attack vector is particularly concerning—users may sign permits thinking it's safe during a freeze.
- **User Impact**: Any user who signs a permit during FULLY_DISABLED state is at risk. The attacker gains timing advantage over other users when the pause lifts.

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged user with knowledge of EIP-2612 permit functionality
- **Preconditions**: 
  - Protocol must enter FULLY_DISABLED state (emergency pause scenario)
  - Users must be convinced to sign permit messages (social engineering, or users self-signing for later use)
  - State must eventually return to FULLY_ENABLED
- **Execution Complexity**: Low - single `permit()` call during pause, followed by `transferFrom()` when state re-enables
- **Frequency**: Can occur during any FULLY_DISABLED period

## Recommendation

Override the `permit()` function to respect `transferState` restrictions:

```solidity
// In src/token/iTRY/iTry.sol, add this function:

/**
 * @notice Override permit to respect transferState
 * @dev During FULLY_DISABLED, no operations including permit should succeed
 */
function permit(
    address owner,
    address spender,
    uint256 value,
    uint256 deadline,
    uint8 v,
    bytes32 r,
    bytes32 s
) public virtual override {
    // Enforce transferState restrictions for permit
    if (transferState == TransferState.FULLY_DISABLED) {
        revert OperationNotAllowed();
    }
    
    // For WHITELIST_ENABLED, only whitelisted users can grant permits
    if (transferState == TransferState.WHITELIST_ENABLED) {
        if (!hasRole(WHITELISTED_ROLE, owner) || !hasRole(WHITELISTED_ROLE, spender)) {
            revert OperationNotAllowed();
        }
    }
    
    // Call parent implementation
    super.permit(owner, spender, value, deadline, v, r, s);
}
```

Alternative mitigation: Override `approve()` with the same checks, as it has the same bypass issue.

## Proof of Concept

```solidity
// File: test/Exploit_PermitBypassFULLY_DISABLED.t.sol
// Run with: forge test --match-test test_PermitBypassDuringFullyDisabled -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_PermitBypass is Test {
    iTry public itry;
    address public admin;
    address public minter;
    address public victim;
    address public attacker;
    
    uint256 public victimPrivateKey = 0xA11CE;
    uint256 public attackerPrivateKey = 0xB0B;
    
    function setUp() public {
        admin = address(this);
        minter = address(0x1);
        victim = vm.addr(victimPrivateKey);
        attacker = vm.addr(attackerPrivateKey);
        
        // Deploy iTry contract
        itry = new iTry();
        itry.initialize(admin, minter);
        
        // Mint tokens to victim
        vm.prank(minter);
        itry.mint(victim, 1000 ether);
    }
    
    function test_PermitBypassDuringFullyDisabled() public {
        // SETUP: Protocol enters FULLY_DISABLED state (emergency pause)
        itry.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        
        // VERIFY: Normal transfers are blocked
        vm.prank(victim);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itry.transfer(attacker, 100 ether);
        
        // EXPLOIT: Attacker tricks victim into signing permit during "safe" pause period
        // Victim signs permit thinking "transfers are frozen, so this is safe"
        bytes32 permitHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                itry.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
                        victim,
                        attacker,
                        500 ether,
                        itry.nonces(victim),
                        block.timestamp + 1 hours
                    )
                )
            )
        );
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(victimPrivateKey, permitHash);
        
        // EXPLOIT: permit() succeeds even during FULLY_DISABLED
        itry.permit(victim, attacker, 500 ether, block.timestamp + 1 hours, v, r, s);
        
        // VERIFY: Allowance was granted during FULLY_DISABLED
        assertEq(itry.allowance(victim, attacker), 500 ether, "Permit succeeded during FULLY_DISABLED");
        
        // EXPLOIT: Admin lifts pause, attacker immediately drains funds
        itry.updateTransferState(IiTryDefinitions.TransferState.FULLY_ENABLED);
        
        vm.prank(attacker);
        itry.transferFrom(victim, attacker, 500 ether);
        
        // VERIFY: Attacker successfully stole funds using permit from pause period
        assertEq(itry.balanceOf(attacker), 500 ether, "Attacker drained victim using permit from FULLY_DISABLED period");
        assertEq(itry.balanceOf(victim), 500 ether, "Victim lost funds");
    }
}
```

## Notes

This vulnerability demonstrates that the `FULLY_DISABLED` emergency pause is incomplete. While it prevents direct token transfers, it does not prevent users from setting up allowances via `permit()` that can be exploited immediately when the pause lifts. 

The attack is particularly dangerous during emergency scenarios where users might lower their guard, believing that the FULLY_DISABLED state provides complete protection. The same issue applies to the standard `approve()` function, which also bypasses `_beforeTokenTransfer()` checks.

The fix should ensure that both `permit()` and `approve()` respect the `transferState` to provide comprehensive emergency pause functionality.

### Citations

**File:** src/token/iTRY/iTry.sol (L15-21)
```text
contract iTry is
    ERC20BurnableUpgradeable,
    ERC20PermitUpgradeable,
    IiTryDefinitions,
    ReentrancyGuardUpgradeable,
    SingleAdminAccessControlUpgradeable
{
```

**File:** src/token/iTRY/iTry.sol (L169-175)
```text
     * @param code Admin can disable all transfers, allow limited addresses only, or fully enable transfers
     */
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L219-221)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```
