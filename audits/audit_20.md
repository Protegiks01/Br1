# VALID VULNERABILITY CONFIRMED

After rigorous validation against the Brix Money Protocol framework, this security claim is **VALID**.

## Title
FULL_RESTRICTED Users Can Bypass Staking Restriction Due to Incomplete Role Check in `_deposit`

## Summary
The `_deposit` function in `StakediTry.sol` only validates `SOFT_RESTRICTED_STAKER_ROLE` while omitting `FULL_RESTRICTED_STAKER_ROLE` checks, directly violating the documented invariant that FULL_RESTRICTED should prevent staking operations. This allows fully-restricted users to deposit iTRY tokens by minting shares to clean addresses they control, effectively bypassing administrative sanctions.

## Impact
**Severity**: Medium - Restriction Bypass

The vulnerability allows users with `FULL_RESTRICTED_STAKER_ROLE` to circumvent administrative sanctions by continuing to stake iTRY tokens and earn yield through the vault. While they cannot withdraw shares themselves, they can mint shares to secondary addresses under their control, effectively laundering their position through the vault and nullifying the intended restriction enforcement.

**Affected Assets**: wiTRY vault shares, iTRY tokens, protocol restriction integrity

**User Impact**: All users with `FULL_RESTRICTED_STAKER_ROLE` but not `SOFT_RESTRICTED_STAKER_ROLE` can bypass restrictions. The dual-role state management creates exploitable transitions when admins grant both roles and subsequently remove only one.

## Finding Description

**Location:** `src/token/wiTRY/StakediTry.sol` - lines 240-252, function `_deposit()`

**Intended Logic:**
According to the role definition comment, `FULL_RESTRICTED_STAKER_ROLE` should prevent an address from transferring, staking, or unstaking. [1](#0-0)  The `_deposit` function implements the staking operation for the ERC4626 vault and should therefore block users with FULL_RESTRICTED_STAKER_ROLE.

**Actual Logic:**
The `_deposit` function only validates `SOFT_RESTRICTED_STAKER_ROLE` for both caller and receiver, completely omitting `FULL_RESTRICTED_STAKER_ROLE` checks. [2](#0-1)  This creates an inconsistency where fully-restricted users can still deposit if they don't simultaneously hold the soft restriction.

**Exploitation Path:**

**Scenario A - Direct Assignment:**
1. Admin calls `addToBlacklist(maliciousUser, true)` which grants only `FULL_RESTRICTED_STAKER_ROLE` [3](#0-2) 
2. User calls `deposit(assets, receiverAddress)` where `receiverAddress` is a clean address controlled by the attacker
3. The `_deposit` check passes because neither caller nor receiver has `SOFT_RESTRICTED_STAKER_ROLE`
4. iTRY tokens are transferred from user to vault, wiTRY shares are minted to receiver, bypassing the restriction

**Scenario B - Dual Role with Partial Removal:**
1. Admin calls `addToBlacklist(user, false)` → user gets `SOFT_RESTRICTED_STAKER_ROLE`
2. Admin calls `addToBlacklist(user, true)` → user now has **both roles** (no mutual exclusivity enforcement)
3. User cannot deposit (blocked by SOFT check) ✓
4. Admin later calls `removeFromBlacklist(user, false)` → only removes `SOFT_RESTRICTED_STAKER_ROLE` [4](#0-3) 
5. User still has `FULL_RESTRICTED_STAKER_ROLE` but can now deposit! ✗

**Security Property Broken:**
The documented behavior that "FULL_RESTRICTED_STAKER_ROLE prevents staking" is violated due to inconsistent validation across the restriction enforcement system.

**Code Evidence - Inconsistency Across Functions:**

The `_withdraw` function correctly validates FULL_RESTRICTED for all three addresses: [5](#0-4) 

The `_beforeTokenTransfer` hook also checks FULL_RESTRICTED: [6](#0-5) 

However, `_beforeTokenTransfer` does NOT prevent minting shares to a clean receiver address when the caller has FULL_RESTRICTED, because during minting: `from = address(0)` (no role check) and `to = cleanReceiver` (no FULL_RESTRICTED role). This allows the bypass to succeed.

## Impact Explanation

**Damage Severity:**
- Restricted users can circumvent administrative sanctions by continuing to stake iTRY tokens through proxy addresses
- Admin-imposed restrictions become ineffective, undermining protocol governance
- Users can effectively "launder" their positions through the vault by depositing from restricted accounts to clean addresses
- While direct withdrawal is blocked, the attacker gains yield-earning shares under their control

**Trigger Conditions:**
- User has iTRY balance and approval for the vault
- User has `FULL_RESTRICTED_STAKER_ROLE` without `SOFT_RESTRICTED_STAKER_ROLE`
- User controls a secondary address (receiver) that is not restricted
- Single transaction execution

## Likelihood Explanation

**Attacker Profile:** Any user assigned `FULL_RESTRICTED_STAKER_ROLE` without `SOFT_RESTRICTED_STAKER_ROLE`, or users in dual-role states with partial role removal

**Preconditions:**
- User must have iTRY balance and vault approval (standard prerequisites)
- User must have `FULL_RESTRICTED_STAKER_ROLE` without `SOFT_RESTRICTED_STAKER_ROLE`
- User needs a secondary address that is not FULL_RESTRICTED (trivial - any new address)

**Execution Complexity:** Single transaction `deposit()` call - trivial to execute

**Frequency:** Repeatable until admin corrects role assignment by adding `SOFT_RESTRICTED_STAKER_ROLE` or enforcing mutual exclusivity

**Overall Likelihood:** HIGH - Easy to execute with minimal preconditions

## Recommendation

**Primary Fix:**
Add comprehensive role checks in the `_deposit` function to match documented behavior:

```solidity
// In src/token/wiTRY/StakediTry.sol, function _deposit, line 247:

// CURRENT (vulnerable):
if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
    revert OperationNotAllowed();
}

// FIXED:
if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver) ||
    hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)) {
    revert OperationNotAllowed();
}
```

**Alternative Mitigation:**
Enforce mutual exclusivity in `addToBlacklist` to prevent users from holding both roles simultaneously. When upgrading from SOFT to FULL restriction, automatically revoke the SOFT role:

```solidity
function addToBlacklist(address target, bool isFullBlacklisting) external onlyRole(BLACKLIST_MANAGER_ROLE) notOwner(target) {
    if (isFullBlacklisting) {
        // Revoke SOFT if granting FULL
        if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, target)) {
            _revokeRole(SOFT_RESTRICTED_STAKER_ROLE, target);
        }
        _grantRole(FULL_RESTRICTED_STAKER_ROLE, target);
    } else {
        _grantRole(SOFT_RESTRICTED_STAKER_ROLE, target);
    }
}
```

## Proof of Concept

The provided PoC demonstrates both exploitation scenarios:
1. Direct assignment of FULL_RESTRICTED without SOFT_RESTRICTED
2. Dual-role state with partial removal creating a bypass window

Both scenarios successfully demonstrate that FULL_RESTRICTED users can deposit to clean receiver addresses, violating the documented invariant.

## Notes

**Critical Observations:**

1. **Inconsistent Validation:** The `_withdraw` function properly checks FULL_RESTRICTED for caller, receiver, and owner, while `_deposit` only checks SOFT_RESTRICTED. This inconsistency is the root cause.

2. **Role Management Flaw:** The `addToBlacklist` and `removeFromBlacklist` functions don't enforce mutual exclusivity, allowing users to hold both roles simultaneously and creating exploitable state transitions.

3. **Test Suite Gap:** Existing tests in `StakediTry.redistributeLockedAmount.t.sol` deposit FIRST then restrict, never testing whether FULL_RESTRICTED users can deposit. This test gap indicates the oversight was not caught during development.

4. **Documentation vs. Implementation:** The comment explicitly states FULL_RESTRICTED prevents "transfer, stake, or unstake," but the implementation only enforces this for transfer and unstake, not stake (deposit).

This vulnerability represents a genuine security flaw where the documented security model is not correctly implemented in code, creating a restriction bypass that undermines administrative sanctions.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L29-30)
```text
    /// @notice The role which prevents an address to transfer, stake, or unstake. The owner of the contract can redirect address staking balance if an address is in full restricting mode.
    bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
```

**File:** src/token/wiTRY/StakediTry.sol (L126-133)
```text
    function addToBlacklist(address target, bool isFullBlacklisting)
        external
        onlyRole(BLACKLIST_MANAGER_ROLE)
        notOwner(target)
    {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _grantRole(role, target);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L140-143)
```text
    function removeFromBlacklist(address target, bool isFullBlacklisting) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _revokeRole(role, target);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L247-249)
```text
        if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/wiTRY/StakediTry.sol (L269-274)
```text
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/wiTRY/StakediTry.sol (L292-298)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
```
