# Validation Result: VALID Medium Severity Vulnerability

After performing thorough validation against the Brix Money Protocol security framework, this claim is **VALID**.

## Summary

The `mintFor` function in iTryIssuer allows whitelisted users to mint iTRY tokens to non-whitelisted recipients in WHITELIST_ENABLED state, violating the documented invariant and causing temporary fund lock until admin intervention. [1](#0-0) 

## Core Issue Validation

**Invariant Violation Confirmed:**
The README explicitly states: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." The word "receive" is explicit and unambiguous. [1](#0-0) 

**Vulnerable Code Path:**

1. The `mintFor` function only validates the caller's role, not the recipient's whitelist status: [2](#0-1) 

2. The minting operation in WHITELIST_ENABLED state only checks that the recipient is not blacklisted, NOT that they are whitelisted: [3](#0-2) 

3. This contrasts with normal transfers which require ALL three parties to be whitelisted: [4](#0-3) 

4. Burns also require the user to be whitelisted: [5](#0-4) 

## Impact Analysis

**Severity: Medium** (per Code4rena framework - temporary loss requiring admin intervention)

**Concrete Impact:**
- Non-whitelisted recipients receive locked iTRY tokens in WHITELIST_ENABLED state
- Cannot transfer (requires all parties whitelisted)
- Cannot burn (requires whitelisted role)
- Cannot redeem via iTryIssuer (requires _WHITELISTED_USER_ROLE)
- Requires admin to call `addWhitelistAddress()` to unlock tokens [6](#0-5) 

**System Architecture Flaw:**
Two separate role systems create the vulnerability:
- iTryIssuer uses `_WHITELISTED_USER_ROLE` [7](#0-6) 
- iTry uses `WHITELISTED_ROLE` [6](#0-5) 

## Likelihood Assessment

- **Attacker Profile**: Any whitelisted user with `_WHITELISTED_USER_ROLE`
- **Preconditions**: Protocol in WHITELIST_ENABLED state (one of three operational modes) [8](#0-7) 
- **Execution**: Single transaction calling `mintFor()` with non-whitelisted recipient
- **Frequency**: Repeatable with each occurrence locking more tokens

## Validation Against Framework

✅ **Scope**: Both files in scope.txt  
✅ **Threat Model**: No admin misbehavior required  
✅ **Known Issues**: Not in Zellic audit known issues  
✅ **Invariant Violation**: Explicitly violates README invariant  
✅ **Impact**: Medium severity - temporary lock requiring intervention  
✅ **Execution Path**: Completely traced and verified  
✅ **Not Standard Behavior**: Custom Brix Money whitelist logic, not standard ERC20  

## Recommendation

**Primary Fix**: Add recipient whitelist validation in minting check:
```solidity
// In src/token/iTRY/iTry.sol, line 201-202:
else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) 
    && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - recipient must be whitelisted in WHITELIST_ENABLED state
}
```

**Alternative**: Add validation in `mintFor` to check recipient whitelist status before minting.

## Notes

This vulnerability represents an **inconsistent security model** where minting bypasses whitelist enforcement that normal transfers strictly enforce. The explicit invariant in the README, combined with the code inconsistency, confirms this is unintentional rather than by design. Recovery requires manual admin intervention for each occurrence, defeating the purpose of WHITELIST_ENABLED mode as a controlled circulation mechanism.

### Citations

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/protocol/iTryIssuer.sol (L270-277)
```text
    function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (uint256 iTRYAmount)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
```

**File:** src/protocol/iTryIssuer.sol (L553-555)
```text
    function addToWhitelist(address target) external onlyRole(_WHITELIST_MANAGER_ROLE) {
        _grantRole(_WHITELISTED_USER_ROLE, target);
    }
```

**File:** src/token/iTRY/iTry.sol (L92-95)
```text
    function addWhitelistAddress(address[] calldata users) external onlyRole(WHITELIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (!hasRole(BLACKLISTED_ROLE, users[i])) _grantRole(WHITELISTED_ROLE, users[i]);
        }
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L208-209)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
```

**File:** src/token/iTRY/iTry.sol (L210-214)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
```

**File:** src/token/iTRY/IiTryDefinitions.sol (L5-9)
```text
    enum TransferState {
        FULLY_DISABLED,
        WHITELIST_ENABLED,
        FULLY_ENABLED
    }
```
