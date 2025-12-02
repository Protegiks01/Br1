# Validation Result: VALID Medium Severity Vulnerability

## Title
Whitelisted Users Can Mint iTRY to Non-Whitelisted Addresses in WHITELIST_ENABLED State, Violating Whitelist Enforcement Invariant

## Summary
The `mintFor` function in iTryIssuer allows whitelisted users to mint iTRY tokens to non-whitelisted recipients when the protocol is in WHITELIST_ENABLED state. This violates the documented invariant that "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" and results in tokens becoming locked until admin intervention. [1](#0-0) 

## Impact
**Severity**: Medium

This is a temporary fund lock issue that requires admin intervention to resolve. The minted tokens cannot be transferred or burned by the non-whitelisted recipient, defeating the purpose of WHITELIST_ENABLED mode which is designed to restrict iTRY circulation to a controlled set of whitelisted addresses only.

## Finding Description

**Location:** `src/protocol/iTryIssuer.sol` (mintFor function) and `src/token/iTRY/iTry.sol` (_beforeTokenTransfer function)

**Intended Logic:** 
According to the documented invariant, in WHITELIST_ENABLED state (TransferState = 1), iTRY tokens should only circulate among whitelisted addresses. The minting process should enforce that recipients are whitelisted to maintain the integrity of the whitelist system and comply with the stated security property. [1](#0-0) 

**Actual Logic:** 
The `mintFor` function only validates that the caller has `_WHITELISTED_USER_ROLE` but performs no validation on the recipient's whitelist status in the iTry token contract: [2](#0-1) 

The iTry token's `_beforeTokenTransfer` hook allows minting to any non-blacklisted address when called by a MINTER_CONTRACT, regardless of whether the recipient has WHITELISTED_ROLE in WHITELIST_ENABLED state: [3](#0-2) 

This contrasts sharply with normal transfers in WHITELIST_ENABLED state, which require ALL three parties (msg.sender, from, to) to be whitelisted: [4](#0-3) 

**Exploitation Path:**
1. Protocol is in WHITELIST_ENABLED state (one of three documented transfer states)
2. A whitelisted user calls `mintFor(nonWhitelistedAddress, dlfAmount, minAmountOut)` with a non-whitelisted but non-blacklisted recipient
3. The function passes access control checks and mints iTRY directly to the non-whitelisted address
4. The non-whitelisted recipient now holds iTRY tokens but cannot transfer them (requires all parties whitelisted) or burn them (requires msg.sender and from to be whitelisted)
5. Tokens remain locked until admin calls `addWhitelistAddress()` to whitelist the recipient [5](#0-4) 

**Security Property Broken:**
Violates the documented invariant: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." The "receive" component of this invariant is not enforced during minting operations.

## Impact Explanation

**Affected Assets**: iTRY tokens minted to non-whitelisted addresses become temporarily locked and unusable without admin intervention.

**Damage Severity**: 
- The tokens cannot be transferred or burned by the non-whitelisted recipient through normal means
- This defeats the purpose of WHITELIST_ENABLED mode, which is designed to restrict iTRY circulation to a controlled set of addresses
- Requires admin intervention (calling `addWhitelistAddress()`) to unlock the tokens [6](#0-5) 

**User Impact**: 
- Any whitelisted user can trigger this, either accidentally or maliciously (griefing)
- Non-whitelisted recipients inadvertently receive locked tokens
- The protocol's ability to enforce whitelist-only circulation is compromised
- Admin resources required to resolve each occurrence

## Likelihood Explanation

**Attacker Profile**: Any whitelisted user with the `_WHITELISTED_USER_ROLE` in iTryIssuer can exploit this

**Preconditions**: 
- Protocol must be in WHITELIST_ENABLED state (one of three documented operational modes) [7](#0-6) 

**Execution Complexity**: Single transaction - simply call `mintFor()` with a non-whitelisted recipient address

**Economic Cost**: Only gas fees, no capital lockup required

**Frequency**: Can be repeated continuously, with each occurrence locking more iTRY tokens

**Overall Likelihood**: Medium-High - Easy to trigger, common operational state

## Recommendation

**Primary Fix**: Add recipient whitelist validation in the iTry token's `_beforeTokenTransfer` function during minting operations when in WHITELIST_ENABLED state:

```solidity
// In src/token/iTRY/iTry.sol, line 201-202:
// CURRENT (vulnerable):
else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
    // minting
}

// FIXED:
else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - recipient must be whitelisted in WHITELIST_ENABLED state
}
```

**Alternative Fix**: Add validation in the `mintFor` function to check recipient whitelist status:

```solidity
// In src/protocol/iTryIssuer.sol, after line 277:
IiTryToken.TransferState currentState = iTryToken.transferState();
if (currentState == IiTryToken.TransferState.WHITELIST_ENABLED) {
    if (!iTryToken.hasRole(iTryToken.WHITELISTED_ROLE(), recipient)) {
        revert RecipientNotWhitelisted(recipient);
    }
}
```

## Notes

**Key Observations:**

1. **Two Separate Role Systems**: There is a disconnect between the access control in iTryIssuer (using `_WHITELISTED_USER_ROLE`) and transfer restrictions in iTry (using `WHITELISTED_ROLE`). These are managed independently through different functions:
   - iTryIssuer: `addToWhitelist()` grants `_WHITELISTED_USER_ROLE`
   - iTry: `addWhitelistAddress()` grants `WHITELISTED_ROLE` [8](#0-7) [6](#0-5) 

2. **Inconsistent Enforcement**: While normal transfers require all three parties (msg.sender, from, to) to be whitelisted in WHITELIST_ENABLED state, minting operations only check that the recipient is not blacklisted, creating an inconsistency in the security model.

3. **Recovery Mechanism**: Tokens are not permanently lost - an admin with WHITELIST_MANAGER_ROLE can call `addWhitelistAddress()` to grant WHITELISTED_ROLE to the recipient, after which they can transfer or burn their tokens. However, this requires manual intervention and violates the stated invariant.

4. **Distinct from Known Issues**: This is different from the known Zellic issue about blacklisted users transferring via allowance. This issue concerns whitelist enforcement during minting, not blacklist bypass via allowance.

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

**File:** src/token/iTRY/iTry.sol (L198-202)
```text
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
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
