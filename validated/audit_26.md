After rigorous validation against the Brix Money Protocol security framework, I confirm this is a **VALID Medium severity vulnerability**.

## Title
Whitelisted Users Can Mint iTRY to Non-Whitelisted Addresses in WHITELIST_ENABLED State, Violating Whitelist Enforcement Invariant

## Summary
The `mintFor` function in iTryIssuer allows whitelisted users to mint iTRY tokens to any non-blacklisted recipient, including non-whitelisted addresses. When the iTry token is in `WHITELIST_ENABLED` state, this violates the documented invariant that "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" by allowing non-whitelisted addresses to receive tokens. [1](#0-0) 

## Impact
**Severity**: Medium

This vulnerability creates a temporary fund lock scenario requiring admin intervention to resolve. Tokens minted to non-whitelisted addresses become unusable until the recipient is either whitelisted (enabling transfers/burns) or blacklisted (enabling recovery via `redistributeLockedAmount`). This defeats the purpose of WHITELIST_ENABLED mode and creates potential griefing vectors.

## Finding Description

**Location:** `src/protocol/iTryIssuer.sol` (mintFor function, lines 270-306) and `src/token/iTRY/iTry.sol` (_beforeTokenTransfer function, lines 177-222)

**Intended Logic:** 
In WHITELIST_ENABLED state, iTRY tokens should only circulate among whitelisted addresses. The protocol invariant explicitly states: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [1](#0-0) 

**Actual Logic:** 

The `mintFor` function only validates that the caller has `_WHITELISTED_USER_ROLE` but performs no validation of the recipient's whitelist status: [2](#0-1) 

The iTry token's `_beforeTokenTransfer` hook permits minting to any non-blacklisted address when called by a MINTER_CONTRACT, regardless of whether the recipient is whitelisted in WHITELIST_ENABLED state: [3](#0-2) 

**Exploitation Path:**
1. Protocol is in WHITELIST_ENABLED state (TransferState = 1) [4](#0-3) 

2. A whitelisted user calls `mintFor(nonWhitelistedAddress, dlfAmount, minAmountOut)` with a non-whitelisted but non-blacklisted recipient
3. The function passes access control (caller is whitelisted in issuer) and mints iTRY directly to the non-whitelisted address
4. The non-whitelisted recipient now holds iTRY tokens but cannot transfer them (requires all parties to be whitelisted) or burn them (requires whitelisted status) [5](#0-4) 

**Security Property Broken:** 
Violates the documented invariant that "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." The "receive" component of this invariant is not enforced during minting operations.

## Impact Explanation

**Affected Assets**: iTRY tokens minted to non-whitelisted addresses become locked and unusable

**Damage Severity**:
- Tokens cannot be transferred (requires all parties whitelisted) or burned (requires sender whitelisted) by the non-whitelisted recipient
- Protocol's ability to enforce whitelist-only circulation is compromised
- Tokens remain locked until admin intervention (whitelisting recipient or blacklisting + redistribution)
- Creates griefing vector where whitelisted users can intentionally or accidentally lock tokens

**User Impact**: 
- Any whitelisted user can trigger this (maliciously or accidentally)
- Non-whitelisted recipients inadvertently receive unusable tokens
- Requires admin intervention to resolve, adding operational overhead

**Trigger Conditions**: Single transaction by any whitelisted user when protocol is in WHITELIST_ENABLED state

## Likelihood Explanation

**Attacker Profile**: Any whitelisted user can exploit this, either maliciously (griefing) or accidentally (user error)

**Preconditions**:
1. Protocol must be in WHITELIST_ENABLED state (one of three documented operational modes)
2. User must have `_WHITELISTED_USER_ROLE` in iTryIssuer contract

**Execution Complexity**: Single transaction calling `mintFor()` with a non-whitelisted recipient address

**Frequency**: Can be repeated continuously, with each occurrence locking more iTRY tokens until admin intervention

**Overall Likelihood**: Medium - Requires specific transfer state but can be triggered by any whitelisted user with single transaction

## Recommendation

**Primary Fix - Add recipient validation in iTryIssuer:**
Modify the `mintFor` function to validate that the recipient is whitelisted when the token is in WHITELIST_ENABLED state:

```solidity
function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
    public
    onlyRole(_WHITELISTED_USER_ROLE)
    nonReentrant
    returns (uint256 iTRYAmount)
{
    if (recipient == address(0)) revert CommonErrors.ZeroAddress();
    
    // Validate recipient whitelist status when protocol enforces whitelist
    IiTryToken.TransferState currentState = iTryToken.transferState();
    if (currentState == IiTryToken.TransferState.WHITELIST_ENABLED) {
        if (!iTryToken.hasRole(iTryToken.WHITELISTED_ROLE(), recipient)) {
            revert RecipientNotWhitelisted(recipient);
        }
    }
    
    // ... rest of function
}
```

**Alternative Fix - Modify token contract:**
Enhance the iTry token's `_beforeTokenTransfer` to require recipient whitelist status during minting in WHITELIST_ENABLED state:

```solidity
// Line 201-202 modification:
else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) 
    && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - recipient must be whitelisted in WHITELIST_ENABLED state
}
```

## Notes

**Root Cause Analysis:**
This vulnerability arises from a disconnect between two separate whitelist systems:

1. iTryIssuer uses `_WHITELISTED_USER_ROLE` to control who can call mint/redeem functions [6](#0-5) 

2. iTry token uses `WHITELISTED_ROLE` to control who can send/receive/burn in WHITELIST_ENABLED state [7](#0-6) 

The issuer checks the caller's whitelist status but not the recipient's whitelist status in the token contract.

**Recovery Mechanisms:**
While tokens become locked, they are not permanently lost. Admins can recover via:
- Whitelisting the recipient (enables transfers/burns)
- Blacklisting the recipient and using `redistributeLockedAmount`

**Distinction from Known Issues:**
This is distinct from the known issue "Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance" which concerns allowance-based transfers by blacklisted users, not minting to non-whitelisted recipients. [8](#0-7)

### Citations

**File:** README.md (L35-35)
```markdown
-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
```

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/protocol/iTryIssuer.sol (L109-110)
```text
    /// @notice Role for whitelisted users who can mint and redeem iTRY
    bytes32 private constant _WHITELISTED_USER_ROLE = keccak256("WHITELISTED_USER_ROLE");
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

**File:** src/token/iTRY/iTry.sol (L32-33)
```text
    /// @notice During transferState 1, whitelisted role can still transfer
    bytes32 public constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L208-214)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
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
