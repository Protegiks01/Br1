# Validation Result: VALID Medium Severity Vulnerability

After performing ruthless technical validation against the Brix Money codebase, I confirm this is a **VALID Medium severity vulnerability**.

## Validation Summary

The claim correctly identifies that `mintFor` in iTryIssuer allows minting iTRY to non-whitelisted recipients during WHITELIST_ENABLED state, violating the documented invariant and resulting in locked tokens.

## Key Evidence Verified

**1. Documented Invariant Violation**

The protocol explicitly states: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [1](#0-0) 

The word "receive" is unambiguous - minting tokens TO an address constitutes receiving them.

**2. Two Separate Role Systems Confirmed**

The codebase uses two distinct whitelisting mechanisms:
- **iTryIssuer whitelist**: `_WHITELISTED_USER_ROLE = keccak256("WHITELISTED_USER_ROLE")` [2](#0-1) 
- **iTry token whitelist**: `WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE")` [3](#0-2) 

These hash to different values and are managed independently through different functions.

**3. mintFor Function Does Not Validate Recipient Whitelist Status**

The function only checks that the caller has `_WHITELISTED_USER_ROLE` but performs no validation on whether the recipient has `WHITELISTED_ROLE` in the iTry token: [4](#0-3) 

**4. Minting in WHITELIST_ENABLED State Allows Non-Whitelisted Recipients**

The `_beforeTokenTransfer` hook in iTry.sol permits minting to any non-blacklisted address when called by a MINTER_CONTRACT, regardless of recipient's WHITELISTED_ROLE: [5](#0-4) 

Line 201-202 checks: `hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)` - notably missing `hasRole(WHITELISTED_ROLE, to)`.

**5. Inconsistent with Normal Transfer Requirements**

In stark contrast, normal transfers in WHITELIST_ENABLED state require ALL parties to be whitelisted: [6](#0-5) 

**6. Non-Whitelisted Recipients Cannot Transfer or Burn**

Once tokens are minted to a non-whitelisted address:
- They cannot transfer (requires all parties whitelisted per lines 210-214)
- They cannot burn (requires msg.sender and from to be whitelisted): [7](#0-6) 

**7. Recovery Requires Admin Intervention**

Locked tokens can only be unlocked by calling `addWhitelistAddress()` with WHITELIST_MANAGER_ROLE: [8](#0-7) 

## Severity Justification: Medium

**Impact**: Temporary fund lock requiring admin intervention - tokens become unusable until recipient is whitelisted. This defeats the purpose of WHITELIST_ENABLED mode (restricting circulation to controlled addresses).

**Likelihood**: Medium-High
- Any whitelisted user can trigger
- Protocol must be in WHITELIST_ENABLED state (one of three normal operational modes): [9](#0-8) 
- Single transaction execution
- Repeatable continuously

Per Code4rena severity framework, temporary fund locks requiring intervention qualify as **Medium severity**.

## Not a Known Issue

This is distinct from the Zellic audit's known issue about "blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance." That issue concerns blacklist bypass via allowance, while this issue concerns **whitelist enforcement during minting operations**.

## Recommendation

Add recipient whitelist validation in the minting condition within `_beforeTokenTransfer` when in WHITELIST_ENABLED state:

```solidity
// Line 201-202 should be:
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) 
    && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - now requires recipient to be whitelisted
```

## Notes

This vulnerability passes all validation framework checks:
- ✅ In-scope files (iTryIssuer.sol, iTry.sol)
- ✅ No admin misbehavior required
- ✅ Not a known Zellic issue
- ✅ Violates documented invariant
- ✅ Unprivileged user can exploit (whitelisted user is normal user role)
- ✅ Complete execution path verified with line numbers
- ✅ Medium severity per C4 framework

The separation of whitelist role systems creates a security gap where iTryIssuer's minting authorization bypasses iTry's transfer restrictions, allowing tokens to enter addresses that cannot subsequently use them.

### Citations

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
