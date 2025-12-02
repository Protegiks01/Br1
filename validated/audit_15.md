After rigorous validation against the Brix Money Protocol security framework, I confirm this is a **VALID Medium severity vulnerability**.

## Validation Summary

This security claim **PASSES ALL VALIDATION CHECKS** and represents a genuine vulnerability in the Brix Money Protocol.

## Title
Whitelisted Users Can Mint iTRY to Non-Whitelisted Addresses in WHITELIST_ENABLED State, Violating Whitelist Enforcement Invariant

## Summary
The `mintFor` function allows whitelisted users to mint iTRY tokens to non-whitelisted recipients when the protocol is in `WHITELIST_ENABLED` state. This directly violates the documented invariant and creates a fund lock scenario requiring admin intervention. The vulnerability arises from a disconnect between two separate whitelist systems: iTryIssuer's `_WHITELISTED_USER_ROLE` (controlling who can mint) and iTry token's `WHITELISTED_ROLE` (controlling who can receive/transfer in WHITELIST_ENABLED state).

## Impact
**Severity**: Medium

The vulnerability creates a temporary fund lock scenario. Tokens minted to non-whitelisted addresses become unusable—recipients cannot transfer them (requires all parties whitelisted) or burn them (requires sender whitelisted). Recovery requires admin intervention to either whitelist the recipient or blacklist them and use `redistributeLockedAmount`. This defeats the purpose of WHITELIST_ENABLED mode and creates a griefing vector. [1](#0-0) 

## Finding Description

**Location:** `src/protocol/iTryIssuer.sol` (mintFor function) and `src/token/iTRY/iTry.sol` (_beforeTokenTransfer function)

**Intended Logic:** 
The protocol invariant explicitly states: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [1](#0-0)  In WHITELIST_ENABLED state, iTRY tokens should only circulate among addresses with the `WHITELISTED_ROLE`.

**Actual Logic:**

The `mintFor` function only validates that the caller has `_WHITELISTED_USER_ROLE` but performs no validation of the recipient's whitelist status: [2](#0-1) 

The iTry token's `_beforeTokenTransfer` hook in WHITELIST_ENABLED state permits minting to any non-blacklisted address, regardless of whether the recipient has `WHITELISTED_ROLE`: [3](#0-2) 

However, once tokens are minted to a non-whitelisted address, that recipient cannot use them because transfers require all parties to have `WHITELISTED_ROLE`: [4](#0-3) 

And burning requires the sender to have `WHITELISTED_ROLE`: [5](#0-4) 

**Exploitation Path:**
1. Protocol is in WHITELIST_ENABLED state (TransferState = 1)
2. Alice (whitelisted user with `_WHITELISTED_USER_ROLE` in iTryIssuer) calls `mintFor(bob, 1000e18, 990e18)` where Bob does NOT have `WHITELISTED_ROLE` in iTry token
3. Function passes access control checks (Alice is whitelisted in issuer, Bob is not blacklisted)
4. iTRY tokens are minted to Bob
5. Bob cannot transfer or burn these tokens because he lacks `WHITELISTED_ROLE`
6. Tokens remain locked until admin whitelists Bob or blacklists him and uses `redistributeLockedAmount` [6](#0-5) 

**Security Property Broken:** 
Violates the invariant's "receive" component: non-whitelisted users can receive tokens via minting in WHITELIST_ENABLED state, contradicting the documented requirement.

## Impact Explanation

**Affected Assets**: iTRY tokens minted to non-whitelisted addresses

**Damage Severity**:
- Tokens cannot be transferred (requires all parties whitelisted) or burned (requires sender whitelisted) by the non-whitelisted recipient
- Protocol's ability to enforce whitelist-only circulation is compromised
- Tokens remain locked until admin intervention (whitelisting recipient or blacklisting + redistribution)
- Creates griefing vector where whitelisted users can intentionally or accidentally lock tokens
- Directly impacts the protocol's stated area of concern: "blacklist/whitelist bugs that would impair rescue operations" [7](#0-6) 

**User Impact**: 
- Any whitelisted user can trigger this (maliciously or accidentally)
- Non-whitelisted recipients inadvertently receive unusable tokens
- Requires admin intervention to resolve

**Trigger Conditions**: Single transaction by any whitelisted user when protocol is in WHITELIST_ENABLED state

## Likelihood Explanation

**Attacker Profile**: Any whitelisted user (not a trusted admin role) can exploit this

**Preconditions**:
1. Protocol in WHITELIST_ENABLED state (one of three operational modes)
2. User has `_WHITELISTED_USER_ROLE` in iTryIssuer [8](#0-7) 

**Execution Complexity**: Single transaction calling `mintFor()` with non-whitelisted recipient

**Frequency**: Repeatable continuously until admin intervention

**Overall Likelihood**: Medium - Requires specific transfer state but trivial to execute

## Recommendation

**Primary Fix - Add recipient validation in iTryIssuer:**
Modify the `mintFor` function to validate that the recipient has `WHITELISTED_ROLE` when the token is in WHITELIST_ENABLED state by querying the iTry token contract and checking the recipient's role status before proceeding with minting.

**Alternative Fix - Modify token contract:**
Enhance the iTry token's `_beforeTokenTransfer` at line 201-202 to require recipient `WHITELISTED_ROLE` during minting in WHITELIST_ENABLED state, making the check: `hasRole(WHITELISTED_ROLE, to)` in addition to the existing `!hasRole(BLACKLISTED_ROLE, to)`.

## Notes

**Root Cause Analysis:**
This vulnerability arises from a disconnect between two separate whitelist systems:
1. iTryIssuer uses `_WHITELISTED_USER_ROLE` to control who can call mint/redeem functions [8](#0-7) 
2. iTry token uses `WHITELISTED_ROLE` to control who can send/receive/burn in WHITELIST_ENABLED state [9](#0-8) 

The issuer checks the caller's whitelist status but not the recipient's whitelist status in the token contract.

**Recovery Mechanisms:**
Tokens are recoverable (not permanently lost) via admin intervention:
- Whitelisting the recipient (enables transfers/burns)
- Blacklisting the recipient and using `redistributeLockedAmount` [6](#0-5) 

**Distinction from Known Issues:**
This is distinct from the known issue about blacklisted users using allowances [10](#0-9) , which concerns allowance-based transfers by blacklisted users, not minting to non-whitelisted recipients in WHITELIST_ENABLED state.

**Validation Confirmation:**
- ✅ In-scope files (iTryIssuer.sol, iTry.sol)
- ✅ No trusted role misbehavior required
- ✅ Not a known issue
- ✅ Violates documented invariant
- ✅ Medium severity per Code4rena framework (temporary fund lock)
- ✅ Directly impacts stated area of concern (whitelist bugs)

### Citations

**File:** README.md (L35-35)
```markdown
-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
```

**File:** README.md (L111-112)
```markdown

The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events. More generally, the areas we want to verify are:
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

**File:** src/token/iTRY/iTry.sol (L112-120)
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
