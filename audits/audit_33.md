# Validation Result: VALID MEDIUM SEVERITY VULNERABILITY

## Title
Whitelist Enforcement Bypass in Minting Operations During WHITELIST_ENABLED State

## Summary
In WHITELIST_ENABLED state, the `_beforeTokenTransfer` validation in both `iTry.sol` and `iTryTokenOFT.sol` fails to enforce whitelist requirements for mint recipients, only checking they are not blacklisted. This allows whitelisted users to mint iTRY tokens to non-whitelisted addresses via `iTryIssuer.mintFor()`, directly violating the protocol's documented invariant that "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [1](#0-0) 

## Impact
**Severity**: Medium

**Rationale**: This vulnerability violates a documented protocol invariant regarding transfer state enforcement, representing a protocol correctness and compliance issue. While it does not result in direct fund theft or protocol insolvency (tokens are frozen in non-whitelisted addresses), it breaks the security guarantees that WHITELIST_ENABLED mode is designed to provide, creating regulatory and reputational risks.

## Finding Description

**Location:** 
- `src/token/iTRY/iTry.sol` lines 201-202, function `_beforeTokenTransfer()`
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` lines 160-161, function `_beforeTokenTransfer()`  
- `src/protocol/iTryIssuer.sol` lines 270-306, function `mintFor()`

**Intended Logic:**
According to the protocol's main invariants documentation: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [1](#0-0) 

This invariant should prevent any non-whitelisted address from receiving iTRY tokens when the protocol operates in compliance mode (TransferState.WHITELIST_ENABLED).

**Actual Logic:**
In WHITELIST_ENABLED state, the minting validation only checks that the recipient is NOT blacklisted, without verifying WHITELISTED_ROLE membership: [2](#0-1) [3](#0-2) 

Meanwhile, `iTryIssuer.mintFor()` accepts a `recipient` parameter without validating the recipient's whitelist status: [4](#0-3) 

**Exploitation Path:**
1. Protocol admin sets `transferState` to WHITELIST_ENABLED for regulatory compliance
2. Whitelisted user Alice (with WHITELISTED_USER_ROLE) calls `iTryIssuer.mintFor(bob_address, 1000e18, 0)` where Bob is NOT whitelisted
3. `mintFor` validates Alice has WHITELISTED_USER_ROLE but does NOT check if Bob is whitelisted
4. The function calls `_mint(recipient, iTRYAmount)` which internally calls `iTryToken.mint(receiver, amount)` [5](#0-4) 

5. In `_beforeTokenTransfer`, the minting validation passes with only `!hasRole(BLACKLISTED_ROLE, to)` check, missing whitelist verification
6. Bob (non-whitelisted) successfully receives iTRY tokens, violating the documented invariant
7. Bob cannot transfer the tokens while in WHITELIST_ENABLED state (frozen), but the invariant is already broken - he RECEIVED them when protocol guarantees say only whitelisted users can receive

**Inconsistency Evidence:**
Normal transfers in WHITELIST_ENABLED state correctly require ALL parties to be whitelisted: [6](#0-5) 

This creates an inconsistency: user-initiated transfers enforce whitelist requirements, but minting operations bypass them.

## Impact Explanation

**Affected Assets**: iTRY token integrity, protocol compliance guarantees

**Damage Severity**:
- Non-whitelisted addresses can accumulate iTRY balances during WHITELIST_ENABLED state, breaking KYC/AML compliance requirements
- If protocol later transitions to FULLY_ENABLED state, accumulated tokens in non-whitelisted addresses become freely transferable, bypassing the intended compliance gate
- Regulatory risk: Protocol claims "Only whitelisted user can send/receive/burn iTry tokens" but allows non-compliant users to hold tokens
- Reputational damage to protocol's compliance guarantees

**User Impact**: 
- Any whitelisted user can intentionally or accidentally mint to non-whitelisted addresses
- Protocol operators lose confidence in whitelist enforcement
- Potential regulatory violations for the protocol

**Mitigating Factors** (preventing High severity):
- Tokens are frozen in non-whitelisted addresses (cannot be transferred while in WHITELIST_ENABLED)
- No direct fund theft or protocol insolvency
- Requires whitelisted user action (more likely user error than malicious exploit)

## Likelihood Explanation

**Attacker Profile**: Any whitelisted user with minting privileges (WHITELISTED_USER_ROLE in iTryIssuer)

**Preconditions**:
- Protocol must be in WHITELIST_ENABLED state (TransferState = 1)
- User must have WHITELISTED_USER_ROLE
- User must have DLF collateral to mint iTRY

**Execution Complexity**: Single transaction - call `mintFor(non_whitelisted_address, amount, minOut)`

**Frequency**: Can be exploited continuously by any whitelisted minter

**Overall Likelihood**: High probability of occurrence given straightforward execution

## Recommendation

Add whitelist validation to minting operations in WHITELIST_ENABLED state.

**Primary Fix - iTry.sol (line 201):**
```solidity
// CURRENT:
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {

// FIXED:
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
```

**Primary Fix - iTryTokenOFT.sol (line 160):**
```solidity
// CURRENT:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {

// FIXED:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
```

**Defense in Depth - iTryIssuer.sol (after line 277):**
```solidity
// Add recipient validation
if (transferState == TransferState.WHITELIST_ENABLED) {
    require(iTryToken.hasRole(WHITELISTED_ROLE, recipient), "Recipient not whitelisted");
}
```

Apply the same fixes to admin redistribution operations: [7](#0-6) [8](#0-7) 

## Notes

**Scope Validation**: All affected contracts are in scope per scope.txt

**Not a Known Issue**: This specific bypass is not listed in the Zellic audit known issues (README lines 33-41)

**Severity Justification**: Medium severity is appropriate because:
- ✅ Violates documented protocol invariant
- ✅ Breaks compliance guarantees
- ✅ Straightforward to execute
- ❌ No direct fund theft or loss (tokens frozen)
- ❌ No protocol insolvency
- ❌ Primarily compliance/correctness issue rather than economic attack

This is a legitimate protocol correctness issue that should be fixed to maintain the integrity of WHITELIST_ENABLED state's security guarantees.

### Citations

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L205-207)
```text
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
```

**File:** src/token/iTRY/iTry.sol (L210-213)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L160-161)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L164-165)
```text
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
```

**File:** src/protocol/iTryIssuer.sol (L270-278)
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

**File:** src/protocol/iTryIssuer.sol (L576-579)
```text
    function _mint(address receiver, uint256 amount) internal {
        _totalIssuedITry += amount;
        iTryToken.mint(receiver, amount);
    }
```
