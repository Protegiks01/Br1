After performing comprehensive validation against the Brix Money Protocol validation framework, I confirm this is a **VALID VULNERABILITY**.

## Title
Whitelist Enforcement Bypass During Cross-Chain Token Reception in WHITELIST_ENABLED State

## Summary
The `iTryTokenOFT` contract fails to verify whitelist status when minting tokens during cross-chain reception while in WHITELIST_ENABLED state. This allows non-whitelisted users to receive iTRY tokens via LayerZero transfers, directly violating the protocol's documented main invariant that "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state."

## Impact
**Severity**: High

This vulnerability violates a critical main invariant explicitly documented in the protocol's README. [1](#0-0)  When the contract operates in WHITELIST_ENABLED state for regulatory compliance (KYC/AML) or controlled distribution, non-whitelisted users can still receive iTRY through cross-chain transfers. This creates legal compliance risks and completely undermines the permissioned access model that the whitelist feature is designed to enforce. The protocol explicitly lists "blacklist/whitelist bugs" as a primary area of concern. [2](#0-1) 

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol`, function `_beforeTokenTransfer()`

**Intended Logic:**
Per the documented main invariant, in WHITELIST_ENABLED state, ONLY whitelisted users should be able to send, receive, or burn iTRY tokens. This applies universally to all transfer paths including cross-chain reception.

**Actual Logic:**
The minting validation path only checks blacklist status, not whitelist status: [3](#0-2) 

In contrast, normal transfers require ALL parties including the recipient to be whitelisted: [4](#0-3) 

**Exploitation Path:**
1. **Setup**: iTryTokenOFT on spoke chain (L2) is in WHITELIST_ENABLED state
2. **Trigger**: Alice (whitelisted on L1) calls `send()` on iTryTokenOFTAdapter with Bob (NOT whitelisted on L2) as recipient
3. **State Change**: Hub chain adapter locks Alice's tokens and sends LayerZero message to L2
4. **Reception**: LayerZero endpoint on L2 calls `lzReceive()` which internally calls `_mint(Bob, amount)`
5. **Validation**: `_beforeTokenTransfer(address(0), Bob, amount)` executes with `msg.sender = endpoint` (which equals `minter` per constructor) [5](#0-4) 
6. **Bypass**: Line 160 condition passes: `endpoint == minter` ✓, `from == address(0)` ✓, `!blacklisted[Bob]` ✓
7. **Result**: Tokens successfully minted to non-whitelisted Bob, completely bypassing whitelist enforcement

**Security Invariant Broken:** [1](#0-0) 

## Impact Explanation

**Affected Assets**: iTRY tokens on spoke chains when in WHITELIST_ENABLED state

**Damage Severity**:
- Complete bypass of whitelist access controls for cross-chain token reception
- Non-whitelisted users can accumulate iTRY tokens through cross-chain transfers
- If whitelist is used for regulatory compliance (KYC/AML requirements), creates legal liability
- Protocol cannot enforce controlled token distribution when accepting cross-chain transfers
- Undermines the entire purpose of the WHITELIST_ENABLED state

**User Impact**: Any address can become recipient of cross-chain iTRY transfers regardless of whitelist status, affecting all users who rely on whitelist enforcement for compliance

**Trigger Conditions**: Occurs on every cross-chain transfer to non-whitelisted recipient while contract is in WHITELIST_ENABLED state

## Likelihood Explanation

**Attacker Profile**: Any whitelisted user on L1, or coordination between whitelisted L1 user and non-whitelisted L2 recipient

**Preconditions**:
1. iTryTokenOFT on L2 is in WHITELIST_ENABLED state (realistic operational state)
2. At least one whitelisted user exists on L1 to initiate transfer (required for protocol operation)

**Execution Complexity**: Single cross-chain transaction - whitelisted user on L1 calls `send()` with non-whitelisted L2 address as recipient

**Economic Cost**: Standard LayerZero cross-chain message fees only (~$10-50), no special capital required

**Frequency**: Exploitable on every cross-chain transfer while in WHITELIST_ENABLED state, unlimited repetition

**Overall Likelihood**: HIGH - Trivial execution, no special state manipulation required beyond normal cross-chain transfer

## Recommendation

**Primary Fix:**
Add whitelist verification to the minting check in WHITELIST_ENABLED state in `_beforeTokenTransfer()`:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, line 160-161:

// CURRENT (vulnerable):
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
    // minting
}

// FIXED:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - now requires recipient to be whitelisted in WHITELIST_ENABLED state
}
```

**Additional Mitigation:**
Consider implementing invariant tests that verify whitelist enforcement across all token transfer paths including cross-chain reception.

## Proof of Concept

The vulnerability is evident from code analysis comparing the two validation paths:

1. **Cross-chain minting** (vulnerable path): [3](#0-2)  - only checks `!blacklisted[to]`

2. **Normal transfers** (correct path): [4](#0-3)  - requires `whitelisted[to]`

The inconsistency creates a bypass: while normal transfers enforce whitelist for all participants, cross-chain minting only checks blacklist, allowing non-whitelisted users to receive iTRY tokens via LayerZero transfers.

---

## Notes

**Critical Context:**
1. The same pattern exists in the hub chain `iTry.sol` contract [6](#0-5)  suggesting this may be a broader architectural issue
2. The minter role is set to the LayerZero endpoint in the constructor [7](#0-6)  which means `msg.sender == minter` during cross-chain reception
3. This vulnerability only manifests in WHITELIST_ENABLED state; FULLY_ENABLED state behavior is as intended
4. This is NOT a "minter acting maliciously" issue - the minter (endpoint) automatically processes messages; the BUG is in the validation logic that should check whitelist but doesn't
5. Once received, non-whitelisted users can also send tokens back cross-chain since the redemption path has the same gap [8](#0-7)  allowing full cross-chain functionality

### Citations

**File:** README.md (L112-112)
```markdown
The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events. More generally, the areas we want to verify are:
```

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L51-53)
```text
    constructor(address _lzEndpoint, address _owner) OFT("iTry Token", "iTRY", _lzEndpoint, _owner) {
        transferState = TransferState.FULLY_ENABLED;
        minter = _lzEndpoint;
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L158-159)
```text
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L160-161)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L168-169)
```text
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```
