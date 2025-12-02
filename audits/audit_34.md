# VALIDATION RESULT: VALID VULNERABILITY

## Title
Whitelist Enforcement Bypass During Cross-Chain Token Reception in WHITELIST_ENABLED State

## Summary
The `iTryTokenOFT` contract fails to verify whitelist status when minting tokens during cross-chain reception while in WHITELIST_ENABLED state. This allows non-whitelisted users to receive iTRY tokens via LayerZero cross-chain transfers, completely bypassing the whitelist enforcement mechanism that applies to normal transfers.

## Impact
**Severity**: High

This vulnerability violates a critical security invariant of the protocol. In WHITELIST_ENABLED state, the protocol intends to restrict iTRY token access to only approved (whitelisted) users, typically for regulatory compliance (KYC/AML) or controlled token distribution. By allowing non-whitelisted recipients to receive tokens through cross-chain transfers, the protocol cannot enforce its permissioned access model, creating legal, compliance, and security risks.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
In WHITELIST_ENABLED state, ONLY whitelisted users should be able to send, receive, or burn iTRY tokens. This is the documented security model for the protocol when operating in restricted mode.

**Actual Logic:**
The minting validation path (lines 160-161) only checks blacklist status, not whitelist status: [1](#0-0) 

In contrast, normal transfers require ALL parties to be whitelisted: [2](#0-1) 

**Exploitation Path:**
1. iTryTokenOFT on spoke chain (L2) is set to WHITELIST_ENABLED state
2. Alice (whitelisted on L1) initiates cross-chain transfer to Bob (NOT whitelisted on L2)
3. Hub chain adapter locks Alice's tokens and sends LayerZero message
4. LayerZero endpoint on L2 calls `lzReceive()` with Bob as recipient
5. Internally, `_credit()` calls `_mint(Bob, amount)` 
6. `_beforeTokenTransfer(address(0), Bob, amount)` executes with `msg.sender = endpoint` (which equals `minter` as set in constructor: [3](#0-2) )
7. Line 160 condition passes: `endpoint == minter` ✓, `from == address(0)` ✓, `!blacklisted[Bob]` ✓
8. Tokens successfully minted to non-whitelisted Bob, bypassing whitelist enforcement

**Security Property Broken:**
The protocol's documented invariant that "In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY" is violated because the receive path (cross-chain minting) bypasses whitelist verification.

## Impact Explanation

**Affected Assets**: iTRY tokens on spoke chain (L2) when in WHITELIST_ENABLED state

**Damage Severity**: 
- Complete bypass of whitelist access controls for cross-chain token reception
- Non-whitelisted users can accumulate iTRY tokens, undermining permissioned access model
- If whitelist is used for regulatory compliance (KYC/AML), creates legal and compliance risks
- Protocol cannot enforce controlled token distribution when accepting cross-chain transfers

**User Impact**: Any address can become recipient of cross-chain iTRY transfers regardless of whitelist status, affecting all users relying on whitelist enforcement

**Trigger Conditions**: Occurs on every cross-chain transfer to non-whitelisted recipient while contract is in WHITELIST_ENABLED state

## Likelihood Explanation

**Attacker Profile**: Any whitelisted user on L1, or coordination between whitelisted L1 user and non-whitelisted L2 recipient

**Preconditions**:
1. iTryTokenOFT on L2 is in WHITELIST_ENABLED state
2. At least one whitelisted user exists on L1 to initiate transfer

**Execution Complexity**: Single cross-chain transaction - whitelisted user on L1 calls `send()` with non-whitelisted L2 address as recipient

**Economic Cost**: Standard LayerZero cross-chain message fees only (~$10-50)

**Frequency**: Exploitable on every cross-chain transfer while in WHITELIST_ENABLED state

**Overall Likelihood**: HIGH - Simple execution, no special state required beyond protocol being in whitelist mode

## Recommendation

**Primary Fix:**
Add whitelist verification to the minting check in WHITELIST_ENABLED state:

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

**Alternative/Additional Mitigation:**
Consider adding validation in the hub chain adapter to check if the destination recipient is whitelisted before initiating the cross-chain transfer, though this requires cross-chain state synchronization.

## Proof of Concept

The provided PoC in the claim is incomplete as it doesn't properly simulate the cross-chain flow. However, the vulnerability is evident from code analysis by comparing:

1. Minting validation: [1](#0-0)  - only checks blacklist
2. Normal transfer validation: [2](#0-1)  - requires whitelist for all parties

The inconsistency is clear: while normal transfers enforce whitelist for all participants (lines 168-169), cross-chain minting only checks blacklist (lines 160-161), creating a bypass.

---

## Notes

**Important Context:**
1. The same pattern exists in the hub chain iTry.sol contract ( [4](#0-3) ), suggesting this may be a broader architectural issue rather than isolated to iTryTokenOFT
2. The minter is set to the LayerZero endpoint address in the constructor ( [3](#0-2) ), which means `msg.sender == minter` during cross-chain reception
3. This vulnerability only manifests when the contract is in WHITELIST_ENABLED state; in FULLY_ENABLED state, the behavior is as intended
4. The lack of test coverage for WHITELIST_ENABLED mode with cross-chain transfers likely contributed to this issue going undetected

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L51-53)
```text
    constructor(address _lzEndpoint, address _owner) OFT("iTry Token", "iTRY", _lzEndpoint, _owner) {
        transferState = TransferState.FULLY_ENABLED;
        minter = _lzEndpoint;
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
