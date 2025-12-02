# VALIDATION RESULT: VALID HIGH SEVERITY VULNERABILITY

After performing ruthless technical validation against the Brix Money Protocol framework, I confirm this is a **legitimate High severity vulnerability**.

## Title
Cross-Chain Whitelist State Mismatch Causes Permanent Loss of User Funds

## Summary
A critical vulnerability exists in `iTryTokenOFT.sol` where the minting validation in `WHITELIST_ENABLED` state only checks that recipients are not blacklisted but fails to verify whitelist status. This asymmetry allows LayerZero to mint iTRY tokens to non-whitelisted users during cross-chain transfers, but those users cannot subsequently transfer or burn their tokens, resulting in permanent fund loss with no recovery mechanism except admin intervention.

## Impact
**Severity**: High

Users bridging iTRY tokens from a hub chain in `FULLY_ENABLED` state to a spoke chain in `WHITELIST_ENABLED` state will have their funds permanently locked if they are not whitelisted on the destination chain. The tokens become trapped: locked in the adapter contract on the hub chain and frozen in an unusable state in the user's wallet on the spoke chain. This affects any regular user who bridges cross-chain without being aware of the spoke-side whitelist requirements, as the hub chain transaction proceeds normally without warning.

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol`, lines 157-172, specifically the minting validation at lines 160-161

**Intended Logic:** 
In `WHITELIST_ENABLED` state, the whitelist enforcement mechanism should ensure that ONLY whitelisted users can send, receive, or burn iTRY tokens. This protects users from receiving tokens they cannot use and maintains the security invariant that all token operations in this state require whitelist membership.

**Actual Logic:** 
The `_beforeTokenTransfer` function contains an asymmetric validation pattern: [1](#0-0) 

The minting path (lines 160-161) only validates `!blacklisted[to]`, allowing tokens to be minted to non-whitelisted addresses during cross-chain transfers.

However, burning and normal transfers require whitelist membership: [2](#0-1) 

This creates a one-way trap where tokens can enter a non-whitelisted wallet but can never leave.

**Exploitation Path:**
1. **Hub Setup**: Hub chain (Ethereum) has iTry in `FULLY_ENABLED` state
2. **Spoke Setup**: Spoke chain has iTryTokenOFT in `WHITELIST_ENABLED` state, User Alice not whitelisted on spoke
3. **Bridge to Spoke**: Alice calls `send()` on `iTryTokenOFTAdapter` to bridge 1000 iTRY from hub to spoke
4. **Tokens Locked**: iTryTokenOFTAdapter locks 1000 iTRY on hub chain
5. **Mint on Spoke**: LayerZero endpoint calls `lzReceive` → `_credit` → `_mint`. The `_beforeTokenTransfer` check passes because it only validates `!blacklisted[to]`, not `whitelisted[to]`. Alice receives 1000 iTRY on spoke.
6. **Cannot Transfer**: Alice attempts to transfer but the check at lines 168-169 requires `whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]` - transaction reverts
7. **Cannot Bridge Back**: Alice tries to bridge back but burn requires `whitelisted[msg.sender] && whitelisted[from]` (lines 166-167) - transaction reverts
8. **Permanent Loss**: Alice's 1000 iTRY is locked in adapter on hub and frozen in her spoke wallet

**Security Property Broken:** 
Violates the whitelist enforcement invariant that in `WHITELIST_ENABLED` state, ONLY whitelisted users can send/receive/burn iTRY. The contract allows non-whitelisted users to receive via cross-chain minting, breaking the invariant.

## Impact Explanation

**Affected Assets**: User iTRY tokens bridged from hub to spoke chain

**Damage Severity**: 
- 100% permanent loss of bridged amount for non-whitelisted users
- Tokens locked in adapter on hub chain (cannot be unlocked without burning on spoke)
- Tokens frozen in user wallet on spoke chain (cannot transfer or burn)
- No automated recovery mechanism exists

**User Impact**: Any user bridging from hub (FULLY_ENABLED or user whitelisted on hub) to spoke (WHITELIST_ENABLED) without being whitelisted on spoke loses their entire bridged amount. Users have no indication from the hub chain that the spoke chain has different whitelist requirements.

## Likelihood Explanation

**Attacker Profile**: Any regular user (not malicious) bridging tokens cross-chain

**Preconditions**: 
- Hub chain in `FULLY_ENABLED` (or user whitelisted on hub)
- Spoke chain in `WHITELIST_ENABLED` 
- User not whitelisted on spoke chain
- These are legitimate operational states, not misconfigurations

**Execution Complexity**: Single transaction calling standard OFT `send()` function

**Economic Cost**: Only gas fees, no special capital required

**Frequency**: Every cross-chain transfer by non-whitelisted users under state mismatch results in permanent fund loss

**Overall Likelihood**: HIGH - Simple execution, legitimate preconditions, affects regular users

## Recommendation

**Primary Fix - Add whitelist check to minting validation:**

Modify the minting validation in `WHITELIST_ENABLED` state to require whitelist membership:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, line 160:

// CURRENT (vulnerable):
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
    // minting
}

// FIXED:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - requires recipient to be whitelisted in WHITELIST_ENABLED state
}
```

**Alternative Mitigation - Implement `_credit` override:**

Following the pattern used in `wiTryOFT.sol`, override the `_credit` function to redirect tokens to owner if recipient is not whitelisted: [3](#0-2) 

Apply similar logic for whitelist validation in `WHITELIST_ENABLED` state.

**Additional Mitigation:**
- Document cross-chain whitelist requirements clearly
- Implement client-side checks before allowing bridge transactions
- Add events when tokens are redirected to owner

## Proof of Concept

The provided PoC is valid and should be runnable using the existing `CrossChainTestBase` infrastructure. It demonstrates:
1. Tokens successfully minted to non-whitelisted user on spoke chain
2. User cannot transfer tokens (requires whitelist)
3. User cannot burn tokens to bridge back (requires whitelist)
4. Funds permanently locked with no recovery path

## Notes

This vulnerability represents a critical asymmetry in validation logic. The key evidence confirming this is a bug rather than intended behavior:

1. **Differential Analysis**: The wiTRY cross-chain implementation (`wiTryOFT.sol`) includes a `_credit` override that redirects tokens to the owner if the recipient is blacklisted [3](#0-2) . This demonstrates awareness of the cross-chain validation issue, but `iTryTokenOFT.sol` lacks equivalent protection for whitelist enforcement.

2. **Asymmetric Validation**: The minting path only checks `!blacklisted[to]` while all other operations require `whitelisted[...]` checks, creating a one-way trap.

3. **No Documentation**: No documentation indicates this is intended behavior or warns users about cross-chain whitelist requirements.

4. **User Impact**: Regular users bridging from hub have no way to know spoke-side requirements, making this a dangerous footgun that causes permanent fund loss.

5. **Recovery Limitation**: Only the owner can recover funds via `redistributeLockedAmount()`, requiring manual intervention for each affected user.

The fix should ensure consistent whitelist validation across all token operations in `WHITELIST_ENABLED` state or implement a safety mechanism similar to `wiTryOFT._credit()`.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L160-161)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L166-169)
```text
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L84-96)
```text
    function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
        internal
        virtual
        override
        returns (uint256 amountReceivedLD)
    {
        // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
        if (blackList[_to]) {
            emit RedistributeFunds(_to, _amountLD);
            return super._credit(owner(), _amountLD, _srcEid);
        } else {
            return super._credit(_to, _amountLD, _srcEid);
        }
```
