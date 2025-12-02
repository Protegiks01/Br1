# Validation Report: Cross-Chain Blacklist Desynchronization in iTRY OFT

## Summary

After rigorous validation against the Brix Money Protocol security framework, I confirm this is a **VALID HIGH SEVERITY** vulnerability. The `iTryTokenOFT` contract lacks the `_credit` override present in `wiTryOFT`, causing permanent fund loss when blacklist states are desynchronized across chains. Tokens are irreversibly burned on the source chain while the destination transfer reverts, violating the token conservation invariant.

## Severity

**HIGH** - Meets Code4rena criteria for direct, permanent loss of user funds with realistic likelihood.

## Vulnerability Confirmation

### Technical Analysis

**Cross-Chain Flow Breakdown:**

When a user on spoke chain (L2) sends iTRY back to hub chain (L1):

1. **Source Chain (L2) - Burn Phase:**
   - User calls `iTryTokenOFT.send()` which burns tokens
   - `_beforeTokenTransfer(user, address(0), amount)` checks if user is blacklisted on L2
   - If NOT blacklisted on L2: burn succeeds [1](#0-0) 

2. **Destination Chain (L1) - Unlock Phase:**
   - `iTryTokenOFTAdapter.lzReceive()` attempts to transfer tokens from adapter to user
   - `iTry._beforeTokenTransfer(adapter, user, amount)` checks if user has `BLACKLISTED_ROLE` on L1
   - If blacklisted on L1: check fails, reverts with `OperationNotAllowed` [2](#0-1) 

**Result:** Tokens permanently burned on L2, locked in adapter on L1, user cannot access them.

### Root Cause

The vulnerability stems from two architectural issues:

1. **Independent Blacklist Storage:** Each chain maintains its own blacklist with no synchronization mechanism [3](#0-2) 

2. **Missing Protection:** Unlike `wiTryOFT` which implements `_credit` override to redirect blacklisted recipients to the owner [4](#0-3) , `iTryTokenOFT` lacks this safeguard. The contract only implements `_beforeTokenTransfer` [5](#0-4)  which cannot prevent the destination chain revert.

### Validation Against Framework

✅ **Scope:** All affected files are in-scope (iTryTokenOFT.sol, iTryTokenOFTAdapter.sol, iTry.sol, wiTryOFT.sol)

✅ **Threat Model:** Does NOT require malicious admin behavior - blacklist desynchronization is a realistic operational scenario

✅ **Known Issues:** NOT listed in README lines 33-41. This is distinct from the allowance bypass issue (line 35)

✅ **Impact:** Permanent, irreversible loss of user funds - no recovery mechanism exists:
   - `redistributeLockedAmount` only works for tokens in user's balance, not adapter
   - Retrying LayerZero message continues to fail while blacklist remains active
   - User loses 100% of tokens in the failed transfer

✅ **Exploitability:** 
   - Attacker Profile: Affects legitimate users (not malicious attack)
   - Preconditions: User blacklisted on destination but not source (realistic)
   - Execution: Single cross-chain transaction
   - Likelihood: Medium-High (blacklisting for compliance may happen retroactively without coordination)

## Impact Analysis

**Affected Assets:** iTRY tokens on spoke chains where users are not locally blacklisted but are blacklisted on destination chains

**Damage Severity:** 100% permanent loss of transferred amount. Tokens burned on source chain with no mechanism to recover or unlock on destination chain.

**User Impact:** Any iTRY holder who:
- Holds tokens on a spoke chain where not blacklisted
- Gets blacklisted on hub/another spoke (without synchronized update)
- Attempts cross-chain transfer to the blacklisted chain

**Security Invariant Violated:** Token conservation across chains - tokens should never be destroyed on one chain without equivalent creation/unlock on another.

## Recommendation

Implement `_credit` override in `iTryTokenOFT` matching the pattern used in `wiTryOFT`:

```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    if (blacklisted[_to]) {
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

This prevents the revert, redirecting blacklisted recipients' funds to the protocol owner for proper handling while maintaining token conservation.

**Alternative long-term solutions:**
1. Cross-chain blacklist synchronization via LayerZero messages
2. Pre-flight destination blacklist verification
3. Shared blacklist registry accessible across all chains

## Notes

The existence of the `_credit` override in `wiTryOFT` demonstrates this is NOT intentional design - it's a protective pattern that should be consistently applied. The vulnerability represents a critical gap in iTRY's cross-chain architecture that `wiTRY` correctly addresses. This inconsistency creates an exploitable edge case with permanent financial consequences for users.

The manual blacklist management across chains without synchronization makes this scenario inevitable in production, especially when blacklisting occurs for regulatory/compliance reasons that may be applied retroactively.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L36-36)
```text
    mapping(address => bool) public blacklisted;
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-177)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L189-195)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
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
