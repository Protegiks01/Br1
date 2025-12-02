# Title
iTryTokenOFTAdapter Lacks Blacklist Protection in _credit Flow, Causing Permanent Fund Loss on Spoke-to-Hub Transfers

# Summary
The `iTryTokenOFTAdapter` contract inherits LayerZero's `OFTAdapter` without overriding the `_credit()` function to handle blacklisted recipients. When iTRY tokens are bridged from spoke chain to hub chain with a blacklisted recipient, the transfer reverts after tokens are already burned on the spoke chain, resulting in permanent fund loss. This vulnerability is particularly concerning because the protocol already implemented the correct fix pattern in `wiTryOFT`.

# Impact
**Severity**: High

This vulnerability causes direct and permanent loss of user funds through cross-chain transfers. When tokens are sent from spoke chain (e.g., MegaETH) to hub chain (Ethereum) to a blacklisted address, the tokens are irrecoverably burned on the source chain while the destination transfer fails. The adapter contract lacks any rescue mechanism, and the LayerZero message will perpetually fail upon retry since the recipient address is fixed in the message payload.

# Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The OFT adapter should facilitate bidirectional cross-chain iTRY transfers between hub and spoke chains while enforcing blacklist restrictions. According to the protocol invariant stated in the README: "Blacklisted users cannot send/receive/mint/burn iTRY tokens in any case." The system should gracefully prevent blacklisted users from receiving tokens without causing fund loss.

**Actual Logic:**
The `iTryTokenOFTAdapter` contract is a minimal wrapper that only defines a constructor and inherits all functionality from LayerZero's base `OFTAdapter`. Critically, it does NOT override the `_credit()` function. When the inherited `_credit()` executes during spoke-to-hub transfers, it attempts to transfer iTRY tokens from the adapter to the recipient. This transfer triggers iTRY's `_beforeTokenTransfer` hook, which enforces blacklist validation. [2](#0-1) 

The blacklist check will revert if the recipient (`to` parameter) has the `BLACKLISTED_ROLE`, causing the entire `lzReceive` transaction to fail. At this point, tokens are already burned on the spoke chain, creating an unrecoverable state.

**Exploitation Path:**
1. **Precondition**: Address Bob is blacklisted on hub chain (Ethereum) but not on spoke chain (MegaETH). Blacklist states are independent per chain.
2. **Action**: Alice on spoke chain initiates cross-chain transfer of 1000 iTRY to Bob on hub chain via `iTryTokenOFT.send()`
3. **Spoke Chain Execution**: The spoke chain `iTryTokenOFT._debit()` successfully burns Alice's 1000 iTRY tokens (no blacklist restriction on spoke for Bob)
4. **Message Transit**: LayerZero message transmitted from spoke to hub
5. **Hub Chain Failure**: 
   - `iTryTokenOFTAdapter.lzReceive()` processes the message
   - Inherited `_credit()` attempts: `iTry.transfer(Bob, 1000e18)`
   - `iTry._beforeTokenTransfer()` executes and detects Bob has `BLACKLISTED_ROLE`
   - Transaction reverts with `OperationNotAllowed()`
6. **Result**: 1000 iTRY permanently burned on spoke chain, 0 iTRY unlocked on hub chain, no recovery mechanism

**Security Property Broken:**
- **Invariant Violation**: README line 124 states "Blacklisted users cannot send/receive/mint/burn iTRY tokens in any case." The current implementation attempts to enforce this through reversion, but causes collateral damage (permanent user fund loss) rather than graceful rejection.
- **Inconsistent Implementation**: The protocol demonstrates awareness of this issue through the `wiTryOFT` implementation, which correctly handles blacklisted recipients by redirecting funds to the owner. [3](#0-2) 

# Impact Explanation

**Affected Assets**: All iTRY tokens transferred cross-chain from spoke to hub chain with blacklisted recipients

**Damage Severity**:
- 100% loss of transferred amount per transaction
- Tokens burned on spoke chain cannot be recovered
- Tokens remain locked in hub adapter balance but cannot be unlocked to blacklisted recipient
- No `rescueTokens()` function exists in `iTryTokenOFTAdapter`
- LayerZero message retry will perpetually fail since recipient address is immutable in the message payload

**User Impact**: 
- **Legitimate users**: Those blacklisted on hub but not on spoke who attempt to bridge their own funds
- **Accidental losses**: Users sending to wrong addresses that happen to be blacklisted
- **Griefing attacks**: Malicious actors can send tokens to victims' blacklisted addresses, causing irreversible loss
- **Cross-chain state desync**: Blacklist management is independent per chain, creating windows for exploitation

**Trigger Conditions**: Any spoke-to-hub cross-chain transfer where the recipient address has the `BLACKLISTED_ROLE` on the hub chain iTRY contract

# Likelihood Explanation

**Attacker Profile**: 
- Any user with access to spoke chain can trigger
- No special permissions required
- Can be used for griefing attacks against blacklisted addresses

**Preconditions**:
1. iTRY must be deployed and operational on spoke chain (design requirement)
2. Target address must have `BLACKLISTED_ROLE` on hub chain iTRY contract
3. Blacklist states differ between chains (inevitable due to independent contract deployments)
4. No requirement for special contract state or timing

**Execution Complexity**: 
- Single transaction: `iTryTokenOFT.send()` on spoke chain with blacklisted recipient parameter
- No front-running required
- No complex multi-step setup
- Economic cost: Standard cross-chain gas fees only (~$10-50)

**Frequency**: 
- Exploitable for every spoke-to-hub transfer to any blacklisted address
- Can be repeated indefinitely until fixed
- Affects all cross-chain iTRY transfers (core protocol functionality)

**Overall Likelihood**: HIGH - Trivially executable, affects fundamental cross-chain operations, no mitigations present

# Recommendation

**Primary Fix (Recommended):** Implement the same blacklist-aware `_credit()` override pattern already deployed in `wiTryOFT`:

```solidity
// Add to iTryTokenOFTAdapter.sol

function _credit(
    address _to,
    uint256 _amountLD,
    uint32 _srcEid
) internal virtual override returns (uint256 amountReceivedLD) {
    // Check if recipient is blacklisted on hub chain
    if (iTry(address(innerToken)).hasRole(
        iTry(address(innerToken)).BLACKLISTED_ROLE(), 
        _to
    )) {
        // Redirect to owner instead of reverting - maintains invariant without fund loss
        emit BlacklistedRecipientRedirect(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}

event BlacklistedRecipientRedirect(
    address indexed originalRecipient,
    address indexed actualRecipient,
    uint256 amount
);
```

This approach:
- ✅ Prevents blacklisted users from receiving tokens (maintains invariant)
- ✅ Prevents fund loss by redirecting to protocol owner
- ✅ Matches the proven pattern already deployed in `wiTryOFT`
- ✅ Emits events for transparency and off-chain monitoring
- ✅ Allows admin to later redistribute tokens appropriately

**Alternative Fix:** Add rescue functionality to `iTryTokenOFTAdapter`, but this is inferior because:
- ❌ Requires manual intervention per incident
- ❌ Doesn't prevent the failed state from occurring
- ❌ Creates operational overhead

**Why This Matters:** The existence of the correct implementation in `wiTryOFT` proves the protocol team is aware of this vulnerability pattern. The absence of the same protection in `iTryTokenOFTAdapter` represents an oversight rather than an intentional design choice.

# Notes

- **Distinct from Known Issues**: This vulnerability is explicitly different from the Zellic audit known issue about "Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance." That issue concerns same-chain transfers exploiting `msg.sender` validation, while this concerns cross-chain transfers where blacklist enforcement causes message failure and permanent fund loss.

- **Cross-Chain Blacklist Desynchronization**: The root cause is architectural - each chain maintains independent blacklist state. A user blacklisted on Ethereum (hub) may not be blacklisted on MegaETH (spoke), or vice versa. Additionally, blacklist status can change between message send and receipt due to time delays.

- **No Recovery Path**: Unlike temporary locks or admin-rescuable scenarios, this creates truly permanent loss because:
  1. Source chain tokens are burned (irreversible)
  2. Destination chain message fails (will always fail on retry due to immutable recipient in payload)
  3. No `rescueTokens()` exists in `iTryTokenOFTAdapter`
  4. Owner can't unilaterally transfer locked tokens from adapter

- **Protocol Precedent**: The `wiTryOFT` contract successfully implements the redirect pattern, demonstrating both awareness of the issue and a proven solution. The inconsistency between `wiTryOFT` (protected) and `iTryTokenOFTAdapter` (vulnerable) strongly suggests this is an implementation oversight.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-29)
```text
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
}
```

**File:** src/token/iTRY/iTry.sol (L189-196)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L84-97)
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
    }
```
