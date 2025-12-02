## Validation Result: VALID HIGH SEVERITY VULNERABILITY

After rigorous technical validation against the Brix Money Protocol codebase, I confirm this security claim is **technically valid**.

---

## Title
iTryTokenOFTAdapter Lacks Blacklist Protection in _credit Flow, Causing Permanent Fund Loss on Spoke-to-Hub Transfers

## Summary
The `iTryTokenOFTAdapter` contract fails to override LayerZero's `_credit()` function to handle blacklisted recipients. When iTRY tokens are bridged from spoke chain (MegaETH) to hub chain (Ethereum) with a blacklisted recipient, tokens are permanently burned on the source chain while the destination transfer reverts, resulting in irrecoverable fund loss. The protocol already implemented the correct mitigation pattern in `wiTryOFT`, making this an inconsistent implementation oversight.

## Impact
**Severity**: High

This vulnerability causes direct and permanent loss of user funds through cross-chain transfers. When tokens are sent from spoke to hub with a blacklisted recipient address, the tokens are irrecoverably burned on the source chain (via OFT `_debit()`), while the destination chain transfer fails during `_credit()` execution when `iTry._beforeTokenTransfer()` detects the blacklisted recipient. The adapter contract lacks rescue mechanisms, and LayerZero message retries will perpetually fail since the recipient address is immutable in the message payload. This affects any spoke-to-hub transfer where the recipient has `BLACKLISTED_ROLE` on the hub chain iTRY contract, regardless of their blacklist status on the spoke chain.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The OFT adapter should facilitate bidirectional cross-chain iTRY transfers between hub and spoke chains while enforcing the protocol invariant stated in README: "Blacklisted users cannot send/receive/mint/burn iTRY tokens in any case." The system should gracefully prevent blacklisted users from receiving tokens without causing fund loss to the sender.

**Actual Logic:**
The `iTryTokenOFTAdapter` contract inherits all functionality from LayerZero's base `OFTAdapter` without overriding `_credit()`. [1](#0-0)  During spoke-to-hub transfers, when the inherited `_credit()` executes, it attempts to transfer iTRY tokens from the adapter to the recipient. This triggers iTRY's `_beforeTokenTransfer` hook [2](#0-1) , which validates that neither `msg.sender`, `from`, nor `to` have `BLACKLISTED_ROLE`. If the recipient is blacklisted, the transaction reverts with `OperationNotAllowed()`, but tokens are already burned on the spoke chain.

**Exploitation Path:**
1. **Precondition**: Address Bob has `BLACKLISTED_ROLE` on hub chain (Ethereum) but not on spoke chain (MegaETH). Blacklist states are independent per chain deployment.
2. **Action**: Alice on spoke chain initiates cross-chain transfer of 1000 iTRY to Bob via `iTryTokenOFT.send(Bob, 1000e18, ...)`
3. **Spoke Execution**: LayerZero OFT base contract calls `_debit()`, which burns Alice's 1000 iTRY tokens (no blacklist check prevents Bob as recipient on spoke chain)
4. **Message Transit**: LayerZero message transmitted from spoke to hub containing Bob's address as recipient
5. **Hub Failure**: 
   - `iTryTokenOFTAdapter.lzReceive()` processes the message
   - Inherited `_credit()` attempts to transfer 1000 iTRY from adapter to Bob
   - `iTry._beforeTokenTransfer(adapter, Bob, 1000e18)` detects Bob has `BLACKLISTED_ROLE`
   - Transaction reverts with `OperationNotAllowed()`
6. **Result**: 1000 iTRY permanently burned on spoke chain, 0 iTRY unlocked on hub chain, no recovery possible

**Security Property Broken:**
The protocol invariant "Blacklisted users cannot send/receive/mint/burn iTRY tokens in any case" is enforced through reversion, but this creates collateral damage—permanent fund loss for the sender—rather than graceful rejection. The protocol demonstrates awareness of this issue through the `wiTryOFT` implementation [3](#0-2) , which correctly handles blacklisted recipients by redirecting funds to the owner instead of reverting.

## Impact Explanation

**Affected Assets**: All iTRY tokens transferred cross-chain from spoke to hub with blacklisted recipients

**Damage Severity**:
- 100% loss of transferred amount per transaction
- Tokens burned on spoke chain are cryptographically irreversible
- Tokens remain locked in hub adapter balance but cannot be unlocked to blacklisted recipient
- No `rescueTokens()` function exists in `iTryTokenOFTAdapter` (verified via code inspection)
- LayerZero message retry mechanism cannot succeed because the recipient address is encoded in the immutable message payload

**User Impact**: 
- **Legitimate users**: Those blacklisted on hub but not on spoke who attempt to bridge their own funds
- **Accidental losses**: Users sending to addresses that are blacklisted unknown to sender
- **Griefing attacks**: Malicious actors can intentionally send tokens to victims' blacklisted addresses, causing irreversible loss
- **Cross-chain state desync**: Blacklist management is independent per chain, creating inevitable windows for this vulnerability

**Trigger Conditions**: Any spoke-to-hub cross-chain transfer where the recipient address has `BLACKLISTED_ROLE` on the hub chain iTRY contract, executable by any user on spoke chain

## Likelihood Explanation

**Attacker Profile**: 
- Any user with access to spoke chain can trigger
- No special permissions or roles required
- Can be weaponized for griefing attacks against blacklisted addresses

**Preconditions**:
1. iTRY deployed and operational on spoke chain (required for protocol functionality)
2. Target address has `BLACKLISTED_ROLE` on hub chain iTRY contract
3. Blacklist states differ between chains (inevitable due to independent contract deployments and potential timing gaps)
4. No special contract state or timing requirements

**Execution Complexity**: 
- Single transaction on spoke chain: `iTryTokenOFT.send(blacklistedAddress, amount, ...)`
- No front-running, sandwich attacks, or complex multi-step setups required
- Economic cost: Standard LayerZero cross-chain gas fees only (~$10-50)

**Frequency**: 
- Exploitable for every spoke-to-hub transfer to any blacklisted address
- Repeatable indefinitely until patched
- Affects fundamental cross-chain operations (core protocol feature)

**Overall Likelihood**: HIGH - Trivially executable by any user, affects core cross-chain functionality, no mitigations present in current implementation

## Recommendation

**Primary Fix (Recommended):** Override `_credit()` in `iTryTokenOFTAdapter` using the same blacklist-aware pattern already deployed in `wiTryOFT`:

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

**Why This Works:**
- ✅ Prevents blacklisted users from receiving tokens (maintains protocol invariant)
- ✅ Prevents fund loss by redirecting to protocol owner for later resolution
- ✅ Matches proven pattern in `wiTryOFT` [3](#0-2) 
- ✅ Emits events for transparency and off-chain monitoring
- ✅ Allows admin to redistribute tokens appropriately after investigation

**Alternative Fix:** Add `rescueTokens()` functionality to `iTryTokenOFTAdapter`, but this is inferior because it requires manual intervention per incident, doesn't prevent the failed state, and creates operational overhead.

## Notes

**Distinct from Known Issues**: This vulnerability is explicitly different from the Zellic audit known issue (README line 35) about "Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance," which concerns same-chain transfers exploiting `msg.sender` validation. This finding concerns cross-chain transfers where blacklist enforcement causes message failure and permanent fund loss—a fundamentally different issue vector.

**No Recovery Path**: Unlike temporary locks or admin-rescuable scenarios, this creates truly permanent loss because:
1. Source chain tokens are burned via OFT `_debit()` (cryptographically irreversible)
2. Destination chain message will always fail on retry (immutable recipient in LayerZero message payload)
3. No `rescueTokens()` exists in `iTryTokenOFTAdapter`
4. Owner cannot unilaterally transfer locked tokens from adapter without fixing the contract

**Protocol Precedent**: The existence of the correct implementation in `wiTryOFT` [3](#0-2)  proves the protocol team is aware of this vulnerability pattern. The inconsistency between `wiTryOFT` (protected) and `iTryTokenOFTAdapter` (vulnerable) strongly suggests this is an implementation oversight rather than an intentional design choice.

**Additional Observation**: The same vulnerability pattern likely exists in `wiTryOFTAdapter` for wiTRY spoke→hub transfers, since `StakediTry` also enforces blacklist checks in `_beforeTokenTransfer` [4](#0-3) , though this specific claim focuses on iTRY transfers.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-28)
```text
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
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

**File:** src/token/wiTRY/StakediTry.sol (L292-299)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
    }
```
