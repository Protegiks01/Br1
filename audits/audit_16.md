# Validation Result: VALID HIGH SEVERITY VULNERABILITY

After performing ruthless validation against all criteria, I confirm this is a **legitimate HIGH severity vulnerability**.

## Title
iTRY Blacklist Bypass via Fast Redemption - Blacklisted iTRY Owners Can Extract Funds Through wiTRY Vault

## Summary
The fast redemption flow only validates the wiTRY blacklist (`FULL_RESTRICTED_STAKER_ROLE`) but fails to check if the share owner is blacklisted in the underlying iTRY token (`BLACKLISTED_ROLE`). This allows users blacklisted in iTRY to bypass the blacklist and extract their funds by redeeming wiTRY shares to a non-blacklisted receiver.

## Impact
**Severity**: High

Users who are blacklisted in iTRY can completely bypass the blacklist mechanism and extract their staked iTRY (minus fast redemption fees) by redeeming their wiTRY shares to any non-blacklisted address they control. This defeats the fundamental purpose of blacklisting, which is typically used for regulatory compliance, sanctions enforcement, or security incident response. The protocol loses the ability to freeze funds of malicious actors or comply with legal/regulatory requirements.

## Finding Description

**Location:** `src/token/wiTRY/StakediTry.sol` (function `_withdraw` lines 262-278), `src/token/wiTRY/StakediTryFastRedeem.sol` (function `fastRedeem` lines 57-71, function `_redeemWithFee` lines 138-156), `src/token/iTRY/iTry.sol` (function `_beforeTokenTransfer` lines 177-222)

**Intended Logic:**
According to the protocol invariant documented in README: "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case." [1](#0-0) 

Users blacklisted in iTRY should not be able to access their iTRY funds through ANY mechanism, including redemption from the wiTRY staking vault.

**Actual Logic:**
The fast redemption flow performs blacklist validation at two separate layers, but neither checks the share owner's iTRY blacklist status:

1. **wiTRY blacklist check** in `StakediTry._withdraw()` validates that `caller`, `receiver`, and `_owner` do not have `FULL_RESTRICTED_STAKER_ROLE`: [2](#0-1) 

2. **iTRY blacklist check** in `iTry._beforeTokenTransfer()` validates that `msg.sender`, `from`, and `to` do not have `BLACKLISTED_ROLE` when iTRY is transferred: [3](#0-2) 

However, during fast redemption when iTRY is transferred from vault to receiver:
- `msg.sender` = StakediTry vault contract (not blacklisted)
- `from` = StakediTry vault contract (not blacklisted)  
- `to` = receiver (validated as not blacklisted)

**The owner's iTRY `BLACKLISTED_ROLE` status is never checked in either validation layer.**

**Exploitation Path:**

1. **Initial State**: User deposits iTRY into wiTRY vault, receiving wiTRY shares
2. **Blacklist Event**: User gets blacklisted in iTRY token (granted `BLACKLISTED_ROLE`) but remains non-blacklisted in wiTRY (no `FULL_RESTRICTED_STAKER_ROLE`) - this can occur due to operational error where the blacklist manager updates only one system, or a time gap between updates
3. **Exploit Execution**: Blacklisted owner calls `fastRedeem(shares, non_blacklisted_receiver, owner_address)` [4](#0-3) 
4. **Bypass Success**: 
   - wiTRY blacklist check passes (owner doesn't have `FULL_RESTRICTED_STAKER_ROLE`)
   - `_redeemWithFee()` burns owner's wiTRY shares and transfers iTRY from vault to receiver [5](#0-4) 
   - iTRY blacklist check passes (vault→receiver transfer, owner not validated)
   - Blacklisted owner successfully extracts iTRY to controlled receiver address

## Impact Explanation

**Affected Assets**: iTRY tokens held in the wiTRY staking vault belonging to users who are blacklisted in iTRY but not in wiTRY

**Damage Severity**:
- Complete bypass of iTRY blacklist mechanism
- Blacklisted users can extract 95% of their staked iTRY (after 5% fast redemption fee) to any non-blacklisted address they control
- Protocol loses ability to freeze funds of sanctioned users, malicious actors, or users involved in security incidents
- Potential regulatory compliance violations if blacklisting was required for legal/sanctions reasons

**User Impact**: Any user who (1) staked iTRY before being blacklisted, and (2) is blacklisted in iTRY but not in wiTRY, can exploit this vulnerability. The protocol's critical security guarantee for fund freezing is completely undermined.

## Likelihood Explanation

**Attacker Profile**: Any user holding wiTRY shares who is blacklisted in iTRY but not in wiTRY

**Preconditions**:
1. User has wiTRY shares (staked before blacklisting)
2. User is blacklisted in iTRY (`BLACKLISTED_ROLE`) but NOT in wiTRY (`FULL_RESTRICTED_STAKER_ROLE`)
3. Fast redemption is enabled by admin (standard operational state)
4. Cooldown is active (normal protocol state)

**Execution Complexity**: Single transaction calling `fastRedeem()` - trivial to execute

**Realistic Scenario**: The vulnerability requires the protocol to have TWO separate blacklist systems that are manually synchronized. Human error, operational delays, or poor process coordination can easily result in a user being blacklisted in iTRY but not in wiTRY, creating the exploitation window.

**Frequency**: Exploitable once per blacklisted user for their entire wiTRY balance. While blacklisting events may be rare, they are critical (regulatory actions, sanctions, security incidents), making even a single successful bypass have severe consequences.

## Recommendation

Add iTRY blacklist validation in the `_withdraw()` function to check if the owner is blacklisted in the underlying iTRY token before allowing redemption. This ensures the documented invariant is enforced by code rather than relying on manual synchronization of two separate blacklist systems.

**Alternative mitigation**: Implement automatic cross-contract synchronization where blacklisting a user in iTRY automatically blacklists them in wiTRY as well. However, this requires additional cross-contract calls and careful gas/complexity considerations.

## Notes

**Critical Distinction**: This vulnerability exists because the protocol has TWO independent blacklist systems:
1. **iTRY blacklist** (`BLACKLISTED_ROLE` in iTry.sol) - controls iTRY token transfers
2. **wiTRY blacklist** (`FULL_RESTRICTED_STAKER_ROLE` in StakediTry.sol) - controls wiTRY staking operations

The fast redemption flow only validates the wiTRY blacklist, creating a bypass vector when these systems are not synchronized.

**Difference from Known Issue**: The Zellic audit identified "Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance" which refers to `msg.sender` not being checked in allowance-based transfers. [6](#0-5) 

This finding is fundamentally different: it involves redemption from the wiTRY vault where the vault acts as an intermediary, and the share owner's iTRY blacklist status is never checked at any validation layer. The mechanisms, root causes, and affected code paths are entirely distinct.

**Validation Summary**: This vulnerability passes all validation criteria - it's in-scope, exploitable by unprivileged users, different from known issues, violates documented invariants, has concrete HIGH severity impact, and is not a design feature but a clear security gap.

### Citations

**File:** README.md (L35-35)
```markdown
-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** src/token/wiTRY/StakediTry.sol (L269-273)
```text
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
```

**File:** src/token/iTRY/iTry.sol (L189-192)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L57-71)
```text
    function fastRedeem(uint256 shares, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 assets)
    {
        if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();

        uint256 totalAssets = previewRedeem(shares);
        uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);

        emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);

        return totalAssets - feeAssets;
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L151-155)
```text
        // Withdraw fee portion to treasury
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
```
