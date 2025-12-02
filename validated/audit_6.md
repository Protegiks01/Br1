Based on my comprehensive technical validation of this security claim, I can confirm this is a **VALID HIGH SEVERITY VULNERABILITY**.

## Title
wiTryOFTAdapter Permanently Locks Shares When Crediting to Blacklisted Users

## Summary
The `wiTryOFTAdapter` contract does not override the `_credit()` function to handle blacklisted recipients during cross-chain message receipt. When shares are bridged back to L1 for a user who was blacklisted after initially sending shares cross-chain, the adapter's unlock attempt will revert, permanently locking those shares in the adapter contract with no recovery mechanism available.

## Impact
**Severity**: High

Permanent loss of user funds (wiTRY shares) with no recovery path. This affects any user who bridges shares cross-chain and subsequently gets blacklisted for legitimate regulatory compliance reasons. The shares become permanently locked in the adapter with no owner-accessible rescue function, and cannot be redistributed via `redistributeLockedAmount` since that function only operates on user balances, not shares locked in the adapter.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The wiTryOFTAdapter should safely handle cross-chain transfers of wiTRY shares using a lock/unlock pattern, ensuring shares can always be returned to legitimate users or redistributed if users become blacklisted.

**Actual Logic:** The adapter uses the base LayerZero `OFTAdapter._credit()` implementation which performs a `safeTransfer()` to unlock shares. When the recipient has `FULL_RESTRICTED_STAKER_ROLE` (blacklisted), the transfer reverts due to StakediTry's `_beforeTokenTransfer` hook [2](#0-1) , causing shares to become permanently locked in the adapter.

**Exploitation Path:**
1. **User bridges shares L1→L2**: Alice bridges 100 wiTRY shares from L1 (Ethereum) to L2 (MegaETH) via `wiTryOFTAdapter.send()`. Adapter locks shares by transferring from Alice to adapter address. LayerZero message sent to L2, wiTryOFT mints shares to Alice on L2.

2. **User gets blacklisted**: Alice gets blacklisted on L1 (admin grants `FULL_RESTRICTED_STAKER_ROLE` due to regulatory reasons).

3. **User attempts to bridge back L2→L1**: Alice attempts to bridge shares back from L2 to L1. L2 wiTryOFT burns Alice's shares. LayerZero message delivered to L1 adapter's `lzReceive()`. Adapter calls `_credit(alice, 100 shares)` to unlock.

4. **Transfer reverts**: The `_credit()` internal call attempts `IERC20(token).safeTransfer(alice, 100 shares)`. StakediTry's `_beforeTokenTransfer` hook checks if recipient (`to`) has `FULL_RESTRICTED_STAKER_ROLE`. Since Alice is blacklisted, the hook reverts with `OperationNotAllowed()`. The LayerZero message fails, shares remain locked in adapter.

5. **No recovery possible**: The `redistributeLockedAmount` function [3](#0-2)  requires the `from` address to have `FULL_RESTRICTED_STAKER_ROLE`, but the adapter itself is not blacklisted—only Alice is. Therefore, this function cannot recover the shares. No rescue function exists in the adapter.

**Security Property Broken:** Violates the protocol's invariant that blacklisted users' funds can be managed through rescue mechanisms, as that function only works on user balances, not shares locked in the adapter contract.

## Impact Explanation

**Affected Assets**: wiTRY shares (ERC4626 vault shares representing staked iTRY)

**Damage Severity**:
- Complete permanent loss of bridged shares for any user blacklisted after initiating cross-chain transfer
- Shares locked in adapter with no owner-accessible rescue function
- Cannot be redistributed via `redistributeLockedAmount` since that only operates on user balances at line 170
- Each affected user loses 100% of their bridged shares

**User Impact**: Any user who bridges wiTRY shares cross-chain and subsequently gets blacklisted loses those shares permanently. This affects legitimate users who may be blacklisted for regulatory compliance reasons after their shares are already in transit or locked on L2.

**Trigger Conditions**: User must have bridged wiTRY shares from L1 to L2, then be blacklisted on L1 before returning shares.

## Likelihood Explanation

**Attacker Profile**: Not an intentional attack—affects any legitimate user who gets blacklisted after bridging shares.

**Preconditions**:
1. User must have bridged wiTRY shares from L1 to L2 (shares locked in adapter)
2. User must be added to `FULL_RESTRICTED_STAKER_ROLE` blacklist on L1 before returning shares
3. User attempts to bridge shares back from L2 to L1

**Execution Complexity**: Not an exploit—occurs through normal protocol operation when administrative action (blacklisting) occurs during cross-chain transfer lifecycle.

**Frequency**: Can occur for every user who gets blacklisted while having shares on L2, which could be multiple users given regulatory requirements for blacklisting.

**Overall Likelihood**: MEDIUM-HIGH - Blacklisting for regulatory compliance is a realistic scenario, and cross-chain transfers create a time window where this can occur.

## Recommendation

The wiTryOFTAdapter should override `_credit()` to mirror the protection logic already implemented in wiTryOFT on spoke chains [4](#0-3) :

**Recommended Fix:**

Add the following override to `wiTryOFTAdapter.sol`:

```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    IStakediTry vault = IStakediTry(address(innerToken));
    if (vault.hasRole(vault.FULL_RESTRICTED_STAKER_ROLE(), _to)) {
        emit FundsRedirectedFromBlacklistedUser(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}

event FundsRedirectedFromBlacklistedUser(address indexed blacklistedUser, address indexed redirectedTo, uint256 amount);
```

**Alternative Mitigation:**

Add a rescue function to the adapter that allows the owner to manually unlock shares for blacklisted users and redirect to a protocol-controlled address for proper redistribution.

## Notes

**Critical Asymmetry Identified:**
- The spoke chain implementation (`wiTryOFT`) has blacklist protection in `_credit()` that redirects tokens to the owner when crediting blacklisted users [4](#0-3) 
- The hub chain implementation (`wiTryOFTAdapter`) lacks this protection entirely [1](#0-0) 
- This asymmetry creates a permanent fund loss scenario unique to the hub chain

**Why Standard Recovery Mechanisms Fail:**
1. `redistributeLockedAmount` [3](#0-2)  requires the source address to have `FULL_RESTRICTED_STAKER_ROLE`—but the adapter itself is not blacklisted, only the user is
2. The adapter contract has no rescue or emergency withdrawal functions
3. LayerZero's base OFTAdapter does not include token recovery mechanisms

**Comparison with Similar Implementation:**
The `wiTryOFT` contract on spoke chains correctly handles this scenario by checking blacklist status and redirecting to owner, demonstrating that the developers were aware of this risk but failed to implement the same protection on the hub chain adapter.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L26-33)
```text
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/wiTRY/StakediTry.sol (L168-185)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && !hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            uint256 iTryToVest = previewRedeem(amountToDistribute);
            _burn(from, amountToDistribute);
            _checkMinShares();
            // to address of address(0) enables burning
            if (to == address(0)) {
                _updateVestingAmount(iTryToVest);
            } else {
                _mint(to, amountToDistribute);
            }

            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
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
