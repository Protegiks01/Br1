# NoVulnerability found for this question.

## Analysis Summary

After thoroughly investigating the `fastWithdraw()` return value, I conclude that returning `totalShares` is **correct** and there is no vulnerability.

## Key Findings

**Documentation Consistency:**
The interface explicitly documents the return value as "Total shares burned" [1](#0-0) , which matches the implementation [2](#0-1) .

**Accurate Accounting:**
The function calculates `totalShares = previewWithdraw(assets)`, then `_redeemWithFee` splits this into `feeShares` (to treasury) and `netShares` (to receiver) [3](#0-2) . Both portions are burned from the owner's balance via separate `_withdraw` calls, meaning `totalShares = feeShares + netShares` represents the actual shares deducted.

**Intentional Design Pattern:**
The codebase follows a consistent pattern:
- Functions returning **assets** → return NET amount (what receiver gets) [4](#0-3) 
- Functions returning **shares** → return TOTAL amount (what owner pays) [2](#0-1) 

**No Exploit Path:**
Returning `netShares` would be **incorrect** because:
1. It wouldn't match what's actually burned from the owner's balance (`totalShares`)
2. It wouldn't match allowance deductions (both `_withdraw` calls consume allowance totaling `totalShares`)
3. External integrations using the return value for accounting would receive inaccurate information

The current implementation correctly reflects the total cost to the owner and is properly documented.

### Citations

**File:** src/token/wiTRY/interfaces/IStakediTryFastRedeem.sol (L41-48)
```text
    /**
     * @notice Fast withdraw assets for immediate withdrawal with a fee
     * @param assets Amount of assets to withdraw (gross, before fee)
     * @param receiver Address to receive the net assets
     * @param owner Address that owns the shares being burned
     * @return shares Total shares burned
     */
    function fastWithdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L76-90)
```text
    function fastWithdraw(uint256 assets, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 shares)
    {
        if (assets > maxWithdraw(owner)) revert ExcessiveWithdrawAmount();

        uint256 totalShares = previewWithdraw(assets);
        uint256 feeAssets = _redeemWithFee(totalShares, assets, receiver, owner);

        emit FastRedeemed(owner, receiver, totalShares, assets, feeAssets);

        return totalShares;
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L138-156)
```text
    function _redeemWithFee(uint256 shares, uint256 assets, address receiver, address owner)
        internal
        returns (uint256 feeAssets)
    {
        feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;

        // Enforce that fast redemption always has a cost
        if (feeAssets == 0) revert InvalidAmount();

        uint256 feeShares = previewWithdraw(feeAssets);
        uint256 netShares = shares - feeShares;
        uint256 netAssets = assets - feeAssets;

        // Withdraw fee portion to treasury
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
    }
```
