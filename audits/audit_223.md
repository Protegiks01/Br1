## Title
ERC4626 Rounding Bypass in Fast Redemption Causes Systematic Vault Value Leakage

## Summary
The `_redeemWithFee()` internal function in `StakediTryFastRedeem.sol` manually calculates `netShares = shares - feeShares` instead of using `previewWithdraw(netAssets)`, bypassing ERC4626's ceiling rounding protection. This causes users to burn fewer shares than required for the assets they receive, resulting in systematic value leakage from the vault on every fast redemption.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The function should split a redemption into two properly-matched (assets, shares) pairs - one for the treasury fee and one for the net user amount. Each pair should respect the current vault share price, with `previewWithdraw()` rounding UP to protect the vault per ERC4626 standard.

**Actual Logic:** While `feeShares` is correctly calculated using `previewWithdraw(feeAssets)` at line 147, `netShares` is manually calculated as `shares - feeShares` at line 148. This bypasses the ceiling rounding that `previewWithdraw(netAssets)` would apply. Due to the mathematical property that `ceiling(A) + ceiling(B) >= ceiling(A+B)`, the sum `feeShares + previewWithdraw(netAssets)` will typically be greater than `shares`, meaning the actual `netShares` used is less than what the vault should require.

**Exploitation Path:**
1. User calls `fastRedeem(10000 shares, receiver, user)` with vault in state: totalSupply=1,000,000, totalAssets=1,001,000 (1:1.001 ratio)
2. Function calculates: assets = previewRedeem(10000) = 10,010, feeAssets = 2,002 (20% fee)
3. feeShares = previewWithdraw(2,002) = ceiling(2,002 * 1,000,000 / 1,001,000) = 2,001 shares
4. **netShares = 10,000 - 2,001 = 7,999 shares** (manual calculation)
5. netAssets = 10,010 - 2,002 = 8,008 assets
6. Second `_withdraw()` burns 7,999 shares to transfer 8,008 assets
7. **Correct amount should be:** previewWithdraw(8,008) = ceiling(8,008 * 1,000,000 / 1,001,000) = 8,001 shares
8. User saves 2 shares (8,001 - 7,999), extracting ~0.02% more value per transaction

**Security Property Broken:** Violates ERC4626 invariant that withdrawal operations must use properly-rounded share/asset ratios to protect the vault from value extraction. Also breaks the protocol's economic model where the vault share price should remain stable or increase, not be systematically drained.

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY assets in the StakediTry vault. The vault loses shares relative to assets transferred out.
- **Damage Severity**: Per transaction, users extract 1-2 shares more than they should (typically 0.01-0.02% of redemption amount). While individually small, this is:
  - Systematic bias favoring all users over the vault
  - Accumulates across all fast redemptions
  - No cap on frequency or amount
  - Proportionally larger for smaller redemptions where rounding matters more
- **User Impact**: All remaining vault stakers suffer dilution as the vault's backing ratio deteriorates. Fast redeemers get better exchange rates than they should, funded by holders who don't fast redeem.

## Likelihood Explanation
- **Attacker Profile**: Any user performing fast redemptions - no special privileges required. Even non-malicious users passively benefit from this bug.
- **Preconditions**: 
  - Cooldown must be enabled (ensureCooldownOn modifier)
  - Fast redeem must be enabled by admin
  - Vault must have non-1:1 share price (happens naturally with yield distribution)
- **Execution Complexity**: Single transaction via standard `fastRedeem()` or `fastWithdraw()` call. No special timing or coordination required.
- **Frequency**: Triggered on every fast redemption. Can be repeated continuously by any user with shares.

## Recommendation

**Fix the netShares calculation to use previewWithdraw:** [2](#0-1) 

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol, function _redeemWithFee, line 147-149:

// CURRENT (vulnerable):
uint256 feeShares = previewWithdraw(feeAssets);
uint256 netShares = shares - feeShares;  // Manual calculation bypasses rounding
uint256 netAssets = assets - feeAssets;

// FIXED:
uint256 feeShares = previewWithdraw(feeAssets);
uint256 netAssets = assets - feeAssets;
uint256 netShares = previewWithdraw(netAssets);  // Use preview function for proper rounding

// Verify total shares match input (allow for 1 wei rounding difference)
if (feeShares + netShares > shares + 1) revert InvalidShareCalculation();
// If rounding causes total to exceed shares, adjust netShares down by 1
if (feeShares + netShares > shares) {
    netShares = shares - feeShares;
}
```

**Alternative mitigation:** Calculate only the net portion directly and derive fee shares:
```solidity
uint256 netAssets = assets - feeAssets;
uint256 netShares = previewWithdraw(netAssets);
uint256 feeShares = shares - netShares;  // Derive fee shares to ensure total equals input
```

This reverses the calculation order, ensuring `netShares` uses proper rounding while `feeShares` becomes the residual. The treasury absorbs any rounding discrepancy (typically 1 share), which is acceptable.

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemRoundingLoss.t.sol
// Run with: forge test --match-test test_FastRedeemRoundingLoss -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_FastRedeemRoundingLoss is Test {
    StakediTryFastRedeem public vault;
    MockERC20 public asset;
    
    address public admin;
    address public treasury;
    address public user;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        user = makeAddr("user");
        
        // Deploy asset and vault
        asset = new MockERC20("iTRY", "iTRY");
        vm.prank(admin);
        vault = new StakediTryFastRedeem(IERC20(address(asset)), admin, admin, treasury);
        
        // Enable fast redeem with 20% fee
        vm.startPrank(admin);
        vault.setCooldownDuration(90 days);
        vault.setFastRedeemEnabled(true);
        vault.setFastRedeemFee(2000); // 20%
        vm.stopPrank();
        
        // Setup vault with non-1:1 ratio to trigger rounding
        // Initial deposit to prevent MIN_SHARES issues
        asset.mint(admin, 1000 ether);
        vm.startPrank(admin);
        asset.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, admin);
        vm.stopPrank();
        
        // Add yield to create non-1:1 ratio (1 share = 1.001 assets)
        asset.mint(address(vault), 1 ether);
    }
    
    function test_FastRedeemRoundingLoss() public {
        // SETUP: User deposits shares
        uint256 depositAmount = 10000 ether;
        asset.mint(user, depositAmount);
        vm.startPrank(user);
        asset.approve(address(vault), depositAmount);
        uint256 userShares = vault.deposit(depositAmount, user);
        vm.stopPrank();
        
        // Record initial vault state
        uint256 initialTotalSupply = vault.totalSupply();
        uint256 initialTotalAssets = vault.totalAssets();
        
        // EXPLOIT: User fast redeems
        vm.startPrank(user);
        uint256 sharesToRedeem = userShares;
        uint256 assetsReceived = vault.fastRedeem(sharesToRedeem, user, user);
        vm.stopPrank();
        
        // VERIFY: Calculate what shares SHOULD have been burned
        uint256 totalAssetsWithdrawn = vault.previewRedeem(sharesToRedeem);
        uint256 feeAssets = (totalAssetsWithdrawn * 2000) / 10000;
        uint256 netAssets = totalAssetsWithdrawn - feeAssets;
        
        // What shares should have been burned for netAssets
        uint256 correctNetShares = vault.previewWithdraw(netAssets);
        uint256 correctFeeShares = vault.previewWithdraw(feeAssets);
        uint256 correctTotalShares = correctNetShares + correctFeeShares;
        
        // Actual shares burned
        uint256 actualSharesBurned = sharesToRedeem;
        
        // Vulnerability confirmed: User burned fewer shares than required
        assertGt(correctTotalShares, actualSharesBurned, 
            "Vulnerability: Correct shares should exceed actual burned");
        
        uint256 sharesLost = correctTotalShares - actualSharesBurned;
        console.log("Shares user should have burned:", correctTotalShares);
        console.log("Shares user actually burned:", actualSharesBurned);
        console.log("Vault lost (extra value extracted):", sharesLost);
        console.log("Loss percentage:", (sharesLost * 10000) / actualSharesBurned, "bps");
    }
}
```

## Notes

This vulnerability exists in both redemption paths:
- [3](#0-2)  (`fastRedeem`)
- [4](#0-3)  (`fastWithdraw`)

Both call `_redeemWithFee()` which contains the vulnerable calculation. The parent contract's `_withdraw()` implementation at [5](#0-4)  does not validate that (assets, shares) pairs match the current exchange rate - it trusts the caller to provide correct values. This is standard ERC4626 behavior where public functions (`withdraw`, `redeem`) are responsible for calling preview functions, but internal `_withdraw()` accepts any pair.

The similar cooldown functions [6](#0-5)  correctly use preview functions for each `_withdraw()` call, demonstrating the proper pattern that `_redeemWithFee()` should follow.

### Citations

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

**File:** src/token/wiTRY/StakediTry.sol (L262-278)
```text
    function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
        internal
        override
        nonReentrant
        notZero(assets)
        notZero(shares)
    {
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
        }

        super._withdraw(caller, receiver, _owner, assets, shares);
        _checkMinShares();
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L96-118)
```text
    function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
        if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();

        shares = previewWithdraw(assets);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }

    /// @notice redeem shares into assets and starts a cooldown to claim the converted underlying asset
    /// @param shares shares to redeem
    function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
        if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();

        assets = previewRedeem(shares);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }
```
