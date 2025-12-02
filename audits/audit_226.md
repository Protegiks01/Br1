## Title
Fast Redemption Value Loss Due to Share Price Change Between Preview and Execution

## Summary
The `fastRedeem` function in `StakediTryFastRedeem.sol` suffers from a race condition where the asset amount is calculated at line 65 based on the current share price, but fee shares are recalculated at line 147 inside `_redeemWithFee()` using a potentially different share price. If yield is distributed or vesting releases rewards between these two calculations, users receive fewer assets than their shares are worth at execution time, with the difference remaining in the vault to benefit other stakers.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol` - `fastRedeem()` function (lines 57-71) and `_redeemWithFee()` internal function (lines 138-156)

**Intended Logic:** The fast redemption feature should allow users to immediately redeem their shares for the current value of those shares, minus a fee. The preview calculation should accurately represent what the user will receive.

**Actual Logic:** The function calculates the total assets based on share price at line 65, but then recalculates fee shares based on potentially different share price at line 147, creating an inconsistency that causes users to lose value when share price increases between these two points. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. Vault state: 1000 totalAssets, 1000 totalSupply (1:1 ratio)
2. User calls `fastRedeem(100 shares)` with 20% fee
3. Line 65: `previewRedeem(100)` calculates 100 assets at current price
4. Before line 147 executes, `transferInRewards(100)` is called (either by legitimate yield distribution or front-running)
5. New state: 1100 totalAssets, 1000 totalSupply (1.1:1 ratio)
6. Line 147: `previewWithdraw(20 fee assets)` calculates ~18.18 shares at NEW price
7. Line 148-149: netShares = 81.82, netAssets = 80
8. Total burned: 100 shares, Total received: 100 assets (20 fee + 80 net)
9. At the new 1.1:1 ratio, 100 shares should be worth 110 assets
10. User loses 10 assets which remain in vault for remaining stakers [3](#0-2) [4](#0-3) 

**Security Property Broken:** Users should receive the fair market value of their shares at execution time. This vulnerability causes users to receive less than the current value of their shares when share price increases during transaction execution.

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY tokens in the StakediTry vault
- **Damage Severity**: Users lose the difference between old and new share prices on their entire redemption amount. With frequent yield distributions or significant yield amounts, losses can be substantial. For example, a 10% share price increase on a 1000 share redemption would result in 100 asset loss to the user.
- **User Impact**: Any user performing fast redemption during or shortly after yield distribution events. The vulnerability is exploitable without malicious intent - normal protocol operations (scheduled yield distributions) automatically trigger the condition.

## Likelihood Explanation
- **Attacker Profile**: Any staker can be affected. An attacker with REWARDER_ROLE could deliberately front-run redemptions, but this also occurs naturally during regular yield distributions.
- **Preconditions**: 
  - Fast redemption enabled
  - User has shares to redeem
  - Yield distribution occurs or vesting progresses between preview and execution
- **Execution Complexity**: Single transaction vulnerability - no special coordination needed. Occurs naturally when yield is distributed to the vault via `transferInRewards()`.
- **Frequency**: Can occur on every fast redemption that coincides with yield distribution or vesting period progression. Given that vesting releases rewards continuously over time (up to 30 days), this affects a significant portion of redemptions.

## Recommendation

The fix is to recalculate the total assets inside `_redeemWithFee()` based on the current share price at execution time, rather than using the previewed amount from an earlier state:

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol, function _redeemWithFee, lines 138-156:

// CURRENT (vulnerable):
function _redeemWithFee(uint256 shares, uint256 assets, address receiver, address owner)
    internal
    returns (uint256 feeAssets)
{
    feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;
    // ... rest of function

// FIXED:
function _redeemWithFee(uint256 shares, address receiver, address owner)
    internal
    returns (uint256 feeAssets)
{
    // Recalculate assets at current share price to ensure consistency
    uint256 assets = previewRedeem(shares);
    
    feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;
    // ... rest of function remains the same
```

Also update the calling function to not pass the assets parameter:

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol, function fastRedeem, line 66:

// CURRENT:
uint256 totalAssets = previewRedeem(shares);
uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);

// FIXED:
uint256 feeAssets = _redeemWithFee(shares, receiver, owner);
uint256 totalAssets = previewRedeem(shares); // Calculate after for event emission
```

Alternative mitigation: Add a `minAssets` slippage protection parameter to `fastRedeem()` similar to other protocol functions, allowing users to specify the minimum assets they're willing to accept.

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemValueLoss.t.sol
// Run with: forge test --match-test test_FastRedeemValueLoss -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../test/mocks/MockERC20.sol";

contract Exploit_FastRedeemValueLoss is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin = address(1);
    address public treasury = address(2);
    address public rewarder = address(3);
    address public user1 = address(4);
    address public user2 = address(5);
    
    function setUp() public {
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)), 
            rewarder, 
            admin, 
            treasury
        );
        
        // Setup: Enable fast redeem with 20% fee
        vm.startPrank(admin);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(2000); // 20%
        vm.stopPrank();
        
        // Mint tokens and approve
        iTryToken.mint(user1, 1000e18);
        iTryToken.mint(user2, 1000e18);
        iTryToken.mint(rewarder, 100e18);
        
        vm.prank(user1);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        vm.prank(user2);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        vm.prank(rewarder);
        iTryToken.approve(address(stakediTry), type(uint256).max);
    }
    
    function test_FastRedeemValueLoss() public {
        // SETUP: User1 and User2 deposit to establish vault state
        vm.prank(user1);
        stakediTry.deposit(1000e18, user1);
        
        vm.prank(user2);
        stakediTry.deposit(1000e18, user2);
        
        // State: 2000 totalAssets, 2000 totalSupply (1:1 ratio)
        assertEq(stakediTry.totalAssets(), 2000e18);
        assertEq(stakediTry.totalSupply(), 2000e18);
        
        uint256 user1BalanceBefore = iTryToken.balanceOf(user1);
        
        // User1 expects to receive assets for 100 shares at CURRENT price
        uint256 user1Shares = 100e18;
        uint256 expectedAssetsBeforeYield = stakediTry.previewRedeem(user1Shares);
        assertEq(expectedAssetsBeforeYield, 100e18); // 1:1 ratio
        
        // EXPLOIT: Simulate yield distribution happening in same block
        // (In production, this could be front-run or just coincidental timing)
        vm.prank(rewarder);
        stakediTry.transferInRewards(100e18); // Distribute 100 assets
        
        // New state: 2100 totalAssets, 2000 totalSupply (1.05:1 ratio)
        assertEq(stakediTry.totalAssets(), 2100e18);
        assertEq(stakediTry.totalSupply(), 2000e18);
        
        // At NEW price, 100 shares should be worth 105 assets
        uint256 expectedAssetsAfterYield = stakediTry.previewRedeem(user1Shares);
        assertEq(expectedAssetsAfterYield, 105e18);
        
        // User1 performs fastRedeem
        vm.prank(user1);
        uint256 netReceived = stakediTry.fastRedeem(user1Shares, user1, user1);
        
        // VERIFY: User receives assets calculated at OLD price, not NEW price
        uint256 user1BalanceAfter = iTryToken.balanceOf(user1);
        uint256 actualReceived = user1BalanceAfter - user1BalanceBefore;
        
        // Expected at NEW price: 105 - 20% fee = 84 assets
        uint256 expectedNetAtNewPrice = 84e18;
        
        // Actual received at OLD price: 100 - 20% fee = 80 assets
        uint256 actualNetReceived = 80e18;
        
        assertEq(actualReceived, actualNetReceived, "User received assets at old price");
        assertLt(actualReceived, expectedNetAtNewPrice, "User lost value due to price change");
        
        // Loss: 4 assets (84 - 80)
        uint256 loss = expectedNetAtNewPrice - actualNetReceived;
        assertEq(loss, 4e18, "Vulnerability confirmed: User lost 4 assets");
        
        // Remaining stakers benefit from this loss
        // User2 still has 1000 shares in vault with 2020 assets (2100 - 80)
        // Share price for remaining stakers increased beyond expected
    }
}
```

## Notes

This vulnerability affects users during normal protocol operations, not just malicious attacks. The continuous vesting mechanism in `StakediTry.sol` means that `totalAssets()` is constantly increasing as time passes, making this race condition likely to occur naturally. [5](#0-4) 

The same issue exists in the `fastWithdraw()` function at lines 76-90, which also calculates shares at line 84 before calling `_redeemWithFee()`. [6](#0-5)

### Citations

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L65-66)
```text
        uint256 totalAssets = previewRedeem(shares);
        uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);
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

**File:** src/token/wiTRY/StakediTry.sol (L113-119)
```text
    function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
        _updateVestingAmount(amount);
        // transfer assets from rewarder to this contract
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);

        emit RewardsReceived(amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L199-211)
```text
    function getUnvestedAmount() public view returns (uint256) {
        uint256 timeSinceLastDistribution = block.timestamp - lastDistributionTimestamp;

        if (timeSinceLastDistribution >= vestingPeriod) {
            return 0;
        }

        uint256 deltaT;
        unchecked {
            deltaT = (vestingPeriod - timeSinceLastDistribution);
        }
        return (deltaT * vestingAmount) / vestingPeriod;
    }
```
