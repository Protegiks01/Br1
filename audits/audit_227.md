## Title
Missing Slippage Protection in Fast Redemption Allows Users to Pay Unexpected Fees Due to Parameter Changes

## Summary
The `fastRedeem()` and `fastWithdraw()` functions in `StakediTryFastRedeem.sol` lack slippage protection parameters, allowing users to pay significantly different fees than expected when `fastRedeemFeeInBPS` is changed while their transaction is in the mempool. Users have no way to specify a maximum acceptable fee, exposing them to unexpected losses of up to 19% of their redemption value.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol` - functions `fastRedeem()` (lines 57-71), `fastWithdraw()` (lines 76-90), `_redeemWithFee()` (lines 138-156)

**Intended Logic:** The fast redemption feature allows users to bypass the cooldown period by paying a fee to the treasury. Users should be able to perform fast redemptions with predictable fee costs.

**Actual Logic:** The fee is calculated dynamically at execution time using the current `fastRedeemFeeInBPS` state variable without any user-specified bounds. [1](#0-0) 

The functions do not accept any slippage protection parameters: [2](#0-1) [3](#0-2) 

The admin can change the fee instantly with no timelock: [4](#0-3) 

**Exploitation Path:**
1. User checks current fee is 100 BPS (1%) and decides to fast redeem 10,000 shares
2. User submits `fastRedeem(10000e18, userAddr, userAddr)` transaction to mempool
3. Admin legitimately updates fee to 2000 BPS (20%) via `setFastRedeemFee(2000)` for business reasons
4. User's transaction executes with 20% fee instead of expected 1%
5. User pays 1,900 iTRY in fees instead of expected 100 iTRY - an unexpected loss of 1,800 iTRY (19% of redemption value)

**Security Property Broken:** Users lack protection against unexpected parameter changes during transaction execution, violating the principle that users should be able to specify acceptable execution conditions (standard DeFi slippage protection).

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY tokens held by users performing fast redemptions
- **Damage Severity**: Users can pay up to 19% more in fees than expected (difference between MIN_FAST_REDEEM_FEE of 1 BPS and MAX_FAST_REDEEM_FEE of 2000 BPS). For a 10,000 iTRY redemption, this means paying 2,000 iTRY in fees instead of 10 iTRY - a loss of 1,990 iTRY.
- **User Impact**: Any user performing fast redemption during a fee parameter change is affected. This is particularly problematic during periods of intended fee adjustments or governance changes.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a design flaw affecting normal users when legitimate admin actions occur
- **Preconditions**: User has staked wiTRY and wants to use fast redemption; admin updates fee parameters (legitimate business decision)
- **Execution Complexity**: Simple - occurs naturally when user transaction and admin parameter update are in same block range
- **Frequency**: Can occur whenever admin adjusts fees while users have pending fast redemption transactions. Given Ethereum's ~12 second block time and potential mempool delays, this is a realistic scenario.

## Recommendation

Add `maxFeeInBPS` parameter to both fast redemption functions to allow users to specify their maximum acceptable fee:

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol:

// CURRENT (vulnerable) - lines 57-71:
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

// FIXED:
function fastRedeem(uint256 shares, address receiver, address owner, uint16 maxFeeInBPS)
    external
    ensureCooldownOn
    ensureFastRedeemEnabled
    returns (uint256 assets)
{
    if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();
    if (fastRedeemFeeInBPS > maxFeeInBPS) revert FeeExceedsMaximum(); // Add this check
    uint256 totalAssets = previewRedeem(shares);
    uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);
    emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);
    return totalAssets - feeAssets;
}

// Apply similar fix to fastWithdraw() at lines 76-90
```

Alternative: Add a timelock mechanism to `setFastRedeemFee()` that delays fee changes by a reasonable period (e.g., 24 hours), allowing users to see pending changes before they take effect.

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemFeeSlippage.t.sol
// Run with: forge test --match-test test_FastRedeemFeeSlippage -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {IStakediTry} from "../src/token/wiTRY/interfaces/IStakediTry.sol";
import {IStakediTryFastRedeem} from "../src/token/wiTRY/interfaces/IStakediTryFastRedeem.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_FastRedeemFeeSlippage is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public user;
    
    uint16 public constant INITIAL_FEE = 100; // 1%
    uint16 public constant CHANGED_FEE = 2000; // 20% (MAX)
    uint256 public constant DEPOSIT_AMOUNT = 10000e18;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        rewarder = makeAddr("rewarder");
        user = makeAddr("user");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTryFastRedeem
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)),
            rewarder,
            admin,
            treasury
        );
        
        // Setup: Enable fast redeem with 1% fee
        vm.startPrank(admin);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(INITIAL_FEE);
        vm.stopPrank();
        
        // Mint and stake for user
        iTryToken.mint(user, DEPOSIT_AMOUNT);
        vm.startPrank(user);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        stakediTry.deposit(DEPOSIT_AMOUNT, user);
        vm.stopPrank();
    }
    
    function test_FastRedeemFeeSlippage() public {
        // SETUP: User checks current fee and decides to redeem
        uint256 userShares = stakediTry.balanceOf(user);
        uint256 expectedAssets = stakediTry.previewRedeem(userShares);
        
        // User expects to pay 1% fee (100 iTRY on 10000 iTRY)
        uint256 expectedFeeAt1Percent = (expectedAssets * INITIAL_FEE) / 10000;
        uint256 expectedNetAt1Percent = expectedAssets - expectedFeeAt1Percent;
        
        console.log("User expects:");
        console.log("  Total assets:", expectedAssets);
        console.log("  Fee at 1%%:", expectedFeeAt1Percent);
        console.log("  Net to receive:", expectedNetAt1Percent);
        
        // EXPLOIT: Admin changes fee to 20% before user's transaction executes
        // (This could be legitimate governance action, not malicious)
        vm.prank(admin);
        stakediTry.setFastRedeemFee(CHANGED_FEE);
        
        // User's transaction executes with new 20% fee
        vm.prank(user);
        uint256 actualNetReceived = stakediTry.fastRedeem(userShares, user, user);
        
        // Calculate actual fee paid
        uint256 actualFeePaid = expectedAssets - actualNetReceived;
        uint256 unexpectedLoss = actualFeePaid - expectedFeeAt1Percent;
        
        console.log("\nActual result:");
        console.log("  Fee paid:", actualFeePaid);
        console.log("  Net received:", actualNetReceived);
        console.log("  UNEXPECTED LOSS:", unexpectedLoss);
        
        // VERIFY: User paid 20% instead of 1% - lost 19% unexpectedly
        uint256 expectedFeeAt20Percent = (expectedAssets * CHANGED_FEE) / 10000;
        assertEq(actualFeePaid, expectedFeeAt20Percent, "User paid 20% fee");
        assertEq(unexpectedLoss, expectedFeeAt20Percent - expectedFeeAt1Percent, "User lost 19% unexpectedly");
        
        // Demonstrate the severity: User lost 1900 iTRY unexpectedly
        assertGt(unexpectedLoss, 1800e18, "User lost over 1800 iTRY (18% of redemption)");
        
        console.log("\nVulnerability confirmed: User has no slippage protection");
        console.log("Loss percentage: 19%% of redemption value");
    }
}
```

## Notes

This vulnerability represents a critical missing feature in the fast redemption mechanism. While the admin role is trusted and the protocol explicitly documents that admin privileges are accepted, this issue is distinct from centralization risks for several reasons:

1. **Design Flaw, Not Malicious Action**: The vulnerability exists even when the admin acts legitimately. Normal fee adjustments for business reasons can cause unexpected user losses.

2. **Standard DeFi Practice**: Slippage protection is a fundamental security feature in DeFi protocols. DEXs, lending protocols, and vaults typically allow users to specify acceptable execution bounds (e.g., `minAmountOut` in Uniswap, `maxLossInBPS` in vaults).

3. **Realistic Timing**: Ethereum's mempool dynamics and block time (~12 seconds) make it highly likely that parameter changes and user transactions will occasionally coincide, even without any intent to harm users.

4. **Significant Impact**: The potential loss is substantial - up to 19% of the redemption value, which far exceeds typical MEV or slippage in normal DeFi operations.

The fee range allowed by the protocol spans from 1 BPS (0.01%) to 2000 BPS (20%), as defined in the contract constants. [5](#0-4) 

This issue should be addressed by adding slippage protection parameters to the user-facing functions, allowing users to specify their risk tolerance when performing fast redemptions.

### Citations

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L26-27)
```text
    uint16 public constant MIN_FAST_REDEEM_FEE = 1; // 0.01% minimum fee (1 basis point)
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L57-61)
```text
    function fastRedeem(uint256 shares, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 assets)
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L76-80)
```text
    function fastWithdraw(uint256 assets, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 shares)
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L103-111)
```text
    function setFastRedeemFee(uint16 feeInBPS) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (feeInBPS < MIN_FAST_REDEEM_FEE || feeInBPS > MAX_FAST_REDEEM_FEE) {
            revert InvalidFastRedeemFee();
        }

        uint16 previousFee = fastRedeemFeeInBPS;
        fastRedeemFeeInBPS = feeInBPS;
        emit FastRedeemFeeUpdated(previousFee, feeInBPS);
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L142-142)
```text
        feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;
```
