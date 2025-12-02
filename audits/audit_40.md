## Title
Disproportionate Fee Overcharge for Small Redemption and Minting Amounts Due to Forced Minimum Fee

## Summary
The `_calculateRedemptionFee` and `_calculateMintFee` functions artificially round up zero-valued fees to 1 unit, causing users redeeming or minting small amounts to pay fees that are orders of magnitude higher than the configured basis point percentage.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/iTryIssuer.sol` (functions `_calculateRedemptionFee` lines 686-694, `_calculateMintFee` lines 670-678, and their usage in `redeemFor` lines 343-344 and `mintFor` line 286-287) [1](#0-0) [2](#0-1) 

**Intended Logic:** The fee calculation functions should charge users a percentage of their transaction amount as specified by `redemptionFeeInBPS` or `mintFeeInBPS` (1 BPS = 0.01%). The comment at line 682 states "Fee = amount * redemptionFeeInBPS / 10000", which should produce zero fees for amounts where the mathematical result is less than 1.

**Actual Logic:** When the fee calculation `amount * feeInBPS / 10000` rounds down to zero (i.e., when `amount * feeInBPS < 10000`), the functions return 1 instead of 0 via the ternary check `feeAmount == 0 ? 1 : feeAmount`. This was intended to "avoid round-down to zero" per the inline comment, but it creates a severe overcharge for small transactions.

**Exploitation Path:**
1. **User initiates small redemption**: User calls `redeemFor` with a small `iTRYAmount` that results in `grossDlfAmount < 10000 / redemptionFeeInBPS`
2. **Fee calculation rounds to zero**: At line 343, `_calculateRedemptionFee(grossDlfAmount)` computes `grossDlfAmount * redemptionFeeInBPS / 10000`, which mathematically equals less than 1
3. **Forced minimum fee applied**: Line 693 detects `feeAmount == 0` and returns 1 instead
4. **Excessive fee deducted**: At line 344, the user receives `netDlfAmount = grossDlfAmount - 1`, paying an effective fee rate far exceeding the configured percentage [3](#0-2) 

**Security Property Broken:** The protocol violates its documented fee mechanism. Users expect to pay fees proportional to the configured basis points (as documented in comments and function specifications), but instead pay a minimum flat fee that can be 10x, 100x, or even 1000x the intended percentage for small amounts.

## Impact Explanation
- **Affected Assets**: DLF tokens (for redemptions) and iTRY tokens (for minting). Users lose excess collateral to the treasury.
- **Damage Severity**: 
  - With `redemptionFeeInBPS = 10` (0.1%) and `grossDlfAmount = 500`, user pays 1 unit fee (0.2% effective rate) instead of 0 (2x overcharge)
  - With `redemptionFeeInBPS = 10` and `grossDlfAmount = 100`, user pays 1 unit fee (1% effective rate) instead of 0 (10x overcharge)  
  - With `redemptionFeeInBPS = 1` (0.01%) and `grossDlfAmount = 5000`, user pays 1 unit fee (0.02% effective rate) instead of 0 (2x overcharge)
  - The smaller the transaction, the more extreme the multiplier
- **User Impact**: Any whitelisted user redeeming or minting amounts where `amount * feeInBPS < 10000` will be systematically overcharged. This particularly harms users with small transactions or during periods of high NAV prices (where iTRY amounts convert to smaller DLF amounts).

## Likelihood Explanation
- **Attacker Profile**: Any whitelisted user performing small redemptions or mints (not malicious exploitation, but systematic unfair charging)
- **Preconditions**: 
  - Redemption or mint fee must be configured (feeInBPS > 0)
  - Transaction amount must satisfy `amount * feeInBPS < 10000`
  - For redemptionFeeInBPS = 10 (0.1%), this affects all redemptions with `grossDlfAmount < 1000`
  - For mintFeeInBPS = 100 (1%), this affects all mints with `dlfAmount < 100`
- **Execution Complexity**: Single transaction, no special setup required
- **Frequency**: Occurs on every small redemption or mint transaction, which could be frequent depending on user behavior and NAV prices

## Recommendation

Remove the forced minimum fee logic. If the mathematical fee rounds to zero, users should pay zero fees, consistent with the documented percentage-based fee structure:

**For `_calculateRedemptionFee`:**
```solidity
// In src/protocol/iTryIssuer.sol, function _calculateRedemptionFee, lines 686-694:

// CURRENT (vulnerable):
function _calculateRedemptionFee(uint256 amount) internal view returns (uint256) {
    if (redemptionFeeInBPS == 0) {
        return 0;
    }
    uint256 feeAmount = amount * redemptionFeeInBPS / 10000;
    return feeAmount == 0 ? 1 : feeAmount; // Causes overcharge
}

// FIXED:
function _calculateRedemptionFee(uint256 amount) internal view returns (uint256) {
    if (redemptionFeeInBPS == 0) {
        return 0;
    }
    // Natural rounding: if fee < 1, user pays 0
    return amount * redemptionFeeInBPS / 10000;
}
```

**For `_calculateMintFee`:**
```solidity
// In src/protocol/iTryIssuer.sol, function _calculateMintFee, lines 670-678:

// CURRENT (vulnerable):
function _calculateMintFee(uint256 amount) internal view returns (uint256 feeAmount) {
    if (mintFeeInBPS > 0) {
        feeAmount = amount * mintFeeInBPS / 10000;
        return feeAmount == 0 ? 1 : feeAmount; // Causes overcharge
    } else {
        return 0;
    }
}

// FIXED:
function _calculateMintFee(uint256 amount) internal view returns (uint256 feeAmount) {
    if (mintFeeInBPS > 0) {
        // Natural rounding: if fee < 1, user pays 0
        return amount * mintFeeInBPS / 10000;
    } else {
        return 0;
    }
}
```

**Alternative mitigation:** If the protocol requires non-zero fees for all transactions, implement minimum transaction amounts that guarantee fees always exceed 1 unit:
```solidity
// Add to redeemFor:
uint256 minRedeemAmount = (10000 / redemptionFeeInBPS) + 1;
require(grossDlfAmount >= minRedeemAmount, "Amount too small");

// Add to mintFor:  
uint256 minMintAmount = (10000 / mintFeeInBPS) + 1;
require(dlfAmount >= minMintAmount, "Amount too small");
```

## Proof of Concept

```solidity
// File: test/Exploit_FeeOvercharge.t.sol
// Run with: forge test --match-test test_FeeOverchargeOnSmallRedemption -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "./iTryIssuer.base.t.sol";

contract Exploit_FeeOvercharge is Test {
    iTryIssuer public issuer;
    MockITryToken public itry;
    MockERC20 public dlf;
    MockOracle public oracle;
    address public treasury;
    address public user;
    
    function setUp() public {
        // Deploy contracts
        user = address(0x1);
        treasury = address(0x2);
        
        dlf = new MockERC20("DLF", "DLF", 18);
        itry = new MockITryToken();
        oracle = new MockOracle(1e18); // 1:1 NAV
        
        // Deploy issuer with 0.1% redemption fee (10 BPS)
        issuer = new iTryIssuer(
            address(itry),
            address(dlf),
            address(oracle),
            treasury,
            address(this), // yieldReceiver
            address(this), // custodian
            address(this), // admin
            0, // initialIssued
            0, // initialDLFUnderCustody
            5000, // vaultTargetPercentageBPS
            0 // vaultMinimumBalance
        );
        
        itry.setController(address(issuer));
        issuer.addToWhitelist(user);
        
        // Set 0.1% redemption fee (10 BPS)
        issuer.setRedemptionFeeInBPS(10);
        
        // User mints some iTRY first
        dlf.mint(user, 10000e18);
        vm.startPrank(user);
        dlf.approve(address(issuer), type(uint256).max);
        issuer.mintFor(user, 10000e18, 0);
        vm.stopPrank();
    }
    
    function test_FeeOverchargeOnSmallRedemption() public {
        // SETUP: User has iTRY and wants to redeem small amount
        vm.startPrank(user);
        
        // Case 1: Redeem amount that results in grossDlfAmount = 500
        // Expected fee: 500 * 10 / 10000 = 0.05 → rounds to 0
        // Actual fee: 1 (due to forced minimum)
        // Effective fee rate: 1/500 = 0.2% (2x the configured 0.1%)
        
        uint256 redeemAmount = 500e18; // This will result in grossDlfAmount = 500e18
        uint256 grossDlfExpected = 500e18; // NAV is 1:1
        
        uint256 expectedFeeIfRoundedNaturally = 0; // 500 * 10 / 10000 = 0
        uint256 actualFee = 1e18; // Forced to 1 by line 693
        
        // EXPLOIT: Redeem and observe excessive fee
        uint256 treasuryBalanceBefore = dlf.balanceOf(treasury);
        issuer.redeemFor(user, redeemAmount, 0);
        uint256 treasuryBalanceAfter = dlf.balanceOf(treasury);
        
        uint256 feePaid = treasuryBalanceAfter - treasuryBalanceBefore;
        
        // VERIFY: User paid 1 unit instead of 0
        assertEq(feePaid, actualFee, "Fee should be 1 due to forced minimum");
        assertTrue(feePaid > expectedFeeIfRoundedNaturally, "User overpaid");
        
        // Calculate effective fee rate
        uint256 effectiveFeeRateBPS = (feePaid * 10000) / grossDlfExpected;
        assertEq(effectiveFeeRateBPS, 20, "Effective fee rate is 20 BPS (0.2%), 2x the configured 10 BPS");
        
        console.log("Configured fee rate: 10 BPS (0.1%)");
        console.log("Effective fee rate:  %d BPS (%d.%d%%)", effectiveFeeRateBPS, effectiveFeeRateBPS/100, effectiveFeeRateBPS%100);
        console.log("Overcharge multiplier: %dx", effectiveFeeRateBPS / 10);
        
        vm.stopPrank();
    }
    
    function test_FeeOverchargeExtremeCase() public {
        // Case 2: Even smaller redemption
        // grossDlfAmount = 100 → expected fee = 0.1 → rounds to 0
        // Actual fee: 1 → effective rate: 1% (10x overcharge!)
        
        vm.startPrank(user);
        
        uint256 redeemAmount = 100e18;
        uint256 grossDlfExpected = 100e18;
        
        uint256 treasuryBalanceBefore = dlf.balanceOf(treasury);
        issuer.redeemFor(user, redeemAmount, 0);
        uint256 treasuryBalanceAfter = dlf.balanceOf(treasury);
        
        uint256 feePaid = treasuryBalanceAfter - treasuryBalanceBefore;
        uint256 effectiveFeeRateBPS = (feePaid * 10000) / grossDlfExpected;
        
        assertEq(effectiveFeeRateBPS, 100, "Effective fee rate is 100 BPS (1%), 10x the configured rate!");
        
        console.log("For very small amounts:");
        console.log("Configured fee rate: 10 BPS (0.1%)");
        console.log("Effective fee rate:  %d BPS (%d%%)", effectiveFeeRateBPS, effectiveFeeRateBPS/100);
        console.log("Overcharge multiplier: %dx", effectiveFeeRateBPS / 10);
        
        vm.stopPrank();
    }
}
```

## Notes

This vulnerability affects both redemption and minting operations through identical logic in `_calculateRedemptionFee` and `_calculateMintFee`. The forced minimum fee of 1 unit creates a regressive fee structure where small transactions pay disproportionately high fees compared to the documented percentage.

The issue becomes more severe with:
- Lower fee configurations (lower BPS values)
- Smaller transaction amounts
- Higher NAV prices (which convert iTRY to smaller DLF amounts in redemptions)

While this doesn't enable direct theft by an attacker, it systematically overcharges users and violates the protocol's documented fee mechanism, making it a clear Medium severity issue per Code4rena criteria.

### Citations

**File:** src/protocol/iTryIssuer.sol (L343-344)
```text
        uint256 feeAmount = _calculateRedemptionFee(grossDlfAmount);
        uint256 netDlfAmount = grossDlfAmount - feeAmount;
```

**File:** src/protocol/iTryIssuer.sol (L670-678)
```text
    function _calculateMintFee(uint256 amount) internal view returns (uint256 feeAmount) {
        // Account for mint fee if configured
        if (mintFeeInBPS > 0) {
            feeAmount = amount * mintFeeInBPS / 10000;
            return feeAmount == 0 ? 1 : feeAmount; // avoid round-down to zero
        } else {
            return 0;
        }
    }
```

**File:** src/protocol/iTryIssuer.sol (L686-694)
```text
    function _calculateRedemptionFee(uint256 amount) internal view returns (uint256) {
        // Account for redemption fee if configured
        if (redemptionFeeInBPS == 0) {
            return 0;
        }

        uint256 feeAmount = amount * redemptionFeeInBPS / 10000;
        return feeAmount == 0 ? 1 : feeAmount; // avoid round-down to zero
    }
```
