## Title
Fee Rounding Logic Causes Complete Loss of User Funds on Small Redemptions

## Summary
The `_calculateRedemptionFee` function bumps fees from 0 to 1 wei when the calculated fee rounds down to zero, which can cause users to receive 0 DLF tokens when redeeming small amounts of iTRY, resulting in 100% loss of their redeemed value. This occurs because there is no validation preventing `netDlfAmount` from being zero in the redemption flow.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/protocol/iTryIssuer.sol` - `_calculateRedemptionFee` function (lines 686-694) and `redeemFor` function (lines 318-370)

**Intended Logic:** The fee bumping logic at line 693 is intended to ensure the protocol collects at least 1 wei of fees when redemption fees are configured, preventing the fee from rounding down to zero. [1](#0-0) 

**Actual Logic:** When users redeem very small amounts of iTRY where `grossDlfAmount * redemptionFeeInBPS < 10000`, the fee calculation rounds to 0 and gets bumped to 1. If `grossDlfAmount = 1`, then `netDlfAmount = grossDlfAmount - feeAmount = 1 - 1 = 0`, causing users to burn their iTRY but receive 0 DLF tokens.

**Exploitation Path:**
1. Protocol has redemption fee configured (any value > 0 BPS)
2. User attempts to redeem a small amount of iTRY such that `grossDlfAmount = iTRYAmount * 1e18 / navPrice` equals 1 wei
3. Fee calculation executes: `feeAmount = 1 * redemptionFeeInBPS / 10000 = 0`, then bumped to 1
4. Net amount calculation: `netDlfAmount = 1 - 1 = 0`
5. The slippage check at line 346-349 only protects if user sets `minAmountOut > 0`, but users may set it to 0 for small transactions [2](#0-1) 
6. User's iTRY is burned via `_burn(msg.sender, iTRYAmount)` at line 351 [3](#0-2) 
7. User receives 0 DLF tokens while treasury receives 1 wei fee

**Security Property Broken:** Users suffer direct theft/loss of funds - their iTRY is burned but they receive nothing in return, violating the fundamental redemption guarantee.

## Impact Explanation
- **Affected Assets**: iTRY tokens and DLF collateral
- **Damage Severity**: Users lose 100% of their redeemed iTRY amount. For example:
  - With 1 BPS (0.01%) fee and `grossDlfAmount = 1`, user loses 1 wei iTRY equivalent
  - More significantly, with any redemption fee > 0, when `grossDlfAmount ≤ (10000 / redemptionFeeInBPS)`, users pay disproportionately high fees (up to 100%)
  - With 100 BPS (1%) fee, any redemption where `grossDlfAmount < 100` results in effective fee rate > 1%
  - At `grossDlfAmount = 1`, effective fee rate is 100% (infinite multiplier of configured rate)
- **User Impact**: Any user redeeming small amounts with `minAmountOut = 0` will lose their entire redemption. This particularly affects users testing the protocol, making micro-transactions, or dealing with dust amounts.

## Likelihood Explanation
- **Attacker Profile**: Not an attack - legitimate users are victims. Any whitelisted user redeeming small amounts is affected.
- **Preconditions**: 
  - Redemption fee configured to any value > 0 BPS
  - User redeems amount where `grossDlfAmount * redemptionFeeInBPS < 10000`
  - User sets `minAmountOut = 0` (common for small transactions to avoid revert)
- **Execution Complexity**: Single transaction, no special timing or coordination required
- **Frequency**: Affects every small redemption that meets the threshold condition

## Recommendation

**Primary Fix:** Add explicit validation to prevent zero net redemption amounts: [4](#0-3) 

```solidity
// In src/protocol/iTryIssuer.sol, function redeemFor, after line 344:

// CURRENT (vulnerable):
uint256 feeAmount = _calculateRedemptionFee(grossDlfAmount);
uint256 netDlfAmount = grossDlfAmount - feeAmount;

// Check if output meets minimum requirement
if (netDlfAmount < minAmountOut) {
    revert OutputBelowMinimum(netDlfAmount, minAmountOut);
}

// FIXED:
uint256 feeAmount = _calculateRedemptionFee(grossDlfAmount);
uint256 netDlfAmount = grossDlfAmount - feeAmount;

// Prevent zero net redemption amount
if (netDlfAmount == 0) {
    revert CommonErrors.ZeroAmount();
}

// Check if output meets minimum requirement
if (netDlfAmount < minAmountOut) {
    revert OutputBelowMinimum(netDlfAmount, minAmountOut);
}
```

**Alternative Fix:** Modify the fee calculation to only charge fees when they can be reasonably calculated:

```solidity
// In src/protocol/iTryIssuer.sol, function _calculateRedemptionFee:

// ALTERNATIVE FIX (more complex but prevents the issue at source):
function _calculateRedemptionFee(uint256 amount) internal view returns (uint256) {
    if (redemptionFeeInBPS == 0) {
        return 0;
    }
    
    uint256 feeAmount = amount * redemptionFeeInBPS / 10000;
    
    // Only bump to 1 if the net amount would still be positive
    if (feeAmount == 0 && amount > 1) {
        return 1;
    }
    return feeAmount;
}
```

## Proof of Concept

```solidity
// File: test/Exploit_ZeroRedemptionAmount.t.sol
// Run with: forge test --match-test test_ZeroRedemptionAmount -vvv

pragma solidity ^0.8.0;

import "./iTryIssuer.base.t.sol";

contract Exploit_ZeroRedemptionAmount is iTryIssuerBaseTest {
    function setUp() public override {
        super.setUp();
        
        // Set a small redemption fee (1 BPS = 0.01%)
        vm.prank(admin);
        issuer.setRedemptionFeeInBPS(1);
    }
    
    function test_ZeroRedemptionAmount() public {
        // SETUP: Mint large amount of iTRY first
        uint256 mintAmount = 1000e18;
        collateralToken.mint(whitelistedUser1, mintAmount);
        vm.prank(whitelistedUser1);
        collateralToken.approve(address(issuer), mintAmount);
        
        vm.prank(whitelistedUser1);
        issuer.mintFor(whitelistedUser1, mintAmount, 0);
        
        uint256 iTryBalanceBefore = iTryToken.balanceOf(whitelistedUser1);
        uint256 dlfBalanceBefore = collateralToken.balanceOf(whitelistedUser1);
        
        // EXPLOIT: Redeem very small amount where grossDlfAmount = 1
        // With NAV = 1e18, we need iTRYAmount = 1
        uint256 smallRedemption = 1;
        
        // Ensure vault has balance
        _setVaultBalance(1000e18);
        
        // User sets minAmountOut = 0 (common for small transactions)
        vm.prank(whitelistedUser1);
        issuer.redeemFor(whitelistedUser1, smallRedemption, 0);
        
        // VERIFY: User lost iTRY but received 0 DLF
        uint256 iTryBalanceAfter = iTryToken.balanceOf(whitelistedUser1);
        uint256 dlfBalanceAfter = collateralToken.balanceOf(whitelistedUser1);
        
        assertEq(
            iTryBalanceBefore - iTryBalanceAfter, 
            smallRedemption, 
            "User's iTRY was burned"
        );
        assertEq(
            dlfBalanceAfter - dlfBalanceBefore,
            0,
            "Vulnerability confirmed: User received 0 DLF despite burning iTRY"
        );
        
        // Additional verification: Treasury received the fee (1 wei)
        // This proves the user's 1 wei DLF went entirely to fees
    }
    
    function test_DisproportionateFees() public {
        // Additional test showing disproportionate fees for small amounts
        vm.prank(admin);
        issuer.setRedemptionFeeInBPS(10); // 0.1% fee
        
        // Setup
        uint256 mintAmount = 1000e18;
        collateralToken.mint(whitelistedUser1, mintAmount);
        vm.prank(whitelistedUser1);
        collateralToken.approve(address(issuer), mintAmount);
        
        vm.prank(whitelistedUser1);
        issuer.mintFor(whitelistedUser1, mintAmount, 0);
        
        _setVaultBalance(1000e18);
        
        // Redeem amount where grossDlfAmount = 10
        // Expected fee: 10 * 10 / 10000 = 0.01, rounds to 0, bumped to 1
        // Effective fee rate: 1/10 = 10% instead of 0.1%
        uint256 redemptionAmount = 10;
        
        uint256 dlfBefore = collateralToken.balanceOf(whitelistedUser1);
        
        vm.prank(whitelistedUser1);
        issuer.redeemFor(whitelistedUser1, redemptionAmount, 0);
        
        uint256 dlfAfter = collateralToken.balanceOf(whitelistedUser1);
        uint256 received = dlfAfter - dlfBefore;
        
        // User should receive ~9.99 (10 - 0.01% fee)
        // But actually receives 9 (10 - 1, due to fee bump)
        // Effective fee: 10% instead of 0.1%
        assertEq(received, 9, "User paid 1 wei fee on 10 wei redemption");
        assertTrue(
            (10 * 10) / 10000 == 0,
            "Mathematical fee rounds to 0"
        );
    }
}
```

## Notes

The vulnerability stems from the fee bumping logic that was designed to prevent the protocol from collecting zero fees when fees are configured. However, this creates a worse outcome where users can lose their entire redemption.

The minting flow has protection against this issue via a check at line 292 that reverts if `iTRYAmount == 0`, but the redemption flow lacks equivalent protection for `netDlfAmount`. [5](#0-4) 

This is not a theoretical edge case - it affects any user making micro-transactions or dealing with dust amounts when redemption fees are active. The issue is particularly concerning because:

1. The `previewRedeem` function would also return 0, so users might think this is expected behavior [6](#0-5) 
2. Users commonly set `minAmountOut = 0` for small transactions to avoid reverts
3. The effective fee rate can be 100x to infinite times higher than the configured rate

### Citations

**File:** src/protocol/iTryIssuer.sol (L206-223)
```text
    /// @inheritdoc IiTryIssuer
    function previewRedeem(uint256 iTRYAmount) external view returns (uint256 dlfAmount) {
        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();

        uint256 navPrice = oracle.price();

        // Calculate gross DLF amount: iTRYAmount * 1e18 / navPrice
        uint256 grossDlfAmount = iTRYAmount * 1e18 / navPrice;

        // Account for redemption fee if configured
        if (redemptionFeeInBPS > 0) {
            dlfAmount = grossDlfAmount - _calculateRedemptionFee(grossDlfAmount);
        } else {
            dlfAmount = grossDlfAmount;
        }

        return dlfAmount;
    }
```

**File:** src/protocol/iTryIssuer.sol (L292-292)
```text
        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();
```

**File:** src/protocol/iTryIssuer.sol (L338-350)
```text
        // Calculate gross DLF amount: iTRYAmount * 1e18 / navPrice
        uint256 grossDlfAmount = iTRYAmount * 1e18 / navPrice;

        if (grossDlfAmount == 0) revert CommonErrors.ZeroAmount();

        uint256 feeAmount = _calculateRedemptionFee(grossDlfAmount);
        uint256 netDlfAmount = grossDlfAmount - feeAmount;

        // Check if output meets minimum requirement
        if (netDlfAmount < minAmountOut) {
            revert OutputBelowMinimum(netDlfAmount, minAmountOut);
        }

```

**File:** src/protocol/iTryIssuer.sol (L351-351)
```text
        _burn(msg.sender, iTRYAmount);
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
