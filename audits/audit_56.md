## Title
Small Amount Minting DOS Due to Fee Rounding Forcing netDlfAmount to Zero

## Summary
The `mintFor` function in iTryIssuer.sol contains a DOS vulnerability for small deposit amounts. When the calculated mint fee rounds down to zero, the `_calculateMintFee` function forces it to 1 wei. For deposits of 1 wei (or a range of small amounts depending on the fee rate), this results in the entire deposit being consumed by fees, leaving `netDlfAmount = 0`, which causes `iTRYAmount = 0` and triggers a revert at line 292.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/protocol/iTryIssuer.sol` - `mintFor` function (lines 270-306) and `_calculateMintFee` function (lines 670-678)

**Intended Logic:** The mint fee calculation should allow users to mint iTRY with any non-zero DLF amount, with fees proportionally deducted based on `mintFeeInBPS`.

**Actual Logic:** The fee calculation contains an anti-round-down-to-zero mechanism that forces any zero fee to 1 wei. [1](#0-0) 

Combined with the mintFor logic that subtracts fees and checks for zero output, this creates a DOS condition: [2](#0-1) 

**Exploitation Path:**
1. User calls `mintFor` with `dlfAmount = 1 wei` (or any small amount below the fee threshold)
2. `_calculateMintFee(1)` computes `1 * 50 / 10000 = 0`, then forces the fee to 1 wei (line 674)
3. `netDlfAmount = 1 - 1 = 0`
4. `iTRYAmount = 0 * navPrice / 1e18 = 0`
5. Transaction reverts with `CommonErrors.ZeroAmount()` at line 292

**Security Property Broken:** Users cannot mint iTRY with small but valid amounts, creating unexpected transaction failures and wasting gas. Additionally, there's an inconsistency where `previewMint` [3](#0-2)  does not check if `iTRYAmount == 0` at the end, so users may receive misleading previews showing 0 output without realizing the actual mint will revert.

## Impact Explanation

- **Affected Assets**: DLF tokens and iTRY minting operations for small amounts
- **Damage Severity**: For the default fee of 50 BPS (0.5%):
  - Any `dlfAmount < 200 wei` will have the fee forced to 1 wei
  - `dlfAmount = 1 wei` results in complete DOS (netDlfAmount = 0)
  - Higher fee rates expand the affected range (e.g., 100 BPS = 1% affects amounts < 100 wei)
- **User Impact**: 
  - Users attempting to mint with dust amounts waste gas on failed transactions
  - Integration contracts or automated systems handling small amounts may experience unexpected failures
  - Inconsistent behavior between `previewMint` (returns 0) and `mintFor` (reverts)

## Likelihood Explanation

- **Attacker Profile**: Any whitelisted user can trigger this, though it's self-inflicted (wastes their own gas)
- **Preconditions**: 
  - `mintFeeInBPS > 0` must be set (default is 50 BPS in tests)
  - User attempts to mint with very small amounts
- **Execution Complexity**: Single transaction - user calls `mintFor` with small `dlfAmount`
- **Frequency**: Can occur on every small mint attempt; the affected range depends on the configured fee rate (threshold = `10000 / mintFeeInBPS` wei)

## Recommendation

Add a minimum deposit amount check at the beginning of `mintFor` to prevent DOS with dust amounts:

```solidity
// In src/protocol/iTryIssuer.sol, function mintFor, after line 280:

// CURRENT (vulnerable):
if (dlfAmount == 0) revert CommonErrors.ZeroAmount();

// Get NAV price from oracle
uint256 navPrice = oracle.price();

// FIXED:
if (dlfAmount == 0) revert CommonErrors.ZeroAmount();

// Add minimum deposit check to prevent fee rounding issues
uint256 minDeposit = mintFeeInBPS > 0 ? (10000 / mintFeeInBPS) + 1 : 1;
if (dlfAmount < minDeposit) revert CommonErrors.ZeroAmount(); // or create a new error: MinimumDepositNotMet

// Get NAV price from oracle
uint256 navPrice = oracle.price();
```

Alternative mitigation: Remove the forced fee of 1 wei in `_calculateMintFee` and accept that very small amounts may have zero fees. However, this may violate protocol fee collection expectations.

## Proof of Concept

```solidity
// File: test/Exploit_SmallAmountMintDOS.t.sol
// Run with: forge test --match-test test_SmallAmountMintDOS -vvv

pragma solidity ^0.8.0;

import "./iTryIssuer.base.t.sol";
import {CommonErrors} from "../src/protocol/periphery/CommonErrors.sol";

contract Exploit_SmallAmountMintDOS is iTryIssuerBaseTest {
    
    function test_SmallAmountMintDOS() public {
        // SETUP: Default fee is 50 BPS (0.5%) as set in base test
        // This means threshold = 10000/50 = 200 wei
        
        // CASE 1: Mint with 1 wei - fee consumes entire amount
        vm.startPrank(whitelistedUser1);
        
        // Check preview (doesn't revert, returns 0)
        uint256 previewAmount = issuer.previewMint(1);
        assertEq(previewAmount, 0, "Preview shows 0 output");
        
        // Actual mint reverts
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.ZeroAmount.selector));
        issuer.mintFor(whitelistedUser1, 1, 0);
        
        // CASE 2: Show threshold - amounts below 200 wei are affected
        for (uint256 i = 1; i < 200; i++) {
            // All these amounts will have fee forced to 1 wei
            // For i = 1, netDlfAmount = 0 (reverts)
            // For i = 2 to 199, netDlfAmount = 1 to 198
            vm.expectRevert(abi.encodeWithSelector(CommonErrors.ZeroAmount.selector));
            issuer.mintFor(whitelistedUser1, i, 0);
        }
        
        // CASE 3: Amount at threshold works (200 wei)
        uint256 iTryMinted = issuer.mintFor(whitelistedUser1, 200, 0);
        assertGt(iTryMinted, 0, "Mint succeeds at threshold");
        
        vm.stopPrank();
    }
    
    function test_SmallAmountDOSWithHigherFee() public {
        // With 1% fee (100 BPS), threshold increases to 100 wei
        vm.prank(admin);
        issuer.setMintFeeInBPS(100); // 1% fee
        
        vm.startPrank(whitelistedUser1);
        
        // dlfAmount = 1 wei fails
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.ZeroAmount.selector));
        issuer.mintFor(whitelistedUser1, 1, 0);
        
        // Amounts below 100 wei all fail
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.ZeroAmount.selector));
        issuer.mintFor(whitelistedUser1, 50, 0);
        
        vm.expectRevert(abi.encodeWithSelector(CommonErrors.ZeroAmount.selector));
        issuer.mintFor(whitelistedUser1, 99, 0);
        
        // At threshold (100 wei), mint succeeds
        uint256 iTryMinted = issuer.mintFor(whitelistedUser1, 100, 0);
        assertGt(iTryMinted, 0, "Mint succeeds at 100 wei threshold");
        
        vm.stopPrank();
    }
}
```

## Notes

While this vulnerability only affects dust amounts and doesn't lead to loss of principal funds, it represents a DOS condition that:
1. Wastes user gas on transactions that pass initial validation but fail later
2. Creates an inconsistency between `previewMint` (returns 0) and `mintFor` (reverts) for the same input
3. Could break integration contracts that attempt to handle small amounts or dust cleanup operations
4. Expands to a wider range with higher fee configurations

The root cause is the anti-rounding mechanism at line 674 that forces zero fees to 1 wei, combined with insufficient validation of the resulting `netDlfAmount` before the NAV price conversion.

### Citations

**File:** src/protocol/iTryIssuer.sol (L190-200)
```text
    function previewMint(uint256 dlfAmount) external view returns (uint256 iTRYAmount) {
        if (dlfAmount == 0) revert CommonErrors.ZeroAmount();

        uint256 navPrice = oracle.price();
        uint256 netDlfAmount = dlfAmount;

        netDlfAmount = dlfAmount - _calculateMintFee(dlfAmount);

        // Calculate iTRY amount: netDlfAmount * navPrice / 1e18
        iTRYAmount = netDlfAmount * navPrice / 1e18;
    }
```

**File:** src/protocol/iTryIssuer.sol (L286-292)
```text
        uint256 feeAmount = _calculateMintFee(dlfAmount);
        uint256 netDlfAmount = feeAmount > 0 ? (dlfAmount - feeAmount) : dlfAmount;

        // Calculate iTRY amount: netDlfAmount * navPrice / 1e18
        iTRYAmount = netDlfAmount * navPrice / 1e18;

        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();
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
