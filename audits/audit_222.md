# NoVulnerability found for this question.

## Analysis

I thoroughly investigated whether setting `fastRedeemFeeInBPS` to `MIN_FAST_REDEEM_FEE` (1 basis point) causes a DOS on fast redemptions for small amounts. Here's what I found:

### The Behavior Exists But Is Intentional

**Fee Calculation Logic:** [1](#0-0) 

When `fastRedeemFeeInBPS = 1` (0.01%), the fee calculation is:
- `feeAssets = (assets * 1) / 10000`
- For amounts < 10,000 wei, this rounds to 0 and triggers the revert

**Minimum Fee Validation:** [2](#0-1) [3](#0-2) 

The admin can legitimately set the fee to 1 basis point, which is within the allowed range.

### However, This Is **Intended Protocol Design**, Not a Vulnerability

**Evidence from Protocol Tests:** [4](#0-3) 

The fuzz test explicitly validates this exact behavior:
- Tests dust amounts (1 wei to 1e6 wei) with all valid fees including `MIN_FAST_REDEEM_FEE`
- Line 654: **Expects the revert** when `feeAmount == 0`
- Comment at line 655: "Fee rounds to zero - should revert per InvalidAmount check"

**Protocol Invariant:** [5](#0-4) 

The protocol **intentionally enforces** that fast redemptions always have a non-zero cost (line 217: "Treasury must always receive non-zero fee"). The revert at line 145 is the enforcement mechanism.

### Impact Assessment

**Amounts Affected:** < 10,000 wei = 0.00000000001 iTRY (10^-11 iTRY)

This is economically negligible:
- Transaction gas costs would be ~1000x higher than the redemption value
- No rational user would fast redeem such dust amounts
- Users can still use regular cooldown redemption for any amount

**Severity Classification:** Low/QA at best
- Does not cause fund loss or theft
- Does not violate any documented invariant (it **enforces** the "always has cost" invariant)
- Only affects dust amounts with no practical use case
- Temporary and easily reversible (admin can increase fee)

## Notes

The protocol correctly implements a design decision to prevent zero-cost fast redemptions. The minimum fee of 1 basis point creates a practical lower bound of ~10,000 wei for fast redemptions, which is intentional and tested behavior. This does not meet the criteria for a High/Medium severity vulnerability in the Code4rena framework.

### Citations

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L26-27)
```text
    uint16 public constant MIN_FAST_REDEEM_FEE = 1; // 0.01% minimum fee (1 basis point)
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L103-106)
```text
    function setFastRedeemFee(uint16 feeInBPS) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (feeInBPS < MIN_FAST_REDEEM_FEE || feeInBPS > MAX_FAST_REDEEM_FEE) {
            revert InvalidFastRedeemFee();
        }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L142-145)
```text
        feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;

        // Enforce that fast redemption always has a cost
        if (feeAssets == 0) revert InvalidAmount();
```

**File:** test/StakediTryFastRedeem.fuzz.t.sol (L184-223)
```text
    /// @notice Fuzz test: Treasury always receives fee (no zero-fee redemptions)
    /// @dev Property: feeAssets > 0 for all valid redemptions (enforces cost for instant liquidity)
    /// @dev Bounds: MIN_SHARES to $1B, all valid fees - ensures fast redeem always has cost
    function testFuzz_fastRedeem_treasuryAlwaysReceivesFee(uint256 shares, uint16 feeInBPS) public {
        // Bound fee to valid range
        feeInBPS = uint16(bound(uint256(feeInBPS), stakediTry.MIN_FAST_REDEEM_FEE(), stakediTry.MAX_FAST_REDEEM_FEE()));

        // Set the fuzzed fee
        vm.prank(admin);
        stakediTry.setFastRedeemFee(feeInBPS);

        // User2 deposits to provide MIN_SHARES buffer
        vm.prank(user2);
        stakediTry.deposit(100_000e18, user2);

        // User deposits
        vm.prank(user1);
        uint256 totalShares = stakediTry.deposit(INITIAL_SUPPLY, user1);

        // Bound shares to valid range
        shares = bound(shares, 1e18, totalShares);

        // Record treasury balance before
        uint256 treasuryBalanceBefore = iTryToken.balanceOf(treasury);

        // Act
        vm.prank(user1);
        stakediTry.fastRedeem(shares, user1, user1);

        // Assert: Treasury always receives non-zero fee
        uint256 treasuryBalanceAfter = iTryToken.balanceOf(treasury);
        uint256 feeReceived = treasuryBalanceAfter - treasuryBalanceBefore;

        assertGt(feeReceived, 0, "Treasury must always receive non-zero fee");

        // Additional check: fee matches calculation
        uint256 totalAssets = stakediTry.previewRedeem(shares);
        uint256 expectedFee = (totalAssets * feeInBPS) / 10000;
        assertEq(feeReceived, expectedFee, "Fee received must match formula");
    }
```

**File:** test/StakediTryFastRedeem.fuzz.t.sol (L631-669)
```text
    function testFuzz_edgeCases_dustAmountHandling(uint256 dustAmount, uint16 feeInBPS) public {
        // Bound to very small amounts (dust)
        dustAmount = bound(dustAmount, 1, 1e6);

        // Bound fee to valid range
        feeInBPS = uint16(bound(uint256(feeInBPS), stakediTry.MIN_FAST_REDEEM_FEE(), stakediTry.MAX_FAST_REDEEM_FEE()));

        // Set fee
        vm.prank(admin);
        stakediTry.setFastRedeemFee(feeInBPS);

        // User2 deposits large buffer
        vm.prank(user2);
        stakediTry.deposit(1_000_000e18, user2);

        // User1 deposits large amount so they can redeem dust
        vm.prank(user1);
        stakediTry.deposit(1_000_000e18, user1);

        // Try to fast withdraw dust amount
        // Calculate fee for dust
        uint256 feeAmount = (dustAmount * feeInBPS) / 10000;

        if (feeAmount == 0) {
            // Fee rounds to zero - should revert per InvalidAmount check
            vm.expectRevert(abi.encodeWithSelector(IStakediTry.InvalidAmount.selector));
            vm.prank(user1);
            stakediTry.fastWithdraw(dustAmount, user1, user1);
        } else {
            // Fee is non-zero - should either succeed or revert for valid reason
            try stakediTry.fastWithdraw(dustAmount, user1, user1) returns (uint256 sharesBurned) {
                // Success case: validate proper accounting
                assertGt(sharesBurned, 0, "Shares must be burned for successful dust redemption");
            } catch {
                // Revert is acceptable for dust amounts (might hit other constraints)
                // Just ensure it doesn't succeed with incorrect accounting
            }
        }
    }
```
