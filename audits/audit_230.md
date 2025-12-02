## Title
Lack of Slippage Protection in Fast Redemption Allows Users to Pay Unexpected Fees

## Summary
The `fastRedeem()` and `fastWithdraw()` functions in `StakediTryFastRedeem.sol` calculate fees using the live `fastRedeemFeeInBPS` value at execution time without any slippage protection parameters. Users who preview their expected output off-chain can receive significantly less than expected if the fee is updated between their calculation and transaction execution, with fee differences ranging from 0.01% to 20%.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol` - `fastRedeem()` function (lines 57-71), `fastWithdraw()` function (lines 76-90), `_redeemWithFee()` internal function (line 142)

**Intended Logic:** Users should be able to preview their fast redemption output and execute the transaction with predictable results, paying the fee they calculated off-chain.

**Actual Logic:** The fee is calculated at execution time using the current `fastRedeemFeeInBPS` value [1](#0-0) , which can be changed by admin via `setFastRedeemFee()` [2](#0-1)  at any time. The fee can range from 1 BPS (0.01%) to 2000 BPS (20%) [3](#0-2) , creating a potential 200x difference. Neither `fastRedeem()` [4](#0-3)  nor `fastWithdraw()` [5](#0-4)  include slippage protection parameters (e.g., `minAmountOut` or `maxFeeInBPS`).

**Exploitation Path:**
1. User queries current `fastRedeemFeeInBPS` (e.g., 100 BPS = 1%) and calculates expected net output for redeeming 1000 shares: expects to receive ~990 iTRY after 1% fee
2. User submits transaction to `fastRedeem(1000, receiver, owner)` with moderate gas price
3. Before user's transaction executes, admin legitimately updates fee to 2000 BPS (20%) via `setFastRedeemFee()`, or user's transaction gets delayed in mempool
4. User's transaction executes with new 20% fee, receiving only ~800 iTRY instead of expected ~990 iTRY - a loss of 190 iTRY (19% of their assets)

**Security Property Broken:** Users should have control over acceptable slippage in financial transactions. Standard DeFi preview-execute pattern requires consistent outputs or explicit slippage protection.

## Impact Explanation
- **Affected Assets**: wiTRY shares being fast redeemed, iTRY tokens being received
- **Damage Severity**: In extreme cases, users can pay up to 19.99% more in fees than expected (if fee changes from minimum 0.01% to maximum 20%). For a 10,000 iTRY redemption, this represents an unexpected loss of ~2,000 iTRY.
- **User Impact**: All users calling `fastRedeem()` or `fastWithdraw()` are vulnerable. This particularly affects users during:
  - High mempool congestion (delayed transaction execution)
  - Admin fee updates (intentional timing or coincidental)
  - MEV scenarios where bots monitor admin transactions

## Likelihood Explanation
- **Attacker Profile**: Not a direct attack by unprivileged users, but users become victims of timing issues. MEV bots could potentially sandwich users around admin fee updates.
- **Preconditions**: 
  - Fast redemption must be enabled
  - User must have wiTRY shares to redeem
  - Fee must be updated between user's off-chain calculation and on-chain execution
- **Execution Complexity**: Simple - happens automatically when admin updates fee during user transaction lifecycle
- **Frequency**: Can occur whenever admin adjusts fees, especially during market volatility when fee changes may be more frequent

## Recommendation

Add slippage protection parameters to both fast redemption functions:

**For fastRedeem():**
- Add `minAssetsOut` parameter to specify minimum acceptable net assets after fee
- Revert if `netAssets < minAssetsOut`

**For fastWithdraw():**
- Add `maxSharesIn` parameter to specify maximum acceptable shares to burn
- Revert if `totalShares > maxSharesIn`

**Alternative:** Add `maxFeeInBPS` parameter to both functions allowing users to specify maximum acceptable fee at execution time.

This follows standard DeFi patterns used in AMM swaps (Uniswap's `amountOutMinimum`, Curve's `min_dy`).

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemFeeSlippage.t.sol
// Run with: forge test --match-test test_FastRedeemFeeSlippage -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_FastRedeemFeeSlippage is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public user;
    
    uint256 constant DEPOSIT_AMOUNT = 10_000e18;
    
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
        
        // Mint tokens to user and approve
        iTryToken.mint(user, DEPOSIT_AMOUNT);
        vm.prank(user);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        // Enable fast redeem with initial low fee (1% = 100 BPS)
        vm.startPrank(admin);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(100); // 1%
        vm.stopPrank();
    }
    
    function test_FastRedeemFeeSlippage() public {
        // SETUP: User deposits and gets shares
        vm.prank(user);
        uint256 shares = stakediTry.deposit(DEPOSIT_AMOUNT, user);
        
        // User previews redemption with current 1% fee
        uint256 expectedGrossAssets = stakediTry.previewRedeem(shares);
        uint16 currentFee = stakediTry.fastRedeemFeeInBPS();
        uint256 expectedFee = (expectedGrossAssets * currentFee) / 10000;
        uint256 expectedNetAssets = expectedGrossAssets - expectedFee;
        
        console.log("User's off-chain calculation:");
        console.log("  Expected gross assets:", expectedGrossAssets);
        console.log("  Current fee (BPS):", currentFee);
        console.log("  Expected fee:", expectedFee);
        console.log("  Expected net assets:", expectedNetAssets);
        
        // ATTACK: Admin updates fee to maximum (20% = 2000 BPS) before user's tx executes
        // This could be legitimate admin action or timing coincidence
        vm.prank(admin);
        stakediTry.setFastRedeemFee(2000); // 20% - maximum allowed
        
        // User's transaction executes with NEW fee
        vm.prank(user);
        uint256 actualNetAssets = stakediTry.fastRedeem(shares, user, user);
        
        // Calculate actual fee that was charged
        uint256 actualFee = expectedGrossAssets - actualNetAssets;
        
        console.log("\nActual execution results:");
        console.log("  Actual fee charged:", actualFee);
        console.log("  Actual net assets:", actualNetAssets);
        console.log("  Fee difference:", actualFee - expectedFee);
        console.log("  Net assets difference:", expectedNetAssets - actualNetAssets);
        
        // VERIFY: User paid significantly more fee than expected
        assertGt(actualFee, expectedFee, "Actual fee should be higher than expected");
        assertLt(actualNetAssets, expectedNetAssets, "User received less than expected");
        
        // Calculate loss as percentage
        uint256 unexpectedLoss = expectedNetAssets - actualNetAssets;
        uint256 lossPercentage = (unexpectedLoss * 10000) / expectedGrossAssets;
        
        console.log("\nUser impact:");
        console.log("  Unexpected loss:", unexpectedLoss);
        console.log("  Loss percentage (BPS):", lossPercentage);
        
        // Verify significant loss occurred (19% difference between 1% and 20% fees)
        assertEq(lossPercentage, 1900, "User lost 19% of assets unexpectedly");
    }
}
```

## Notes

This vulnerability represents a **design flaw** rather than a malicious admin attack. Even with honest protocol operators, users need protection against:

1. **Timing issues**: Legitimate fee updates occurring while user transactions are pending in mempool
2. **MEV vulnerability**: Sophisticated actors monitoring admin transactions to exploit fee changes
3. **Network congestion**: User transactions with low gas prices executing after fee updates

The issue violates standard DeFi UX expectations where preview functions should accurately predict execution outcomes, or explicit slippage protection parameters should be provided. This is analogous to AMM swaps requiring `minAmountOut` parameters to protect users.

The protocol already demonstrates awareness of fee bounds (MIN/MAX constants), but lacks the final protection layer of user-specified slippage tolerance at transaction time.

### Citations

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L26-27)
```text
    uint16 public constant MIN_FAST_REDEEM_FEE = 1; // 0.01% minimum fee (1 basis point)
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L57-62)
```text
    function fastRedeem(uint256 shares, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 assets)
    {
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L76-81)
```text
    function fastWithdraw(uint256 assets, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 shares)
    {
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
