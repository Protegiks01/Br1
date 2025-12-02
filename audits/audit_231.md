## Title
Lack of Slippage Protection in Fast Redemption Enables Unexpected 20% Asset Loss

## Summary
The `fastRedeem()` and `fastWithdraw()` functions in `StakediTryFastRedeem.sol` lack slippage protection parameters, and the constructor sets a default fee of 20% (MAX_FAST_REDEEM_FEE). Combined with the absence of fee-aware preview functions, users can unexpectedly lose 20% of their assets when fast redeeming without manually checking the `fastRedeemFeeInBPS` state variable.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol` - `fastRedeem()` function (lines 57-71), `fastWithdraw()` function (lines 76-90), constructor (line 49)

**Intended Logic:** The fast redemption feature should allow users to bypass the cooldown period by paying a fee. Users should be able to preview and control the maximum fee they're willing to pay.

**Actual Logic:** The constructor initializes the fee at the maximum allowed value (20%). [1](#0-0)  The `fastRedeem()` and `fastWithdraw()` functions accept no slippage protection parameters (`minAssetsOut` or similar). [2](#0-1)  The fee is calculated and deducted internally without user consent for the specific amount. [3](#0-2) 

**Exploitation Path:**
1. Protocol deploys with 20% default fee set in constructor
2. Admin enables fast redemption via `setFastRedeemEnabled(true)`
3. User checks ERC4626 standard `previewRedeem(1000 shares)` → returns 1000 iTRY
4. User calls `fastRedeem(1000 shares, receiver, owner)` expecting ~1000 iTRY (perhaps anticipating a small 1-5% fee)
5. Contract calculates `feeAssets = 1000 * 2000 / 10000 = 200 iTRY` (20% fee)
6. User receives only 800 iTRY instead of expected amount
7. 200 iTRY (20% of assets) is sent to treasury, resulting in immediate and irreversible loss

**Security Property Broken:** User asset protection - users should have transparency and control over fees before execution. The lack of slippage protection violates the principle that users should be able to specify minimum acceptable outputs to prevent unexpected losses.

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY tokens held by any user attempting fast redemption
- **Damage Severity**: Users lose up to 20% of their staked assets (the maximum allowed fee). For a user with 10,000 iTRY worth of wiTRY shares, they would lose 2,000 iTRY to fees if they don't manually verify the fee rate before calling the function.
- **User Impact**: Any user who uses fast redemption without first reading the `fastRedeemFeeInBPS` state variable and manually calculating the fee. This affects users relying on frontend integrations, mobile wallets, or automated strategies that don't explicitly display the fee amount before execution.

## Likelihood Explanation
- **Attacker Profile**: Any legitimate user attempting fast redemption who doesn't manually check state variables
- **Preconditions**: 
  - Fast redemption must be enabled by admin
  - User must have wiTRY shares to redeem
  - Default 20% fee must still be in effect (or any fee higher than user expects)
- **Execution Complexity**: Single transaction - user simply calls `fastRedeem()` or `fastWithdraw()`
- **Frequency**: Occurs on every fast redemption until user discovers the fee rate or admin lowers it. Each affected user can lose 20% once, but this impacts all users until the fee is adjusted.

## Recommendation

Add slippage protection parameters and implement fee-aware preview functions:

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol:

// ADD PREVIEW FUNCTIONS (after line 51):
/**
 * @notice Preview the net assets a user would receive from fast redeeming shares
 * @param shares Amount of shares to fast redeem
 * @return netAssets Assets user would receive after fee deduction
 * @return feeAssets Fee amount in assets
 */
function previewFastRedeem(uint256 shares) external view returns (uint256 netAssets, uint256 feeAssets) {
    uint256 totalAssets = previewRedeem(shares);
    feeAssets = (totalAssets * fastRedeemFeeInBPS) / BASIS_POINTS;
    netAssets = totalAssets - feeAssets;
    return (netAssets, feeAssets);
}

/**
 * @notice Preview the shares needed and net assets for fast withdrawing a target amount
 * @param assets Target assets to withdraw (before fee)
 * @return shares Total shares that would be burned
 * @return netAssets Net assets after fee deduction
 * @return feeAssets Fee amount in assets
 */
function previewFastWithdraw(uint256 assets) external view returns (uint256 shares, uint256 netAssets, uint256 feeAssets) {
    shares = previewWithdraw(assets);
    feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;
    netAssets = assets - feeAssets;
    return (shares, netAssets, feeAssets);
}

// MODIFY EXISTING FUNCTIONS (lines 57-71 and 76-90):
// CURRENT (vulnerable):
function fastRedeem(uint256 shares, address receiver, address owner)
    external
    ensureCooldownOn
    ensureFastRedeemEnabled
    returns (uint256 assets)

// FIXED:
function fastRedeem(uint256 shares, address receiver, address owner, uint256 minAssetsOut)
    external
    ensureCooldownOn
    ensureFastRedeemEnabled
    returns (uint256 assets)
{
    if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();

    uint256 totalAssets = previewRedeem(shares);
    uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);
    uint256 netAssets = totalAssets - feeAssets;
    
    // Add slippage protection
    if (netAssets < minAssetsOut) revert SlippageExceeded(netAssets, minAssetsOut);

    emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);

    return netAssets;
}

// Similar changes for fastWithdraw with minAssetsOut parameter
```

**Alternative Mitigation:** If modifying function signatures is undesirable, implement a more conservative default fee:
- Set constructor default to MIN_FAST_REDEEM_FEE (1 basis point = 0.01%) instead of MAX_FAST_REDEEM_FEE
- Require admin to explicitly increase fee if needed
- Add prominent documentation warning about fee checks

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemSurpriseFee.t.sol
// Run with: forge test --match-test test_FastRedeemSurpriseFee -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../src/token/iTry/iTry.sol";

contract Exploit_FastRedeemSurpriseFee is Test {
    StakediTryFastRedeem vault;
    iTry itry;
    address user = address(0x1234);
    address treasury = address(0x5678);
    address owner = address(this);
    
    function setUp() public {
        // Deploy iTRY token
        itry = new iTry(owner);
        
        // Deploy vault with 20% default fee
        vault = new StakediTryFastRedeem(
            IERC20(address(itry)),
            owner, // initial rewarder
            owner, // admin
            treasury // fast redeem treasury
        );
        
        // Mint iTRY to user and approve vault
        itry.grantRole(itry.MINTER_ROLE(), owner);
        itry.mint(user, 10000 ether);
        
        // User deposits into vault
        vm.startPrank(user);
        itry.approve(address(vault), type(uint256).max);
        vault.deposit(10000 ether, user);
        vm.stopPrank();
        
        // Admin enables fast redeem (but doesn't lower fee)
        vault.setFastRedeemEnabled(true);
    }
    
    function test_FastRedeemSurpriseFee() public {
        // SETUP: User has 10000 wiTRY shares
        uint256 userShares = vault.balanceOf(user);
        assertEq(userShares, 10000 ether, "User should have 10000 shares");
        
        // User checks preview (standard ERC4626 function)
        uint256 expectedAssets = vault.previewRedeem(userShares);
        assertEq(expectedAssets, 10000 ether, "Preview shows 10000 iTRY");
        
        // User expects to receive ~10000 iTRY (maybe minus 1-5% fee)
        // But doesn't check fastRedeemFeeInBPS
        
        // EXPLOIT: User calls fastRedeem expecting full amount
        vm.prank(user);
        uint256 actualAssets = vault.fastRedeem(userShares, user, user);
        
        // VERIFY: User receives only 80% of expected amount!
        assertEq(actualAssets, 8000 ether, "User received only 8000 iTRY");
        assertEq(itry.balanceOf(user), 8000 ether, "User balance is 8000 iTRY");
        assertEq(itry.balanceOf(treasury), 2000 ether, "Treasury got 2000 iTRY fee");
        
        // User lost 20% (2000 iTRY) unexpectedly
        uint256 loss = expectedAssets - actualAssets;
        assertEq(loss, 2000 ether, "Vulnerability confirmed: User lost 2000 iTRY (20%)");
        
        console.log("Expected assets:", expectedAssets / 1 ether);
        console.log("Actual assets received:", actualAssets / 1 ether);
        console.log("Unexpected loss:", loss / 1 ether, "iTRY (20% of assets)");
    }
}
```

## Notes

**Key Distinctions:**
1. While `fastRedeemFeeInBPS` is a public state variable that users CAN query, the protocol provides no user-friendly way to preview the fee-adjusted amount before execution. [4](#0-3) 

2. Cross-chain operations implement slippage protection via `_assertSlippage` with `minAmountLD` parameters, [5](#0-4)  but the direct fast redemption functions completely lack this protection mechanism.

3. The constructor comment indicates the fee "Start at maximum fee (20%)" suggesting this is intentional, but there's no corresponding user protection mechanism to ensure users are aware of this fee before execution.

4. Standard ERC4626 `previewRedeem()` returns the gross amount without fee deduction, creating a false expectation for users who rely on this preview function. [6](#0-5) 

**This is not a known issue** - the Zellic audit findings do not mention fast redemption fee transparency or slippage protection issues. The vulnerability stems from the combination of an extremely high default fee with the absence of preview functions and slippage controls, creating a realistic scenario where users suffer unexpected 20% losses.

### Citations

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L24-24)
```text
    uint16 public fastRedeemFeeInBPS;
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L49-49)
```text
        fastRedeemFeeInBPS = MAX_FAST_REDEEM_FEE; // Start at maximum fee (20%)
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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L142-142)
```text
        feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L309-310)
```text
    function _assertSlippage(uint256 _amountLD, uint256 _minAmountLD) internal view virtual {
        if (_amountLD < _minAmountLD) revert SlippageExceeded(_amountLD, _minAmountLD);
```
