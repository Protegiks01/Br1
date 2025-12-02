## Title
Insufficient Treasury Validation Allows Share Price Manipulation Through Circular Fee Transfers

## Summary
The `setFastRedeemTreasury` function in `StakediTryFastRedeem.sol` only validates that the treasury address is not zero, but fails to prevent setting it to the vault itself or other critical protocol contracts like the silo. [1](#0-0)  This allows fast redemption fees to be transferred back into the vault's iTRY balance, artificially inflating the share price and redistributing value between stakers.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol`, function `setFastRedeemTreasury`, lines 116-122

**Intended Logic:** The fast redemption treasury should be an external address (separate protocol treasury) that collects fees from users who bypass the cooldown period. Fees should leave the vault to maintain proper share price accounting. [2](#0-1) 

**Actual Logic:** The validation only prevents zero address but allows setting the vault itself as the treasury. [1](#0-0)  When fast redemption occurs with `treasury = address(this)`, the fee portion is transferred back to the vault through the `_withdraw` call. [3](#0-2)  These fee tokens remain in the vault's iTRY balance and become part of `totalAssets()` calculation. [4](#0-3) 

**Exploitation Path:**
1. Admin calls `setFastRedeemTreasury(address(stakediTry))` to set treasury to the vault itself - passes validation since it's not address(0)
2. User1 deposits 10,000 iTRY and receives shares at 1:1 ratio (assuming initialized vault)
3. User2 deposits 10,000 iTRY and receives shares at 1:1 ratio
4. User2 calls `fastRedeem()` to withdraw all shares immediately with 5% fee (500 iTRY)
5. The `_redeemWithFee` function executes two `_withdraw` calls: [5](#0-4) 
   - First: Transfers 500 iTRY fee to treasury (which is the vault itself)
   - Second: Transfers 9,500 iTRY net amount to User2
6. The vault's iTRY balance now includes the 500 iTRY fee that was "paid" but stayed in the vault
7. `totalAssets()` increases by 500 iTRY (only User1's shares remain outstanding)
8. Share price inflates: User1's shares are now worth more iTRY than originally deposited
9. User1 can redeem for more iTRY than entitled, effectively capturing User2's fee payment

**Security Property Broken:** Violates ERC4626 share accounting integrity and fair value distribution among stakers. Fast redemption fees should exit the vault system, not artificially inflate share values for remaining stakers.

## Impact Explanation
- **Affected Assets**: wiTRY shares (vault tokens) and iTRY tokens (underlying assets)
- **Damage Severity**: Fast redemption fees (configured up to 20% maximum) [6](#0-5)  are redistributed to remaining stakers instead of going to protocol treasury. For a vault with 1M iTRY staked and 10% using fast redemption at 5% fee, approximately 5,000 iTRY in fees would be inappropriately redistributed to non-redeeming stakers
- **User Impact**: All remaining stakers benefit at the expense of fast redeemers. While fast redeemers expect to pay a fee, they don't expect that fee to benefit other users rather than the protocol. This creates perverse incentives and unfair value distribution

## Likelihood Explanation
- **Attacker Profile:** Requires DEFAULT_ADMIN_ROLE to misconfigure the treasury. Not exploitable by unprivileged users directly, but realistic admin mistake (e.g., setting to vault address thinking it accumulates protocol value)
- **Preconditions:** 
  - Vault must be initialized with fast redemption enabled
  - Admin must set treasury to the vault contract address (or silo address)
  - Users must perform fast redemptions while this misconfiguration exists
- **Execution Complexity:** Single admin transaction to misconfigure, automatic exploitation through normal fast redemption usage
- **Frequency:** Continuous - every fast redemption while misconfigured redistributes fees incorrectly

## Recommendation

Add validation to prevent setting critical protocol contracts as the treasury: [1](#0-0) 

**Recommended Fix:**
```solidity
function setFastRedeemTreasury(address treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (treasury == address(0)) revert InvalidZeroAddress();
    // Prevent circular transfers that would inflate share price
    if (treasury == address(this)) revert InvalidTreasury();
    // Prevent fees from being locked in silo (designed only for cooldown iTRY)
    if (treasury == address(silo)) revert InvalidTreasury();
    
    address previousTreasury = fastRedeemTreasury;
    fastRedeemTreasury = treasury;
    emit FastRedeemTreasuryUpdated(previousTreasury, treasury);
}
```

Add a custom error:
```solidity
error InvalidTreasury();
```

**Alternative Mitigation:** Consider adding validation in the constructor as well [7](#0-6)  to prevent deployment with misconfigured treasury.

## Proof of Concept

```solidity
// File: test/Exploit_TreasuryShareInflation.t.sol
// Run with: forge test --match-test test_TreasuryVaultInflatesSharePrice -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../test/mocks/MockERC20.sol";

contract Exploit_TreasuryShareInflation is Test {
    StakediTryFastRedeem public vault;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public user1;
    address public user2;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy vault
        vm.prank(admin);
        vault = new StakediTryFastRedeem(
            IERC20(address(iTryToken)),
            admin,
            admin,
            treasury
        );
        
        // Enable fast redemption
        vm.startPrank(admin);
        vault.setFastRedeemEnabled(true);
        vault.setFastRedeemFee(500); // 5% fee
        vm.stopPrank();
        
        // Mint and approve tokens
        iTryToken.mint(user1, 10_000e18);
        iTryToken.mint(user2, 10_000e18);
        
        vm.prank(user1);
        iTryToken.approve(address(vault), type(uint256).max);
        
        vm.prank(user2);
        iTryToken.approve(address(vault), type(uint256).max);
    }
    
    function test_TreasuryVaultInflatesSharePrice() public {
        // SETUP: Initial deposits
        vm.prank(user1);
        uint256 shares1 = vault.deposit(10_000e18, user1);
        
        vm.prank(user2);
        uint256 shares2 = vault.deposit(10_000e18, user2);
        
        // Record initial share values
        uint256 initialSharePrice = vault.convertToAssets(1e18);
        console.log("Initial share price (assets per 1 wiTRY):", initialSharePrice);
        
        // EXPLOIT: Admin misconfigures treasury to vault itself
        vm.prank(admin);
        vault.setFastRedeemTreasury(address(vault)); // No revert! Only checks != address(0)
        
        // User2 fast redeems all shares
        vm.prank(user2);
        uint256 netReceived = vault.fastRedeem(shares2, user2, user2);
        
        console.log("User2 net received:", netReceived);
        console.log("Expected net (95% of 10k):", 9_500e18);
        
        // VERIFY: Share price has inflated
        uint256 inflatedSharePrice = vault.convertToAssets(1e18);
        console.log("Share price after fast redeem:", inflatedSharePrice);
        
        // User1 can now redeem for MORE than originally deposited
        uint256 user1Redeemable = vault.convertToAssets(shares1);
        console.log("User1 can now redeem:", user1Redeemable);
        console.log("User1 originally deposited:", 10_000e18);
        
        // Assertions proving the vulnerability
        assertGt(
            inflatedSharePrice, 
            initialSharePrice, 
            "Share price should have inflated from circular fee transfer"
        );
        
        assertGt(
            user1Redeemable,
            10_000e18,
            "User1 can redeem more than deposited - captured User2's fee"
        );
        
        // The fee that should have gone to treasury is now in vault
        assertEq(
            iTryToken.balanceOf(treasury),
            0,
            "Treasury received nothing - fees went to vault"
        );
        
        // Vault balance increased by the fee amount
        uint256 vaultBalance = iTryToken.balanceOf(address(vault));
        console.log("Vault iTRY balance:", vaultBalance);
        assertGt(
            vaultBalance,
            10_000e18,
            "Vault balance increased beyond User1's deposit"
        );
    }
}
```

## Notes

**Additional Context:**
1. **Silo vulnerability**: While less severe, setting treasury to the silo address [8](#0-7)  would lock fees in the cooldown contract, requiring admin rescue operations and potentially mixing with user cooldown funds

2. **Why this is not a "centralization risk"**: This is not about malicious admin behavior but rather insufficient input validation that allows an honest configuration mistake with economic consequences. The admin is trusted but should be protected from making economically harmful errors

3. **ERC4626 accounting violation**: The ERC4626 standard expects share prices to reflect actual economic value. Circular fee transfers break this assumption by artificially inflating `totalAssets()` [4](#0-3)  without corresponding value creation

4. **Production deployment evidence**: The deployment script shows treasury is meant to be a separate address [9](#0-8)  supporting that self-referential configuration is unintended

### Citations

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L10-15)
```text
 * @title StakediTryFastRedeem
 * @notice Extends StakediTryV2 with fast redemption functionality
 * @dev Allows users to bypass the cooldown period by paying a fee that goes to the treasury.
 *      This provides liquidity to users who need immediate access to their funds while
 *      maintaining the protocol's stability through fee collection.
 */
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L26-27)
```text
    uint16 public constant MIN_FAST_REDEEM_FEE = 1; // 0.01% minimum fee (1 basis point)
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L42-50)
```text
    constructor(IERC20 _asset, address initialRewarder, address owner, address _fastRedeemTreasury)
        StakediTryV2(_asset, initialRewarder, owner)
    {
        if (_fastRedeemTreasury == address(0)) revert InvalidZeroAddress();

        fastRedeemTreasury = _fastRedeemTreasury;
        fastRedeemEnabled = false;
        fastRedeemFeeInBPS = MAX_FAST_REDEEM_FEE; // Start at maximum fee (20%)
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L116-122)
```text
    function setFastRedeemTreasury(address treasury) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (treasury == address(0)) revert InvalidZeroAddress();

        address previousTreasury = fastRedeemTreasury;
        fastRedeemTreasury = treasury;
        emit FastRedeemTreasuryUpdated(previousTreasury, treasury);
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

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L22-22)
```text
    iTrySilo public immutable silo;
```

**File:** script/deploy/hub/02_DeployProtocol.s.sol (L183-183)
```text
                treasuryAddress // fastRedeemTreasury
```
