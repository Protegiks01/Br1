## Title
Missing Vault Self-Reference Validation in setFastRedeemTreasury Causes Protocol Revenue Loss and Share Price Manipulation

## Summary
The `setFastRedeemTreasury` function in `StakediTryFastRedeem.sol` only validates that the treasury address is not zero but fails to prevent setting it to the vault's own address (address(this)). This misconfiguration causes accounting errors during fast redemptions where fee shares are burned but fee assets remain in the vault, artificially inflating the share price and causing permanent loss of protocol treasury fees.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `setFastRedeemTreasury` function should configure a treasury address to receive fast redemption fees. The treasury should be an external address that collects protocol revenue, separate from the vault itself.

**Actual Logic:** The function only validates `treasury != address(0)` but permits setting `treasury = address(this)` (the vault contract). When users perform fast redemptions with this misconfiguration, the `_redeemWithFee` function executes two `_withdraw` calls: [2](#0-1) 

The first `_withdraw` to `fastRedeemTreasury` (line 152) burns fee shares and "transfers" fee assets to the vault (circular transfer - no actual balance change). The second `_withdraw` to the receiver (line 155) burns net shares and transfers net assets to the user. This results in all shares being burned but only net assets leaving the vault, breaking the share/asset ratio.

**Exploitation Path:**
1. **Admin misconfiguration**: Admin calls `setFastRedeemTreasury(address(vault))` - no validation prevents this
2. **User fast redemption**: Any user calls `fastRedeem(shares, receiver, owner)` with 20% fee
3. **Fee withdrawal to vault**: `_withdraw` burns fee shares (e.g., 200) and "transfers" 200 iTRY to vault (self-transfer, no balance change)
4. **Net withdrawal to user**: `_withdraw` burns net shares (e.g., 800) and transfers 800 iTRY to user (actual balance reduction)
5. **Accounting error**: Vault loses 800 iTRY and 1000 shares (200+800), but should have lost 1000 iTRY. Share price artificially increases from 1:1 to ~1.022:1
6. **Protocol revenue loss**: Treasury receives zero fees; remaining stakers gain value at protocol's expense

**Security Property Broken:** This violates the intended economic model where fast redemption fees compensate the protocol treasury for providing immediate liquidity. It also breaks the ERC4626 invariant that burning shares should proportionally reduce total assets.

## Impact Explanation
- **Affected Assets**: Protocol treasury revenue (iTRY fees), all wiTRY stakers' share valuations
- **Damage Severity**: Complete loss of all fast redemption fee revenue. For example, with a 20% fast redeem fee and 1M iTRY in fast redemptions, the protocol loses 200k iTRY in fees. Remaining stakers unfairly gain this value through inflated share prices, creating an economic imbalance.
- **User Impact**: All fast redemption users unknowingly donate their fees to remaining stakers instead of the protocol treasury. Remaining stakers benefit disproportionately. The misconfiguration persists until admin corrects it, affecting all fast redemptions during that period.

## Likelihood Explanation
- **Attacker Profile**: Not a direct attack - requires admin misconfiguration. However, the lack of validation makes this configuration error highly likely during deployment, testing, or emergency treasury updates.
- **Preconditions**: Admin must call `setFastRedeemTreasury` with vault address, and fast redemption must be enabled.
- **Execution Complexity**: Once misconfigured, every normal fast redemption operation automatically triggers the accounting error. No special attacker actions required.
- **Frequency**: Continuous - every fast redemption compounds the loss until corrected. Given that fast redemption is a core feature to bypass cooldown periods, this represents significant ongoing revenue leakage.

## Recommendation
Add validation to prevent setting the treasury to the vault's own address:

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol, function setFastRedeemTreasury, line 117:

// CURRENT (vulnerable):
if (treasury == address(0)) revert InvalidZeroAddress();

// FIXED:
if (treasury == address(0)) revert InvalidZeroAddress();
if (treasury == address(this)) revert InvalidTreasuryAddress(); // Add new check to prevent vault self-reference
```

Alternative mitigation: Add validation in the constructor as well to prevent initial misconfiguration: [3](#0-2) 

Add the same `if (treasury == address(this)) revert InvalidTreasuryAddress();` check after line 45.

## Proof of Concept
```solidity
// File: test/Exploit_TreasuryVaultSelfReference.t.sol
// Run with: forge test --match-test test_TreasuryVaultSelfReference -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_TreasuryVaultSelfReference is Test {
    StakediTryFastRedeem vault;
    iTry itry;
    address admin = address(0x1);
    address alice = address(0x2);
    address bob = address(0x3);
    
    function setUp() public {
        // Deploy and initialize iTRY
        vm.startPrank(admin);
        itry = new iTry();
        itry.initialize(admin, admin);
        
        // Deploy vault
        vault = new StakediTryFastRedeem(
            IERC20(address(itry)),
            admin, // rewarder
            admin, // owner
            admin  // initial treasury (valid)
        );
        
        // Enable fast redeem
        vault.setFastRedeemEnabled(true);
        vault.setFastRedeemFee(2000); // 20% fee
        
        // Mint iTRY to users
        itry.mint(alice, 10000e18);
        itry.mint(bob, 10000e18);
        vm.stopPrank();
        
        // Users deposit to vault
        vm.startPrank(alice);
        itry.approve(address(vault), type(uint256).max);
        vault.deposit(10000e18, alice);
        vm.stopPrank();
        
        vm.startPrank(bob);
        itry.approve(address(vault), type(uint256).max);
        vault.deposit(10000e18, bob);
        vm.stopPrank();
    }
    
    function test_TreasuryVaultSelfReference() public {
        // SETUP: Initial vault state
        uint256 initialTotalAssets = vault.totalAssets();
        uint256 initialTotalShares = vault.totalSupply();
        uint256 initialSharePrice = (initialTotalAssets * 1e18) / initialTotalShares;
        
        assertEq(initialTotalAssets, 20000e18, "Initial assets should be 20000");
        assertEq(initialTotalShares, 20000e18, "Initial shares should be 20000");
        assertEq(initialSharePrice, 1e18, "Initial share price should be 1:1");
        
        // MISCONFIGURATION: Admin sets treasury to vault itself (no validation prevents this)
        vm.prank(admin);
        vault.setFastRedeemTreasury(address(vault)); // This should fail but doesn't!
        
        // EXPLOIT: Alice fast redeems 1000 shares with 20% fee
        vm.startPrank(alice);
        uint256 aliceInitialShares = vault.balanceOf(alice);
        uint256 sharesToRedeem = 1000e18;
        
        // Fast redeem
        uint256 netAssets = vault.fastRedeem(sharesToRedeem, alice, alice);
        vm.stopPrank();
        
        // VERIFY: Accounting error
        uint256 finalTotalAssets = vault.totalAssets();
        uint256 finalTotalShares = vault.totalSupply();
        uint256 finalSharePrice = (finalTotalAssets * 1e18) / finalTotalShares;
        
        // Expected: 1000 iTRY should have left (800 to Alice + 200 to treasury)
        // Actual: Only 800 iTRY left (to Alice), 200 stayed in vault
        assertEq(finalTotalAssets, 19200e18, "Assets should be 19200 (20000 - 800)");
        assertEq(finalTotalShares, 19000e18, "Shares should be 19000 (20000 - 1000)");
        
        // Share price inflated!
        assertTrue(finalSharePrice > initialSharePrice, "Share price should increase");
        assertApproxEqRel(finalSharePrice, 1.010526e18, 0.001e18, "Share price inflated to ~1.0105:1");
        
        // Protocol lost 200 iTRY in fees (20% of 1000)
        uint256 expectedFeeRevenue = 200e18;
        uint256 actualProtocolLoss = initialTotalAssets - finalTotalAssets - netAssets;
        assertEq(actualProtocolLoss, 0, "Protocol received 0 fees instead of 200 iTRY");
        
        console.log("Initial share price:", initialSharePrice);
        console.log("Final share price:", finalSharePrice);
        console.log("Protocol lost fees:", expectedFeeRevenue);
        console.log("Remaining stakers gained value:", finalTotalAssets - (finalTotalShares * initialSharePrice / 1e18));
    }
}
```

## Notes
This vulnerability is categorized as **Medium** severity rather than High because:
- It requires admin misconfiguration (not directly exploitable by unprivileged users)
- It causes loss of protocol treasury revenue, not direct user fund theft
- However, the lack of validation makes this configuration error realistic and the impact compounds with every fast redemption

The issue is in scope per the provided contract list and represents a concrete financial loss vector that violates the intended economic model of the fast redemption mechanism.

### Citations

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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L151-155)
```text
        // Withdraw fee portion to treasury
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
```
