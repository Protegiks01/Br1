## Title
Silent Integer Truncation in Cooldown Storage Causes Mismatch Between Returned and Stored Asset Amounts

## Summary
The `cooldownSharesByComposer` function in `StakediTryCrosschain.sol` returns a `uint256` assets value calculated from `previewRedeem`, but the internal `_startComposerCooldown` function stores this value by explicitly casting it to `uint152` without overflow checks. [1](#0-0)  This creates a critical mismatch: the function returns the full amount to the caller, but if the assets value exceeds `type(uint152).max` (≈5.7×10²⁷ tokens), the stored cooldown amount will be silently truncated. [2](#0-1) 

## Impact
**Severity**: Low

## Finding Description

**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` - `cooldownSharesByComposer` function (lines 36-48) and `_startComposerCooldown` internal function (lines 170-181)

**Intended Logic:** The function should calculate the asset amount equivalent to the burned shares, store this exact amount in the redeemer's cooldown, and return it to the caller for event emission and tracking. The stored value should match the returned value exactly.

**Actual Logic:** The function calculates `assets = previewRedeem(shares)` as a `uint256`, [3](#0-2)  returns this full value, but internally casts to `uint152` when storing: `cooldowns[redeemer].underlyingAmount += uint152(assets)`. [2](#0-1)  In Solidity 0.8.20, explicit type casts do NOT have overflow protection and will silently truncate values exceeding the target type's maximum.

**Exploitation Path:**
1. A user (or multiple users to the same redeemer address) initiates cross-chain cooldowns that accumulate to exceed `type(uint152).max` ≈ 5,708,990,770,823,839,524,233,143,877,797,980,545,530,986,495 (≈5.7×10⁴⁵ wei or ≈5.7×10²⁷ tokens with 18 decimals)
2. The `cooldownSharesByComposer` function calculates the correct uint256 assets amount via `previewRedeem`
3. The function returns this full uint256 value to `wiTryVaultComposer`, which emits it in the `CooldownInitiated` event [4](#0-3) 
4. However, the actual stored value in `cooldowns[redeemer].underlyingAmount` is truncated to fit uint152
5. When `unstakeThroughComposer` is called, it reads and withdraws only the truncated stored amount [5](#0-4) 
6. The user permanently loses the difference between the full amount and the truncated amount

**Security Property Broken:** This violates the **Cooldown Integrity** invariant - users who complete the cooldown period should be able to unstake the exact amount they locked, not a truncated portion. The stored cooldown amount must accurately reflect the assets locked for the user.

## Impact Explanation

- **Affected Assets**: iTRY tokens locked in the iTrySilo during cooldown periods
- **Damage Severity**: Any assets exceeding `type(uint152).max` are permanently lost. The truncation wraps around (e.g., `type(uint152).max + 1` becomes `0`), causing complete or partial loss of the cooldown amount
- **User Impact**: While the threshold is extremely high (≈5.7×10²⁷ iTRY tokens), the issue affects any user whose accumulated cooldowns reach this limit. The cross-chain nature allows multiple cooldown accumulations to the same address. The same issue exists in the base `cooldownShares` and `cooldownAssets` functions. [6](#0-5) [7](#0-6) 

## Likelihood Explanation

- **Attacker Profile**: Any user or set of users can trigger this by accumulating large cooldown amounts
- **Preconditions**: Cooldown functionality must be enabled (`cooldownDuration > 0`), and accumulated cooldowns must exceed `type(uint152).max`
- **Execution Complexity**: Simple to trigger once the threshold is reached, though reaching the threshold requires an astronomically large token amount
- **Frequency**: Can occur whenever the accumulated cooldown amount exceeds the uint152 maximum

## Recommendation

Add explicit overflow validation before casting to uint152: [8](#0-7) 

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function _startComposerCooldown:

// CURRENT (vulnerable):
cooldowns[redeemer].underlyingAmount += uint152(assets);

// FIXED:
uint256 newAmount = uint256(cooldowns[redeemer].underlyingAmount) + assets;
if (newAmount > type(uint152).max) revert ExcessiveCooldownAmount();
cooldowns[redeemer].underlyingAmount = uint152(newAmount);
```

Apply the same fix to `cooldownShares` and `cooldownAssets` in `StakediTryCooldown.sol`. [9](#0-8) [10](#0-9) 

Alternative: Use OpenZeppelin's SafeCast library:
```solidity
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

cooldowns[redeemer].underlyingAmount += SafeCast.toUint152(assets);
```

**Note:** The same casting issue exists for `cooldownEnd` stored as `uint104`, though this has a much higher practical threshold (Unix timestamp overflow in trillions of years). [11](#0-10) 

## Proof of Concept

```solidity
// File: test/Exploit_CooldownTruncation.t.sol
// Run with: forge test --match-test test_CooldownTruncation -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_CooldownTruncation is Test {
    StakediTryCrosschain vault;
    iTry itry;
    address composer;
    address redeemer;
    
    function setUp() public {
        // Deploy contracts
        itry = new iTry(address(this), "iTRY", "iTRY");
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            address(this), // rewarder
            address(this), // owner
            address(this)  // treasury
        );
        
        composer = address(0x1);
        redeemer = address(0x2);
        
        // Grant composer role
        vault.grantRole(vault.COMPOSER_ROLE(), composer);
        
        // Setup: Mint large amount of iTRY and deposit to vault as composer
        uint256 largeAmount = type(uint152).max + 1000;
        itry.mint(composer, largeAmount);
        
        vm.startPrank(composer);
        itry.approve(address(vault), largeAmount);
        vault.deposit(largeAmount, composer);
        vm.stopPrank();
    }
    
    function test_CooldownTruncation() public {
        // SETUP: Calculate shares that would exceed uint152.max in assets
        uint256 targetAssets = type(uint152).max + 500;
        uint256 shares = vault.previewWithdraw(targetAssets);
        
        // EXPLOIT: Call cooldownSharesByComposer
        vm.prank(composer);
        uint256 returnedAssets = vault.cooldownSharesByComposer(shares, redeemer);
        
        // VERIFY: The returned value is the full amount
        assertEq(returnedAssets, targetAssets, "Returned assets should be full amount");
        
        // But the stored value is truncated
        (uint104 cooldownEnd, uint152 storedAssets) = vault.cooldowns(redeemer);
        
        // The stored amount is truncated due to uint152 cast
        assertLt(storedAssets, returnedAssets, "Stored assets are truncated");
        assertEq(storedAssets, uint152(targetAssets), "Stored assets match truncated cast");
        
        // When unstaking, user only receives the truncated amount
        vm.warp(block.timestamp + vault.cooldownDuration());
        vm.prank(composer);
        uint256 unstakedAssets = vault.unstakeThroughComposer(redeemer);
        
        assertEq(unstakedAssets, storedAssets, "User receives truncated amount");
        assertLt(unstakedAssets, returnedAssets, "Vulnerability confirmed: User loses excess");
        
        console.log("Expected assets:", returnedAssets);
        console.log("Actual received:", unstakedAssets);
        console.log("Loss:", returnedAssets - unstakedAssets);
    }
}
```

**Notes:**
- The UserCooldown struct defines `underlyingAmount` as `uint152` [12](#0-11) 
- The vulnerability creates the exact mismatch described in the security question: the return value differs from the stored value
- While the threshold is impractically high, the lack of validation means this could cause permanent fund loss if ever reached
- This is a design flaw that should be addressed with proper overflow checks or SafeCast usage

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L46-47)
```text
        assets = previewRedeem(shares);
        _startComposerCooldown(composer, redeemer, shares, assets);
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L86-93)
```text
        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L170-181)
```text
    function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

        // Interaction: External call to base contract (protected by nonReentrant modifier)
        _withdraw(composer, address(silo), composer, assets, shares);

        // Effects: State changes after external call (following CEI pattern)
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);

        emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L94-95)
```text
        uint256 assetAmount = IStakediTryCrosschain(address(VAULT)).cooldownSharesByComposer(_shareAmount, redeemer);
        emit CooldownInitiated(_redeemer, redeemer, _shareAmount, assetAmount);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L96-105)
```text
    function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
        if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();

        shares = previewWithdraw(assets);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L109-118)
```text
    function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
        if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();

        assets = previewRedeem(shares);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }
```

**File:** src/token/wiTRY/interfaces/IStakediTryCooldown.sol (L7-10)
```text
struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
}
```
