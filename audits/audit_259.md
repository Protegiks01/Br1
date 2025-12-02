## Title
Silent uint152 Truncation in Cooldown Functions Causes Permanent Loss of User Funds

## Summary
The `cooldownShares` and `cooldownAssets` functions in `StakediTryCooldown.sol` cast `assets` (uint256) to uint152 without validation, causing silent truncation when the asset amount exceeds `type(uint152).max`. Users lose funds permanently as their shares are burned but their cooldown balance is recorded at the truncated value.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (StakediTryV2 contract)
- `cooldownShares()` function, line 115
- `cooldownAssets()` function, line 102
- Also affects `StakediTryCrosschain.sol`, line 178

**Intended Logic:** When users initiate a cooldown, their shares should be burned and the equivalent asset amount should be recorded in their cooldown balance. After the cooldown period, they should be able to unstake and receive the full asset amount corresponding to their burned shares.

**Actual Logic:** The functions cast the asset amount to uint152 without any validation. In Solidity 0.8.20, explicit type casting does NOT trigger overflow protection—it performs modulo arithmetic, silently truncating values that exceed the target type's maximum. [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. User accumulates wiTRY shares worth more than `type(uint152).max` assets (approximately 5.7 × 10^45 wei, or 5.7 × 10^27 tokens with 18 decimals)
2. User calls `cooldownShares(shares)` where `assets = previewRedeem(shares)` returns a value > `type(uint152).max`
3. The cast `uint152(assets)` silently truncates the value (e.g., if assets = `type(uint152).max + 1000`, the truncated value would be 999)
4. The full `assets` and `shares` are passed to `_withdraw()`, burning the user's shares and transferring assets to the silo
5. However, `cooldowns[msg.sender].underlyingAmount` only records the truncated value
6. When the user later calls `unstake()`, they receive only the truncated amount from the silo, permanently losing the difference [4](#0-3) 

**Security Property Broken:** 
- **Cooldown Integrity Invariant**: Users must receive the full asset value of their burned shares after cooldown completion
- **ERC4626 Share-to-Asset Equivalence**: Redeeming X shares should always yield the correct Y assets without silent data loss

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY assets held in the StakediTry vault
- **Damage Severity**: Users permanently lose the difference between their actual asset entitlement and the truncated uint152 value. For example, if a user's assets = `type(uint152).max + 1e18`, they lose approximately 1 iTRY token (or more depending on how far above the limit they are)
- **User Impact**: Any whale user or early staker whose share value (through deposits or yield accumulation) exceeds `type(uint152).max` in assets. This also affects cross-chain unstaking via the composer mechanism, which has the same vulnerability. [5](#0-4) 

## Likelihood Explanation
- **Attacker Profile**: Any legitimate user with a sufficiently large position, or potentially an attacker who accumulates positions over time
- **Preconditions**: 
  - Vault must have accumulated sufficient value such that a user's share balance converts to > `type(uint152).max` assets
  - This becomes more likely as the protocol matures and early stakers accumulate yield over time
  - No explicit deposit limits in the ERC4626 implementation to prevent this [6](#0-5) 

- **Execution Complexity**: Single transaction calling `cooldownShares()` or `cooldownAssets()`
- **Frequency**: Once per affected user, but the vulnerability exists permanently for any user whose assets exceed the limit

## Recommendation

Add validation to ensure `assets` fits within uint152 before casting:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol:

// CURRENT (vulnerable) - Line 115:
cooldowns[msg.sender].underlyingAmount += uint152(assets);

// FIXED:
if (assets > type(uint152).max) revert ExcessiveRedeemAmount();
cooldowns[msg.sender].underlyingAmount += uint152(assets);

// Apply the same fix to:
// - cooldownAssets() at line 102
// - StakediTryCrosschain._startComposerCooldown() at line 178
```

**Alternative mitigation:** Consider using uint256 for `underlyingAmount` in the `UserCooldown` struct to eliminate the constraint entirely. The struct would still fit within a single storage slot by adjusting `cooldownEnd` to a smaller type if needed, or accepting the use of two slots for safety.

```solidity
// In src/token/wiTRY/interfaces/IStakediTryCooldown.sol:

// CURRENT:
struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
}

// ALTERNATIVE:
struct UserCooldown {
    uint256 cooldownEnd;
    uint256 underlyingAmount;
}
```

## Proof of Concept

```solidity
// File: test/Exploit_Uint152Truncation.t.sol
// Run with: forge test --match-test test_uint152TruncationCausesLoss -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "./mocks/MockERC20.sol";

contract Exploit_Uint152Truncation is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public rewarder;
    address public treasury;
    address public whaleUser;
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        whaleUser = makeAddr("whaleUser");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)),
            rewarder,
            admin,
            treasury
        );
        
        // Enable cooldown with 90 day duration
        vm.prank(admin);
        stakediTry.setCooldownDuration(90 days);
    }
    
    function test_uint152TruncationCausesLoss() public {
        // SETUP: Mint assets exceeding uint152 max to simulate whale position
        // type(uint152).max = 5708990770823839524233143877797980545530986495
        uint256 assetsAboveLimit = type(uint152).max + 1e24; // Exceeds limit by 1e24
        
        iTryToken.mint(whaleUser, assetsAboveLimit);
        
        // Whale deposits into vault
        vm.startPrank(whaleUser);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        uint256 shares = stakediTry.deposit(assetsAboveLimit, whaleUser);
        vm.stopPrank();
        
        // EXPLOIT: Whale initiates cooldown with their shares
        vm.prank(whaleUser);
        uint256 assetsFromCooldown = stakediTry.cooldownShares(shares);
        
        // VERIFY: Check that assets were calculated correctly
        assertEq(assetsFromCooldown, assetsAboveLimit, "previewRedeem should return full assets");
        
        // Check the recorded cooldown amount - this is where truncation occurs
        (uint104 cooldownEnd, uint152 recordedAmount) = stakediTry.cooldowns(whaleUser);
        
        // The recorded amount should be truncated
        uint256 expectedTruncated = uint152(assetsAboveLimit); // Modulo arithmetic
        assertEq(
            uint256(recordedAmount), 
            expectedTruncated, 
            "Recorded amount should be truncated"
        );
        
        // Calculate loss
        uint256 loss = assetsAboveLimit - uint256(recordedAmount);
        
        // Verify significant loss occurred
        assertGt(loss, 0, "User should have lost funds due to truncation");
        assertEq(loss, 1e24, "User lost exactly 1e24 wei due to truncation");
        
        // Fast forward past cooldown
        vm.warp(block.timestamp + 90 days + 1);
        
        // User unstakes and receives only the truncated amount
        vm.prank(whaleUser);
        stakediTry.unstake(whaleUser);
        
        // Verify user received truncated amount, not full amount
        assertEq(
            iTryToken.balanceOf(whaleUser),
            uint256(recordedAmount),
            "User received only truncated amount"
        );
        
        assertLt(
            iTryToken.balanceOf(whaleUser),
            assetsAboveLimit,
            "User did not receive full assets - FUNDS LOST"
        );
        
        // The difference remains locked in the silo forever
        assertEq(
            iTryToken.balanceOf(address(stakediTry.silo())),
            loss,
            "Lost funds remain in silo"
        );
    }
}
```

**Notes:**
- This vulnerability exists in three locations: `cooldownShares()`, `cooldownAssets()`, and cross-chain composer cooldowns
- The issue is a direct consequence of using explicit type casting without validation in Solidity 0.8.x, where casts do not benefit from automatic overflow protection
- While `type(uint152).max` is an extremely large number (~5.7 × 10^27 tokens), the lack of any upper bound validation means this is a latent vulnerability that could manifest as the protocol scales
- The += operator on line 115 does have overflow protection, but the damage is already done during the cast before the addition
- This violates the fundamental ERC4626 principle that users should receive fair value for their shares

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L80-92)
```text
    function unstake(address receiver) external {
        UserCooldown storage userCooldown = cooldowns[msg.sender];
        uint256 assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(receiver, assets);
        } else {
            revert InvalidCooldown();
        }
    }
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

**File:** src/token/wiTRY/StakediTry.sol (L213-216)
```text
    /// @dev Necessary because both ERC20 (from ERC20Permit) and ERC4626 declare decimals()
    function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
        return 18;
    }
```
