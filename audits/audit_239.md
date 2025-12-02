## Title
Cross-chain Users Denied Immediate Unstaking When Cooldown is Disabled

## Summary
When admin sets `cooldownDuration` to 0 to disable cooldowns, local users can immediately unstake their funds via the `unstake()` function, but cross-chain users with composer-initiated cooldowns remain locked until their original `cooldownEnd` timestamp because `unstakeThroughComposer()` lacks the bypass logic.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` (function `unstakeThroughComposer`, line 89)

**Intended Logic:** 
According to the documentation, when cooldown is set to 0, users should be able to immediately claim their assets regardless of their cooldown status. [1](#0-0) 

The regular `unstake()` function implements this bypass correctly: [2](#0-1) 

**Actual Logic:** 
The `unstakeThroughComposer()` function used for cross-chain unstaking only checks if the cooldown period has elapsed, without checking if cooldowns have been globally disabled: [3](#0-2) 

**Exploitation Path:**
1. Cross-chain user initiates unstake from L2 via `UnstakeMessenger`, which calls `cooldownSharesByComposer()` on L1 [4](#0-3) 

2. Cooldown is set with `cooldownEnd = block.timestamp + cooldownDuration` (e.g., 90 days from now) [5](#0-4) 

3. Admin decides to disable cooldowns by calling `setCooldownDuration(0)` before the 90 days elapse [6](#0-5) 

4. Local users with pending cooldowns can immediately call `unstake()` to claim their funds (due to the `|| cooldownDuration == 0` bypass)

5. Cross-chain user sends unstake message from L2, which arrives at `wiTryVaultComposer._handleUnstake()` and calls `unstakeThroughComposer()` [7](#0-6) 

6. The transaction reverts because `unstakeThroughComposer()` lacks the cooldown-disabled bypass, forcing the cross-chain user to wait until their original `cooldownEnd` timestamp (90 days)

**Security Property Broken:** 
This violates the documented behavior that "unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo". Cross-chain users are unfairly disadvantaged compared to local users when cooldowns are disabled.

## Impact Explanation
- **Affected Assets**: iTRY tokens locked in cooldown for cross-chain users who initiated unstaking before cooldown was disabled
- **Damage Severity**: Cross-chain users experience temporary fund lock until their original cooldownEnd timestamp, while local users with identical cooldown states can immediately access their funds. If cooldown was 90 days and disabled after 10 days, cross-chain users must wait 80 additional days while local users get immediate access.
- **User Impact**: All cross-chain users with pending cooldowns at the time cooldownDuration is set to 0 are affected. This creates inconsistent treatment between local and cross-chain users.

## Likelihood Explanation
- **Attacker Profile**: Not an attack per se, but a design flaw affecting legitimate cross-chain users when admin makes parameter changes
- **Preconditions**: 
  - Cross-chain user must have initiated cooldown via composer
  - Admin must disable cooldowns (set `cooldownDuration = 0`) before cooldown completes
  - User attempts to complete unstaking via `wiTryVaultComposer`
- **Execution Complexity**: Normal cross-chain unstaking flow - no special exploitation needed
- **Frequency**: Occurs whenever admin disables cooldowns while cross-chain users have pending cooldowns

## Recommendation

Add the same cooldown-disabled bypass to `unstakeThroughComposer()` that exists in the regular `unstake()` function:

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function unstakeThroughComposer, line 89:

// CURRENT (vulnerable):
if (block.timestamp >= userCooldown.cooldownEnd) {

// FIXED:
if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
    // Allow immediate unstaking when cooldowns are globally disabled
```

This ensures consistent behavior between local and cross-chain unstaking paths.

## Proof of Concept

```solidity
// File: test/Exploit_CrosschainCooldownBypass.t.sol
// Run with: forge test --match-test test_crosschainUserLockedWhenCooldownDisabled -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_CrosschainCooldownBypass is Test {
    StakediTryCrosschain vault;
    iTry itry;
    address owner;
    address composer;
    address localUser;
    address crosschainUser;
    
    function setUp() public {
        owner = address(this);
        composer = makeAddr("composer");
        localUser = makeAddr("localUser");
        crosschainUser = makeAddr("crosschainUser");
        
        // Deploy contracts
        itry = new iTry(owner);
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            address(0), // rewarder
            owner,
            address(0)  // fast redeem treasury
        );
        
        // Grant composer role
        vault.grantRole(vault.COMPOSER_ROLE(), composer);
        
        // Setup: Both users deposit 100 iTRY
        itry.mint(localUser, 100e18);
        itry.mint(composer, 100e18);
        
        vm.prank(localUser);
        itry.approve(address(vault), 100e18);
        vm.prank(localUser);
        vault.deposit(100e18, localUser);
        
        vm.prank(composer);
        itry.approve(address(vault), 100e18);
        vm.prank(composer);
        vault.deposit(100e18, composer);
    }
    
    function test_crosschainUserLockedWhenCooldownDisabled() public {
        // SETUP: Both users initiate cooldowns with 90-day cooldown period
        uint256 shares = vault.balanceOf(localUser);
        
        // Local user initiates cooldown
        vm.prank(localUser);
        vault.cooldownShares(shares);
        
        // Crosschain user initiates cooldown via composer
        vm.prank(composer);
        vault.cooldownSharesByComposer(shares, crosschainUser);
        
        // Fast forward 10 days (cooldown not complete)
        vm.warp(block.timestamp + 10 days);
        
        // Admin disables cooldowns
        vault.setCooldownDuration(0);
        
        // VERIFY: Local user can unstake immediately (bypass works)
        vm.prank(localUser);
        vault.unstake(localUser);
        assertEq(itry.balanceOf(localUser), 100e18, "Local user successfully unstaked");
        
        // VERIFY: Crosschain user CANNOT unstake (bypass missing)
        vm.prank(composer);
        vm.expectRevert(); // Reverts with InvalidCooldown
        vault.unstakeThroughComposer(crosschainUser);
        
        // Crosschain user must wait full 90 days even though cooldowns are disabled
        vm.warp(block.timestamp + 80 days);
        vm.prank(composer);
        vault.unstakeThroughComposer(crosschainUser);
        
        assertEq(itry.balanceOf(composer), 100e18, "Crosschain user had to wait full cooldown period");
    }
}
```

## Notes

This vulnerability demonstrates an inconsistency in how cooldown bypass logic is implemented across different unstaking paths. While the regular `unstake()` function correctly implements the documented behavior of allowing immediate unstaking when `cooldownDuration` is set to 0, the `unstakeThroughComposer()` function lacks this bypass. This creates unfair treatment where cross-chain users remain locked in cooldown even after the admin has disabled cooldowns globally, while local users can immediately access their funds.

The fix is straightforward: add the same `|| cooldownDuration == 0` condition to the validation check in `unstakeThroughComposer()` to ensure consistent behavior across both unstaking paths.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L78-78)
```text
    /// @dev unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L84-84)
```text
        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L122-129)
```text
    function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (duration > MAX_COOLDOWN_DURATION) {
            revert InvalidCooldown();
        }

        uint24 previousDuration = cooldownDuration;
        cooldownDuration = duration;
        emit CooldownDurationUpdated(previousDuration, cooldownDuration);
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L89-89)
```text
        if (block.timestamp >= userCooldown.cooldownEnd) {
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L170-171)
```text
    function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L177-178)
```text
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L255-255)
```text
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
```
