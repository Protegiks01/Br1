## Title
Cooldown Timer Reset Vulnerability: Initiating New Cooldown Overwrites Existing Timer, Unfairly Extending Wait Period for All Accumulated Assets

## Summary
The `_startComposerCooldown` function in `StakediTryCrosschain.sol` and the user-facing `cooldownShares`/`cooldownAssets` functions in `StakediTryCooldown.sol` overwrite the `cooldownEnd` timestamp when initiating a new cooldown, while accumulating the `underlyingAmount`. This causes users with existing cooldowns to lose their cooldown progress and restart the full cooldown period for all their assets, violating the Cooldown Integrity invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/token/wiTRY/StakediTryCrosschain.sol` - `_startComposerCooldown()` function
- `src/token/wiTRY/StakediTryCooldown.sol` - `cooldownShares()` and `cooldownAssets()` functions

**Intended Logic:** Users should be able to accumulate multiple cooldown requests, with each cooldown maintaining its individual timing so that assets become available for unstaking as their respective cooldown periods complete.

**Actual Logic:** The code uses assignment (`=`) to set `cooldownEnd` and addition (`+=`) to accumulate `underlyingAmount`, causing the cooldown timer to reset to the full duration every time a new cooldown is initiated, regardless of how much time has already elapsed on existing cooldowns. [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **User initiates first cooldown**: User calls `cooldownShares(1000e18)` to start cooldown for 1000 iTRY. The `cooldownEnd` is set to `block.timestamp + 90 days`.

2. **Time passes**: 80 days pass. User now has only 10 days remaining before they can unstake their 1000 iTRY.

3. **User initiates second cooldown**: User calls `cooldownShares(100e18)` to add 100 iTRY to cooldown. The code executes:
   - Line 114 OVERWRITES: `cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;` 
   - Line 115 ACCUMULATES: `cooldowns[msg.sender].underlyingAmount += uint152(assets);`

4. **Unfair outcome**: User now must wait another 90 days (not 10 days) to unstake ALL 1100 iTRY. The 80 days of cooldown progress on the original 1000 iTRY is completely lost.

**Security Property Broken:** Violates **Cooldown Integrity** invariant - users should complete their cooldown period as expected, but instead lose progress unfairly.

## Impact Explanation

- **Affected Assets**: All iTRY tokens that users stake as wiTRY and subsequently place in cooldown for unstaking.

- **Damage Severity**: Users lose time-value of their staked funds. In the worst case, a user with 1000 iTRY having only 1 day remaining (89 days elapsed) who initiates a 1 iTRY cooldown would have to wait another full 90 days to unstake ALL 1001 iTRY, effectively losing 89 days of liquidity access worth potentially significant opportunity cost.

- **User Impact**: 
  - **Direct users**: Any staker who calls `cooldownShares()` or `cooldownAssets()` multiple times before completing unstake
  - **Cross-chain users**: Users unstaking via LayerZero where composers call `cooldownSharesByComposer()` or `cooldownAssetsByComposer()` on their behalf
  - Affects all users who naturally accumulate multiple unstaking requests over time

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - this affects legitimate users performing normal operations. However, a malicious or compromised composer could grief cross-chain users by repeatedly initiating tiny cooldowns to perpetually extend wait times.

- **Preconditions**: 
  - User has existing cooldown with `underlyingAmount > 0`
  - User initiates a new cooldown request before completing the first
  - Cooldown duration is set (default 90 days)

- **Execution Complexity**: Single transaction - happens automatically whenever a user with existing cooldown calls any cooldown function.

- **Frequency**: Can occur multiple times per user across their staking lifecycle. Extremely common for users who perform partial unstaking operations or accumulate multiple unstake requests.

## Recommendation

The fix requires tracking cooldowns in a way that preserves timing for previously cooling assets. Here are two approaches:

**Approach 1: Reject new cooldowns when one is active** [4](#0-3) 

**Approach 2: Maintain separate cooldown queue (more complex but better UX)**

Implement a queue or array-based structure to track multiple cooldowns with individual timestamps. This allows proper time-based unlocking but requires significant refactoring.

**Recommended Fix (Approach 1 - Simpler):**

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol

function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
    if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
    
    // NEW: Prevent new cooldown if one is already active
    if (cooldowns[msg.sender].underlyingAmount > 0) {
        revert("Cannot initiate new cooldown while previous cooldown is active");
    }

    shares = previewWithdraw(assets);
    cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    cooldowns[msg.sender].underlyingAmount = uint152(assets); // Changed from += to =

    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}

function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
    if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();
    
    // NEW: Prevent new cooldown if one is already active
    if (cooldowns[msg.sender].underlyingAmount > 0) {
        revert("Cannot initiate new cooldown while previous cooldown is active");
    }

    assets = previewRedeem(shares);
    cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    cooldowns[msg.sender].underlyingAmount = uint152(assets); // Changed from += to =

    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}
```

Apply the same logic to `_startComposerCooldown()`: [5](#0-4) 

## Proof of Concept

```solidity
// File: test/Exploit_CooldownTimerReset.t.sol
// Run with: forge test --match-test test_CooldownTimerResetVulnerability -vvv

pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {StakediTryCrosschain} from "../src/token/wiTRY/StakediTryCrosschain.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_CooldownTimerReset is Test {
    iTry public itryToken;
    StakediTryCrosschain public vault;
    
    address public owner;
    address public rewarder;
    address public treasury;
    address public alice;
    
    function setUp() public {
        owner = makeAddr("owner");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        alice = makeAddr("alice");
        
        // Deploy iTry with proxy
        iTry itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner,
            owner
        );
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(IERC20(address(itryToken)), rewarder, owner, treasury);
        
        // Mint iTRY to alice and approve vault
        vm.startPrank(owner);
        itryToken.mint(alice, 10000e18);
        vm.stopPrank();
        
        vm.startPrank(alice);
        itryToken.approve(address(vault), type(uint256).max);
        vm.stopPrank();
    }
    
    function test_CooldownTimerResetVulnerability() public {
        // SETUP: Alice deposits 2000 iTRY and gets shares
        vm.prank(alice);
        uint256 totalShares = vault.deposit(2000e18, alice);
        
        // Alice initiates first cooldown for 1000 iTRY worth of shares
        uint256 firstCooldownShares = totalShares / 2;
        vm.prank(alice);
        uint256 firstAssets = vault.cooldownShares(firstCooldownShares);
        
        // Record first cooldown state
        (uint104 cooldownEnd1, uint256 amount1) = vault.cooldowns(alice);
        uint256 expectedUnstakeTime1 = block.timestamp + vault.cooldownDuration();
        
        console.log("First cooldown initiated:");
        console.log("  Assets in cooldown:", amount1);
        console.log("  Cooldown end time:", cooldownEnd1);
        console.log("  Days to wait:", (cooldownEnd1 - block.timestamp) / 1 days);
        
        assertEq(amount1, firstAssets, "First cooldown amount should be recorded");
        assertEq(cooldownEnd1, expectedUnstakeTime1, "First cooldown end should be 90 days from now");
        
        // EXPLOIT: Fast forward 80 days (user has only 10 days left!)
        vm.warp(block.timestamp + 80 days);
        
        console.log("\n80 days passed...");
        console.log("  Days remaining on original cooldown:", (cooldownEnd1 - block.timestamp) / 1 days);
        
        // Alice initiates second cooldown for remaining 100 iTRY worth of shares
        uint256 secondCooldownShares = totalShares - firstCooldownShares;
        vm.prank(alice);
        uint256 secondAssets = vault.cooldownShares(secondCooldownShares);
        
        // VERIFY: Check the vulnerability
        (uint104 cooldownEnd2, uint256 amount2) = vault.cooldowns(alice);
        
        console.log("\nSecond cooldown initiated:");
        console.log("  Total assets in cooldown:", amount2);
        console.log("  New cooldown end time:", cooldownEnd2);
        console.log("  Days to wait NOW:", (cooldownEnd2 - block.timestamp) / 1 days);
        
        // The vulnerability: assets accumulated but timer reset!
        assertEq(amount2, firstAssets + secondAssets, "Assets should accumulate");
        assertGt(cooldownEnd2, cooldownEnd1, "Timer was RESET instead of maintained");
        
        // Alice lost 80 days of progress
        uint256 daysLostProgress = (cooldownEnd2 - cooldownEnd1) / 1 days;
        console.log("\nVULNERABILITY CONFIRMED:");
        console.log("  Alice lost", daysLostProgress, "days of cooldown progress");
        console.log("  Original 1000 iTRY had 10 days left, now must wait 90 days");
        console.log("  Total iTRY locked:", amount2 / 1e18, "iTRY");
        
        // Try to unstake - should fail because timer was reset
        vm.warp(cooldownEnd1 + 1); // Move to when first cooldown should have completed
        vm.prank(alice);
        vm.expectRevert(); // Will revert because cooldownEnd2 is 80 days in the future
        vault.unstake(alice);
        
        console.log("\nAlice cannot unstake even though first cooldown time passed");
        console.log("She must wait until:", cooldownEnd2);
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **Existing test confirms behavior**: The test `test_cooldownSharesByComposer_multipleCooldownsAccumulate()` explicitly documents this behavior at line 229 with the comment "should overwrite timestamp but accumulate assets", indicating the development team may have intended this design. However, this creates an unfair user experience and violates reasonable expectations around cooldown mechanics. [6](#0-5) 

2. **Affects both direct and cross-chain users**: The vulnerability exists in both the user-facing functions (`cooldownShares`, `cooldownAssets`) and the composer-gated cross-chain function (`_startComposerCooldown`).

3. **No workaround**: Users cannot avoid this issue if they need to perform multiple unstaking operations before completing their first cooldown.

4. **Time-value loss**: While users don't lose their principal iTRY, they lose significant time-value of capital, which in DeFi contexts can represent substantial opportunity cost (lost yield, trading opportunities, etc.).

### Citations

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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L114-115)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);
```

**File:** test/crosschainTests/StakediTryCrosschain.t.sol (L213-236)
```text
    function test_cooldownSharesByComposer_multipleCooldownsAccumulate() public {
        // Setup
        vm.prank(owner);
        vault.grantRole(COMPOSER_ROLE, vaultComposer);
        _mintAndDeposit(vaultComposer, 200e18);

        // First cooldown
        vm.prank(vaultComposer);
        uint256 assets1 = vault.cooldownSharesByComposer(50e18, alice);

        (uint104 cooldownEnd1, uint256 amount1) = vault.cooldowns(alice);
        assertEq(amount1, assets1);

        // Fast forward time (but not past cooldown)
        vm.warp(block.timestamp + 30 days);

        // Second cooldown (should overwrite timestamp but accumulate assets)
        vm.prank(vaultComposer);
        uint256 assets2 = vault.cooldownSharesByComposer(50e18, alice);

        (uint104 cooldownEnd2, uint256 amount2) = vault.cooldowns(alice);
        assertEq(amount2, assets1 + assets2); // Assets accumulate
        assertGt(cooldownEnd2, cooldownEnd1); // Timestamp updates (overwrites)
    }
```
