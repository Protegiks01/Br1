## Title
Cooldown Duration Gaming via Minimal Asset Addition After Governance Reduction

## Summary
Users with pending cooldowns can exploit governance-initiated `cooldownDuration` decreases by adding minimal assets (even 1 wei) to their existing cooldown, which resets their `cooldownEnd` timestamp to the new shorter duration while accumulating all previously locked assets. This allows users to bypass most of their original cooldown period, violating Invariant 6 (Cooldown Integrity) and creating unfair advantages.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` - `cooldownAssets()` function (lines 96-105) and `cooldownShares()` function (lines 109-118)

**Intended Logic:** When governance updates `cooldownDuration`, the change should only affect NEW cooldown initiations. Users who already initiated cooldowns should complete their originally committed cooldown period to ensure fairness and maintain the stability mechanism's effectiveness.

**Actual Logic:** The cooldown accumulation mechanism unconditionally resets `cooldownEnd` to `block.timestamp + cooldownDuration` when users add any amount to their existing cooldown. [1](#0-0)  This allows users to retroactively apply shorter cooldown durations to their previously locked funds by adding minimal amounts after a governance decrease.

**Exploitation Path:**
1. User initiates cooldown with 1000 iTRY when `cooldownDuration = 90 days` → `cooldownEnd = block.timestamp + 90 days`
2. Only 1 day passes (89 days remaining in original cooldown)
3. Governance reduces `cooldownDuration` to 10 days via `setCooldownDuration()` [2](#0-1) 
4. User calls `cooldownAssets(1 wei)` which:
   - Resets `cooldownEnd = block.timestamp + 10 days` (new shorter duration)
   - Accumulates `underlyingAmount = 1000 + 0.000000000000000001 iTRY`
5. User waits only 10 days from step 4 (total 11 days from start)
6. User calls `unstake()` which passes the condition `block.timestamp >= userCooldown.cooldownEnd` [3](#0-2)  and withdraws all 1000+ iTRY
7. User bypassed 79 days of their original 90-day cooldown commitment

**Security Property Broken:** Invariant 6 - "Users must complete cooldown period before unstaking wiTRY". While users technically complete "a" cooldown period, they bypass their originally committed cooldown duration by exploiting governance changes.

## Impact Explanation
- **Affected Assets**: wiTRY shares and underlying iTRY assets locked in the `iTrySilo` [4](#0-3) 
- **Damage Severity**: Users can exit 70-80+ days earlier than intended (in a 90-to-10-day reduction scenario), undermining the cooldown mechanism's purpose as a stability control. While no direct theft occurs, sophisticated users gain unfair early exit advantages over users who don't exploit this mechanism.
- **User Impact**: Creates two classes of users:
  - Informed users who monitor governance and add minimal amounts to reset cooldowns (exit much earlier)
  - Uninformed users who wait out their original cooldown (disadvantaged by 70-80+ days)

## Likelihood Explanation
- **Attacker Profile**: Any user with an active cooldown and sufficient iTRY balance to add minimal amounts
- **Preconditions**: 
  - User has pending cooldown with substantial time remaining
  - Governance reduces `cooldownDuration` (not uncommon for operational adjustments)
  - User must have at least 1 wei of withdrawable assets to trigger the reset
- **Execution Complexity**: Single transaction calling `cooldownAssets()` or `cooldownShares()` with minimal amount. No special timing required beyond waiting for governance action.
- **Frequency**: Exploitable whenever governance decreases `cooldownDuration`, potentially multiple times if governance adjusts duration repeatedly

## Recommendation

Track the original cooldown deadline separately from accumulated assets and prevent cooldown resets that would shorten the waiting period:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function cooldownAssets, lines 96-105:

// CURRENT (vulnerable):
function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
    if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
    shares = previewWithdraw(assets);
    
    cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    cooldowns[msg.sender].underlyingAmount += uint152(assets);
    
    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}

// FIXED:
function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
    if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
    shares = previewWithdraw(assets);
    
    uint104 newCooldownEnd = uint104(block.timestamp) + cooldownDuration;
    // Only extend cooldown, never shorten it
    if (newCooldownEnd > cooldowns[msg.sender].cooldownEnd) {
        cooldowns[msg.sender].cooldownEnd = newCooldownEnd;
    }
    // If existing cooldown is 0 or new deadline is earlier (shouldn't happen but defensive), use existing or new
    if (cooldowns[msg.sender].cooldownEnd == 0) {
        cooldowns[msg.sender].cooldownEnd = newCooldownEnd;
    }
    cooldowns[msg.sender].underlyingAmount += uint152(assets);
    
    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}
```

Apply the same fix to `cooldownShares()` at lines 109-118. This ensures that adding to an existing cooldown can only extend the waiting period, never shorten it, preserving the original commitment while still allowing accumulation of multiple cooldown requests.

**Alternative mitigation:** Prevent adding to existing cooldowns entirely - require users to wait until their current cooldown completes before initiating a new one.

## Proof of Concept

```solidity
// File: test/Exploit_CooldownDurationGaming.t.sol
// Run with: forge test --match-test test_CooldownDurationGamingExploit -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_CooldownDurationGaming is Test {
    StakediTryFastRedeem public vault;
    MockERC20 public itryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public attacker;
    address public normalUser;
    
    uint256 constant INITIAL_SUPPLY = 10_000e18;
    uint24 constant LONG_COOLDOWN = 90 days;
    uint24 constant SHORT_COOLDOWN = 10 days;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        rewarder = makeAddr("rewarder");
        attacker = makeAddr("attacker");
        normalUser = makeAddr("normalUser");
        
        itryToken = new MockERC20("iTRY", "iTRY");
        
        vm.prank(admin);
        vault = new StakediTryFastRedeem(IERC20(address(itryToken)), rewarder, admin, treasury);
        
        // Mint tokens
        itryToken.mint(attacker, INITIAL_SUPPLY);
        itryToken.mint(normalUser, INITIAL_SUPPLY);
        
        // Approve vault
        vm.prank(attacker);
        itryToken.approve(address(vault), type(uint256).max);
        
        vm.prank(normalUser);
        itryToken.approve(address(vault), type(uint256).max);
    }
    
    function test_CooldownDurationGamingExploit() public {
        // SETUP: Both users stake 1000 iTRY
        uint256 stakeAmount = 1000e18;
        
        vm.prank(attacker);
        vault.deposit(stakeAmount, attacker);
        
        vm.prank(normalUser);
        vault.deposit(stakeAmount, normalUser);
        
        // Both users initiate cooldown with 90-day duration
        vm.prank(attacker);
        vault.cooldownAssets(stakeAmount);
        
        vm.prank(normalUser);
        vault.cooldownAssets(stakeAmount);
        
        (uint104 attackerInitialEnd, uint256 attackerInitialAmount) = vault.cooldowns(attacker);
        (uint104 normalUserInitialEnd, uint256 normalUserInitialAmount) = vault.cooldowns(normalUser);
        
        assertEq(attackerInitialEnd, normalUserInitialEnd, "Both should have same cooldown end initially");
        assertEq(attackerInitialAmount, normalUserInitialAmount, "Both should have same amount initially");
        
        // Fast forward 1 day
        vm.warp(block.timestamp + 1 days);
        
        // EXPLOIT: Governance reduces cooldown to 10 days
        vm.prank(admin);
        vault.setCooldownDuration(SHORT_COOLDOWN);
        
        // Attacker adds 1 wei to reset cooldown to new shorter duration
        vm.prank(attacker);
        itryToken.mint(attacker, 1);
        vm.prank(attacker);
        vault.deposit(1, attacker);
        vm.prank(attacker);
        vault.cooldownAssets(1);
        
        (uint104 attackerNewEnd, uint256 attackerNewAmount) = vault.cooldowns(attacker);
        (uint104 normalUserEnd, uint256 normalUserAmount) = vault.cooldowns(normalUser);
        
        // VERIFY: Attacker's cooldown reset to 10 days from now
        assertEq(attackerNewEnd, block.timestamp + SHORT_COOLDOWN, "Attacker cooldown reset to short duration");
        assertEq(attackerNewAmount, stakeAmount + 1, "Attacker amount accumulated");
        
        // Normal user still has 89 days remaining (90 - 1 day elapsed)
        assertEq(normalUserEnd, attackerInitialEnd, "Normal user cooldown unchanged");
        
        // Fast forward 10 days
        vm.warp(block.timestamp + SHORT_COOLDOWN);
        
        // Attacker can unstake (total 11 days from start)
        uint256 attackerBalanceBefore = itryToken.balanceOf(attacker);
        vm.prank(attacker);
        vault.unstake(attacker);
        uint256 attackerBalanceAfter = itryToken.balanceOf(attacker);
        
        assertGt(attackerBalanceAfter, attackerBalanceBefore, "Attacker successfully unstaked");
        
        // Normal user CANNOT unstake yet (only 11 days passed, needs 90)
        vm.prank(normalUser);
        vm.expectRevert();
        vault.unstake(normalUser);
        
        // IMPACT: Attacker bypassed 79 days of cooldown (90 - 11 = 79 days saved)
        uint256 daysSaved = (normalUserEnd - block.timestamp) / 1 days;
        assertEq(daysSaved, 79, "Vulnerability confirmed: Attacker saved 79 days by gaming cooldown duration change");
    }
}
```

## Notes

This vulnerability is **not** the same as the emergency exit mechanism where `cooldownDuration = 0` allows immediate unstaking [3](#0-2) . That feature intentionally allows ALL users to exit when cooldowns are disabled. This vulnerability specifically exploits the cooldown accumulation design [5](#0-4)  which resets timestamps but was not designed to handle governance-driven cooldown duration reductions.

The same vulnerability exists in the composer-initiated cooldown path via `_startComposerCooldown()` [6](#0-5)  where repeated composer calls could similarly reset cooldowns to shorter durations after governance changes.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L22-22)
```text
    iTrySilo public immutable silo;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L84-84)
```text
        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L101-102)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L122-130)
```text
    function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (duration > MAX_COOLDOWN_DURATION) {
            revert InvalidCooldown();
        }

        uint24 previousDuration = cooldownDuration;
        cooldownDuration = duration;
        emit CooldownDurationUpdated(previousDuration, cooldownDuration);
    }
```

**File:** test/crosschainTests/StakediTryCrosschain.t.sol (L229-235)
```text
        // Second cooldown (should overwrite timestamp but accumulate assets)
        vm.prank(vaultComposer);
        uint256 assets2 = vault.cooldownSharesByComposer(50e18, alice);

        (uint104 cooldownEnd2, uint256 amount2) = vault.cooldowns(alice);
        assertEq(amount2, assets1 + assets2); // Assets accumulate
        assertGt(cooldownEnd2, cooldownEnd1); // Timestamp updates (overwrites)
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L177-178)
```text
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);
```
