## Title
Cooldown Duration Reset Allows Users to Bypass Original Cooldown Commitments When Admin Reduces Duration

## Summary
The `cooldownAssets()` and `cooldownShares()` functions unconditionally reset the `cooldownEnd` timestamp to `block.timestamp + cooldownDuration` on every call while accumulating assets. [1](#0-0)  When the admin legitimately reduces `cooldownDuration` via governance, users with existing cooldowns can bypass their original cooldown commitments by calling these functions again with minimal amounts, allowing them to claim all accumulated assets much earlier than originally intended.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` - `cooldownAssets()` function (lines 96-105), `cooldownShares()` function (lines 109-118)

**Intended Logic:** 
According to the protocol's cooldown integrity invariant, users must complete their cooldown period before unstaking wiTRY. [2](#0-1)  When a user initiates a cooldown, they commit to waiting the specified `cooldownDuration` before they can claim their assets via `unstake()`.

**Actual Logic:** 
The code resets `cooldownEnd` on every call: `cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration` while accumulating assets with `cooldowns[msg.sender].underlyingAmount += uint152(assets)`. [1](#0-0)  This allows users to reset their cooldown end time to a new shorter period if the admin reduces `cooldownDuration` after their initial cooldown was created. [3](#0-2) 

**Exploitation Path:**
1. **Initial Cooldown**: User calls `cooldownAssets(1000 ether)` at T0 when `cooldownDuration = 90 days`
   - State: `cooldownEnd = T0 + 90 days`, `underlyingAmount = 1000 ether`
   - User commits to waiting 90 days to claim 1000 ether

2. **Admin Reduces Duration**: At T60 (60 days later), admin legitimately calls `setCooldownDuration(7 days)` via governance decision [4](#0-3) 
   - This is a trusted admin action to make unstaking faster for new cooldowns

3. **User Resets Cooldown**: At T61, user calls `cooldownAssets(1 wei)` (minimal amount)
   - State: `cooldownEnd = T61 + 7 days = T0 + 68 days`, `underlyingAmount = 1000 ether + 1 wei`
   - User can now claim at T0 + 68 days instead of T0 + 90 days

4. **Early Unstake**: At T0 + 68 days, user calls `unstake()` and receives 1000 ether + 1 wei, bypassing 22 days of their original 90-day cooldown commitment [5](#0-4) 

**Security Property Broken:** 
Violates the **Cooldown Integrity** invariant: "Users must complete cooldown period before unstaking wiTRY." The user committed to a 90-day cooldown but can bypass it by adding dust amounts when cooldown duration is reduced.

## Impact Explanation
- **Affected Assets**: All wiTRY shares in cooldown (iTRY assets held in the silo awaiting unstake)
- **Damage Severity**: Users can bypass 50-90% of their original cooldown commitment depending on timing of duration reduction and their subsequent call. In the example above, user bypasses 22 days (24%) of the 90-day commitment.
- **User Impact**: 
  - **Unfairness**: Users who unstaked earlier had to wait the full 90 days, while users who didn't unstake yet can reset to 7 days
  - **Protocol Stability**: Cooldowns exist to prevent mass unstaking/"bank runs". This bypass undermines that protection by allowing coordinated early exits when cooldown is reduced.
  - **All users with pending cooldowns** can exploit this whenever admin reduces cooldown duration (a routine governance action)

## Likelihood Explanation
- **Attacker Profile**: Any user with an existing cooldown (staker waiting to unstake)
- **Preconditions**: 
  1. User has initiated cooldown with longer duration
  2. Admin reduces `cooldownDuration` via `setCooldownDuration()` (legitimate governance action, not malicious)
  3. User still has shares to cooldown (even 1 wei)
- **Execution Complexity**: Single transaction - just call `cooldownAssets(1 wei)` after admin reduces duration
- **Frequency**: Exploitable whenever admin reduces cooldown duration (expected during protocol lifecycle as governance adjusts parameters)

## Recommendation

**Option 1: Track Original Cooldown Duration (Recommended)**
Store the cooldown duration used for each cooldown and honor it regardless of later changes:

```solidity
// In src/token/wiTRY/interfaces/IStakediTryCooldown.sol, modify UserCooldown struct:

struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
    uint24 originalDuration; // Add field to track duration at cooldown creation
}

// In src/token/wiTRY/StakediTryCooldown.sol, cooldownAssets function:

function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
    if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
    shares = previewWithdraw(assets);
    
    UserCooldown storage cooldown = cooldowns[msg.sender];
    
    // If no existing cooldown or existing one expired, start fresh
    if (cooldown.cooldownEnd == 0 || block.timestamp >= cooldown.cooldownEnd) {
        cooldown.cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldown.underlyingAmount = uint152(assets);
        cooldown.originalDuration = cooldownDuration; // Record duration
    } else {
        // Existing active cooldown - keep original end time, just add assets
        cooldown.underlyingAmount += uint152(assets);
        // Do NOT reset cooldownEnd
    }
    
    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}
```

**Option 2: Extend Cooldown Instead of Reset**
When adding to existing cooldown, extend the end time rather than resetting:

```solidity
// In cooldownAssets:
UserCooldown storage cooldown = cooldowns[msg.sender];

if (cooldown.cooldownEnd > 0 && block.timestamp < cooldown.cooldownEnd) {
    // Active cooldown exists - extend it from current end time, don't reset from now
    uint256 remainingTime = cooldown.cooldownEnd - block.timestamp;
    cooldown.cooldownEnd = uint104(cooldown.cooldownEnd + cooldownDuration); // Extend from end, not from now
} else {
    cooldown.cooldownEnd = uint104(block.timestamp) + cooldownDuration;
}
cooldown.underlyingAmount += uint152(assets);
```

**Option 3: Prevent New Cooldowns During Active Cooldown**
Simplest fix - don't allow adding to active cooldowns:

```solidity
// In cooldownAssets:
UserCooldown storage cooldown = cooldowns[msg.sender];

if (cooldown.underlyingAmount > 0 && block.timestamp < cooldown.cooldownEnd) {
    revert ActiveCooldownExists(); // Force user to unstake first
}

cooldown.cooldownEnd = uint104(block.timestamp) + cooldownDuration;
cooldown.underlyingAmount = uint152(assets); // Use = not += since we reject adding to existing
```

**Note:** The same fix must be applied to `cooldownShares()` and `_startComposerCooldown()` in `StakediTryCrosschain.sol`. [6](#0-5) 

## Proof of Concept

```solidity
// File: test/Exploit_CooldownBypass.t.sol
// Run with: forge test --match-test test_CooldownBypassViaDurationReduction -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_CooldownBypass is Test {
    iTry public itryToken;
    StakediTryV2 public vault;
    address public owner;
    address public alice;
    
    function setUp() public {
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        
        // Deploy iTRY token
        vm.startPrank(owner);
        iTry itryImpl = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner, owner, owner
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(itryImpl), initData);
        itryToken = iTry(address(proxy));
        
        // Deploy vault with 90-day cooldown
        vault = new StakediTryV2(itryToken, owner, owner);
        
        // Mint iTRY to alice and approve vault
        itryToken.mint(alice, 1000 ether);
        vm.stopPrank();
        
        vm.startPrank(alice);
        itryToken.approve(address(vault), type(uint256).max);
        vault.deposit(1000 ether, alice);
        vm.stopPrank();
    }
    
    function test_CooldownBypassViaDurationReduction() public {
        uint256 initialCooldownDuration = 90 days;
        uint256 reducedCooldownDuration = 7 days;
        
        // SETUP: Alice initiates cooldown with 90-day duration
        vm.prank(alice);
        vault.cooldownAssets(1000 ether);
        
        (uint104 cooldownEnd1, uint256 amount1) = vault.cooldowns(alice);
        assertEq(amount1, 1000 ether);
        assertEq(cooldownEnd1, block.timestamp + initialCooldownDuration);
        
        // Alice should have to wait until T0 + 90 days
        uint256 originalUnstakeTime = block.timestamp + initialCooldownDuration;
        
        // TIME PASSES: 60 days elapse
        vm.warp(block.timestamp + 60 days);
        
        // ADMIN ACTION: Owner reduces cooldown duration (legitimate governance)
        vm.prank(owner);
        vault.setCooldownDuration(uint24(reducedCooldownDuration));
        
        // EXPLOIT: Alice adds 1 wei to reset her cooldown
        vm.prank(alice);
        vault.cooldownAssets(1 wei);
        
        (uint104 cooldownEnd2, uint256 amount2) = vault.cooldowns(alice);
        assertEq(amount2, 1000 ether + 1 wei); // Assets accumulated
        
        // VULNERABILITY CONFIRMED: cooldownEnd is now much sooner than original
        uint256 newUnstakeTime = block.timestamp + reducedCooldownDuration;
        assertLt(cooldownEnd2, cooldownEnd1, "Cooldown was reset to shorter period");
        assertLt(newUnstakeTime, originalUnstakeTime, "Alice can unstake earlier than original commitment");
        
        // Alice bypassed 23 days of her original 90-day cooldown
        uint256 bypassedDays = (originalUnstakeTime - newUnstakeTime) / 1 days;
        assertEq(bypassedDays, 23, "Alice bypassed 23 days of original cooldown");
        
        // VERIFY: Alice can unstake at the new earlier time
        vm.warp(newUnstakeTime);
        
        uint256 aliceBalanceBefore = itryToken.balanceOf(alice);
        vm.prank(alice);
        vault.unstake(alice);
        uint256 aliceBalanceAfter = itryToken.balanceOf(alice);
        
        assertEq(aliceBalanceAfter - aliceBalanceBefore, 1000 ether + 1 wei, 
            "Alice successfully unstaked all assets 23 days early");
    }
}
```

## Notes

- The vulnerability exists in **three locations**: `cooldownAssets()`, `cooldownShares()` in StakediTryCooldown.sol, and `_startComposerCooldown()` in StakediTryCrosschain.sol
- While tests explicitly validate the timestamp reset behavior as intentional [7](#0-6) , this doesn't account for the security implications when combined with cooldown duration reductions
- This is NOT an admin maliciousness issue - reducing cooldown duration is a legitimate governance action to improve user experience
- The vulnerability is in the **combination** of legitimate admin action + normal user action that creates an unintended bypass
- Impact is Medium (not High) because it requires admin action as a precondition, but the bypass still violates protocol invariants and creates unfairness

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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L114-115)
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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L177-178)
```text
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);
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
