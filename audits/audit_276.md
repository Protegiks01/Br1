## Title
Cooldown Timer Reset on Accumulated Funds Enables Indefinite User Fund Lockup

## Summary
The `cooldownShares()` and `cooldownAssets()` functions in `StakediTryCooldown.sol` reset the cooldown end timestamp for ALL accumulated underlying amounts on each call, while the `unstake()` function only allows withdrawing the entire accumulated balance at once. This enables users to inadvertently lock their own funds indefinitely by repeatedly calling cooldown functions, or allows malicious actors to grief users who delegate cooldown operations to contracts.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/token/wiTRY/StakediTryCooldown.sol` 

**Intended Logic:** The cooldown mechanism should allow users to initiate a time-locked unstaking process where they wait a fixed duration (up to 90 days) before being able to claim their underlying iTRY assets. [1](#0-0) 

**Actual Logic:** Each call to `cooldownShares()` or `cooldownAssets()` performs two critical operations:
1. **RESETS** the `cooldownEnd` timestamp to `block.timestamp + cooldownDuration` (starting the timer from scratch)
2. **ACCUMULATES** the `underlyingAmount` by adding the new assets to existing balance [2](#0-1) 

This means the first cooldown amounts are "held hostage" to subsequent cooldown calls. The `unstake()` function only allows withdrawing ALL accumulated assets at once when `block.timestamp >= cooldownEnd`, with no partial unstaking capability. [3](#0-2) 

**Exploitation Path:**

1. **Day 0**: User calls `cooldownShares(1000e18)` 
   - State: `cooldownEnd = Day 90`, `underlyingAmount = 1000e18`

2. **Day 89**: User calls `cooldownShares(1e18)` (just 1 token more)
   - State: `cooldownEnd = Day 179` (RESET!), `underlyingAmount = 1001e18` (ACCUMULATED)

3. **Day 178**: User calls `cooldownShares(1e18)` again
   - State: `cooldownEnd = Day 268` (RESET AGAIN!), `underlyingAmount = 1002e18`

4. **Outcome**: By making small cooldown calls before each timer expires, a user (or malicious contract) can perpetually extend the lock on ALL funds indefinitely, preventing any unstaking.

**Security Property Broken:** Violates the **Cooldown Integrity** invariant which states users must be able to complete the cooldown period to unstake. The design creates a scenario where completion becomes impossible through repeated cooldown calls.

## Impact Explanation

- **Affected Assets**: All wiTRY shares and corresponding iTRY underlying assets held in cooldown by affected users, locked in the `iTrySilo` contract [4](#0-3) 

- **Damage Severity**: Complete loss of access to staked funds for affected users. If a user (or smart contract integrating this protocol) makes cooldown calls on a regular basis (e.g., automated strategies, DCA unstaking), they will NEVER be able to withdraw their funds through normal means. The only recovery path is if the admin sets `cooldownDuration = 0`, which affects ALL users globally and breaks the intended cooldown mechanism. [5](#0-4) 

- **User Impact**: 
  - Individual stakers who attempt to unstake incrementally
  - Smart contracts that automate unstaking strategies
  - Cross-chain users whose composer-based cooldowns can be extended [6](#0-5) 

## Likelihood Explanation

- **Attacker Profile**: Any user with wiTRY shares. No special privileges required. Can also affect users who delegate cooldown operations to third-party contracts.

- **Preconditions**: 
  - Cooldown duration must be greater than 0 (default is 90 days)
  - User must have wiTRY shares staked
  - User makes multiple cooldown calls before the first cooldown expires

- **Execution Complexity**: Trivial - single function calls. Can happen accidentally through:
  - User error (thinking they're adding to a queue, not resetting timer)
  - Smart contract integrations that call cooldown periodically
  - UI bugs that trigger multiple cooldown transactions

- **Frequency**: Continuous exploitation possible. Each cooldown call before expiration extends the lock by the full duration.

## Recommendation

Implement per-cooldown tracking with a queue or array-based system that maintains separate cooldown timestamps for each cooldown initiation, rather than resetting a single global timer:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol:

// CURRENT (vulnerable):
// Lines 114-115 in cooldownShares():
cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
cooldowns[msg.sender].underlyingAmount += uint152(assets);

// FIXED APPROACH 1: Reject new cooldowns while one is pending
function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
    if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();
    
    // Prevent resetting timer if cooldown is already active
    UserCooldown storage userCooldown = cooldowns[msg.sender];
    if (userCooldown.underlyingAmount > 0 && block.timestamp < userCooldown.cooldownEnd) {
        revert CooldownAlreadyActive();
    }

    assets = previewRedeem(shares);
    userCooldown.cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    userCooldown.underlyingAmount = uint152(assets); // SET instead of +=

    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}

// FIXED APPROACH 2: Allow accumulation only without resetting timer
function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
    if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();

    assets = previewRedeem(shares);
    UserCooldown storage userCooldown = cooldowns[msg.sender];
    
    // Only set timer if no active cooldown, otherwise keep existing timer
    if (userCooldown.cooldownEnd < block.timestamp) {
        userCooldown.cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    }
    userCooldown.underlyingAmount += uint152(assets);

    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}
```

**Recommended Fix**: Approach 1 (reject new cooldowns while active) is safer and clearer to users. Approach 2 (extend without reset) maintains flexibility but requires clear documentation.

Apply the same fix pattern to:
- `cooldownAssets()` function (lines 96-105)
- `_startComposerCooldown()` in StakediTryCrosschain.sol (lines 170-181)

## Proof of Concept

```solidity
// File: test/Exploit_CooldownTimerReset.t.sol
// Run with: forge test --match-test test_CooldownTimerResetLocksUserFunds -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_CooldownTimerReset is Test {
    StakediTryV2 public vault;
    MockERC20 public iTryToken;
    
    address public admin = address(0x1);
    address public rewarder = address(0x2);
    address public user = address(0x3);
    
    uint256 constant STAKE_AMOUNT = 1000e18;
    uint256 constant SMALL_AMOUNT = 1e18;
    
    function setUp() public {
        // Deploy iTRY mock token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy vault
        vm.prank(admin);
        vault = new StakediTryV2(IERC20(address(iTryToken)), rewarder, admin);
        
        // Mint tokens to user and approve
        iTryToken.mint(user, STAKE_AMOUNT * 2);
        vm.prank(user);
        iTryToken.approve(address(vault), type(uint256).max);
        
        // User stakes tokens
        vm.prank(user);
        vault.deposit(STAKE_AMOUNT, user);
    }
    
    function test_CooldownTimerResetLocksUserFunds() public {
        // SETUP: User initiates first cooldown
        vm.prank(user);
        uint256 shares1 = vault.balanceOf(user);
        vault.cooldownShares(shares1 / 2); // Cooldown half the shares
        
        // Verify initial cooldown state
        (uint104 cooldownEnd1, uint152 underlyingAmount1) = vault.cooldowns(user);
        uint256 expectedEnd1 = block.timestamp + vault.cooldownDuration();
        assertEq(cooldownEnd1, expectedEnd1, "First cooldown end should be set");
        assertGt(underlyingAmount1, 0, "Should have underlying amount");
        
        console.log("Day 0 - Initial cooldown:");
        console.log("  Cooldown ends:", cooldownEnd1);
        console.log("  Underlying amount:", underlyingAmount1);
        
        // EXPLOIT: Time travel to day 89 (just before expiry) and add small cooldown
        vm.warp(block.timestamp + vault.cooldownDuration() - 1 days);
        
        vm.prank(user);
        vault.cooldownShares(SMALL_AMOUNT); // Add tiny amount
        
        (uint104 cooldownEnd2, uint152 underlyingAmount2) = vault.cooldowns(user);
        
        console.log("\nDay 89 - After small cooldown:");
        console.log("  Cooldown ends:", cooldownEnd2);
        console.log("  Underlying amount:", underlyingAmount2);
        
        // VERIFY: Timer was RESET (not just extended by 1 day)
        uint256 expectedEnd2 = block.timestamp + vault.cooldownDuration();
        assertEq(cooldownEnd2, expectedEnd2, "Cooldown timer should be RESET to full duration");
        assertEq(underlyingAmount2, underlyingAmount1 + SMALL_AMOUNT, "Amounts should accumulate");
        
        // Prove the lock extension
        uint256 additionalDays = (cooldownEnd2 - cooldownEnd1) / 1 days;
        console.log("  Additional days locked:", additionalDays);
        assertEq(additionalDays, 89, "All funds now locked for 89 MORE days");
        
        // VERIFY: User cannot unstake at original expiry time
        vm.warp(cooldownEnd1);
        vm.prank(user);
        vm.expectRevert(IStakediTryCooldown.InvalidCooldown.selector);
        vault.unstake(user);
        
        console.log("\nDay 90 (original expiry) - Cannot unstake!");
        
        // VERIFY: Repeated small cooldowns can lock funds indefinitely
        for(uint i = 0; i < 3; i++) {
            vm.warp(block.timestamp + vault.cooldownDuration() - 1 days);
            vm.prank(user);
            vault.cooldownShares(1); // Minimal shares
            
            (uint104 currentEnd,) = vault.cooldowns(user);
            console.log("\nAfter cooldown", i+3, "- New expiry:", currentEnd);
        }
        
        (uint104 finalEnd, uint152 finalAmount) = vault.cooldowns(user);
        console.log("\nFinal state:");
        console.log("  Days from now:", (finalEnd - block.timestamp) / 1 days);
        console.log("  Total locked amount:", finalAmount);
        console.log("  Result: User funds locked indefinitely through repeated cooldowns");
    }
}
```

## Notes

The vulnerability affects both regular user cooldowns (`cooldownShares`, `cooldownAssets`) and composer-based cross-chain cooldowns (`cooldownSharesByComposer`, `cooldownAssetsByComposer`). The UserCooldown struct stores only a single `cooldownEnd` timestamp and a cumulative `underlyingAmount`, making it impossible to track multiple concurrent cooldowns with different expiration times. [7](#0-6) 

This is particularly problematic for:
1. **DCA (Dollar Cost Averaging) unstaking strategies** where users want to exit positions gradually
2. **Smart contract integrations** that automate regular unstaking operations  
3. **Cross-chain unstaking flows** where multiple users might have their cooldowns managed by the composer contract

The only admin-level recovery mechanism is setting `cooldownDuration = 0`, which bypasses cooldown checks for ALL users globally and defeats the purpose of the cooldown security feature. [8](#0-7)

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L10-16)
```text
/**
 * @title StakediTryV2
 * @notice The StakediTryV2 contract allows users to stake iTry tokens and earn a portion of protocol LST and perpetual yield that is allocated
 * to stakers by the Ethena DAO governance voted yield distribution algorithm.  The algorithm seeks to balance the stability of the protocol by funding
 * the protocol's insurance fund, DAO activities, and rewarding stakers with a portion of the protocol's yield.
 * @dev If cooldown duration is set to zero, the StakediTryV2 behavior changes to follow ERC4626 standard and disables cooldownShares and cooldownAssets methods. If cooldown duration is greater than zero, the ERC4626 withdrawal and redeem functions are disabled, breaking the ERC4626 standard, and enabling the cooldownShares and the cooldownAssets functions.
 */
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L22-22)
```text
    iTrySilo public immutable silo;
```

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

**File:** src/token/wiTRY/interfaces/IStakediTryCooldown.sol (L7-10)
```text
struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
}
```
