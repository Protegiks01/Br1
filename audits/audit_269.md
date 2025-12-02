## Title
Front-running Cooldown Duration Increase Allows Unfair Early Exit

## Summary
When `setCooldownDuration` is called to increase the cooldown period, users can front-run this transaction to lock in the shorter cooldown duration. The `cooldownEnd` timestamp is calculated using the current `cooldownDuration` at the time of cooldown initiation and is never updated when the global duration changes, creating an exploitable timing asymmetry that grants sophisticated users significant advantages over regular users.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (StakediTryV2 contract, functions `cooldownShares` line 109-118, `cooldownAssets` line 96-105, `setCooldownDuration` line 122-130, `unstake` line 80-92)

**Intended Logic:** The cooldown mechanism is designed to enforce a waiting period before users can unstake their wiTRY shares, preventing rapid exit and protecting protocol stability. The `setCooldownDuration` function allows the admin to adjust this period based on market conditions and risk assessment.

**Actual Logic:** When users initiate a cooldown, their `cooldownEnd` timestamp is calculated as `block.timestamp + cooldownDuration`. [1](#0-0) [2](#0-1)  This stored timestamp is never updated when `setCooldownDuration` changes the global `cooldownDuration`. [3](#0-2)  The `unstake` function validates completion using only the stored `cooldownEnd` value. [4](#0-3) 

**Exploitation Path:**
1. Current state: `cooldownDuration = 1 day`, Alice has 1000 wiTRY shares staked
2. Admin transaction to call `setCooldownDuration(90 days)` appears in mempool
3. Alice observes this transaction and front-runs with `cooldownShares(1000)`
4. Alice's cooldown is recorded: `cooldowns[alice].cooldownEnd = block.timestamp + 1 day` (using OLD duration)
5. Admin transaction executes: `cooldownDuration = 90 days`
6. After 1 day, Alice calls `unstake(alice)` and successfully withdraws all her iTRY
7. Bob, who initiated cooldown after the duration change, must wait the full 90 days

**Security Property Broken:** This violates the fairness principle of the protocol and creates information asymmetry. While not explicitly stated as an invariant, the cooldown mechanism's purpose—to prevent destabilizing exits—is undermined when sophisticated users can bypass extended cooldowns by front-running parameter changes.

## Impact Explanation
- **Affected Assets**: wiTRY shares and underlying iTRY tokens
- **Damage Severity**: Users who front-run cooldown duration increases gain 89-day timing advantage (in the 1→90 day example), allowing them to redeploy capital, exit before potential depegs, or avoid crisis scenarios while regular users remain locked
- **User Impact**: All users who cannot monitor mempool or lack front-running capability are disadvantaged. In crisis scenarios where admin increases cooldown to prevent bank runs, sophisticated users can escape while trapping regular users, potentially exacerbating the crisis.

## Likelihood Explanation
- **Attacker Profile**: Any user with staked wiTRY who can monitor the mempool and submit front-running transactions (requires basic MEV infrastructure but no special privileges)
- **Preconditions**: Admin must decide to increase `cooldownDuration` (expected during market stress or risk events), and user must have staked wiTRY shares available to cooldown
- **Execution Complexity**: Single transaction front-running the admin's `setCooldownDuration` call—trivial to execute for users with mempool monitoring
- **Frequency**: Can be exploited by any user whenever admin increases cooldown duration, which may occur during protocol crises when the impact is most severe

## Recommendation
Implement one of the following mitigations:

**Option A: Proportional Cooldown Extension**
When duration increases, extend existing cooldowns proportionally:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function setCooldownDuration:

function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (duration > MAX_COOLDOWN_DURATION) {
        revert InvalidCooldown();
    }
    
    uint24 previousDuration = cooldownDuration;
    
    // If increasing duration, extend all active cooldowns proportionally
    if (duration > previousDuration && previousDuration > 0) {
        // Note: This requires iterating through all cooldowns, which is gas-intensive
        // Consider maintaining an array of active cooldown addresses or 
        // implementing the update lazily in unstake()
    }
    
    cooldownDuration = duration;
    emit CooldownDurationUpdated(previousDuration, cooldownDuration);
}
```

**Option B: Lazy Update in Unstake (Recommended)**
Check if cooldown was initiated before the last duration change and adjust accordingly:

```solidity
// Add a state variable to track last duration change
uint256 public lastDurationChangeTimestamp;

// In setCooldownDuration:
function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (duration > MAX_COOLDOWN_DURATION) {
        revert InvalidCooldown();
    }
    
    uint24 previousDuration = cooldownDuration;
    cooldownDuration = duration;
    lastDurationChangeTimestamp = block.timestamp; // Track when change occurred
    emit CooldownDurationUpdated(previousDuration, cooldownDuration);
}

// In unstake, add validation:
function unstake(address receiver) external {
    UserCooldown storage userCooldown = cooldowns[msg.sender];
    uint256 assets = userCooldown.underlyingAmount;
    
    // Calculate effective cooldown end considering duration changes
    uint256 effectiveCooldownEnd = userCooldown.cooldownEnd;
    
    // If duration changed after this cooldown started, and it increased,
    // ensure user respects the new duration from when they initiated
    uint256 cooldownStartTime = uint256(userCooldown.cooldownEnd) - cooldownDuration;
    if (cooldownStartTime < lastDurationChangeTimestamp && cooldownDuration > 0) {
        effectiveCooldownEnd = cooldownStartTime + cooldownDuration;
    }
    
    if (block.timestamp >= effectiveCooldownEnd || cooldownDuration == 0) {
        userCooldown.cooldownEnd = 0;
        userCooldown.underlyingAmount = 0;
        silo.withdraw(receiver, assets);
    } else {
        revert InvalidCooldown();
    }
}
```

**Option C: Timelock Parameter Changes**
Add a timelock to `setCooldownDuration` so users cannot front-run (duration change takes effect after delay), preventing the front-running attack entirely.

## Proof of Concept

```solidity
// File: test/Exploit_CooldownFrontrun.t.sol
// Run with: forge test --match-test test_CooldownDurationFrontrun -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_CooldownFrontrun is Test {
    StakediTryFastRedeem public vault;
    MockERC20 public iTryToken;
    
    address public admin;
    address public alice; // Sophisticated user who front-runs
    address public bob;   // Regular user
    
    uint256 constant INITIAL_BALANCE = 1000e18;
    
    function setUp() public {
        admin = makeAddr("admin");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy iTRY and vault
        iTryToken = new MockERC20("iTRY", "iTRY");
        vm.prank(admin);
        vault = new StakediTryFastRedeem(
            IERC20(address(iTryToken)),
            admin, // rewarder
            admin, // owner
            admin  // treasury
        );
        
        // Setup: Mint and stake for both users
        iTryToken.mint(alice, INITIAL_BALANCE);
        iTryToken.mint(bob, INITIAL_BALANCE);
        
        vm.prank(alice);
        iTryToken.approve(address(vault), type(uint256).max);
        vm.prank(bob);
        iTryToken.approve(address(vault), type(uint256).max);
        
        vm.prank(alice);
        vault.deposit(INITIAL_BALANCE, alice);
        vm.prank(bob);
        vault.deposit(INITIAL_BALANCE, bob);
    }
    
    function test_CooldownDurationFrontrun() public {
        // SETUP: Initial cooldown is 1 day
        assertEq(vault.cooldownDuration(), 90 days, "Initial cooldown is 90 days");
        
        // Reduce it to 1 day for testing
        vm.prank(admin);
        vault.setCooldownDuration(1 days);
        assertEq(vault.cooldownDuration(), 1 days);
        
        uint256 aliceShares = vault.balanceOf(alice);
        uint256 bobShares = vault.balanceOf(bob);
        
        // EXPLOIT: Alice sees admin tx to increase cooldown to 90 days
        // Alice front-runs and locks in 1-day cooldown
        vm.prank(alice);
        vault.cooldownShares(aliceShares);
        
        // Admin transaction executes: increase cooldown to 90 days
        vm.prank(admin);
        vault.setCooldownDuration(90 days);
        
        // Bob initiates cooldown AFTER the change (now must wait 90 days)
        vm.prank(bob);
        vault.cooldownShares(bobShares);
        
        // VERIFY: Fast forward 1 day
        vm.warp(block.timestamp + 1 days + 1);
        
        // Alice can unstake after just 1 day (front-ran the change)
        vm.prank(alice);
        vault.unstake(alice);
        assertEq(iTryToken.balanceOf(alice), INITIAL_BALANCE, "Alice got funds back after 1 day");
        
        // Bob cannot unstake yet (must wait 90 days)
        vm.prank(bob);
        vm.expectRevert();
        vault.unstake(bob);
        
        // Fast forward to 90 days
        vm.warp(block.timestamp + 89 days);
        
        // Now Bob can finally unstake
        vm.prank(bob);
        vault.unstake(bob);
        assertEq(iTryToken.balanceOf(bob), INITIAL_BALANCE, "Bob got funds back after 90 days");
        
        // RESULT: Alice exited 89 days earlier than Bob for the same operation
        console.log("Alice unstaked after: 1 day");
        console.log("Bob unstaked after: 90 days");
        console.log("Timing advantage: 89 days");
    }
}
```

## Notes

The asymmetry is by design (existing cooldowns use stored `cooldownEnd` values), but the **exploitability during parameter increases** was likely not considered. This is particularly problematic because:

1. **Crisis Amplification**: When protocol needs to increase cooldowns due to risk (the most likely scenario for increases), sophisticated users can escape while regular users are trapped, potentially worsening the crisis through selective exit

2. **Cross-chain Impact**: The same issue affects composer-initiated cooldowns in `StakediTryCrosschain.sol` [5](#0-4) , where cross-chain users can also exploit this asymmetry

3. **Mempool Visibility**: Unlike some MEV, this doesn't require sophisticated sandwich attack infrastructure—simply monitoring for `setCooldownDuration` calls and submitting a cooldown transaction before it executes

While the cooldown integrity invariant technically isn't violated (users complete *a* cooldown period), the **fairness and stability objectives** of the cooldown mechanism are compromised when insiders can systematically bypass extended cooldowns during critical periods.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L84-84)
```text
        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L101-101)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L114-114)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L128-128)
```text
        cooldownDuration = duration;
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
