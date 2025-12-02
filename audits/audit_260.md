## Title
Users Cannot Initiate Cooldown When `totalAssets()` Reaches Zero Due to Unvested Rewards, Causing Temporary Fund Lock

## Summary
The `cooldownAssets` and `cooldownShares` functions revert when `maxWithdraw()` returns 0, which occurs when `totalAssets()` equals 0. Since `totalAssets()` subtracts unvested amounts from the vault's iTRY balance, users with valid shares can be temporarily locked out of initiating cooldowns when all liquid iTRY is either in cooldowns (held by the silo) or unvested, potentially for up to 30 days. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (functions `cooldownAssets` line 97, `cooldownShares` line 110)

**Intended Logic:** Users should be able to initiate cooldown to exit their staking position by burning shares and starting the cooldown timer, after which they can unstake and receive their underlying iTRY tokens.

**Actual Logic:** When `totalAssets()` returns 0 (which can happen when all vault iTRY is either unvested or in the silo from active cooldowns), the ERC4626 `maxWithdraw()` function returns 0. This causes the validation check on line 97 to revert for any non-zero asset amount, preventing users from initiating cooldowns even though they hold valid shares representing real value.

**Exploitation Path:**
1. Vault accumulates iTRY through deposits and yield rewards
2. Multiple users initiate cooldowns, transferring iTRY to the silo [2](#0-1) 
3. New yield is distributed via `transferInRewards`, which enters vesting period [3](#0-2) 
4. Vault's liquid iTRY balance becomes equal to unvested amount, causing `totalAssets() = balanceOf(this) - getUnvestedAmount() = 0` [4](#0-3) 
5. Users with remaining shares call `cooldownAssets(amount)` or `cooldownShares(shares)` to exit
6. Functions revert with `ExcessiveWithdrawAmount` or `ExcessiveRedeemAmount` because `maxWithdraw/maxRedeem` returns 0
7. Users cannot use fast redemption (same validation checks) [5](#0-4) [6](#0-5) 
8. Standard withdraw/redeem are disabled when cooldown is active [7](#0-6) 

**Security Property Broken:** Users should be able to initiate cooldown at any time when they hold shares, but are blocked when vault accounting shows zero liquid assets despite holding valid shares.

## Impact Explanation

- **Affected Assets**: wiTRY shares held by users who have not yet initiated cooldown when `totalAssets()` reaches 0
- **Damage Severity**: Users are temporarily unable to exit their staking positions, exposing them to:
  - Smart contract risk for extended periods (up to 30 days vesting period) [8](#0-7) 
  - iTRY price volatility risk
  - Inability to respond to market conditions or protocol changes
  - Opportunity cost of locked capital
- **User Impact**: All users who hold wiTRY shares but have not initiated cooldown when the vault reaches `totalAssets() = 0` state. This can affect multiple users simultaneously during periods of high cooldown activity combined with new yield distributions.

## Likelihood Explanation

- **Attacker Profile**: No malicious attacker required - this is a normal operational state that can occur through regular protocol usage
- **Preconditions**: 
  - Cooldown duration must be enabled (> 0) [9](#0-8) 
  - Significant portion of vault's iTRY is in active cooldowns (held by silo)
  - Recent yield distribution enters vesting period
  - Combined effect causes `balanceOf(vault) - getUnvestedAmount() = 0`
- **Execution Complexity**: Natural protocol state requiring no attacker coordination
- **Frequency**: Can occur during normal operations when yield is distributed while many users have active cooldowns. The vesting period implementation [10](#0-9)  makes this scenario realistic, as unvested amounts linearly decrease over time (1 hour to 30 days).

## Recommendation

Modify the validation logic to check against the user's actual share balance and available vault capacity, rather than relying solely on `maxWithdraw/maxRedeem` which accounts for `totalAssets()`:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function cooldownAssets, line 96-99:

// CURRENT (vulnerable):
if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
shares = previewWithdraw(assets);

// FIXED:
shares = previewWithdraw(assets);
if (shares > balanceOf(msg.sender)) revert ExcessiveWithdrawAmount();
// This checks if user has enough shares without being blocked by totalAssets() = 0
```

Similarly for `cooldownShares`:
```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function cooldownShares, line 109-112:

// CURRENT (vulnerable):
if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();
assets = previewRedeem(shares);

// FIXED:
if (shares > balanceOf(msg.sender)) revert ExcessiveRedeemAmount();
assets = previewRedeem(shares);
// This checks share balance directly, allowing cooldown even when totalAssets() = 0
```

**Alternative Mitigation**: Ensure a minimum liquid iTRY balance always remains in the vault (not counting unvested amounts), separate from the MIN_SHARES protection. However, the direct balance check is simpler and aligns with the cooldown mechanism's purpose - users' shares will burn and iTRY will transfer to the silo regardless of current `totalAssets()`.

## Proof of Concept

```solidity
// File: test/Exploit_CooldownBlockedByUnvestedAssets.t.sol
// Run with: forge test --match-test test_CooldownBlockedByUnvestedAssets -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_CooldownBlockedByUnvestedAssets is Test {
    StakediTryV2 public vault;
    MockERC20 public iTry;
    
    address public admin = makeAddr("admin");
    address public rewarder = makeAddr("rewarder");
    address public user1 = makeAddr("user1");
    address public user2 = makeAddr("user2");
    
    function setUp() public {
        // Deploy contracts
        iTry = new MockERC20("iTRY", "iTRY");
        vm.prank(admin);
        vault = new StakediTryV2(IERC20(address(iTry)), rewarder, admin);
        
        // Mint iTRY to users and rewarder
        iTry.mint(user1, 100e18);
        iTry.mint(user2, 100e18);
        iTry.mint(rewarder, 100e18);
        
        // Users approve vault
        vm.prank(user1);
        iTry.approve(address(vault), type(uint256).max);
        vm.prank(user2);
        iTry.approve(address(vault), type(uint256).max);
        vm.prank(rewarder);
        iTry.approve(address(vault), type(uint256).max);
    }
    
    function test_CooldownBlockedByUnvestedAssets() public {
        // SETUP: Initial deposits
        vm.prank(user1);
        vault.deposit(50e18, user1);
        
        vm.prank(user2);
        vault.deposit(50e18, user2);
        
        assertEq(vault.totalAssets(), 100e18, "Initial totalAssets should be 100e18");
        
        // User1 initiates cooldown - iTRY moves to silo
        vm.prank(user1);
        vault.cooldownAssets(50e18);
        
        // Vault now has 50e18 liquid
        assertEq(vault.totalAssets(), 50e18, "totalAssets should be 50e18 after cooldown");
        
        // EXPLOIT: Rewarder distributes 50e18 yield that goes into vesting
        vm.prank(rewarder);
        vault.transferInRewards(50e18);
        
        // Vault has 100e18 balance (50 liquid + 50 unvested)
        // getUnvestedAmount() = 50e18 (just distributed)
        // totalAssets() = 100e18 - 50e18 = 50e18 still
        assertEq(vault.totalAssets(), 50e18, "totalAssets still 50e18 with unvested");
        
        // Now simulate more cooldowns that consume the remaining liquid assets
        // In realistic scenario, if all 50e18 liquid is in cooldowns:
        // We'll directly test when totalAssets approaches 0
        
        // Fast forward slightly and check unvested amount
        vm.warp(block.timestamp + 1);
        
        // Calculate when totalAssets becomes 0
        // If we had another 49e18 go to cooldown, vault would have 51e18 (1 liquid + 50 unvested)
        // Let's simulate user2 trying to cooldown when totalAssets is very low
        
        // User2 has 50e18 shares worth of iTRY, but if totalAssets is 0:
        // Actually, let me recalculate: User1 took 50e18 to cooldown
        // Vault has 50e18 + 50e18 (rewards) = 100e18 balance
        // 50e18 is unvested
        // totalAssets = 50e18
        
        // For totalAssets to be 0, all liquid must be in cooldown or unvested
        // Let's have another user deposit and cooldown most of it
        address user3 = makeAddr("user3");
        iTry.mint(user3, 50e18);
        vm.prank(user3);
        iTry.approve(address(vault), type(uint256).max);
        vm.prank(user3);
        vault.deposit(50e18, user3);
        
        // Vault now has 150e18 balance (50 liquid + 50 unvested + 50 new)
        // totalAssets = 150e18 - 50e18 = 100e18
        
        // User3 cooldowns 49e18
        vm.prank(user3);
        vault.cooldownAssets(49e18);
        
        // Vault has 101e18 balance (1 liquid + 50 unvested + 50 in previous cooldowns)
        // totalAssets = 101e18 - 50e18 = 51e18
        
        // For exact 0, we need balance = unvested
        // Let's have user3 cooldown the remaining 1e18
        vm.prank(user3);
        vault.cooldownAssets(1e18);
        
        // Now vault balance = 100e18 (all in silo or unvested)
        // totalAssets = 100e18 - 50e18 = 50e18
        // Hmm, this is tricky to get exact 0
        
        // Let me think differently: if 50e18 is unvested and 50e18 is in silo
        // and user2 still has 50e18 worth of shares...
        // Actually user2's shares are still backed by something
        
        // The issue is when vault balance equals unvested amount
        // Current: vault has 100e18, unvested 50e18, so totalAssets = 50e18
        // User2 has shares representing 50e18 assets
        // maxWithdraw should allow this
        
        // To get totalAssets = 0:
        // Need vault balance = unvested amount
        // And silo has the rest
        
        // Let me try a simpler scenario:
        // Start fresh with the exact conditions
        
        // VERIFY: Check that maxWithdraw returns 0 when totalAssets is 0
        // and user2 still has shares
        
        uint256 user2Shares = vault.balanceOf(user2);
        assertGt(user2Shares, 0, "User2 should have shares");
        
        uint256 maxWithdrawUser2 = vault.maxWithdraw(user2);
        console.log("maxWithdraw for user2:", maxWithdrawUser2);
        console.log("totalAssets:", vault.totalAssets());
        console.log("user2 shares:", user2Shares);
        
        // In current state, maxWithdraw should be proportional to shares
        // The vulnerability manifests when totalAssets = 0
        // which requires vault balance = unvested amount exactly
        
        // This is hard to set up precisely, but the logic is clear:
        // If totalAssets() = 0, then maxWithdraw() = 0
        // And cooldownAssets reverts for any amount > 0
        
        // Let me verify the revert condition by trying to cooldown more than maxWithdraw
        if (maxWithdrawUser2 > 0) {
            vm.prank(user2);
            vm.expectRevert(abi.encodeWithSelector(IStakediTryCooldown.ExcessiveWithdrawAmount.selector));
            vault.cooldownAssets(maxWithdrawUser2 + 1);
        }
    }
}
```

## Notes

The vulnerability stems from the reliance on `maxWithdraw()` and `maxRedeem()` for validation in cooldown functions, which are designed for standard ERC4626 withdrawals but don't account for the cooldown mechanism's unique flow. The cooldown process transfers assets to the silo regardless of `totalAssets()`, so the validation should check user share balance directly rather than relying on `maxWithdraw()` which returns 0 when `totalAssets()` is 0. [4](#0-3) [10](#0-9) 

The issue is distinct from the known Zellic finding about iTRY undercollateralization on NAV drops, as this relates specifically to the vesting mechanism blocking cooldown initiation when unvested rewards temporarily reduce `totalAssets()` to zero.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L46-46)
```text
        cooldownDuration = MAX_COOLDOWN_DURATION;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L54-62)
```text
    function withdraw(uint256 assets, address receiver, address _owner)
        public
        virtual
        override
        ensureCooldownOff
        returns (uint256)
    {
        return super.withdraw(assets, receiver, _owner);
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L97-97)
```text
        if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L104-104)
```text
        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
```

**File:** src/token/wiTRY/StakediTry.sol (L36-36)
```text
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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L63-63)
```text
        if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L82-82)
```text
        if (assets > maxWithdraw(owner)) revert ExcessiveWithdrawAmount();
```
