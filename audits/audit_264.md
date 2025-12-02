## Title
Retroactive Cooldown Enforcement Traps Existing Depositors in Unexpected Lockup Period

## Summary
When the admin enables the cooldown mechanism after users have deposited their assets (while cooldown was disabled), existing depositors are retroactively forced into the cooldown flow, requiring them to wait up to 90 days to withdraw their funds. The `redeem()` and `withdraw()` functions check the current cooldown state via the `ensureCooldownOff` modifier, not the state at deposit time, trapping users who entered the vault expecting instant withdrawals.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (StakediTryV2 contract, `redeem()` function lines 67-75, `withdraw()` function lines 54-62)

**Intended Logic:** The contract is designed to operate in two modes based on cooldown duration. When `cooldownDuration = 0`, it follows ERC4626 standard with instant withdrawals. When `cooldownDuration > 0`, it requires users to initiate a cooldown period before unstaking. [1](#0-0) 

**Actual Logic:** The `redeem()` and `withdraw()` functions enforce the `ensureCooldownOff` modifier, which checks the **current** cooldown state, not the state at deposit time. When an admin changes `cooldownDuration` from 0 to a non-zero value, all existing depositors immediately lose access to instant withdrawals. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. **Initial State**: User deposits 1000 iTRY when `cooldownDuration = 0`, receiving wiTRY shares with expectation of instant withdrawals per ERC4626 standard
2. **State Change**: Admin calls `setCooldownDuration(90 days)` to enable cooldown mechanism [4](#0-3) 
3. **Withdrawal Blocked**: User attempts to call `redeem(shares, receiver, owner)` but transaction reverts with `OperationNotAllowed()` because `cooldownDuration != 0`
4. **Forced Cooldown**: User must now call `cooldownShares()` or `cooldownAssets()`, wait up to 90 days, then call `unstake()` to recover their funds [5](#0-4) 

**Security Property Broken:** While not explicitly listed in the critical invariants, this violates the principle of user consent and reasonable expectations. Users who deposit under one set of withdrawal rules should not be retroactively subjected to materially different and more restrictive conditions without any grandfathering mechanism.

## Impact Explanation
- **Affected Assets**: All wiTRY shares held by users who deposited when cooldown was disabled become subject to unexpected lockup
- **Damage Severity**: Users face temporary liquidity constraint of up to 90 days (MAX_COOLDOWN_DURATION). While funds are eventually recoverable (not permanent loss), the unexpected lockup can cause significant harm, especially if users deposited expecting instant access for time-sensitive needs [6](#0-5) 
- **User Impact**: All existing depositors at the time cooldown is enabled are affected. This could impact hundreds or thousands of users who made deposits based on the instant withdrawal capability

## Likelihood Explanation
- **Attacker Profile**: Not applicable - this is an admin configuration change that unintentionally harms existing users
- **Preconditions**: 
  - Users have deposited when `cooldownDuration = 0`
  - Admin enables cooldown by calling `setCooldownDuration(duration > 0)`
  - No grandfathering mechanism exists for existing deposits
- **Execution Complexity**: Single admin transaction to change cooldown duration. The impact is immediate and automatic for all existing depositors
- **Frequency**: This can occur whenever the admin decides to enable or re-enable the cooldown mechanism after a period of instant withdrawals

## Recommendation

Implement a grandfathering mechanism that tracks the cooldown state at deposit time, or provide a grace period for existing depositors:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol:

// OPTION 1: Track deposit timestamp per user
mapping(address => uint256) public depositTimestamps;
uint256 public lastCooldownChangeTimestamp;

function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (duration > MAX_COOLDOWN_DURATION) {
        revert InvalidCooldown();
    }
    
    uint24 previousDuration = cooldownDuration;
    cooldownDuration = duration;
    lastCooldownChangeTimestamp = block.timestamp; // Track when cooldown was changed
    emit CooldownDurationUpdated(previousDuration, cooldownDuration);
}

// Modify ensureCooldownOff to allow grace period
modifier ensureCooldownOff() {
    if (cooldownDuration != 0) {
        // Allow instant withdrawal for deposits made before cooldown was enabled
        if (depositTimestamps[msg.sender] >= lastCooldownChangeTimestamp) {
            revert OperationNotAllowed();
        }
    }
    _;
}

// OPTION 2: Add an emergency withdrawal function with time limit
function emergencyWithdraw(uint256 shares, address receiver, address _owner) 
    external 
    returns (uint256) 
{
    // Only allow emergency withdrawals for users who deposited before cooldown was enabled
    // and within a grace period (e.g., 7 days after cooldown activation)
    require(
        depositTimestamps[_owner] < lastCooldownChangeTimestamp &&
        block.timestamp < lastCooldownChangeTimestamp + 7 days,
        "Emergency withdrawal not available"
    );
    return super.redeem(shares, receiver, _owner);
}
```

**Alternative**: Document this behavior clearly and ensure users are notified before enabling cooldown, giving them time to withdraw if they don't want to be subject to the cooldown mechanism.

## Proof of Concept

```solidity
// File: test/Exploit_RetroactiveCooldownLockup.t.sol
// Run with: forge test --match-test test_RetroactiveCooldownLockup -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_RetroactiveCooldownLockup is Test {
    StakediTryFastRedeem public vault;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public user;
    
    uint256 constant DEPOSIT_AMOUNT = 1000e18;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        rewarder = makeAddr("rewarder");
        user = makeAddr("user");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy vault with cooldown DISABLED (constructor sets it to MAX, so we need to disable it)
        vm.prank(admin);
        vault = new StakediTryFastRedeem(
            IERC20(address(iTryToken)), 
            rewarder, 
            admin, 
            treasury
        );
        
        // Admin disables cooldown initially
        vm.prank(admin);
        vault.setCooldownDuration(0);
        
        // Mint tokens to user
        iTryToken.mint(user, DEPOSIT_AMOUNT);
        
        // User approves vault
        vm.prank(user);
        iTryToken.approve(address(vault), type(uint256).max);
    }
    
    function test_RetroactiveCooldownLockup() public {
        // ===== SETUP: User deposits when cooldown is DISABLED =====
        console.log("=== Phase 1: User deposits with instant withdrawal available ===");
        
        vm.prank(user);
        uint256 shares = vault.deposit(DEPOSIT_AMOUNT, user);
        
        console.log("User deposited:", DEPOSIT_AMOUNT);
        console.log("User received shares:", shares);
        console.log("Cooldown duration:", vault.cooldownDuration());
        assertEq(vault.cooldownDuration(), 0, "Cooldown should be disabled");
        
        // Verify user can withdraw instantly
        vm.prank(user);
        uint256 maxRedeemable = vault.maxRedeem(user);
        console.log("Max redeemable shares:", maxRedeemable);
        assertEq(maxRedeemable, shares, "User should be able to redeem all shares");
        
        // ===== EXPLOIT: Admin enables cooldown, trapping existing deposits =====
        console.log("\n=== Phase 2: Admin enables cooldown ===");
        
        vm.prank(admin);
        vault.setCooldownDuration(90 days);
        
        console.log("Cooldown enabled with duration:", vault.cooldownDuration());
        assertEq(vault.cooldownDuration(), 90 days, "Cooldown should now be 90 days");
        
        // ===== VERIFY: User's funds are now trapped =====
        console.log("\n=== Phase 3: User attempts instant withdrawal - BLOCKED ===");
        
        // Try to redeem - should revert
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IStakediTry.OperationNotAllowed.selector));
        vault.redeem(shares, user, user);
        
        console.log("ERROR: User's redeem() call reverted with OperationNotAllowed");
        
        // Try to withdraw - should also revert
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IStakediTry.OperationNotAllowed.selector));
        vault.withdraw(DEPOSIT_AMOUNT, user, user);
        
        console.log("ERROR: User's withdraw() call reverted with OperationNotAllowed");
        
        // ===== VERIFY: User is forced into cooldown mechanism =====
        console.log("\n=== Phase 4: User forced to use cooldown mechanism ===");
        
        vm.prank(user);
        uint256 assets = vault.cooldownShares(shares);
        
        (uint104 cooldownEnd, uint152 underlyingAmount) = vault.cooldowns(user);
        console.log("User initiated cooldown");
        console.log("Cooldown end timestamp:", cooldownEnd);
        console.log("Current timestamp:", block.timestamp);
        console.log("Time until withdrawal available:", cooldownEnd - block.timestamp);
        console.log("Locked assets:", underlyingAmount);
        
        // Verify user must wait the full cooldown period
        assertEq(cooldownEnd, block.timestamp + 90 days, "User must wait 90 days");
        assertEq(underlyingAmount, DEPOSIT_AMOUNT, "All user assets are locked");
        
        // Attempt to unstake before cooldown ends - should revert
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IStakediTryCooldown.InvalidCooldown.selector));
        vault.unstake(user);
        
        console.log("ERROR: Cannot unstake until 90 days have passed");
        
        // Fast forward to after cooldown
        vm.warp(block.timestamp + 90 days);
        
        // Now unstake works
        vm.prank(user);
        vault.unstake(user);
        
        console.log("\n=== Vulnerability Confirmed ===");
        console.log("User who deposited expecting instant withdrawal");
        console.log("was forced to wait 90 days due to retroactive cooldown enforcement");
        
        assertEq(iTryToken.balanceOf(user), DEPOSIT_AMOUNT, "User finally received funds after 90 days");
    }
}
```

## Notes

This vulnerability demonstrates a significant UX and fairness issue where users who make deposits under one set of rules (instant withdrawals) can have those rules changed retroactively without their consent. While the admin role is trusted and this is not a direct theft of funds, it represents an unexpected temporary lockup that could cause significant harm to users who deposited expecting liquidity.

The issue is particularly concerning because:
1. The ERC4626 standard implies certain withdrawal guarantees that are violated when cooldown is enabled retroactively
2. Users have no warning or opportunity to withdraw before the cooldown is enabled
3. The alternative "fast redeem" option requires both cooldown to be ON and charges fees up to 20%, making it unavailable or costly for affected users [7](#0-6)

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L15-15)
```text
 * @dev If cooldown duration is set to zero, the StakediTryV2 behavior changes to follow ERC4626 standard and disables cooldownShares and cooldownAssets methods. If cooldown duration is greater than zero, the ERC4626 withdrawal and redeem functions are disabled, breaking the ERC4626 standard, and enabling the cooldownShares and the cooldownAssets functions.
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L24-24)
```text
    uint24 public constant MAX_COOLDOWN_DURATION = 90 days;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L29-32)
```text
    modifier ensureCooldownOff() {
        if (cooldownDuration != 0) revert OperationNotAllowed();
        _;
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L67-75)
```text
    function redeem(uint256 shares, address receiver, address _owner)
        public
        virtual
        override
        ensureCooldownOff
        returns (uint256)
    {
        return super.redeem(shares, receiver, _owner);
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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L57-71)
```text
    function fastRedeem(uint256 shares, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 assets)
    {
        if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();

        uint256 totalAssets = previewRedeem(shares);
        uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);

        emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);

        return totalAssets - feeAssets;
    }
```
