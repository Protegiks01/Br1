## Title
No Escape Hatch for Users When Cooldown Terms Change Retroactively

## Summary
The `withdraw()` and `redeem()` functions in StakediTryCooldown.sol are blocked by the `ensureCooldownOff` modifier when cooldown is enabled. [1](#0-0)  Users who deposited when cooldown was disabled have no escape hatch to withdraw under original terms if cooldown is later enabled - they must either wait through a new cooldown period or pay fast redemption fees.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (withdraw and redeem functions, lines 54-75; setCooldownDuration, lines 122-130)

**Intended Logic:** 
The protocol intends to allow admin to switch between two modes: [2](#0-1) 
- When cooldownDuration = 0: Standard ERC4626 behavior with immediate withdrawals
- When cooldownDuration > 0: Cooldown-based withdrawals with 90-day waiting period

**Actual Logic:**
When cooldown changes from disabled (0) to enabled (>0), ALL users - including those who deposited expecting immediate withdrawals - are retroactively forced to use the cooldown mechanism. The `ensureCooldownOff` modifier blocks `withdraw()` and `redeem()` functions: [3](#0-2) 

**Exploitation Path:**
1. Admin calls `setCooldownDuration(0)` to disable cooldown (e.g., for emergency liquidity or testing)
2. User deposits 1000 iTRY via `deposit()`, receiving wiTRY shares, expecting ERC4626 standard with immediate withdrawal capability
3. Admin calls `setCooldownDuration(90 days)` to re-enable cooldown for risk management
4. User attempts `withdraw()` or `redeem()` → reverts due to `ensureCooldownOff` modifier [1](#0-0) 
5. User's only options:
   - Call `cooldownAssets()` and wait 90 days [4](#0-3) 
   - Call `fastRedeem()` if enabled and pay up to 20% fee [5](#0-4) 
   - Wait for admin to disable cooldown again

The `unstake()` function doesn't help because it requires an existing cooldown entry: [6](#0-5)  Users who deposited before cooldown was enabled have no cooldown entry (cooldownEnd = 0, underlyingAmount = 0).

**Security Property Broken:** 
Users suffer unexpected financial harm (90-day time lock or 20% fees) due to retroactive term changes without protection mechanisms. This violates reasonable expectations of withdrawal terms at deposit time.

## Impact Explanation
- **Affected Assets**: wiTRY shares and underlying iTRY tokens of users who deposited during cooldown-disabled periods
- **Damage Severity**: Users face either:
  - 90-day liquidity lock (time value of money loss, opportunity cost)
  - Up to 20% fee payment for immediate access via `fastRedeem()` [7](#0-6) 
  - Dependence on admin goodwill to disable cooldown
- **User Impact**: All users who deposit when cooldown is disabled are affected if cooldown is later enabled. Given the protocol starts with cooldown enabled by default [8](#0-7) , this primarily affects users during temporary cooldown-disabled periods.

## Likelihood Explanation
- **Attacker Profile**: Not an attacker scenario - this is a user protection gap affecting legitimate users
- **Preconditions**: 
  - Admin temporarily disables cooldown (cooldownDuration = 0)
  - Users deposit during this window
  - Admin re-enables cooldown
- **Execution Complexity**: The issue manifests through normal protocol operations, not exploitation
- **Frequency**: Occurs whenever admin changes cooldown settings, affecting all users who deposited under different terms

## Recommendation

**Option 1: Grandfather Mechanism**
```solidity
// Add to StakediTryV2 contract:
mapping(address => uint24) public userCooldownAtDeposit;

// Modify _deposit to record cooldown setting:
function _deposit(address caller, address receiver, uint256 assets, uint256 shares) internal override {
    // Record the cooldown duration at time of deposit
    if (userCooldownAtDeposit[receiver] == 0) {
        userCooldownAtDeposit[receiver] = cooldownDuration;
    }
    super._deposit(caller, receiver, assets, shares);
}

// Add new function allowing withdrawal under original terms:
function withdrawWithOriginalTerms(uint256 assets, address receiver, address _owner) external returns (uint256) {
    require(userCooldownAtDeposit[_owner] == 0, "Must use current cooldown");
    require(cooldownDuration > 0, "Use regular withdraw");
    return super.withdraw(assets, receiver, _owner);
}
```

**Option 2: Grace Period**
```solidity
// Modify setCooldownDuration:
uint256 public cooldownChangeTimestamp;
uint256 public constant GRACE_PERIOD = 7 days;

function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (duration > MAX_COOLDOWN_DURATION) revert InvalidCooldown();
    cooldownChangeTimestamp = block.timestamp;
    // ... rest of function
}

// Modify withdraw to allow grace period:
function withdraw(uint256 assets, address receiver, address _owner) public virtual override returns (uint256) {
    if (cooldownDuration != 0 && block.timestamp > cooldownChangeTimestamp + GRACE_PERIOD) {
        revert OperationNotAllowed();
    }
    return super.withdraw(assets, receiver, _owner);
}
```

**Option 3: Clear Documentation**
At minimum, add clear warnings in NatSpec comments and documentation that cooldown terms can change and affect existing depositors.

## Proof of Concept

```solidity
// File: test/Exploit_CooldownRetroactive.t.sol
// Run with: forge test --match-test test_RetroactiveCooldownTrapsUsers -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../test/mocks/MockERC20.sol";

contract Exploit_CooldownRetroactive is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public user;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        rewarder = makeAddr("rewarder");
        user = makeAddr("user");
        
        // Deploy contracts
        iTryToken = new MockERC20("iTRY", "iTRY");
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)),
            rewarder,
            admin,
            treasury
        );
        
        // Mint tokens to user
        iTryToken.mint(user, 1000e18);
        vm.prank(user);
        iTryToken.approve(address(stakediTry), type(uint256).max);
    }
    
    function test_RetroactiveCooldownTrapsUsers() public {
        // STEP 1: Admin disables cooldown (e.g., for emergency liquidity)
        vm.prank(admin);
        stakediTry.setCooldownDuration(0);
        assertEq(stakediTry.cooldownDuration(), 0, "Cooldown should be disabled");
        
        // STEP 2: User deposits expecting immediate withdrawal capability
        vm.prank(user);
        stakediTry.deposit(1000e18, user);
        
        uint256 userShares = stakediTry.balanceOf(user);
        assertGt(userShares, 0, "User should have shares");
        
        // STEP 3: User verifies they can withdraw immediately (before cooldown re-enabled)
        // This works as expected
        vm.prank(user);
        uint256 maxWithdrawable = stakediTry.maxWithdraw(user);
        assertEq(maxWithdrawable, 1000e18, "User should be able to withdraw all");
        
        // STEP 4: Admin re-enables cooldown (for risk management)
        vm.prank(admin);
        stakediTry.setCooldownDuration(90 days);
        assertEq(stakediTry.cooldownDuration(), 90 days, "Cooldown should be enabled");
        
        // STEP 5: User tries to withdraw - BLOCKED!
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IStakediTry.OperationNotAllowed.selector)
        );
        stakediTry.withdraw(1000e18, user, user);
        
        // STEP 6: User tries redeem - ALSO BLOCKED!
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IStakediTry.OperationNotAllowed.selector)
        );
        stakediTry.redeem(userShares, user, user);
        
        // STEP 7: Verify user has NO escape hatch
        // Option A: Must initiate cooldown and wait 90 days
        vm.prank(user);
        stakediTry.cooldownAssets(1000e18);
        
        // User still can't get funds immediately
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(IStakediTryCooldown.InvalidCooldown.selector)
        );
        stakediTry.unstake(user);
        
        // Option B: Fast redeem is disabled by default
        assertFalse(stakediTry.fastRedeemEnabled(), "Fast redeem disabled by default");
        
        // Option C: Even if admin enables fast redeem, user must pay 20% fee
        vm.prank(admin);
        stakediTry.setFastRedeemEnabled(true);
        vm.prank(admin);
        stakediTry.setFastRedeemFee(2000); // 20% fee
        
        uint256 balanceBefore = iTryToken.balanceOf(user);
        vm.prank(user);
        stakediTry.fastRedeem(userShares, user, user);
        uint256 balanceAfter = iTryToken.balanceOf(user);
        
        // User receives only 80% of their deposit
        assertEq(balanceAfter - balanceBefore, 800e18, "User loses 20% to fees");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("User deposited when cooldown was 0 (immediate withdrawal)");
        console.log("Admin enabled cooldown to 90 days");
        console.log("User lost 200 iTRY (20%%) to fees for immediate access");
        console.log("OR would have to wait 90 days - NO ESCAPE HATCH");
    }
}
```

## Notes

The core issue is that `setCooldownDuration()` [9](#0-8)  has no protection mechanism for existing users. The protocol defaults to cooldown enabled (90 days), but if admin ever disables it temporarily, users who deposit during that window get trapped when it's re-enabled.

Fast redemption provides partial mitigation but has its own limitations:
- Disabled by default [10](#0-9) 
- Requires admin to enable it
- Charges up to 20% fees [11](#0-10) 
- Only works when cooldown is enabled [12](#0-11) 

The `unstake()` function's check `cooldownDuration == 0` [13](#0-12)  allows emergency exits if cooldown is disabled again, but this depends on admin action and doesn't help users who deposited when cooldown was disabled unless they've already initiated a cooldown.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L15-16)
```text
 * @dev If cooldown duration is set to zero, the StakediTryV2 behavior changes to follow ERC4626 standard and disables cooldownShares and cooldownAssets methods. If cooldown duration is greater than zero, the ERC4626 withdrawal and redeem functions are disabled, breaking the ERC4626 standard, and enabling the cooldownShares and the cooldownAssets functions.
 */
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L29-32)
```text
    modifier ensureCooldownOff() {
        if (cooldownDuration != 0) revert OperationNotAllowed();
        _;
    }
```

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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L27-27)
```text
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L48-49)
```text
        fastRedeemEnabled = false;
        fastRedeemFeeInBPS = MAX_FAST_REDEEM_FEE; // Start at maximum fee (20%)
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
