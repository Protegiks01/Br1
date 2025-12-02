## Title
Blacklisted Users Can Bypass Fund Freeze by Initiating Cooldown Before Restriction

## Summary
The `unstake()` function in `StakediTryCooldown.sol` fails to enforce `FULL_RESTRICTED_STAKER_ROLE` checks, allowing users who initiated cooldown before being blacklisted to successfully extract their iTRY tokens after receiving the restriction role. This bypasses the intended security mechanism where blacklisted users' funds should be frozen and only redistributable by admin.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (StakediTryV2 contract, `unstake` function, lines 80-92)

**Intended Logic:** Users with `FULL_RESTRICTED_STAKER_ROLE` (blacklisted in the vault) should have their funds frozen and only accessible through admin-controlled `redistributeLockedAmount()`. The base contract's `_withdraw()` function enforces this by checking if caller, receiver, or owner has the restricted role. [1](#0-0) 

**Actual Logic:** The `cooldownShares()` function properly calls `_withdraw()` which includes role checks [2](#0-1) , but the `unstake()` function completely bypasses these checks by directly calling `silo.withdraw()` without any role validation [3](#0-2) 

**Exploitation Path:**
1. User stakes iTRY tokens to receive wiTRY shares (user has no restrictions)
2. User calls `cooldownShares(shares)` - the `_withdraw()` check passes since user is not blacklisted, shares are burned, iTRY is sent to silo, cooldown period begins
3. During cooldown period: Admin blacklists user by calling `addToBlacklist(user, true)` which grants `FULL_RESTRICTED_STAKER_ROLE` [4](#0-3) 
4. After cooldown completes: User calls `unstake(receiver)` - function only checks cooldown completion, not role restrictions, and successfully transfers iTRY from silo to receiver

**Security Property Broken:** The protocol's blacklist enforcement mechanism for wiTRY vault is completely bypassed. The intended behavior is that users with `FULL_RESTRICTED_STAKER_ROLE` cannot transfer, stake, or unstake, and their balance can only be redistributed by owner. [5](#0-4) 

## Impact Explanation
- **Affected Assets**: wiTRY shares and underlying iTRY tokens held in the vault system
- **Damage Severity**: Complete bypass of vault-level blacklist enforcement. Users who should have funds frozen can extract 100% of their cooled-down assets. Admin loses ability to prevent fund extraction from blacklisted users who initiated cooldown before restriction.
- **User Impact**: Any user who suspects they may be blacklisted can front-run the blacklist by initiating cooldown. Even sophisticated exploiters who committed fraud can secure their funds by timing cooldown initiation before detection.

## Likelihood Explanation
- **Attacker Profile**: Any vault staker who anticipates being blacklisted (regulatory action, fraud detection, sanctions list addition)
- **Preconditions**: User must have staked wiTRY and initiated cooldown before receiving `FULL_RESTRICTED_STAKER_ROLE`. Cooldown must complete (up to 90 days but typically configured to shorter periods).
- **Execution Complexity**: Two simple transactions separated by cooldown period - `cooldownShares()` followed by `unstake()` after time passes. No special timing or front-running required beyond initiating cooldown before blacklist.
- **Frequency**: Each user can execute once per cooldown cycle. Attack can be repeated by initiating new cooldowns.

## Recommendation

Add `FULL_RESTRICTED_STAKER_ROLE` check to the `unstake()` function:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function unstake, lines 80-92:

// CURRENT (vulnerable):
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

// FIXED:
function unstake(address receiver) external {
    // Check if caller or receiver has restricted role
    if (
        hasRole(FULL_RESTRICTED_STAKER_ROLE, msg.sender) 
        || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
    ) {
        revert OperationNotAllowed();
    }
    
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

**Alternative mitigation:** Implement a check in `silo.withdraw()` that validates the caller's cooldown originator doesn't have restricted roles, though the above fix is cleaner and more aligned with existing patterns.

**Additional fix needed:** The same vulnerability exists in `unstakeThroughComposer()` in StakediTryCrosschain.sol [6](#0-5)  - this function should also check if the `receiver` has `FULL_RESTRICTED_STAKER_ROLE` before allowing unstake.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypassViaCooldown.t.sol
// Run with: forge test --match-test test_BlacklistBypassViaCooldown -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_BlacklistBypass is Test {
    StakediTryV2 public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public rewarder;
    address public attacker;
    
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    bytes32 public constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        attacker = makeAddr("attacker");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTryV2 with cooldown
        vm.prank(admin);
        stakediTry = new StakediTryV2(IERC20(address(iTryToken)), rewarder, admin);
        
        // Grant blacklist manager role to admin
        vm.prank(admin);
        stakediTry.grantRole(BLACKLIST_MANAGER_ROLE, admin);
        
        // Mint iTRY to attacker and approve
        iTryToken.mint(attacker, 1000e18);
        vm.prank(attacker);
        iTryToken.approve(address(stakediTry), type(uint256).max);
    }
    
    function test_BlacklistBypassViaCooldown() public {
        // SETUP: Attacker stakes iTRY
        vm.prank(attacker);
        uint256 shares = stakediTry.deposit(100e18, attacker);
        
        assertEq(stakediTry.balanceOf(attacker), shares, "Attacker should have shares");
        assertFalse(stakediTry.hasRole(FULL_RESTRICTED_STAKER_ROLE, attacker), "Attacker not blacklisted yet");
        
        // EXPLOIT STEP 1: Attacker initiates cooldown (while not blacklisted)
        vm.prank(attacker);
        stakediTry.cooldownShares(shares);
        
        assertEq(stakediTry.balanceOf(attacker), 0, "Shares burned during cooldown");
        (uint256 cooldownEnd, uint256 underlyingAmount) = stakediTry.cooldowns(attacker);
        assertGt(cooldownEnd, block.timestamp, "Cooldown should be active");
        assertEq(underlyingAmount, 100e18, "Underlying amount should be recorded");
        
        // EXPLOIT STEP 2: During cooldown, admin blacklists attacker
        vm.prank(admin);
        stakediTry.addToBlacklist(attacker, true);
        
        assertTrue(stakediTry.hasRole(FULL_RESTRICTED_STAKER_ROLE, attacker), "Attacker now blacklisted");
        
        // EXPLOIT STEP 3: Time passes, cooldown completes
        vm.warp(cooldownEnd + 1);
        
        // EXPLOIT STEP 4: Blacklisted attacker successfully unstakes!
        uint256 attackerBalanceBefore = iTryToken.balanceOf(attacker);
        
        vm.prank(attacker);
        stakediTry.unstake(attacker); // THIS SHOULD REVERT BUT DOESN'T!
        
        // VERIFY: Blacklisted user successfully extracted funds
        uint256 attackerBalanceAfter = iTryToken.balanceOf(attacker);
        assertEq(attackerBalanceAfter, attackerBalanceBefore + 100e18, 
            "Vulnerability confirmed: Blacklisted user extracted iTRY by bypassing role check in unstake()");
        
        // Verify cooldown was cleared
        (uint256 cooldownEndAfter, uint256 underlyingAmountAfter) = stakediTry.cooldowns(attacker);
        assertEq(cooldownEndAfter, 0, "Cooldown cleared");
        assertEq(underlyingAmountAfter, 0, "Underlying amount cleared");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- Attacker staked 100 iTRY");
        console.log("- Attacker initiated cooldown while not blacklisted");
        console.log("- Admin blacklisted attacker during cooldown");
        console.log("- Attacker successfully unstaked 100 iTRY despite being blacklisted");
        console.log("- Protocol's blacklist enforcement was completely bypassed");
    }
}
```

## Notes

This vulnerability represents a complete bypass of the vault's blacklist enforcement mechanism. While the base contract correctly implements role checks in `_withdraw()`, the `unstake()` function creates an alternative withdrawal path that lacks these critical security checks.

The vulnerability is particularly severe because:
1. It allows sophisticated actors to front-run blacklisting actions by initiating cooldowns
2. The cooldown period (up to 90 days) provides a long window where users remain vulnerable to blacklisting but can still extract funds
3. It undermines the entire purpose of the `FULL_RESTRICTED_STAKER_ROLE` and `redistributeLockedAmount()` mechanism

The same pattern appears in `unstakeThroughComposer()` for cross-chain unstaking, creating multiple attack vectors for the same underlying issue.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L29-30)
```text
    /// @notice The role which prevents an address to transfer, stake, or unstake. The owner of the contract can redirect address staking balance if an address is in full restricting mode.
    bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
```

**File:** src/token/wiTRY/StakediTry.sol (L126-133)
```text
    function addToBlacklist(address target, bool isFullBlacklisting)
        external
        onlyRole(BLACKLIST_MANAGER_ROLE)
        notOwner(target)
    {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _grantRole(role, target);
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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L77-101)
```text
    function unstakeThroughComposer(address receiver)
        external
        onlyRole(COMPOSER_ROLE)
        nonReentrant
        returns (uint256 assets)
    {
        // Validate valid receiver
        if (receiver == address(0)) revert InvalidZeroAddress();

        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
        } else {
            revert InvalidCooldown();
        }

        emit UnstakeThroughComposer(msg.sender, receiver, assets);

        return assets;
    }
```
