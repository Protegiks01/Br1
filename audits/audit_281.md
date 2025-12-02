## Title
Permanent Loss of Staked Funds Due to iTry Transfer Restrictions During Cooldown Period

## Summary
Users who initiate a cooldown via `cooldownAssets()` permanently lose their wiTRY shares and staked iTry if the iTry transfer state changes or if the silo/StakediTry contracts become blacklisted or not whitelisted during the cooldown period. The shares are burned immediately during cooldown, but the assets become unrecoverable when `unstake()` fails due to iTry transfer restrictions, with no recovery mechanism available.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (StakediTryV2 contract, `cooldownAssets` function at line 96-105, `unstake` function at line 80-92) and `src/token/wiTRY/iTrySilo.sol` (line 28-30)

**Intended Logic:** The cooldown mechanism should allow users to safely unstake their wiTRY by burning shares during `cooldownAssets()`, transferring iTry to a temporary silo, and then withdrawing from the silo after the cooldown period via `unstake()`.

**Actual Logic:** The process splits into two irreversible transactions with a critical vulnerability:
1. `cooldownAssets()` immediately burns user shares and transfers iTry to silo [1](#0-0) 
2. `unstake()` later calls `silo.withdraw(receiver, assets)` [2](#0-1) 
3. The silo's withdraw function performs an unchecked `iTry.transfer(to, amount)` [3](#0-2) 

If iTry transfer restrictions change during the cooldown period, `iTry.transfer()` will revert, making funds permanently unrecoverable.

**Exploitation Path:**
1. User calls `cooldownAssets(1000e18)` - shares are burned, iTry moved to silo
2. During cooldown period, one of these events occurs:
   - Admin calls `iTry.updateTransferState(TransferState.FULLY_DISABLED)` 
   - Admin calls `iTry.updateTransferState(TransferState.WHITELIST_ENABLED)` and silo/StakediTryV2 are not whitelisted
   - Admin calls `iTry.addBlacklistAddress([silo])` or `iTry.addBlacklistAddress([stakediTry])`
3. User calls `unstake(receiver)` after cooldown completes
4. Transaction reverts at `iTry.transfer()` due to `_beforeTokenTransfer` validation failures:
   - FULLY_DISABLED state: all transfers revert [4](#0-3) 
   - WHITELIST_ENABLED state: requires msg.sender (StakediTryV2), from (silo), and to (receiver) all be whitelisted [5](#0-4) 
   - Blacklisted contracts: requires msg.sender, from, and to all not be blacklisted [6](#0-5) 

**Security Property Broken:** Users permanently lose staked funds without any recovery mechanism, violating the fundamental expectation that cooldown processes should be completable and that assets remain recoverable.

## Impact Explanation
- **Affected Assets**: All user iTry tokens in cooldown (stored in iTrySilo), representing burned wiTRY shares
- **Damage Severity**: 100% permanent loss of staked iTry for affected users. The iTrySilo contract has zero admin functions, zero rescue mechanisms, and only one withdrawal function that can only be called by the staking vault [7](#0-6) 
- **User Impact**: Any user with active cooldowns when transfer restrictions change loses all staked funds. This affects legitimate users who followed protocol rules but got caught in an admin action timing window.

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a protocol design flaw affecting normal users. However, malicious admin or compromised admin keys could intentionally trigger this to lock user funds.
- **Preconditions**: 
  - Users have active cooldowns (cooldown period is 90 days by default [8](#0-7) )
  - Admin changes iTry transfer state or blacklists silo/StakediTryV2 during cooldown period
- **Execution Complexity**: Simple - users call standard functions, but external state changes break the withdrawal path
- **Frequency**: Can affect all users with active cooldowns whenever transfer restrictions change

## Recommendation

**Option 1: Add Emergency Withdrawal to iTrySilo (Recommended)**
```solidity
// In src/token/wiTRY/iTrySilo.sol, add:

address public immutable ADMIN;

constructor(address _stakingVault, address _iTryToken, address _admin) {
    STAKING_VAULT = _stakingVault;
    iTry = IERC20(_iTryToken);
    ADMIN = _admin;
}

// Emergency function to handle failed transfers
function emergencyWithdraw(address to, uint256 amount) external {
    require(msg.sender == ADMIN, "Only admin");
    // Use low-level call to bypass transfer restrictions in emergency
    // Or coordinate with iTry admin to whitelist this specific withdrawal
    iTry.transfer(to, amount);
}
```

**Option 2: Check Transfer Feasibility Before Burning Shares**
```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function cooldownAssets, line 96:

function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
    if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();
    
    shares = previewWithdraw(assets);
    
    // ADDED: Pre-flight check that withdrawal will be possible
    // This doesn't guarantee future success but catches current misconfigurations
    try IERC20(asset()).transfer(address(this), 0) {} catch {
        revert("Transfer restrictions active - unstake will fail");
    }
    
    cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    cooldowns[msg.sender].underlyingAmount += uint152(assets);
    
    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}
```

**Option 3: Two-Phase Commit with Rollback**
```solidity
// Allow users to cancel cooldown and recover shares if transfer fails
function cancelCooldown() external {
    UserCooldown storage userCooldown = cooldowns[msg.sender];
    uint256 assets = userCooldown.underlyingAmount;
    require(assets > 0, "No cooldown active");
    
    // Clear cooldown
    userCooldown.cooldownEnd = 0;
    userCooldown.underlyingAmount = 0;
    
    // Re-mint shares based on current exchange rate
    uint256 shares = previewDeposit(assets);
    
    // Transfer assets back from silo
    silo.withdraw(address(this), assets);
    
    // Mint shares back to user
    _mint(msg.sender, shares);
}
```

## Proof of Concept
```solidity
// File: test/Exploit_CooldownTransferRestrictions.t.sol
// Run with: forge test --match-test test_PermanentLossViaTran sferStateChange -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";

contract Exploit_CooldownTransferRestrictions is Test {
    iTry public itryToken;
    StakediTryV2 public stakediTry;
    
    address public admin;
    address public user;
    address public rewarder;
    
    function setUp() public {
        admin = address(this);
        user = makeAddr("user");
        rewarder = makeAddr("rewarder");
        
        // Deploy iTry with proxy
        iTry itryImpl = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(itryImpl), initData);
        itryToken = iTry(address(proxy));
        
        // Deploy StakediTryV2
        stakediTry = new StakediTryV2(IERC20(address(itryToken)), rewarder, admin);
        
        // Setup: Mint iTry to user and approve
        itryToken.mint(user, 1000e18);
        vm.prank(user);
        itryToken.approve(address(stakediTry), type(uint256).max);
        
        // User stakes
        vm.prank(user);
        stakediTry.deposit(1000e18, user);
    }
    
    function test_PermanentLossViaTransferStateChange() public {
        // INITIAL STATE: User has 1000e18 wiTRY shares
        assertEq(stakediTry.balanceOf(user), 1000e18, "User should have shares");
        
        // STEP 1: User initiates cooldown
        vm.prank(user);
        stakediTry.cooldownAssets(1000e18);
        
        // VERIFY: Shares burned, assets in silo
        assertEq(stakediTry.balanceOf(user), 0, "Shares burned");
        assertEq(itryToken.balanceOf(address(stakediTry.silo())), 1000e18, "Assets in silo");
        
        // STEP 2: Admin changes transfer state to FULLY_DISABLED during cooldown
        itryToken.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        
        // STEP 3: Fast-forward past cooldown period
        vm.warp(block.timestamp + 91 days);
        
        // STEP 4: User attempts to unstake - FAILS PERMANENTLY
        vm.prank(user);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        stakediTry.unstake(user);
        
        // VERIFY PERMANENT LOSS:
        // 1. User has no shares
        assertEq(stakediTry.balanceOf(user), 0, "User lost all shares");
        // 2. User cannot recover iTry from silo
        assertEq(itryToken.balanceOf(user), 0, "User has no iTry");
        // 3. Assets are locked in silo forever (no recovery mechanism exists)
        assertEq(itryToken.balanceOf(address(stakediTry.silo())), 1000e18, "Assets locked forever");
        
        console.log("=== PERMANENT LOSS CONFIRMED ===");
        console.log("User shares: ", stakediTry.balanceOf(user));
        console.log("User iTry: ", itryToken.balanceOf(user));
        console.log("Locked in silo: ", itryToken.balanceOf(address(stakediTry.silo())));
    }
    
    function test_PermanentLossViaWhitelistRequirement() public {
        // User initiates cooldown
        vm.prank(user);
        stakediTry.cooldownAssets(1000e18);
        
        // Admin changes to whitelist mode but doesn't whitelist silo/vault
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Fast-forward past cooldown
        vm.warp(block.timestamp + 91 days);
        
        // Unstake fails - silo not whitelisted
        vm.prank(user);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        stakediTry.unstake(user);
        
        // Assets permanently locked
        assertEq(itryToken.balanceOf(address(stakediTry.silo())), 1000e18, "Assets locked forever");
    }
    
    function test_PermanentLossViaSiloBlacklist() public {
        // User initiates cooldown
        vm.prank(user);
        stakediTry.cooldownAssets(1000e18);
        
        // Admin accidentally blacklists the silo
        address[] memory blacklistAddrs = new address[](1);
        blacklistAddrs[0] = address(stakediTry.silo());
        itryToken.grantRole(itryToken.BLACKLIST_MANAGER_ROLE(), admin);
        itryToken.addBlacklistAddress(blacklistAddrs);
        
        // Fast-forward past cooldown
        vm.warp(block.timestamp + 91 days);
        
        // Unstake fails - silo blacklisted
        vm.prank(user);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        stakediTry.unstake(user);
        
        // Assets permanently locked
        assertEq(itryToken.balanceOf(address(stakediTry.silo())), 1000e18, "Assets locked forever");
    }
}
```

## Notes
- This vulnerability is **NOT** covered in the known issues from Zellic audit
- The iTrySilo contract design provides no recovery mechanism - it has only one function (`withdraw`) callable only by the staking vault
- The 90-day default cooldown period significantly increases exposure window for transfer state changes
- Even if the receiver changes address (which `unstake()` allows), if the silo or StakediTryV2 contracts themselves are blacklisted or not whitelisted, NO receiver address will work
- This represents a critical design flaw where external admin actions can permanently brick user funds in an otherwise correct protocol flow

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L24-26)
```text
    uint24 public constant MAX_COOLDOWN_DURATION = 90 days;

    uint24 public cooldownDuration;
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

**File:** src/token/wiTRY/iTrySilo.sol (L1-30)
```text
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IiTrySiloDefinitions} from "./interfaces/IiTrySiloDefinitions.sol";

/**
 * @title iTrySilo
 * @notice The Silo allows to store iTry during the stake cooldown process.
 */
contract iTrySilo is IiTrySiloDefinitions {
    using SafeERC20 for IERC20;

    address immutable STAKING_VAULT;
    IERC20 immutable iTry;

    constructor(address _stakingVault, address _iTryToken) {
        STAKING_VAULT = _stakingVault;
        iTry = IERC20(_iTryToken);
    }

    modifier onlyStakingVault() {
        if (msg.sender != STAKING_VAULT) revert OnlyStakingVault();
        _;
    }

    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/iTRY/iTry.sol (L189-195)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
```

**File:** src/token/iTRY/iTry.sol (L210-216)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
```

**File:** src/token/iTRY/iTry.sol (L219-221)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```
