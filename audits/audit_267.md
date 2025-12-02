## Title
Cross-Chain Users Cannot Benefit From Cooldown Disable Mechanism

## Summary
The `unstakeThroughComposer()` function in `StakediTryCrosschain.sol` does not check if `cooldownDuration == 0` like the regular `unstake()` function does. This prevents cross-chain users from immediately claiming their assets when the admin legitimately disables the cooldown period, while regular users can unstake instantly. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` - `unstakeThroughComposer()` function (lines 77-101)

**Intended Logic:** According to the documentation, when `cooldownDuration` is set to 0, users should be able to immediately claim their assets locked in the Silo regardless of their original cooldown end timestamp. [2](#0-1) 

**Actual Logic:** The regular `unstake()` function properly implements this behavior by checking `block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0`. [3](#0-2) 

However, the `unstakeThroughComposer()` function used for cross-chain unstaking only checks `block.timestamp >= userCooldown.cooldownEnd` without the `|| cooldownDuration == 0` condition. [4](#0-3) 

**Exploitation Path:**
1. User on spoke chain initiates cross-chain unstaking via `UnstakeMessenger`, which routes through `wiTryVaultComposer` to call `cooldownSharesByComposer()` or `cooldownAssetsByComposer()` with cooldownDuration = 90 days
2. User's cooldown is set: `cooldownEnd = block.timestamp + 90 days` and assets are locked in Silo [5](#0-4) 
3. Admin legitimately sets `cooldownDuration = 0` (for emergency exit, protocol migration, or other valid operational reasons) via `setCooldownDuration()` [6](#0-5) 
4. Regular users with pending cooldowns can immediately call `unstake()` and receive their funds due to the `cooldownDuration == 0` bypass
5. Cross-chain user initiates unstake via spoke chain, message is delivered to `wiTryVaultComposer._handleUnstake()` which calls `vault.unstakeThroughComposer(user)` [7](#0-6) 
6. The `unstakeThroughComposer()` function reverts with `InvalidCooldown()` because it only checks timestamp, not `cooldownDuration == 0`
7. Cross-chain user's funds remain locked for up to 90 days while regular users were freed immediately

**Security Property Broken:** The cooldown disable mechanism is inconsistently implemented across regular and cross-chain unstaking paths, violating the documented protocol behavior that setting `cooldownDuration = 0` allows users to claim assets from Silo.

## Impact Explanation
- **Affected Assets**: iTRY tokens locked in the `iTrySilo` contract for cross-chain users who initiated cooldowns before `cooldownDuration` was set to 0
- **Damage Severity**: Cross-chain users face temporary fund lock (up to 90 days) while regular users with identical cooldown states can immediately withdraw. This creates unfair treatment and breaks the protocol's emergency exit mechanism for cross-chain participants.
- **User Impact**: All cross-chain users who have active cooldowns when admin disables the cooldown period. The impact is particularly severe if `cooldownDuration = 0` is set for emergency reasons (exploit mitigation, protocol migration, etc.) where immediate exit is the intended behavior.

## Likelihood Explanation
- **Attacker Profile**: This is not an attack by malicious users, but rather a design flaw that manifests when the admin legitimately changes `cooldownDuration` to 0
- **Preconditions**: Cross-chain users must have initiated cooldown via composer before `cooldownDuration` is set to 0
- **Execution Complexity**: The issue occurs automatically - no complex attack is needed. The admin simply sets `cooldownDuration = 0` as documented, but cross-chain users don't receive the intended benefit
- **Frequency**: This affects all cross-chain users with pending cooldowns whenever `cooldownDuration` is changed to 0, which could occur during emergency situations, protocol upgrades, or governance decisions

## Recommendation

**FIXED:**
```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function unstakeThroughComposer, line 89:

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

    // FIXED: Add cooldownDuration == 0 check to match unstake() behavior
    if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
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

This change ensures cross-chain users receive the same cooldown disable benefit as regular users, maintaining consistent protocol behavior across all unstaking paths.

## Proof of Concept

```solidity
// File: test/Exploit_CrosschainCooldownBypass.t.sol
// Run with: forge test --match-test test_CrosschainCooldownDisableNotRespected -vvv

pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {StakediTryCrosschain} from "../src/token/wiTRY/StakediTryCrosschain.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_CrosschainCooldownDisable is Test {
    iTry public itryToken;
    StakediTryCrosschain public vault;
    
    address public owner;
    address public rewarder;
    address public treasury;
    address public regularUser;
    address public crosschainUser;
    address public composer;
    
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public COMPOSER_ROLE;
    
    function setUp() public {
        // Setup accounts
        owner = makeAddr("owner");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        regularUser = makeAddr("regularUser");
        crosschainUser = makeAddr("crosschainUser");
        composer = makeAddr("composer");
        
        // Deploy iTry token
        iTry itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner,
            owner
        );
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(IERC20(address(itryToken)), rewarder, owner, treasury);
        
        COMPOSER_ROLE = vault.COMPOSER_ROLE();
        
        // Grant composer role
        vm.prank(owner);
        vault.grantRole(COMPOSER_ROLE, composer);
        
        // Mint tokens and setup initial deposits
        vm.startPrank(owner);
        itryToken.mint(regularUser, 1000 ether);
        itryToken.mint(composer, 2000 ether);
        vm.stopPrank();
        
        // Regular user deposits
        vm.startPrank(regularUser);
        itryToken.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, regularUser);
        vm.stopPrank();
        
        // Composer deposits (on behalf of crosschain user)
        vm.startPrank(composer);
        itryToken.approve(address(vault), 2000 ether);
        vault.deposit(2000 ether, composer);
        vm.stopPrank();
    }
    
    function test_CrosschainCooldownDisableNotRespected() public {
        // SETUP: Both users initiate cooldowns
        uint256 cooldownDuration = vault.cooldownDuration(); // 90 days
        
        // Regular user starts cooldown
        vm.prank(regularUser);
        uint256 regularUserAssets = vault.cooldownShares(vault.balanceOf(regularUser));
        
        // Crosschain user starts cooldown via composer
        vm.prank(composer);
        uint256 crosschainUserAssets = vault.cooldownSharesByComposer(
            vault.balanceOf(composer),
            crosschainUser
        );
        
        console.log("Initial state:");
        console.log("- Regular user cooldown assets:", regularUserAssets);
        console.log("- Crosschain user cooldown assets:", crosschainUserAssets);
        console.log("- Cooldown duration:", cooldownDuration);
        
        // Fast forward 30 days (not enough to complete cooldown)
        vm.warp(block.timestamp + 30 days);
        
        // ADMIN ACTION: Legitimate cooldown disable (emergency exit scenario)
        vm.prank(owner);
        vault.setCooldownDuration(0);
        
        console.log("\nAfter cooldown disabled:");
        console.log("- New cooldown duration:", vault.cooldownDuration());
        
        // EXPLOIT DEMONSTRATION: Regular user CAN unstake immediately
        vm.prank(regularUser);
        vault.unstake(regularUser);
        
        uint256 regularUserBalance = itryToken.balanceOf(regularUser);
        console.log("- Regular user successfully unstaked:", regularUserBalance);
        assertEq(regularUserBalance, regularUserAssets, "Regular user should receive assets");
        
        // VULNERABILITY: Crosschain user CANNOT unstake even though cooldown is disabled
        vm.prank(composer);
        vm.expectRevert(abi.encodeWithSignature("InvalidCooldown()"));
        vault.unstakeThroughComposer(crosschainUser);
        
        console.log("- Crosschain user unstake REVERTED (funds still locked)");
        
        // VERIFY: Crosschain user must wait full original cooldown period
        console.log("\nVerifying crosschain user is still locked...");
        
        // Fast forward to complete original cooldown (90 days total from start)
        vm.warp(block.timestamp + 60 days); // 30 + 60 = 90 days
        
        // Now crosschain user can finally unstake
        vm.prank(composer);
        vault.unstakeThroughComposer(crosschainUser);
        
        uint256 composerBalance = itryToken.balanceOf(composer);
        console.log("- Crosschain user finally unstaked after 90 days:", composerBalance);
        
        assertEq(
            composerBalance,
            crosschainUserAssets,
            "Crosschain user locked for full period despite cooldown being disabled"
        );
    }
}
```

## Notes

This vulnerability demonstrates an **inconsistency in the cooldown disable mechanism** rather than a malicious admin attack. The issue violates the documented behavior that "unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo" [2](#0-1) .

The impact is particularly concerning because:
1. The protocol documents `cooldownDuration = 0` as a mechanism to allow immediate asset claims from Silo
2. This could be used for legitimate emergency scenarios (exploit mitigation, protocol migration, etc.)
3. Regular users receive the benefit while cross-chain users remain locked, creating unfair treatment
4. The cross-chain flow is explicitly designed to be feature-equivalent to regular unstaking [8](#0-7) 

This is not a centralization risk (admin acting maliciously) but rather a **logic bug** where a legitimate admin action doesn't work as documented for a subset of users.

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L9-16)
```text
/**
 * @title StakediTryCrosschain
 * @notice Extends StakediTryFastRedeem with role-gated helpers for trusted composers
 * @dev A composer (e.g. wiTryVaultComposer) can burn its own shares after bridging them in and
 *      assign the resulting cooldown entitlement to an end-user redeemer. This contract
 *      keeps the cooldown accounting in the redeemer slot while still relying on the base
 *      `_withdraw` routine to maintain iTRY system integrity.
 */
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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L170-180)
```text
    function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

        // Interaction: External call to base contract (protected by nonReentrant modifier)
        _withdraw(composer, address(silo), composer, assets, shares);

        // Effects: State changes after external call (following CEI pattern)
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);

        emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L78-78)
```text
    /// @dev unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L84-84)
```text
        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L254-255)
```text
        // Call vault to unstake
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
```
