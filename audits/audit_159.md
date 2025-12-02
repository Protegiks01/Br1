## Title
Cross-Chain Users Cannot Unstake When Cooldown is Disabled Due to Missing Validation Check

## Summary
The `unstakeThroughComposer` function in `StakediTryCrosschain.sol` lacks the `cooldownDuration == 0` check that exists in the regular `unstake` function, causing cross-chain users' funds to remain locked for up to 90 days even after the admin disables the cooldown mechanism globally.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` (function `unstakeThroughComposer`, lines 77-101)

**Intended Logic:** When the admin sets `cooldownDuration = 0` to disable the cooldown mechanism, ALL users (both local and cross-chain) should be able to immediately claim their cooled-down assets, regardless of their `cooldownEnd` timestamp. This is the documented behavior per the protocol specification. [1](#0-0) 

**Actual Logic:** The `unstakeThroughComposer` function only validates `block.timestamp >= userCooldown.cooldownEnd` without checking if `cooldownDuration == 0`. This creates a discriminatory validation logic:

- Regular `unstake()` (local users): [2](#0-1) 

- `unstakeThroughComposer()` (cross-chain users): [3](#0-2) 

**Exploitation Path:**
1. User on spoke chain bridges wiTRY and initiates cooldown via `wiTryVaultComposer._initiateCooldown` (sets `cooldownEnd = block.timestamp + 90 days, underlyingAmount = X iTRY`)
2. Before cooldown expires, protocol admin calls `setCooldownDuration(0)` to disable the cooldown mechanism globally
3. Local users on hub can immediately call `unstake(receiver)` to claim their cooled-down assets due to the `|| cooldownDuration == 0` bypass
4. Cross-chain user sends unstake message via `UnstakeMessenger.unstake(returnTripAllocation)` on spoke chain
5. LayerZero message arrives at hub, triggering `wiTryVaultComposer._handleUnstake` → `unstakeThroughComposer(user)`
6. Validation fails: `block.timestamp >= userCooldown.cooldownEnd` evaluates to FALSE (cooldown timestamp is still 90 days in future)
7. Transaction reverts with `InvalidCooldown()`, user's iTRY remains locked in silo
8. User must wait up to 90 days for original `cooldownEnd` to expire, despite cooldown being disabled for all other users

**Security Property Broken:** Violates **Cooldown Integrity** invariant - the protocol must handle cooldown state transitions consistently across all user paths (local vs cross-chain). When cooldown is disabled (`cooldownDuration == 0`), the protocol explicitly allows immediate unstaking, but this is not enforced for cross-chain users.

## Impact Explanation
- **Affected Assets**: iTRY tokens held in cooldown state within `iTrySilo` for cross-chain users
- **Damage Severity**: Temporary fund lock for up to MAX_COOLDOWN_DURATION (90 days). While funds are eventually recoverable, users are denied access to their assets for an extended period despite the protocol disabling the cooldown mechanism
- **User Impact**: All cross-chain users with pending cooldowns at the time `cooldownDuration` is set to 0. This affects any user who initiated cross-chain cooldown before the admin change, which could be hundreds of users depending on protocol adoption

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a discriminatory bug affecting legitimate cross-chain users
- **Preconditions**: 
  - User has initiated cooldown via cross-chain flow (cooldownEnd > block.timestamp)
  - Admin sets `cooldownDuration = 0` to disable cooldown
  - User attempts to unstake via cross-chain message before original cooldownEnd expires
- **Execution Complexity**: Simple - user calls `UnstakeMessenger.unstake()` on spoke chain, which is the standard cross-chain unstake flow
- **Frequency**: Occurs every time admin toggles cooldown mechanism while cross-chain users have pending cooldowns. Given that `setCooldownDuration` is an admin function that may be called to change protocol economics, this is a realistic scenario

## Recommendation

In `src/token/wiTRY/StakediTryCrosschain.sol`, modify the `unstakeThroughComposer` function to include the same cooldown bypass logic as the regular `unstake` function: [3](#0-2) 

**FIXED:**
```solidity
// Add the same bypass condition as regular unstake() function
if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
    userCooldown.cooldownEnd = 0;
    userCooldown.underlyingAmount = 0;
    
    silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
} else {
    revert InvalidCooldown();
}
```

**Alternative mitigation:** Add documentation warning that `setCooldownDuration(0)` will not immediately enable cross-chain users to unstake, and recommend that admins avoid toggling cooldown while users have pending cooldowns. However, code-level fix is strongly preferred over documentation-only mitigation.

## Proof of Concept

```solidity
// File: test/Exploit_CrosschainUnstakeWithDisabledCooldown.t.sol
// Run with: forge test --match-test test_CrosschainUserLockedWhenCooldownDisabled -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_CrosschainUnstakeLock is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    iTry itry;
    address user = address(0x123);
    address admin = address(0xABCD);
    
    function setUp() public {
        // Deploy iTRY token
        vm.startPrank(admin);
        itry = new iTry(admin, admin, admin);
        
        // Deploy StakediTryCrosschain vault with 90-day cooldown
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            admin, // rewarder
            admin, // owner
            admin  // fastRedeemTreasury
        );
        
        // Deploy wiTryVaultComposer
        composer = new wiTryVaultComposer(
            address(vault),
            address(itry), // assetOFT
            address(vault), // shareOFT (simplified)
            address(0x1234) // endpoint
        );
        
        // Grant composer role to wiTryVaultComposer
        vault.grantRole(vault.COMPOSER_ROLE(), address(composer));
        
        // Mint iTRY to user and approve vault
        itry.mint(user, 1000 ether);
        vm.stopPrank();
    }
    
    function test_CrosschainUserLockedWhenCooldownDisabled() public {
        // SETUP: User stakes iTRY via cross-chain flow
        vm.startPrank(user);
        itry.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, user);
        vm.stopPrank();
        
        // User initiates cooldown via composer (simulating cross-chain)
        vm.startPrank(address(composer));
        uint256 shares = vault.balanceOf(address(composer));
        vault.cooldownSharesByComposer(shares, user);
        vm.stopPrank();
        
        // Verify user has pending cooldown
        (uint104 cooldownEnd, uint152 underlyingAmount) = vault.cooldowns(user);
        assertGt(cooldownEnd, block.timestamp, "Cooldown should be active");
        assertGt(underlyingAmount, 0, "Should have underlying amount");
        
        // EXPLOIT: Admin disables cooldown mechanism
        vm.prank(admin);
        vault.setCooldownDuration(0);
        
        // Local user can now unstake immediately (not shown in PoC, but would succeed)
        
        // Cross-chain user attempts to unstake via composer
        vm.startPrank(address(composer));
        vm.expectRevert(abi.encodeWithSignature("InvalidCooldown()"));
        vault.unstakeThroughComposer(user);
        vm.stopPrank();
        
        // VERIFY: Cross-chain user is locked despite cooldown being disabled
        (cooldownEnd, underlyingAmount) = vault.cooldowns(user);
        assertGt(underlyingAmount, 0, "Funds still locked in cooldown");
        
        // User must wait until original cooldownEnd (90 days) despite cooldown being disabled
        vm.warp(cooldownEnd + 1);
        
        // Now unstake succeeds
        vm.startPrank(address(composer));
        uint256 assets = vault.unstakeThroughComposer(user);
        assertGt(assets, 0, "Finally able to unstake after 90 days");
        vm.stopPrank();
    }
}
```

## Notes

This vulnerability specifically affects the **cross-chain unstake path** and creates an inconsistency in how the protocol treats local vs. cross-chain users when the cooldown mechanism is disabled. While the funds are not permanently lost, a 90-day lock represents significant user impact and violates the protocol's stated behavior regarding cooldown disabling.

The root cause is the missing `|| cooldownDuration == 0` condition in the validation logic at line 89 of `StakediTryCrosschain.sol`. This check exists in the regular `unstake()` function but was not replicated in `unstakeThroughComposer()`, creating the discriminatory behavior.

The fix is straightforward and should be applied to maintain consistency across all unstake code paths.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L84-84)
```text
        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L120-120)
```text
    /// @notice Set cooldown duration. If cooldown duration is set to zero, the StakediTryV2 behavior changes to follow ERC4626 standard and disables cooldownShares and cooldownAssets methods. If cooldown duration is greater than zero, the ERC4626 withdrawal and redeem functions are disabled, breaking the ERC4626 standard, and enabling the cooldownShares and the cooldownAssets functions.
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L89-95)
```text
        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
        } else {
            revert InvalidCooldown();
```
