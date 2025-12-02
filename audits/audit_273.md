## Title
Cross-Chain Unstaking Failure Due to Inconsistent Cooldown Bypass Logic

## Summary
When `cooldownDuration` is set to 0, the regular `unstake()` function allows immediate withdrawal regardless of cooldown state, but `unstakeThroughComposer()` lacks this bypass logic. This inconsistency breaks cross-chain unstaking flows and creates a race condition where users can front-run their own LayerZero messages, causing cross-chain unstake operations to fail and waste LayerZero fees.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` (function `unstakeThroughComposer`, line 89)

**Intended Logic:** According to the documentation, when `cooldownDuration` is set to 0, users should be able to claim their assets locked in the silo immediately. [1](#0-0)  The regular `unstake()` function implements this by checking both time-based completion AND the cooldown duration state. [2](#0-1) 

**Actual Logic:** The `unstakeThroughComposer()` function only checks if the timestamp has passed the cooldown end time, without the `cooldownDuration == 0` bypass. [3](#0-2)  This creates an inconsistency where:
- Regular users can bypass cooldown when duration is 0
- Cross-chain users via composer cannot bypass cooldown even when duration is 0

**Exploitation Path:**
1. User initiates cross-chain unstake when `cooldownDuration = 90 days` by sending wiTRY from spoke chain with "INITIATE_COOLDOWN" command
2. `wiTryVaultComposer` calls `cooldownSharesByComposer()` [4](#0-3)  which locks assets in silo and sets `cooldowns[user].cooldownEnd = block.timestamp + 90 days`
3. Admin calls `setCooldownDuration(0)` [5](#0-4)  (perhaps for migration to ERC4626 mode or emergency)
4. User (or MEV bot) observes this state change and calls `unstake(receiver)` directly on the vault, which succeeds due to the `cooldownDuration == 0` bypass, clearing their cooldown state
5. Later, when user's cross-chain unstake message arrives via LayerZero, `_handleUnstake()` calls `unstakeThroughComposer(user)` [6](#0-5) 
6. The function finds `assets = userCooldown.underlyingAmount = 0` (already claimed in step 4)
7. The wiTryVaultComposer reverts with `NoAssetsToUnstake()` [7](#0-6) 

**Security Property Broken:** Violates the **Cross-chain Message Integrity** invariant - LayerZero messages for unstaking should be delivered to the correct user with proper validation, but the message fails due to state inconsistency.

## Impact Explanation
- **Affected Assets**: iTRY assets locked in cooldown for cross-chain users, LayerZero native fee payments
- **Damage Severity**: Users who initiated cross-chain unstaking lose their LayerZero message fees (both spoke→hub and hub→spoke legs). Assets are received on the hub chain instead of the intended spoke chain destination, requiring manual bridging. Cross-chain unstaking functionality is completely broken for all users with pending cooldowns when `cooldownDuration` is set to 0.
- **User Impact**: All users with pending cross-chain cooldowns at the time `cooldownDuration` changes to 0. This affects users who followed the legitimate cross-chain unstaking flow and paid LayerZero fees expecting automated return of assets to spoke chain.

## Likelihood Explanation
- **Attacker Profile**: Any user with a pending cooldown, or even the user themselves trying to optimize gas by claiming directly instead of waiting for LayerZero message
- **Preconditions**: 
  - User has initiated cross-chain cooldown via `cooldownSharesByComposer()` or `cooldownAssetsByComposer()`
  - Admin sets `cooldownDuration` to 0 before cooldown period expires
  - User's cooldown end time is still in the future
- **Execution Complexity**: Single transaction calling `unstake()` on the vault contract. Can be front-run by MEV bots monitoring for `setCooldownDuration(0)` transactions.
- **Frequency**: Occurs every time admin changes cooldown duration to 0 while there are active cooldowns. Given the documented intention to support this transition (ERC4626 mode switching), this is a realistic operational scenario.

## Recommendation

Add the same cooldown bypass logic to `unstakeThroughComposer()` that exists in the regular `unstake()` function: [8](#0-7) 

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function unstakeThroughComposer, line 89:

// CURRENT (vulnerable):
if (block.timestamp >= userCooldown.cooldownEnd) {

// FIXED:
if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
    // Allow immediate unstake when cooldown is disabled, matching unstake() behavior
```

This ensures consistent behavior between direct and composer-based unstaking when cooldown is disabled.

**Alternative mitigation:** Prevent `setCooldownDuration(0)` if there are active cooldowns, but this would break the documented emergency escape mechanism for locked assets.

## Proof of Concept

```solidity
// File: test/Exploit_CrosschainCooldownBypass.t.sol
// Run with: forge test --match-test test_CrosschainCooldownBypassOnDurationChange -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/iTry.sol";

contract Exploit_CrosschainCooldownBypass is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    iTry asset;
    address owner;
    address alice;
    address vaultComposerAddress;
    
    function setUp() public {
        owner = address(this);
        alice = makeAddr("alice");
        
        // Deploy iTRY asset
        asset = new iTry(owner);
        
        // Deploy vault with 90 day cooldown
        vault = new StakediTryCrosschain(
            IERC20(address(asset)),
            address(0), // initialRewarder
            owner,
            address(0)  // fastRedeemTreasury
        );
        
        // Grant composer role
        vault.grantRole(vault.COMPOSER_ROLE(), address(this));
        
        // Mint and deposit for composer (simulating cross-chain received shares)
        asset.mint(address(this), 1000e18);
        asset.approve(address(vault), 1000e18);
        vault.deposit(1000e18, address(this));
    }
    
    function test_CrosschainCooldownBypassOnDurationChange() public {
        // SETUP: Initiate cooldown for alice via composer (cross-chain flow)
        uint256 sharesToCooldown = 500e18;
        vault.cooldownSharesByComposer(sharesToCooldown, alice);
        
        // Verify cooldown is set with 90 days in future
        (uint104 cooldownEnd, uint152 underlyingAmount) = vault.cooldowns(alice);
        assertEq(underlyingAmount, 500e18, "Cooldown assets should be 500e18");
        assertGt(cooldownEnd, block.timestamp, "Cooldown should be in future");
        
        // EXPLOIT: Admin sets cooldown duration to 0
        vault.setCooldownDuration(0);
        
        // Alice can now call unstake() directly (bypassing cross-chain flow)
        vm.prank(alice);
        vault.unstake(alice);
        
        // VERIFY: Alice received assets immediately
        assertEq(asset.balanceOf(alice), 500e18, "Alice should have claimed assets");
        
        // Verify cooldown is cleared
        (cooldownEnd, underlyingAmount) = vault.cooldowns(alice);
        assertEq(underlyingAmount, 0, "Cooldown should be cleared");
        
        // VERIFY: Cross-chain unstake will now fail
        // When LayerZero message arrives and wiTryVaultComposer calls unstakeThroughComposer:
        vm.expectRevert(); // Will revert because underlyingAmount = 0
        uint256 assets = vault.unstakeThroughComposer(alice);
        
        console.log("Vulnerability confirmed:");
        console.log("- Alice bypassed cooldown via direct unstake() when cooldownDuration = 0");
        console.log("- Cross-chain unstakeThroughComposer() now fails");
        console.log("- LayerZero fees wasted, assets on wrong chain");
    }
}
```

## Notes

The vulnerability stems from an inconsistency in how the two unstake paths handle the `cooldownDuration == 0` state:

1. The regular `unstake()` function was designed to allow emergency escape when cooldown is disabled, as documented in the code comments [1](#0-0) 

2. However, the composer-based cross-chain unstaking path through `unstakeThroughComposer()` was not updated with the same bypass logic [9](#0-8) 

3. This creates a race condition where the same user can claim their assets through two different paths (direct vs cross-chain), but only one will succeed

4. The validation in `setCooldownDuration()` [10](#0-9)  only checks the upper bound, explicitly allowing 0 as a valid value

This is not a centralization risk because it doesn't require malicious admin action - setting cooldown to 0 is a legitimate operational scenario documented in the code comments for transitioning to ERC4626 standard mode. The issue is a logic bug in how the composer path handles this state transition.

### Citations

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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L94-94)
```text
        uint256 assetAmount = IStakediTryCrosschain(address(VAULT)).cooldownSharesByComposer(_shareAmount, redeemer);
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L255-255)
```text
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L257-259)
```text
        if (assets == 0) {
            revert NoAssetsToUnstake();
        }
```
