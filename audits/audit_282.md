## Title
Cross-chain Users Cannot Access Emergency Withdrawals When `cooldownDuration` Set to Zero

## Summary
The `unstakeThroughComposer()` function in `StakediTryCrosschain.sol` lacks the emergency withdrawal bypass (`cooldownDuration == 0`) condition that exists in the regular `unstake()` function. When administrators set `cooldownDuration = 0` for emergency withdrawals, L1 users can immediately withdraw their funds, but cross-chain L2 users remain locked until their original `cooldownEnd` timestamp, creating discriminatory treatment between user groups.

## Impact
**Severity**: Medium

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The emergency withdrawal feature (setting `cooldownDuration = 0`) is documented to allow users to bypass cooldown periods and claim their assets from the silo immediately. The comment in `StakediTryCooldown.sol` explicitly states: "unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo." [2](#0-1) 

**Actual Logic:** The regular `unstake()` function checks: [3](#0-2) 

However, `unstakeThroughComposer()` only checks: [4](#0-3) 

This missing condition means cross-chain users cannot benefit from the emergency withdrawal feature.

**Exploitation Path:**
1. Cross-chain user on L2 initiates cooldown via `UnstakeMessenger`, which calls `cooldownSharesByComposer()` on L1, setting their `cooldownEnd = block.timestamp + 90 days`
2. Emergency scenario occurs - admin sets `cooldownDuration = 0` to allow immediate withdrawals
3. L1 users call `unstake()` and immediately withdraw (bypasses cooldown due to `cooldownDuration == 0` condition)
4. Cross-chain user on L2 sends unstake message via `UnstakeMessenger`
5. `wiTryVaultComposer._handleUnstake()` calls `unstakeThroughComposer(user)`: [5](#0-4) 
6. Function reverts with `InvalidCooldown()` because condition `block.timestamp >= userCooldown.cooldownEnd` is false
7. Cross-chain user remains locked until their original `cooldownEnd` (90 days from step 1), while L1 users already withdrew

**Security Property Broken:** Violates cooldown integrity and equal treatment - cross-chain users cannot access emergency withdrawal functionality that is explicitly designed for all users with pending cooldowns.

## Impact Explanation

- **Affected Assets**: iTRY tokens locked in cooldown for cross-chain users who initiated unstaking from L2 chains
- **Damage Severity**: Cross-chain users experience extended fund lock during emergency scenarios when immediate access is critical. While not permanent loss, this creates:
  - Liquidity crisis for affected users during emergencies
  - Discriminatory treatment between L1 and cross-chain users
  - Broken protocol promise of emergency withdrawal capability
- **User Impact**: All cross-chain users with active cooldowns when `cooldownDuration` is set to 0. Given the protocol's LayerZero integration emphasizes cross-chain functionality, this could affect a significant portion of the user base.

## Likelihood Explanation

- **Attacker Profile**: Not an attack - this is a protocol design flaw affecting legitimate cross-chain users during emergency scenarios
- **Preconditions**: 
  - User has initiated cross-chain unstake with active cooldown
  - Admin sets `cooldownDuration = 0` for emergency withdrawals
  - User attempts to complete unstake before their original `cooldownEnd`
- **Execution Complexity**: Standard user flow - user sends unstake message via LayerZero from L2
- **Frequency**: Occurs every time admin activates emergency withdrawal mode (`cooldownDuration = 0`) while cross-chain users have pending cooldowns

## Recommendation

Add the `cooldownDuration == 0` bypass condition to `unstakeThroughComposer()`:

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function unstakeThroughComposer, line 89:

// CURRENT (vulnerable):
if (block.timestamp >= userCooldown.cooldownEnd) {

// FIXED:
if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
    // This allows cross-chain users to also benefit from emergency withdrawals
    // when cooldownDuration is set to 0, maintaining parity with L1 users
```

This single-line fix ensures cross-chain users have equal access to emergency withdrawal functionality.

## Proof of Concept

```solidity
// File: test/Exploit_CrosschainEmergencyWithdrawalBypass.t.sol
// Run with: forge test --match-test test_CrosschainEmergencyWithdrawalBypass -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_CrosschainEmergencyWithdrawalBypass is Test {
    iTry public itryToken;
    StakediTryCrosschain public vault;
    
    address public owner;
    address public rewarder;
    address public treasury;
    address public l1User;
    address public l2User;
    address public composer;
    
    bytes32 public constant COMPOSER_ROLE = keccak256("COMPOSER_ROLE");
    
    function setUp() public {
        owner = makeAddr("owner");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        l1User = makeAddr("l1User");
        l2User = makeAddr("l2User");
        composer = makeAddr("composer");
        
        // Deploy iTry
        iTry itryImpl = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner,
            owner
        );
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImpl), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(
            IERC20(address(itryToken)),
            rewarder,
            owner,
            treasury
        );
        
        // Grant composer role
        vm.prank(owner);
        vault.grantRole(COMPOSER_ROLE, composer);
    }
    
    function test_CrosschainEmergencyWithdrawalBypass() public {
        // SETUP: Both L1 and L2 users deposit and initiate cooldowns
        uint256 depositAmount = 100e18;
        
        // L1 user deposits directly
        vm.startPrank(owner);
        itryToken.mint(l1User, depositAmount);
        vm.stopPrank();
        
        vm.startPrank(l1User);
        itryToken.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, l1User);
        vault.cooldownShares(vault.balanceOf(l1User));
        vm.stopPrank();
        
        // L2 user deposits via composer (simulating cross-chain flow)
        vm.startPrank(owner);
        itryToken.mint(composer, depositAmount);
        vm.stopPrank();
        
        vm.startPrank(composer);
        itryToken.approve(address(vault), depositAmount);
        vault.deposit(depositAmount, composer);
        vault.cooldownSharesByComposer(vault.balanceOf(composer), l2User);
        vm.stopPrank();
        
        // Record initial balances
        uint256 l1InitialBalance = itryToken.balanceOf(l1User);
        uint256 composerInitialBalance = itryToken.balanceOf(composer);
        
        // Verify both have active cooldowns
        (, uint256 l1Amount) = vault.cooldowns(l1User);
        (, uint256 l2Amount) = vault.cooldowns(l2User);
        assertGt(l1Amount, 0, "L1 user should have cooldown");
        assertGt(l2Amount, 0, "L2 user should have cooldown");
        
        // EXPLOIT: Admin sets cooldownDuration to 0 for emergency withdrawals
        vm.prank(owner);
        vault.setCooldownDuration(0);
        
        // L1 user can immediately unstake (emergency withdrawal works)
        vm.prank(l1User);
        vault.unstake(l1User);
        assertEq(
            itryToken.balanceOf(l1User),
            l1InitialBalance + depositAmount,
            "L1 user should receive funds immediately"
        );
        
        // L2 user CANNOT unstake via composer (emergency withdrawal FAILS)
        vm.prank(composer);
        vm.expectRevert(IStakediTryCooldown.InvalidCooldown.selector);
        vault.unstakeThroughComposer(l2User);
        
        // VERIFY: Vulnerability confirmed
        assertEq(
            itryToken.balanceOf(composer),
            composerInitialBalance,
            "Vulnerability confirmed: L2 user locked out of emergency withdrawal"
        );
        
        // L2 user must wait until original cooldownEnd
        (uint104 l2CooldownEnd,) = vault.cooldowns(l2User);
        vm.warp(l2CooldownEnd + 1);
        
        vm.prank(composer);
        vault.unstakeThroughComposer(l2User);
        assertEq(
            itryToken.balanceOf(composer),
            composerInitialBalance + depositAmount,
            "L2 user finally gets funds after waiting full cooldown period"
        );
    }
}
```

## Notes

The vulnerability demonstrates a critical oversight in the cross-chain unstaking implementation. While the regular `unstake()` function correctly includes the emergency bypass condition (`cooldownDuration == 0`), this was not replicated in `unstakeThroughComposer()`. 

This creates an inconsistent user experience where:
- **L1 direct stakers** can immediately access emergency withdrawals
- **L2 cross-chain stakers** remain locked despite the same emergency conditions

The fix is straightforward and maintains protocol invariants while ensuring equal treatment for all user types during emergency scenarios. This is particularly important given the protocol's emphasis on cross-chain functionality via LayerZero integration.

### Citations

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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L77-92)
```text
    /// @notice Claim the staking amount after the cooldown has finished. The address can only retire the full amount of assets.
    /// @dev unstake can be called after cooldown have been set to 0, to let accounts to be able to claim remaining assets locked at Silo
    /// @param receiver Address to send the assets by the staker
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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L254-255)
```text
        // Call vault to unstake
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
```
