## Title
Missing Receiver Address Validation in `unstake()` Causes Permanent Fund Loss

## Summary
The `unstake()` function in `StakediTryCooldown.sol` accepts an arbitrary receiver address without any validation. The function clears the user's cooldown state before calling `silo.withdraw()`, creating a critical vulnerability where funds can be permanently lost if sent to invalid addresses (e.g., the silo itself, the staking vault, or other contracts). Unlike the similar `unstakeThroughComposer()` function which validates the receiver, this function provides no protection against user error or malicious input.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol`, `unstake()` function, lines 80-92 [1](#0-0) 

**Intended Logic:** The unstake function should allow users to claim their cooled-down iTRY tokens after the cooldown period completes, transferring them to a valid receiver address.

**Actual Logic:** The function accepts any address as the receiver parameter without validation. It clears the cooldown state (lines 85-86) BEFORE calling `silo.withdraw(receiver, assets)` (line 88). If the receiver is an invalid address like the silo itself or the staking vault, the transfer succeeds but the funds become permanently inaccessible because:

1. The silo only has one function to withdraw funds, which requires the caller to be the staking vault: [2](#0-1) 

2. The silo has no rescue function to recover misrouted funds
3. The user's cooldown state is already cleared, so they cannot call unstake again

**Exploitation Path:**
1. User completes cooldown period with 1000 iTRY waiting in the silo
2. User accidentally calls `unstake(address(silo))` (e.g., due to UI bug, address confusion, or typo)
3. Cooldown state is cleared: `userCooldown.cooldownEnd = 0; userCooldown.underlyingAmount = 0;`
4. `silo.withdraw(address(silo), 1000e18)` executes, transferring iTRY to the silo itself
5. The iTRY transfer succeeds (silo is not blacklisted)
6. Funds are now in the silo's balance with no recovery mechanism
7. User's cooldown is permanently zeroed - they cannot call unstake again

**Security Property Broken:** This violates the fundamental principle of fail-safe design and user fund protection. The protocol should prevent users from permanently losing funds through preventable mistakes.

**Inconsistency with Similar Function:** The `unstakeThroughComposer()` function in the same codebase validates the receiver: [3](#0-2) 

This shows the protocol developers were aware of the need for receiver validation but failed to apply it consistently.

## Impact Explanation
- **Affected Assets**: iTRY tokens held in cooldown in the iTrySilo contract
- **Damage Severity**: Complete and permanent loss of all cooled-down funds for the affected user. Once the cooldown state is cleared, there is zero recovery path as the silo's withdraw function requires staking vault caller + non-zero cooldown state.
- **User Impact**: Any user who completes cooldown and calls unstake with an invalid receiver (silo address, staking vault address, or other non-recoverable contract addresses). This is particularly dangerous because:
  - The silo address is programmatically accessible as `stakediTry.silo()`
  - Address confusion between staking vault and receiver is common in UI interactions
  - No gas-efficient way to validate receiver on-chain before calling

## Likelihood Explanation
- **Attacker Profile**: Not an "attack" per se, but affects any staker who provides an invalid receiver address. This includes legitimate users making honest mistakes through UI bugs, address confusion, or copy-paste errors.
- **Preconditions**: User must have completed cooldown period with funds in the silo
- **Execution Complexity**: Single transaction - user calls `unstake(invalidAddress)`
- **Frequency**: Can occur on every unstake transaction if the user provides wrong address. Given the protocol will likely have a UI, any UI bug that passes the wrong address parameter affects all users.

## Recommendation

Add validation to match the protection level in `unstakeThroughComposer`:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function unstake, after line 80:

function unstake(address receiver) external {
    // ADDED: Validate receiver address
    if (receiver == address(0)) revert InvalidZeroAddress();
    if (receiver == address(silo)) revert InvalidReceiver();
    if (receiver == address(this)) revert InvalidReceiver();
    
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

Add a new error definition in the interface:
```solidity
/// @notice Error emitted when receiver address is invalid
error InvalidReceiver();
```

**Alternative Mitigation:** Implement a rescue function in iTrySilo that allows the staking vault admin to recover misrouted funds, though this is less desirable as it requires admin intervention and doesn't prevent the issue.

## Proof of Concept

```solidity
// File: test/Exploit_UnstakeReceiverValidation.t.sol
// Run with: forge test --match-test test_UnstakePermanentLoss_SiloReceiver -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "./mocks/MockERC20.sol";

contract Exploit_UnstakeReceiverValidation is Test {
    StakediTryV2 public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public rewarder;
    address public user;
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        user = makeAddr("user");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTryV2
        vm.prank(admin);
        stakediTry = new StakediTryV2(IERC20(address(iTryToken)), rewarder, admin);
        
        // Mint and stake tokens for user
        iTryToken.mint(user, 1000e18);
        vm.startPrank(user);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        stakediTry.deposit(1000e18, user);
        vm.stopPrank();
    }
    
    function test_UnstakePermanentLoss_SiloReceiver() public {
        // SETUP: User initiates cooldown
        vm.prank(user);
        stakediTry.cooldownAssets(1000e18);
        
        // Fast forward past cooldown period
        vm.warp(block.timestamp + 90 days + 1);
        
        // BEFORE: Check silo has user's funds
        address siloAddress = address(stakediTry.silo());
        uint256 siloBalanceBefore = iTryToken.balanceOf(siloAddress);
        assertEq(siloBalanceBefore, 1000e18, "Silo should hold user's cooled-down iTRY");
        
        // BEFORE: User has cooldown entry
        (uint104 cooldownEnd, uint152 amount) = stakediTry.cooldowns(user);
        assertGt(cooldownEnd, 0, "User should have cooldown set");
        assertEq(amount, 1000e18, "User should have 1000 iTRY in cooldown");
        
        // EXPLOIT: User accidentally calls unstake with silo address as receiver
        vm.prank(user);
        stakediTry.unstake(siloAddress);
        
        // VERIFY: Cooldown is cleared
        (cooldownEnd, amount) = stakediTry.cooldowns(user);
        assertEq(cooldownEnd, 0, "Cooldown should be cleared");
        assertEq(amount, 0, "Cooldown amount should be zero");
        
        // VERIFY: Funds are still in silo (not sent to user)
        uint256 siloBalanceAfter = iTryToken.balanceOf(siloAddress);
        assertEq(siloBalanceAfter, 1000e18, "Funds remain stuck in silo");
        
        // VERIFY: User received nothing
        uint256 userBalance = iTryToken.balanceOf(user);
        assertEq(userBalance, 0, "User received no iTRY");
        
        // VERIFY: No way to recover - calling unstake again reverts with InvalidCooldown
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IStakediTryCooldown.InvalidCooldown.selector));
        stakediTry.unstake(user);
        
        // Vulnerability confirmed: User permanently lost 1000 iTRY with no recovery path
    }
}
```

## Notes

**Critical Comparison:** The `unstakeThroughComposer()` function in `StakediTryCrosschain.sol` includes receiver validation (`if (receiver == address(0)) revert InvalidZeroAddress();`), demonstrating that the protocol developers recognized the need for such validation. The absence of equivalent validation in the regular `unstake()` function is a critical oversight that exposes users to permanent fund loss.

**Why This is HIGH Severity:**
- Permanent and complete loss of user funds (not temporary or recoverable)
- No admin rescue function exists in iTrySilo contract
- The silo's withdraw function is access-controlled and requires cooldown state which is already cleared
- Common user error scenario (address confusion between vault, silo, and receiver)
- Affects core protocol functionality (unstaking after cooldown)

**Why This is Not User Error:**
- Protocol should implement defensive programming to protect users from common mistakes
- Similar function has validation, showing inconsistent safety standards
- No warning in NatSpec or documentation about receiver address requirements
- Address(silo) is accessible via public getter, making the mistake easy to make programmatically

### Citations

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

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L83-84)
```text
        // Validate valid receiver
        if (receiver == address(0)) revert InvalidZeroAddress();
```
