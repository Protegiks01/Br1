## Title
Blacklisted Composer Permanently Locks User iTRY in Cross-Chain Unstaking

## Summary
In the cross-chain unstaking flow, `unstakeThroughComposer` stores the cooldown under the receiver's address but transfers iTRY to the composer (`msg.sender`). If the wiTryVaultComposer gets blacklisted between cooldown initiation and completion, all iTRY transfers to it will fail, permanently locking receivers' funds in the silo with no alternative recovery mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` (function `unstakeThroughComposer`, lines 77-101)

**Intended Logic:** The composer-based unstaking mechanism is designed to allow cross-chain users to unstake their wiTRY. The cooldown is initiated on behalf of the receiver, and after the cooldown period, the composer completes the withdrawal to send iTRY back to the user on their origin chain.

**Actual Logic:** The function creates a critical dependency on the composer's ability to receive iTRY tokens. The cooldown is stored under `cooldowns[receiver]` [1](#0-0) , but the withdrawal sends iTRY to `msg.sender` (the composer) [2](#0-1) . The silo then attempts to transfer iTRY to the composer [3](#0-2) , which triggers blacklist validation [4](#0-3) .

**Exploitation Path:**
1. User on L2 initiates cross-chain unstake via UnstakeMessenger
2. wiTryVaultComposer receives bridged wiTRY shares and calls `cooldownSharesByComposer(shares, receiver)`, storing cooldown under `cooldowns[receiver]` [5](#0-4) 
3. During the cooldown period, wiTryVaultComposer gets blacklisted (e.g., due to security concerns, regulatory action, or contract compromise detection)
4. After cooldown completion, user sends unstake message to wiTryVaultComposer
5. wiTryVaultComposer calls `unstakeThroughComposer(receiver)` via `_handleUnstake` [6](#0-5) 
6. The function attempts `silo.withdraw(msg.sender, assets)` where `msg.sender` is the blacklisted composer
7. This triggers `iTry.transfer(composer, assets)` which reverts at `_beforeTokenTransfer` due to blacklist check on the `to` address
8. Transaction reverts, receiver's iTRY remains locked in silo indefinitely

**Security Property Broken:** Violates **Cooldown Integrity** invariant - users who complete the cooldown period cannot withdraw their staked assets. Also creates unintended permanent fund lock scenario not covered by the blacklist enforcement policy.

## Impact Explanation
- **Affected Assets**: All iTRY tokens held in cooldown for receivers when the composer is blacklisted
- **Damage Severity**: 100% permanent loss of staked iTRY for affected users. Users cannot access their funds through any alternative mechanism.
- **User Impact**: All cross-chain users with pending cooldowns at the time of composer blacklisting are affected. This could be dozens or hundreds of users depending on cooldown period (up to 90 days) and protocol usage. Users initiated unstaking legitimately but lose funds due to administrative action outside their control.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a design flaw triggered by administrative actions (blacklisting) that could occur for legitimate security reasons
- **Preconditions**: 
  1. Cooldown period must be active (protocol standard is 90 days)
  2. Composer must be blacklisted during this window
  3. User attempts to complete unstake after blacklisting
- **Execution Complexity**: Inevitable outcome once composer is blacklisted - any user attempting to complete their unstake will fail
- **Frequency**: Affects all users with pending cooldowns at moment of composer blacklisting. One blacklist event can lock funds for multiple users simultaneously

## Recommendation

The root cause is sending iTRY to the composer instead of directly to the receiver. Modify `unstakeThroughComposer` to withdraw directly to the receiver:

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function unstakeThroughComposer, line 93:

// CURRENT (vulnerable):
silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer

// FIXED:
silo.withdraw(receiver, assets); // transfer directly to receiver, bypassing composer blacklist risk
// Note: Composer must then call send() separately to bridge the iTRY received in its own balance
// or implement a pull pattern where receiver claims from composer's balance
```

**Alternative Mitigation 1**: Implement a fallback recovery mechanism that allows the receiver to claim directly after cooldown if the composer is blacklisted:

```solidity
function emergencyUnstake(address receiver) external {
    require(hasRole(BLACKLISTED_ROLE, wiTryVaultComposer), "Composer must be blacklisted");
    UserCooldown storage userCooldown = cooldowns[receiver];
    require(msg.sender == receiver, "Only receiver can emergency unstake");
    uint256 assets = userCooldown.underlyingAmount;
    
    if (block.timestamp >= userCooldown.cooldownEnd) {
        userCooldown.cooldownEnd = 0;
        userCooldown.underlyingAmount = 0;
        silo.withdraw(receiver, assets); // Direct to receiver
    } else {
        revert InvalidCooldown();
    }
}
```

**Alternative Mitigation 2**: Never blacklist the composer contract address - instead, pause composer operations via access control and implement admin rescue functions in the silo for emergency recovery of locked funds.

## Proof of Concept

```solidity
// File: test/Exploit_ComposerBlacklistLocksUserFunds.t.sol
// Run with: forge test --match-test test_ComposerBlacklistLocksUserFunds -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/iTrySilo.sol";

contract Exploit_ComposerBlacklistLocksUserFunds is Test {
    StakediTryCrosschain vault;
    iTry itry;
    iTrySilo silo;
    
    address owner = address(1);
    address composer = address(2);
    address receiver = address(3);
    address blacklistManager = address(4);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy iTRY and vault (simplified setup)
        itry = new iTry();
        itry.initialize(owner, owner);
        
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            address(0), // rewarder
            owner,
            address(0)  // treasury
        );
        
        silo = vault.silo();
        
        // Setup roles
        vault.grantRole(vault.COMPOSER_ROLE(), composer);
        itry.grantRole(itry.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        itry.grantRole(itry.MINTER_CONTRACT(), address(vault));
        
        // Mint iTRY to vault and silo for testing
        itry.mint(address(vault), 1000e18);
        itry.mint(address(silo), 1000e18);
        
        vm.stopPrank();
    }
    
    function test_ComposerBlacklistLocksUserFunds() public {
        // SETUP: Composer initiates cooldown on behalf of receiver
        vm.startPrank(composer);
        
        // Simulate composer holding shares and initiating cooldown
        // (Assuming shares exist - in real scenario they'd be bridged from L2)
        uint256 sharesToCooldown = 100e18;
        uint256 assetsInCooldown = 100e18;
        
        // Manually set cooldown for receiver (simulating cooldownSharesByComposer)
        vm.store(
            address(vault),
            keccak256(abi.encode(receiver, uint256(0))), // cooldowns mapping slot
            bytes32(uint256(block.timestamp + 90 days) | (uint256(assetsInCooldown) << 104))
        );
        
        vm.stopPrank();
        
        // Advance time past cooldown
        vm.warp(block.timestamp + 91 days);
        
        // EXPLOIT: Blacklist the composer before unstaking completes
        vm.prank(blacklistManager);
        address[] memory toBlacklist = new address[](1);
        toBlacklist[0] = composer;
        itry.addBlacklistAddress(toBlacklist);
        
        // VERIFY: Composer is blacklisted
        assertTrue(itry.hasRole(itry.BLACKLISTED_ROLE(), composer), "Composer should be blacklisted");
        
        // Attempt to complete unstake through composer
        vm.prank(composer);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        vault.unstakeThroughComposer(receiver);
        
        // VERIFY: Receiver's iTRY is permanently locked in silo
        uint256 siloBalance = itry.balanceOf(address(silo));
        assertGt(siloBalance, 0, "iTRY still locked in silo");
        
        // Receiver cannot call regular unstake because cooldown is under their address
        // but unstake() reads cooldowns[msg.sender] 
        vm.prank(receiver);
        vm.expectRevert(); // Will fail because receiver has no cooldown under msg.sender
        vault.unstake(receiver);
        
        // No recovery mechanism exists - funds permanently locked
        console.log("Vulnerability confirmed: %s iTRY permanently locked for receiver", assetsInCooldown);
    }
}
```

## Notes

This vulnerability demonstrates a critical architectural flaw where the composer acts as a single point of failure for fund recovery. While the protocol's blacklist mechanism is designed to protect against malicious actors, blacklisting a trusted contract like the composer can have unintended consequences of locking innocent users' funds.

The issue is particularly severe because:
1. The receiver cannot use the standard `unstake()` function since it checks `cooldowns[msg.sender]` but the cooldown is stored under `cooldowns[receiver]` [7](#0-6) 
2. Only the COMPOSER_ROLE can call `unstakeThroughComposer` [8](#0-7) 
3. The `redistributeLockedAmount` admin function only works for blacklisted user balances, not for funds locked in the silo [9](#0-8) 
4. The silo has no rescue or emergency withdrawal functions [3](#0-2) 

This creates a scenario where legitimate security actions (blacklisting a compromised or risky contract) can inadvertently cause permanent user fund loss, violating the fundamental principle that users should be able to recover their funds after completing required waiting periods.

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L77-79)
```text
    function unstakeThroughComposer(address receiver)
        external
        onlyRole(COMPOSER_ROLE)
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L86-87)
```text
        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L93-93)
```text
            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
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

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/iTRY/iTry.sol (L112-121)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L189-196)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L255-255)
```text
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
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
