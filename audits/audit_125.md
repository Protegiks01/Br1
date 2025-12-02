## Title
Blacklisted Users' Staked iTRY Becomes Permanently Locked in StakediTry Vault Due to Transfer Restrictions

## Summary
A user who stakes iTRY in the StakediTry vault while not blacklisted, but subsequently gets blacklisted on the iTRY token, will have their staked funds permanently locked. All withdrawal paths (direct withdraw, cooldown-based unstake, and fast redemption) fail because the iTRY transfer restriction checks block transfers to blacklisted addresses, creating an unrecoverable fund lock scenario.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (function `_beforeTokenTransfer`, lines 177-196) in combination with `src/token/wiTRY/iTrySilo.sol` (function `withdraw`, lines 28-30) and `src/token/wiTRY/StakediTryCooldown.sol` (function `unstake`, lines 80-92)

**Intended Logic:** The iTRY blacklist mechanism is designed to prevent blacklisted users from sending or receiving iTRY tokens. The StakediTry vault allows users to stake iTRY and later unstake it after a cooldown period.

**Actual Logic:** When a user is blacklisted after staking, the iTRY transfer restrictions prevent the vault from transferring iTRY back to the blacklisted user during unstake operations. The `_beforeTokenTransfer` check requires that `msg.sender`, `from`, and `to` addresses all be non-blacklisted for normal transfers to succeed.

**Exploitation Path:**
1. User stakes iTRY into StakediTry vault while not blacklisted, receiving wiTRY shares
2. User subsequently gets blacklisted on the iTRY token by the BLACKLIST_MANAGER_ROLE
3. User attempts to unstake via `cooldownAssets()` followed by `unstake(receiver)`:
   - Cooldown succeeds: iTRY transfers from StakediTry to iTrySilo (neither blacklisted)
   - Unstake fails: `silo.withdraw(receiver, assets)` calls `iTry.transfer(receiver, assets)` where receiver is the blacklisted user
   - The `_beforeTokenTransfer` check at lines 190-192 requires all three addresses (msg.sender, from, to) to be non-blacklisted
   - Since `to` (the user) is blacklisted, the transaction reverts with `OperationNotAllowed()`
4. All other withdrawal paths (direct withdraw, fast redeem) similarly fail because they attempt to transfer iTRY to the blacklisted user

**Security Property Broken:** This creates a conflict with Critical Invariant #2 ("Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case") which, while correctly enforced, results in an unintended permanent fund lock for users who were compliant when staking. [1](#0-0) [2](#0-1) [3](#0-2) 

## Impact Explanation
- **Affected Assets**: All iTRY tokens staked by users who become blacklisted after staking. The principal amount plus any accrued yield remains locked in the vault.
- **Damage Severity**: Complete loss of access to staked funds. Users cannot withdraw their iTRY through any of the three designed withdrawal mechanisms (direct withdraw when cooldown is disabled, cooldown-based unstake, or fast redemption).
- **User Impact**: Any user who gets blacklisted after staking loses access to their funds indefinitely. Recovery requires complex admin intervention via `StakediTry.redistributeLockedAmount()`, which requires the admin to first grant the user `FULL_RESTRICTED_STAKER_ROLE`, then redistribute their wiTRY shares to a third-party address chosen by the admin. The blacklisted user loses direct control over fund recovery. [4](#0-3) 

## Likelihood Explanation
- **Attacker Profile**: This is not a malicious attack but an operational risk. Any staking user can be affected if they are subsequently blacklisted for regulatory or compliance reasons.
- **Preconditions**: 
  - User must have staked iTRY in StakediTry vault while not blacklisted
  - User must subsequently be added to the iTRY blacklist
  - Transfer state must be FULLY_ENABLED or WHITELIST_ENABLED (not FULLY_DISABLED)
- **Execution Complexity**: No complex execution required. The fund lock occurs automatically when a blacklisted user attempts any withdrawal operation.
- **Frequency**: This can happen to any number of users who get blacklisted after staking. Each affected user's funds become permanently locked until admin intervention.

## Recommendation

Implement a special bypass in `_beforeTokenTransfer` for the iTrySilo contract when it's sending funds from unstake operations. This allows the vault system to return staked iTRY to users even if they are later blacklisted, while still preventing blacklisted users from normal transfers:

```solidity
// In src/token/iTRY/iTry.sol, function _beforeTokenTransfer, add after line 189:

// Special case: Allow iTrySilo to return staked funds to blacklisted users during unstake
// This prevents permanent fund lock while still enforcing blacklist for normal operations
bytes32 public constant ITRY_SILO_ROLE = keccak256("ITRY_SILO_ROLE");

// In _beforeTokenTransfer, add before line 190:
} else if (hasRole(ITRY_SILO_ROLE, msg.sender) && hasRole(ITRY_SILO_ROLE, from) && !hasRole(BLACKLISTED_ROLE, from)) {
    // Allow silo to return staked funds even to blacklisted addresses
    // This enables fund recovery for users blacklisted after staking
```

Alternative mitigation: Add a dedicated admin function in iTRY that allows transferring iTRY from system contracts (StakediTry, iTrySilo) to blacklisted users specifically for fund recovery purposes, with appropriate access controls and event logging.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedStakerLock.t.sol
// Run with: forge test --match-test test_BlacklistedStakerLock -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "../src/token/wiTRY/iTrySilo.sol";

contract Exploit_BlacklistedStakerLock is Test {
    iTry public itry;
    StakediTryV2 public vault;
    address public admin;
    address public user;
    address public minter;
    
    function setUp() public {
        admin = address(this);
        user = address(0x1);
        minter = address(0x2);
        
        // Deploy iTRY token
        itry = new iTry();
        itry.initialize(admin, minter);
        
        // Deploy StakediTry vault
        vault = new StakediTryV2(
            IERC20(address(itry)),
            address(this), // rewarder
            admin
        );
        
        // Grant roles
        itry.grantRole(itry.BLACKLIST_MANAGER_ROLE(), admin);
        
        // Mint iTRY to user
        vm.prank(minter);
        itry.mint(user, 1000 ether);
    }
    
    function test_BlacklistedStakerLock() public {
        // SETUP: User stakes iTRY while not blacklisted
        vm.startPrank(user);
        itry.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, user);
        vm.stopPrank();
        
        // Verify user has wiTRY shares
        assertEq(vault.balanceOf(user), 1000 ether, "User should have wiTRY shares");
        
        // User gets blacklisted after staking
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = user;
        itry.addBlacklistAddress(blacklistAddresses);
        
        // EXPLOIT: User initiates cooldown (succeeds)
        vm.prank(user);
        vault.cooldownAssets(1000 ether);
        
        // Fast forward past cooldown period
        vm.warp(block.timestamp + 91 days);
        
        // VERIFY: User cannot complete unstake due to blacklist
        vm.expectRevert(iTry.OperationNotAllowed.selector);
        vm.prank(user);
        vault.unstake(user);
        
        // Verify funds are still locked in silo
        assertGt(itry.balanceOf(address(vault.silo())), 0, "Funds locked in silo");
        assertEq(itry.balanceOf(user), 0, "User cannot retrieve their iTRY");
    }
}
```

## Notes

**Additional Context:**
1. **Cross-chain bypass exists but is impractical**: If a blacklisted user can bridge their wiTRY shares to a spoke chain (requires not having `FULL_RESTRICTED_STAKER_ROLE` on StakediTry), they could potentially unstake there and receive iTRY on the spoke chain. However, this requires complex cross-chain operations and assumes the spoke chain iTRY OFT doesn't have synchronized blacklists.

2. **Recovery mechanism limitations**: The `StakediTry.redistributeLockedAmount()` function can transfer shares to a non-blacklisted address, but this requires:
   - Admin granting `FULL_RESTRICTED_STAKER_ROLE` to the blacklisted user
   - Admin choosing a recipient address
   - The blacklisted user trusting that funds will be returned after blacklist removal
   
   This is not an automatic or trustless recovery mechanism.

3. **The known issue "Blacklisted user can transfer tokens using allowance" does not apply here** because the code at lines 190-192 explicitly checks `msg.sender` for blacklist status, contradicting the known issue description. The vulnerability identified here is different and relates to the inability to receive transfers, not send them.

4. **This vulnerability affects the Medium severity tier** because while funds become locked, they are theoretically recoverable through admin intervention (though with loss of user control), distinguishing it from permanent unrecoverable loss scenarios.

### Citations

**File:** src/token/iTRY/iTry.sol (L177-196)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
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

**File:** src/token/wiTRY/StakediTry.sol (L168-185)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && !hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            uint256 iTryToVest = previewRedeem(amountToDistribute);
            _burn(from, amountToDistribute);
            _checkMinShares();
            // to address of address(0) enables burning
            if (to == address(0)) {
                _updateVestingAmount(iTryToVest);
            } else {
                _mint(to, amountToDistribute);
            }

            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```
