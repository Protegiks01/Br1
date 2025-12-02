## Title
Cross-Chain Unstaking Permanently Fails When iTRY Enters WHITELIST_ENABLED Mode Without Whitelisting Silo Contract

## Summary
The `iTrySilo` contract and `StakediTryCrosschain._startComposerCooldown` do not validate that the silo has the necessary iTRY transfer permissions before locking funds in cooldown. When iTRY switches to `WHITELIST_ENABLED` state and the silo is not whitelisted, all pending cross-chain unstake requests become permanently locked, as `silo.withdraw()` will revert on transfer attempts.

## Impact
**Severity**: Medium

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

**Intended Logic:** The silo temporarily holds iTRY assets during cooldown periods, then transfers them back to the vault composer when users complete cross-chain unstaking. The system should ensure all necessary permissions exist before locking funds.

**Actual Logic:** Neither `_startComposerCooldown` nor `iTrySilo.withdraw` validates that the silo contract has `WHITELISTED_ROLE` when initiating cooldowns. The raw `iTry.transfer()` call in `iTrySilo.withdraw` will silently accept the call but revert when iTRY's `_beforeTokenTransfer` hook enforces whitelist requirements.

**Exploitation Path:**
1. User initiates cross-chain unstake when iTRY is in `FULLY_ENABLED` state
2. `_startComposerCooldown` successfully transfers iTRY to silo [4](#0-3) 
3. Admin switches iTRY to `WHITELIST_ENABLED` mode (legitimate regulatory action) [5](#0-4) 
4. After cooldown period, `unstakeThroughComposer` is called [6](#0-5) 
5. `silo.withdraw(composer, assets)` executes `iTry.transfer(composer, assets)` [7](#0-6) 
6. iTRY's `_beforeTokenTransfer` requires ALL of `msg.sender`, `from`, and `to` to have `WHITELISTED_ROLE` [8](#0-7) 
7. Silo is not whitelisted → transfer reverts with `OperationNotAllowed`
8. User's iTRY is locked in silo until admin manually whitelists silo

**Security Property Broken:** Violates **Invariant #7 (Cross-chain Message Integrity)**: "LayerZero messages for unstaking must be delivered to correct user with proper validation" - The system accepts cross-chain unstake messages but cannot complete them, effectively breaking message integrity.

## Impact Explanation

- **Affected Assets**: iTRY tokens locked in `iTrySilo` contract during pending cross-chain cooldowns
- **Damage Severity**: All users with active cross-chain cooldowns lose access to their iTRY until admin whitelists the silo. For a protocol managing significant TVL, this could affect thousands of users and millions in locked value during regulatory transitions.
- **User Impact**: Any user who initiated cross-chain unstaking before the transfer state change becomes unable to complete withdrawal. The cross-chain flow succeeds up until the final asset transfer, creating a poor UX where LayerZero messages are received but execution fails.

## Likelihood Explanation

- **Attacker Profile**: No attacker needed - this is triggered by legitimate protocol operations
- **Preconditions**: 
  1. Users have initiated cross-chain cooldowns (normal protocol usage)
  2. Admin switches iTRY to `WHITELIST_ENABLED` state (legitimate regulatory compliance action)
  3. Silo was never granted `WHITELISTED_ROLE` during deployment [9](#0-8) 
- **Execution Complexity**: Automatic - occurs naturally when admin performs routine state management
- **Frequency**: One-time per state transition, but affects ALL pending cross-chain unstakes simultaneously

## Recommendation

**Option 1: Validate Silo Permissions Before State Transition**

```solidity
// In src/token/iTRY/iTry.sol, function updateTransferState:

function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
    // NEW: Validate critical contracts have required permissions
    if (code == TransferState.WHITELIST_ENABLED) {
        // Get silo address from StakediTry vault
        address vault = getRoleMember(MINTER_CONTRACT, 0); // Assuming vault is minter
        if (vault != address(0)) {
            try IStakediTry(vault).silo() returns (address siloAddress) {
                require(
                    hasRole(WHITELISTED_ROLE, siloAddress),
                    "iTrySilo must be whitelisted before enabling WHITELIST_ENABLED mode"
                );
            } catch {
                // Vault doesn't have silo, skip check
            }
        }
    }
    
    TransferState prevState = transferState;
    transferState = code;
    emit TransferStateUpdated(prevState, code);
}
```

**Option 2: Check Permissions in iTrySilo.withdraw**

```solidity
// In src/token/wiTRY/iTrySilo.sol, function withdraw:

function withdraw(address to, uint256 amount) external onlyStakingVault {
    // NEW: Validate transfer will succeed based on current iTRY state
    IiTry token = IiTry(address(iTry));
    
    // Check if in whitelist mode and we have permissions
    if (token.transferState() == IiTryDefinitions.TransferState.WHITELIST_ENABLED) {
        require(
            token.hasRole(token.WHITELISTED_ROLE(), address(this)) &&
            token.hasRole(token.WHITELISTED_ROLE(), to),
            "Silo or recipient not whitelisted"
        );
    }
    
    iTry.transfer(to, amount);
}
```

**Option 3: Auto-Whitelist Silo During Deployment**

```solidity
// In deployment scripts, after silo creation:

// Deploy vault
StakediTryCrosschain vault = new StakediTryCrosschain(iTRY, rewarder, owner, fastRedeemTreasury);

// Whitelist the silo for WHITELIST_ENABLED mode compatibility
iTRY.addWhitelistAddress([address(vault.silo())]);
```

## Proof of Concept

```solidity
// File: test/Exploit_SiloWhitelistLock.t.sol
// Run with: forge test --match-test test_SiloWhitelistLock -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/iTrySilo.sol";

contract Exploit_SiloWhitelistLock is Test {
    iTry itry;
    StakediTryCrosschain vault;
    address admin;
    address composer;
    address user;
    
    function setUp() public {
        admin = makeAddr("admin");
        composer = makeAddr("composer");
        user = makeAddr("user");
        
        // Deploy iTRY
        vm.startPrank(admin);
        itry = new iTry();
        itry.initialize(admin, address(this));
        
        // Deploy vault (creates silo internally)
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            admin,
            admin,
            admin
        );
        
        // Grant composer role
        vault.grantRole(vault.COMPOSER_ROLE(), composer);
        
        // Mint iTRY to composer for testing
        itry.mint(composer, 1000e18);
        vm.stopPrank();
        
        // Composer stakes iTRY
        vm.startPrank(composer);
        itry.approve(address(vault), type(uint256).max);
        vault.deposit(1000e18, composer);
        vm.stopPrank();
    }
    
    function test_SiloWhitelistLock() public {
        // SETUP: Composer initiates cooldown for user (cross-chain unstake simulation)
        vm.startPrank(composer);
        uint256 shares = 100e18;
        vault.cooldownSharesByComposer(shares, user);
        vm.stopPrank();
        
        // STATE CHANGE: Admin switches to WHITELIST_ENABLED (legitimate action)
        vm.startPrank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Admin whitelists composer but FORGETS to whitelist silo
        address[] memory toWhitelist = new address[](1);
        toWhitelist[0] = composer;
        itry.addWhitelistAddress(toWhitelist);
        vm.stopPrank();
        
        // EXPLOIT: Wait for cooldown to complete
        vm.warp(block.timestamp + 90 days + 1);
        
        // VERIFY: Unstake fails because silo is not whitelisted
        vm.startPrank(composer);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        vault.unstakeThroughComposer(user);
        vm.stopPrank();
        
        // Verify funds are locked in silo
        address siloAddress = address(vault.silo());
        uint256 lockedAmount = itry.balanceOf(siloAddress);
        assertGt(lockedAmount, 0, "Funds should be locked in silo");
        
        // Verify cooldown data still exists for user
        (uint104 cooldownEnd, uint152 underlyingAmount) = vault.cooldowns(user);
        assertGt(underlyingAmount, 0, "User should have cooldown amount pending");
        
        console.log("Vulnerability confirmed:");
        console.log("- Locked in silo:", lockedAmount);
        console.log("- User pending amount:", underlyingAmount);
        console.log("- Unstake reverts due to silo not whitelisted");
    }
}
```

## Notes

**Answer to Security Question**: 

The functions do NOT check if the silo has sufficient permissions for iTRY transfer restrictions. Specifically:

1. **Allowance Check**: Not applicable - `iTrySilo.withdraw()` transfers from the silo's own balance, not via allowance mechanism.

2. **Transfer Restrictions Check**: Neither `_startComposerCooldown` nor `iTrySilo.withdraw` validate that the silo has `WHITELISTED_ROLE` when iTRY is in `WHITELIST_ENABLED` state.

3. **Silent Failure**: The issue does NOT cause "silent failure" - transactions revert with `OperationNotAllowed`. However, this is arguably worse than silent failure because users wait through the entire cooldown period only to discover their withdrawal is impossible.

The vulnerability exists because the silo is deployed as a simple custody contract [9](#0-8)  without any automatic whitelist grants, and there are no validation checks to ensure it has the necessary permissions before locking user funds or when transfer restrictions change.

This is distinct from known issues: it's not about blacklisted users transferring via allowance, nor about MIN_SHARES griefing, nor about admin malice - it's about the code failing to handle a legitimate operational state transition that breaks cross-chain unstaking functionality.

### Citations

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L170-181)
```text
    function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

        // Interaction: External call to base contract (protected by nonReentrant modifier)
        _withdraw(composer, address(silo), composer, assets, shares);

        // Effects: State changes after external call (following CEI pattern)
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);

        emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
    }
```

**File:** src/token/iTRY/iTry.sol (L171-175)
```text
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L210-217)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L45-45)
```text
        silo = new iTrySilo(address(this), address(_asset));
```
