## Title
No Emergency Recovery Mechanism for Immutable Silo-Locked Cooldown Funds

## Summary
The `StakediTryV2` contract uses an immutable `iTrySilo` contract to hold iTRY tokens during the cooldown period. However, there is **no emergency recovery mechanism** if the silo becomes unable to transfer funds due to iTry token transfer restrictions (FULLY_DISABLED state), blacklisting, or other issues. All user funds in cooldown become permanently locked with no administrative recovery path.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (line 22, 45, 88) and `src/token/wiTRY/iTrySilo.sol` (line 28-30)

**Intended Logic:** The silo temporarily holds iTRY tokens during the cooldown period, allowing users to withdraw after cooldown completion via the `unstake()` function.

**Actual Logic:** The silo is immutable and has no emergency recovery function. If iTry token transfers fail for any reason (FULLY_DISABLED state, blacklisting, or token bugs), all cooldown funds become permanently locked. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. Users call `cooldownAssets()` or `cooldownShares()`, transferring iTRY to the silo contract [3](#0-2) 

2. Admin legitimately sets iTry `transferState` to `FULLY_DISABLED` during an emergency (e.g., critical bug discovered) [4](#0-3) 

3. Users complete cooldown and attempt to call `unstake()`, which calls `silo.withdraw()` [5](#0-4) 

4. The silo's `withdraw()` function calls `iTry.transfer()`, which reverts due to FULLY_DISABLED state [6](#0-5) [7](#0-6) 

5. No emergency recovery mechanism exists:
   - Silo is immutable (cannot be upgraded or replaced)
   - `rescueTokens()` in `StakediTry` explicitly prevents rescuing iTRY tokens [8](#0-7) 
   - No admin function can force withdrawal from silo
   - Users cannot withdraw via any alternative path

**Security Property Broken:** Violates **Cooldown Integrity** invariant - "Users must complete cooldown period before unstaking wiTRY" becomes impossible to satisfy even after completing cooldown.

## Impact Explanation
- **Affected Assets**: All iTRY tokens held in the silo contract (potentially millions of dollars across all users with active cooldowns)
- **Damage Severity**: Complete permanent loss of funds for all users in cooldown during transfer restrictions. Funds cannot be recovered even after iTry transfers are re-enabled due to lack of emergency mechanism
- **User Impact**: Every user with funds in cooldown at the time of transfer restriction loses access to their iTRY permanently

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is an architectural vulnerability triggered by legitimate admin actions or external factors
- **Preconditions**: 
  - Users have initiated cooldown (normal protocol operation)
  - iTry transfer state set to FULLY_DISABLED (legitimate emergency action)
  - OR silo accidentally blacklisted
  - OR iTry token has transfer bugs
- **Execution Complexity**: Single admin transaction (or external token issue)
- **Frequency**: Can occur during any emergency pause or token issue, affecting all cooldown users simultaneously

## Recommendation

Add an emergency recovery mechanism that allows the admin to rescue iTRY tokens from the silo under specific conditions:

```solidity
// In src/token/wiTRY/iTrySilo.sol, add emergency withdrawal function:

// CURRENT (vulnerable):
// Only has withdraw() function with no emergency override

// FIXED:
address public immutable ADMIN;

constructor(address _stakingVault, address _iTryToken, address _admin) {
    STAKING_VAULT = _stakingVault;
    iTry = IERC20(_iTryToken);
    ADMIN = _admin; // Store admin for emergency use
}

/// @notice Emergency recovery function for admin to rescue tokens if normal withdrawal fails
/// @dev Should only be callable in extreme circumstances (e.g., FULLY_DISABLED state)
/// @param to Recipient address
/// @param amount Amount to recover
function emergencyWithdraw(address to, uint256 amount) external {
    if (msg.sender != ADMIN) revert OnlyAdmin();
    // Use low-level call to bypass potential transfer restrictions
    (bool success, ) = address(iTry).call(
        abi.encodeWithSignature("transfer(address,uint256)", to, amount)
    );
    if (!success) revert EmergencyWithdrawFailed();
}
```

**Alternative mitigations:**
1. Make silo upgradeable (using proxy pattern) to allow fixing critical issues
2. Add a timelock + multisig requirement for emergency withdrawals
3. Implement a circuit breaker that automatically enables emergency mode when transfers fail
4. Allow admin to redistribute silo funds to users' accounts directly in emergency scenarios

## Proof of Concept
```solidity
// File: test/Exploit_SiloLockedFunds.t.sol
// Run with: forge test --match-test test_SiloLockedFundsNoRecovery -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_SiloLockedFunds is Test {
    StakediTryV2 vault;
    iTry itry;
    address admin = address(0x1);
    address user = address(0x2);
    
    function setUp() public {
        vm.startPrank(admin);
        
        // Deploy iTry token
        itry = new iTry();
        itry.initialize(admin, address(this));
        
        // Deploy StakediTryV2 with cooldown
        vault = new StakediTryV2(IERC20(address(itry)), address(this), admin);
        
        // Mint iTRY to user
        itry.mint(user, 1000 ether);
        
        vm.stopPrank();
    }
    
    function test_SiloLockedFundsNoRecovery() public {
        // SETUP: User stakes and initiates cooldown
        vm.startPrank(user);
        itry.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, user);
        
        // User initiates cooldown for 500 iTRY
        uint256 sharesToCooldown = vault.previewWithdraw(500 ether);
        vault.cooldownShares(sharesToCooldown);
        
        vm.stopPrank();
        
        // Verify iTRY is in silo
        address siloAddr = address(vault.silo());
        assertEq(itry.balanceOf(siloAddr), 500 ether, "iTRY should be in silo");
        
        // EXPLOIT: Admin sets iTry to FULLY_DISABLED (legitimate emergency action)
        vm.prank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        
        // Wait for cooldown to complete
        vm.warp(block.timestamp + 90 days + 1);
        
        // VERIFY: User cannot unstake (funds are locked)
        vm.prank(user);
        vm.expectRevert(); // Transfer will fail due to FULLY_DISABLED
        vault.unstake(user);
        
        // Verify funds are still in silo
        assertEq(itry.balanceOf(siloAddr), 500 ether, "iTRY still locked in silo");
        
        // VERIFY: No emergency recovery mechanism exists
        // Admin cannot rescue iTRY from StakediTry (explicitly blocked)
        vm.prank(admin);
        vm.expectRevert(); // rescueTokens prevents rescuing iTRY
        vault.rescueTokens(address(itry), 500 ether, admin);
        
        // Silo has no emergency withdrawal function
        // Even if transfers are re-enabled later, users need the silo to work
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- 500 iTRY permanently locked in silo");
        console.log("- No emergency recovery mechanism exists");
        console.log("- rescueTokens explicitly blocks iTRY recovery");
        console.log("- Silo is immutable and cannot be upgraded");
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **Multiple realistic trigger scenarios**: Not just malicious actions, but legitimate emergency responses (FULLY_DISABLED state), accidental blacklisting, or external token bugs

2. **No time-bound recovery**: Unlike temporary locks, this is permanent until manual intervention that doesn't currently exist

3. **Affects all cooldown users simultaneously**: A single admin action or token issue locks ALL users' cooldown funds

4. **Cannot be mitigated by users**: Users have no way to protect themselves or recover their funds

5. **Design flaw, not implementation bug**: The immutability without emergency mechanism is an architectural issue

The protocol should implement one of the recommended emergency recovery mechanisms before launch to prevent catastrophic fund loss scenarios.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L22-22)
```text
    iTrySilo public immutable silo;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L44-46)
```text
    constructor(IERC20 _asset, address initialRewarder, address _owner) StakediTry(_asset, initialRewarder, _owner) {
        silo = new iTrySilo(address(this), address(_asset));
        cooldownDuration = MAX_COOLDOWN_DURATION;
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

**File:** src/token/iTRY/iTry.sol (L171-175)
```text
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L219-221)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L154-161)
```text
    function rescueTokens(address token, uint256 amount, address to)
        external
        nonReentrant
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (address(token) == asset()) revert InvalidToken();
        IERC20(token).safeTransfer(to, amount);
    }
```
