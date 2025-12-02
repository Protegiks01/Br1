## Title
FULL_RESTRICTED Users Can Bypass Unstaking Restrictions via Missing Role Check in `unstake()` Function

## Summary
The `unstake()` function in `StakediTryCooldown.sol` fails to validate whether `msg.sender` or the `receiver` parameter have the `FULL_RESTRICTED_STAKER_ROLE`, allowing users who were blacklisted after initiating a cooldown to extract their staked position by completing the unstake process. This bypasses the documented invariant that FULL_RESTRICTED users "cannot transfer, stake, or unstake."

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` - `unstake()` function (lines 80-92)

**Intended Logic:** According to the role documentation, `FULL_RESTRICTED_STAKER_ROLE` prevents addresses from transferring, staking, or unstaking wiTRY shares. [1](#0-0) 

The protocol implements protection checks in multiple functions:
- `_beforeTokenTransfer`: blocks transfers from/to FULL_RESTRICTED users [2](#0-1) 
- `_withdraw`: blocks withdrawals involving FULL_RESTRICTED users as caller, receiver, or owner [3](#0-2) 
- `_deposit`: blocks deposits involving SOFT_RESTRICTED users [4](#0-3) 

**Actual Logic:** The `unstake()` function completely lacks any role validation checks. [5](#0-4)  It only validates cooldown timing before calling `silo.withdraw(receiver, assets)` to transfer iTRY to the specified receiver, with no checks on either `msg.sender` or `receiver` for restricted roles.

**Exploitation Path:**
1. Alice stakes 10,000 iTRY tokens to receive wiTRY shares
2. Alice calls `cooldownShares(shares)` to initiate unstaking - this succeeds as she's not yet restricted, burning her shares and placing iTRY in the silo with a cooldown timestamp
3. Protocol administrators add Alice to FULL_RESTRICTED_STAKER_ROLE via `addToBlacklist(Alice, true)` due to compliance concerns
4. After the cooldown period expires, Alice calls `unstake(Bob)` where Bob is her controlled address or helper contract
5. The `unstake()` function executes without checking Alice's restriction status, transferring 10,000 iTRY from silo to Bob
6. Alice has successfully extracted her entire staked position despite being FULL_RESTRICTED

**Security Property Broken:** This violates the critical invariant that FULL_RESTRICTED_STAKER_ROLE prevents unstaking. The protocol's `redistributeLockedAmount()` function exists specifically to allow admins to redistribute locked shares from FULL_RESTRICTED users [6](#0-5) , indicating the protocol design expects these users' positions to be frozen and admin-controlled, not self-extractable.

## Impact Explanation
- **Affected Assets**: All wiTRY shares and underlying iTRY tokens held by users who initiate cooldowns before being restricted
- **Damage Severity**: Complete bypass of FULL_RESTRICTED_STAKER_ROLE enforcement. Users facing regulatory action, legal holds, or protocol sanctions can extract 100% of their staked assets by timing their cooldown initiation or exploiting the window between cooldown start and restriction imposition
- **User Impact**: This undermines the entire purpose of the restriction mechanism. Malicious actors can initiate cooldowns preemptively if they anticipate being blacklisted, or in worst case scenarios where restrictions are applied during an active cooldown period

## Likelihood Explanation
- **Attacker Profile**: Any staker who either (1) anticipates being blacklisted and front-runs with cooldown initiation, or (2) has an active cooldown when blacklisted
- **Preconditions**: 
  - User must have initiated cooldown via `cooldownShares` or `cooldownAssets` before or immediately upon learning of impending restriction
  - Cooldown period must complete (typically 90 days per MAX_COOLDOWN_DURATION)
  - User's iTRY balance in cooldown must be non-zero
- **Execution Complexity**: Single transaction calling `unstake()` after cooldown expires - trivially executable
- **Frequency**: Exploitable once per cooldown period for each user, but can affect multiple users simultaneously. The long cooldown period (up to 90 days) creates a substantial window where users can be restricted after cooldown initiation

## Recommendation

Add role validation checks in the `unstake()` function to match the protection pattern used in other withdrawal functions:

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
    // Check msg.sender is not restricted from unstaking
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, msg.sender)) {
        revert OperationNotAllowed();
    }
    // Check receiver is not restricted from receiving
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)) {
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

**Alternative mitigation:** Import and check SOFT_RESTRICTED_STAKER_ROLE as well if the protocol intends to prevent soft-restricted users from unstaking (though the current design only blocks them from staking/depositing).

**Note on the original question:** The known issue about `transferFrom` and `msg.sender` not being checked does NOT directly enable this vulnerability. StakediTry's `_beforeTokenTransfer` correctly checks the `from` address, preventing FULL_RESTRICTED users from transferring their shares via `transferFrom`. However, this separate vulnerability in `unstake()` provides an alternative extraction path that bypasses all share transfer restrictions entirely.

## Proof of Concept

```solidity
// File: test/Exploit_FullRestrictedUnstakeBypass.t.sol
// Run with: forge test --match-test test_FullRestrictedUnstakeBypass -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_FullRestrictedUnstakeBypass is Test {
    StakediTryCrosschain vault;
    iTry itry;
    address alice;
    address bob; // Alice's helper address
    address admin;
    address rewarder;
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy iTRY and vault
        vm.startPrank(admin);
        itry = new iTry();
        itry.initialize(admin, admin); // admin as minter
        
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            rewarder,
            admin,
            admin // fastRedeemTreasury
        );
        
        // Grant blacklist manager role to admin
        vault.grantRole(vault.BLACKLIST_MANAGER_ROLE(), admin);
        vm.stopPrank();
        
        // Mint iTRY to Alice
        vm.prank(admin);
        itry.mint(alice, 10_000 ether);
    }
    
    function test_FullRestrictedUnstakeBypass() public {
        // SETUP: Alice stakes iTRY
        vm.startPrank(alice);
        itry.approve(address(vault), 10_000 ether);
        vault.deposit(10_000 ether, alice);
        
        uint256 aliceShares = vault.balanceOf(alice);
        assertGt(aliceShares, 0, "Alice should have shares");
        
        // Alice initiates cooldown to unstake
        vault.cooldownShares(aliceShares);
        
        // Verify shares burned and cooldown set
        assertEq(vault.balanceOf(alice), 0, "Shares should be burned");
        (uint104 cooldownEnd, uint152 underlyingAmount) = vault.cooldowns(alice);
        assertGt(cooldownEnd, block.timestamp, "Cooldown should be active");
        assertEq(underlyingAmount, 10_000 ether, "iTRY should be in cooldown");
        vm.stopPrank();
        
        // EXPLOIT: Admin blacklists Alice with FULL_RESTRICTED during cooldown
        vm.prank(admin);
        vault.addToBlacklist(alice, true); // true = full restriction
        
        // Verify Alice is restricted
        assertTrue(vault.hasRole(vault.FULL_RESTRICTED_STAKER_ROLE(), alice), "Alice should be restricted");
        
        // Fast forward past cooldown period
        vm.warp(cooldownEnd + 1);
        
        // VULNERABILITY: Alice can still unstake despite being FULL_RESTRICTED!
        vm.prank(alice);
        vault.unstake(bob); // Send iTRY to helper address
        
        // VERIFY: Exploit success - Alice extracted her position
        assertEq(itry.balanceOf(bob), 10_000 ether, "Bob received iTRY from restricted Alice");
        
        // Verify cooldown cleared
        (uint104 finalCooldownEnd, uint152 finalUnderlyingAmount) = vault.cooldowns(alice);
        assertEq(finalCooldownEnd, 0, "Cooldown should be cleared");
        assertEq(finalUnderlyingAmount, 0, "Underlying amount should be zero");
        
        console.log("VULNERABILITY CONFIRMED: FULL_RESTRICTED user Alice extracted %e iTRY via unstake()", itry.balanceOf(bob));
    }
}
```

## Notes

**Direct answer to the security question:** No, the known `transferFrom`/allowance issue where `msg.sender` isn't checked does NOT directly allow a FULL_RESTRICTED user to extract their staked wiTRY position. The `_beforeTokenTransfer` function in StakediTry correctly checks the `from` address, preventing share transfers even via approved helpers.

However, this investigation revealed a **separate and more critical vulnerability**: The `unstake()` function completely bypasses FULL_RESTRICTED_STAKER_ROLE enforcement by lacking any role checks whatsoever. This allows restricted users with active cooldowns to extract their entire staked position, defeating the purpose of the restriction mechanism and the admin's `redistributeLockedAmount` functionality.

The vulnerability is particularly concerning because:
1. The 90-day cooldown period creates a large window where users can be restricted after initiating cooldown
2. Sophisticated users may front-run anticipated restrictions by preemptively starting cooldowns
3. It undermines compliance and regulatory enforcement mechanisms that the restriction roles were designed to support

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L29-30)
```text
    /// @notice The role which prevents an address to transfer, stake, or unstake. The owner of the contract can redirect address staking balance if an address is in full restricting mode.
    bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
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

**File:** src/token/wiTRY/StakediTry.sol (L247-249)
```text
        if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/wiTRY/StakediTry.sol (L269-274)
```text
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/wiTRY/StakediTry.sol (L292-299)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
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
