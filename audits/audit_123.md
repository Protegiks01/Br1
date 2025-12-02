## Title
Blacklisted Users Can Transfer Tokens in WHITELIST_ENABLED State Due to Inconsistent Role Grant Mechanisms

## Summary
In `iTry.sol`, the `WHITELIST_MANAGER_ROLE` uses `addWhitelistAddress()` with blacklist validation, while `DEFAULT_ADMIN_ROLE` can directly call `grantRole()` to bypass this check. When a user has both `BLACKLISTED_ROLE` and `WHITELISTED_ROLE`, the `_beforeTokenTransfer` function in `WHITELIST_ENABLED` state only verifies whitelist status without checking blacklist, allowing blacklisted users to transfer tokens and violating Critical Invariant #2.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (functions: `addWhitelistAddress`, `_beforeTokenTransfer`, inherited `grantRole`) [1](#0-0) [2](#0-1) [3](#0-2) 

**Intended Logic:** The protocol enforces that blacklisted users cannot transfer tokens under any circumstances. The `addWhitelistAddress` function checks if a user is not blacklisted before granting whitelist privileges.

**Actual Logic:** While `WHITELIST_MANAGER_ROLE` must use `addWhitelistAddress()` which contains the blacklist check, `DEFAULT_ADMIN_ROLE` can call the inherited `grantRole(WHITELISTED_ROLE, user)` directly, bypassing this safety check. In `WHITELIST_ENABLED` transfer state, the normal transfer logic only validates `WHITELISTED_ROLE` presence without checking for `BLACKLISTED_ROLE`, allowing blacklisted users with whitelist role to transfer.

**Exploitation Path:**
1. User gets blacklisted through `addBlacklistAddress()` (granted `BLACKLISTED_ROLE`)
2. `DEFAULT_ADMIN_ROLE` calls `grantRole(WHITELISTED_ROLE, user)` directly (either by mistake, race condition with whitelist manager operations, or confusion about proper procedure)
3. Transfer state is set to `WHITELIST_ENABLED`
4. The blacklisted user can now call `transfer()` or `transferFrom()` - the `_beforeTokenTransfer` hook at lines 211-213 validates only whitelist status for normal transfers, not blacklist status
5. Blacklisted user successfully transfers tokens despite being blacklisted

**Security Property Broken:** Critical Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case."

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by blacklisted users who are incorrectly granted whitelist role
- **Damage Severity**: Blacklisted users (potentially sanctioned addresses, malicious actors, or users under regulatory restrictions) can transfer tokens to extract value or continue operations, completely bypassing the blacklist mechanism designed to freeze their assets
- **User Impact**: Any blacklisted user who receives `WHITELISTED_ROLE` through the direct `grantRole()` path can freely transfer tokens when `transferState` is `WHITELIST_ENABLED`, undermining regulatory compliance and security measures

## Likelihood Explanation
- **Attacker Profile**: A blacklisted user who has been granted `WHITELISTED_ROLE` by `DEFAULT_ADMIN_ROLE` (either through operational error or race conditions between admin operations)
- **Preconditions**: 
  - User must have both `BLACKLISTED_ROLE` and `WHITELISTED_ROLE` 
  - Transfer state must be `WHITELIST_ENABLED`
  - This can occur through operational mistakes, confusion between admin and whitelist manager, or race conditions during simultaneous role management operations
- **Execution Complexity**: Single transaction - user simply calls `transfer()` or `transferFrom()` once the inconsistent role state exists
- **Frequency**: Can be exploited continuously as long as the user maintains both roles and transfer state remains `WHITELIST_ENABLED`

## Recommendation

**Fix Option 1: Add blacklist check in WHITELIST_ENABLED transfer logic**

In `src/token/iTRY/iTry.sol`, function `_beforeTokenTransfer`, lines 211-213:

Add explicit blacklist validation for the normal transfer case in `WHITELIST_ENABLED` state: [4](#0-3) 

```solidity
// FIXED:
} else if (
    hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
        && hasRole(WHITELISTED_ROLE, to)
        && !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
        && !hasRole(BLACKLISTED_ROLE, to)
) {
    // normal case - whitelist required AND blacklist forbidden
```

**Fix Option 2: Override grantRole to enforce blacklist-whitelist mutual exclusion** [2](#0-1) 

Override `grantRole` in `iTry.sol` to add validation:

```solidity
function grantRole(bytes32 role, address account) public override {
    if (role == WHITELISTED_ROLE && hasRole(BLACKLISTED_ROLE, account)) {
        revert OperationNotAllowed();
    }
    if (role == BLACKLISTED_ROLE && hasRole(WHITELISTED_ROLE, account)) {
        _revokeRole(WHITELISTED_ROLE, account);
    }
    super.grantRole(role, account);
}
```

**Recommended approach:** Implement both fixes for defense-in-depth. Fix Option 1 ensures blacklist always takes precedence in transfer validation. Fix Option 2 prevents the inconsistent state from occurring in the first place.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistWhitelistBypass.t.sol
// Run with: forge test --match-test test_BlacklistWhitelistBypass -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_BlacklistWhitelistBypass is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    
    address public admin;
    address public minter;
    address public blacklistedUser;
    address public normalUser;
    
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    bytes32 constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    bytes32 constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
    bytes32 constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    bytes32 constant WHITELIST_MANAGER_ROLE = keccak256("WHITELIST_MANAGER_ROLE");
    
    function setUp() public {
        admin = address(this);
        minter = makeAddr("minter");
        blacklistedUser = makeAddr("blacklistedUser");
        normalUser = makeAddr("normalUser");
        
        // Deploy iTry implementation and proxy
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            minter
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Grant necessary roles
        itryToken.grantRole(BLACKLIST_MANAGER_ROLE, admin);
        itryToken.grantRole(WHITELIST_MANAGER_ROLE, admin);
        
        // Mint tokens to blacklistedUser
        vm.prank(minter);
        itryToken.mint(blacklistedUser, 1000 ether);
        
        // Mint tokens to normalUser
        vm.prank(minter);
        itryToken.mint(normalUser, 1000 ether);
    }
    
    function test_BlacklistWhitelistBypass() public {
        // SETUP: Blacklist the user
        address[] memory usersToBlacklist = new address[](1);
        usersToBlacklist[0] = blacklistedUser;
        itryToken.addBlacklistAddress(usersToBlacklist);
        
        // Verify user is blacklisted
        assertTrue(itryToken.hasRole(BLACKLISTED_ROLE, blacklistedUser), "User should be blacklisted");
        
        // EXPLOIT: Admin grants WHITELISTED_ROLE directly, bypassing addWhitelistAddress check
        itryToken.grantRole(WHITELISTED_ROLE, blacklistedUser);
        
        // Verify user has both roles (inconsistent state)
        assertTrue(itryToken.hasRole(BLACKLISTED_ROLE, blacklistedUser), "User still blacklisted");
        assertTrue(itryToken.hasRole(WHITELISTED_ROLE, blacklistedUser), "User now whitelisted too");
        
        // Set transfer state to WHITELIST_ENABLED
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Whitelist normalUser to have a valid recipient
        address[] memory usersToWhitelist = new address[](1);
        usersToWhitelist[0] = normalUser;
        itryToken.addWhitelistAddress(usersToWhitelist);
        
        // VERIFY: Blacklisted user can transfer despite being blacklisted
        uint256 transferAmount = 100 ether;
        uint256 balanceBefore = itryToken.balanceOf(normalUser);
        
        vm.prank(blacklistedUser);
        itryToken.transfer(normalUser, transferAmount);
        
        uint256 balanceAfter = itryToken.balanceOf(normalUser);
        
        // Vulnerability confirmed: blacklisted user successfully transferred tokens
        assertEq(
            balanceAfter - balanceBefore, 
            transferAmount, 
            "Vulnerability confirmed: Blacklisted user bypassed restrictions in WHITELIST_ENABLED state"
        );
        
        // Additional verification: check balances
        assertEq(itryToken.balanceOf(blacklistedUser), 900 ether, "Blacklisted user balance decreased");
        assertEq(itryToken.balanceOf(normalUser), 1100 ether, "Normal user received tokens from blacklisted user");
    }
}
```

## Notes

The vulnerability stems from the architectural decision to use OpenZeppelin's AccessControl with two different role management paths:
1. Purpose-built functions (`addWhitelistAddress`, `addBlacklistAddress`) with business logic
2. Inherited `grantRole`/`revokeRole` functions that bypass this logic

The spoke chain implementation (`iTryTokenOFT.sol`) uses simple boolean mappings with consistent checks and does not suffer from this vulnerability. However, the hub chain's role-based approach creates an attack surface when roles are managed through multiple entry points with different validation rules.

This issue is distinct from the known Zellic finding about allowance-based transfers, as it specifically involves the interaction between role management and transfer state enforcement, not the `msg.sender` validation issue.

### Citations

**File:** src/token/iTRY/iTry.sol (L92-96)
```text
    function addWhitelistAddress(address[] calldata users) external onlyRole(WHITELIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (!hasRole(BLACKLISTED_ROLE, users[i])) _grantRole(WHITELISTED_ROLE, users[i]);
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L208-216)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
```

**File:** src/utils/SingleAdminAccessControlUpgradeable.sol (L41-43)
```text
    function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
        _grantRole(role, account);
    }
```
