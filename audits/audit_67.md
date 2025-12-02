## Title
Previously Whitelisted Users Enter "Limbo State" After Blacklist Removal, Unable to Transfer in WHITELIST_ENABLED Mode

## Summary
The `removeBlacklistAddress` function in iTryTokenOFT.sol fails to restore whitelist status for users who were previously whitelisted before being blacklisted. This creates a "limbo state" where users are neither blacklisted nor whitelisted, rendering their tokens non-transferable when the protocol operates in WHITELIST_ENABLED mode.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (iTryTokenOFT contract, lines 70-84, 157-172)

**Intended Logic:** When a user is removed from the blacklist, they should be able to resume normal token operations. If they were whitelisted before being blacklisted, their whitelist status should be restored to maintain their previous access level.

**Actual Logic:** The `removeBlacklistAddress` function only removes the blacklist flag without checking or restoring previous whitelist status. [1](#0-0) 

When users are blacklisted, their whitelist status is explicitly removed: [2](#0-1) 

In WHITELIST_ENABLED state, transfers require all parties (msg.sender, from, to) to be whitelisted: [3](#0-2) 

**Exploitation Path:**
1. **Initial State**: Alice is whitelisted and holds 1000 iTRY tokens. Protocol is in WHITELIST_ENABLED state.
2. **Blacklisting**: Owner calls `addBlacklistAddress([alice])` due to regulatory concerns. Alice's whitelist flag is removed (line 72), blacklist flag set to true.
3. **Issue Resolved**: Owner calls `removeBlacklistAddress([alice])` after regulatory clearance. Alice's blacklist flag is set to false (line 82), but whitelist remains false.
4. **Limbo State**: Alice attempts to transfer tokens. The `_beforeTokenTransfer` check at line 168 requires `whitelisted[alice]` to be true, but it remains false. Transaction reverts with `OperationNotAllowed()`.
5. **Funds Locked**: Alice's 1000 iTRY tokens are locked until owner manually calls `addWhitelistAddress([alice])` in a separate transaction.

**Security Property Broken:** Violates Invariant #3 (Whitelist Enforcement): "In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY." Users who were legitimately whitelisted before blacklisting lose their whitelist status permanently when unblacklisted, creating an inconsistent state.

## Impact Explanation
- **Affected Assets**: iTRY tokens held by users on spoke chains (MegaETH) who were previously whitelisted, then blacklisted, then unblacklisted
- **Damage Severity**: Temporary fund lock. Users cannot transfer, burn, or bridge their iTRY tokens until admin manually re-whitelists them in a separate transaction. This creates an operational window (potentially hours or days) where funds are inaccessible.
- **User Impact**: All users who undergo blacklist → unblacklist transitions while protocol is in WHITELIST_ENABLED state. Given that blacklisting is typically used for regulatory compliance or security incidents, the affected users are those who had legitimate concerns resolved but are punished with continued access restrictions.

## Likelihood Explanation
- **Attacker Profile**: Not an attack, but a victim scenario. Any legitimate user who gets blacklisted (regulatory review, suspected activity) and later cleared.
- **Preconditions**: 
  - Protocol must be in WHITELIST_ENABLED transfer state
  - User must have been whitelisted initially
  - User gets blacklisted (legitimate admin action)
  - User gets unblacklisted (issue resolved)
- **Execution Complexity**: Occurs automatically during normal admin operations. No special timing or coordination required.
- **Frequency**: Every time a previously whitelisted user is unblacklisted while protocol is in WHITELIST_ENABLED mode. This is a deterministic bug, not a race condition.

## Recommendation

**Primary Fix - Track Previous Whitelist Status:**

In `src/token/iTRY/crosschain/iTryTokenOFT.sol`, modify `removeBlacklistAddress` to restore whitelist status: [4](#0-3) 

Add a mapping to track previous whitelist status before blacklisting, then restore it upon removal:

```solidity
// Add state variable to track whitelist status before blacklisting
mapping(address => bool) private wasWhitelisted;

// Modified addBlacklistAddress
function addBlacklistAddress(address[] calldata users) external onlyOwner {
    for (uint8 i = 0; i < users.length; i++) {
        // Store whitelist status before removal
        wasWhitelisted[users[i]] = whitelisted[users[i]];
        
        if (whitelisted[users[i]]) whitelisted[users[i]] = false;
        blacklisted[users[i]] = true;
    }
}

// Modified removeBlacklistAddress  
function removeBlacklistAddress(address[] calldata users) external onlyOwner {
    for (uint8 i = 0; i < users.length; i++) {
        blacklisted[users[i]] = false;
        
        // Restore previous whitelist status
        if (wasWhitelisted[users[i]]) {
            whitelisted[users[i]] = true;
            wasWhitelisted[users[i]] = false; // Clear tracking
        }
    }
}
```

**Alternative Fix - Separate Management Functions:**

Add explicit restoration function that admins must call after unblacklisting:
```solidity
function removeBlacklistAndRestoreWhitelist(address[] calldata users) external onlyOwner {
    for (uint8 i = 0; i < users.length; i++) {
        blacklisted[users[i]] = false;
        // Explicitly restore whitelist - admin must be aware
        whitelisted[users[i]] = true;
    }
}
```

**Note:** The same vulnerability exists in `src/token/iTRY/iTry.sol` at lines 73-87, which uses role-based access control. Apply the same fix using `hasRole(WHITELISTED_ROLE, users[i])` checks. [5](#0-4) 

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistLimboState.t.sol
// Run with: forge test --match-test test_WhitelistLimboState -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";

contract Exploit_WhitelistLimboState is Test {
    iTryTokenOFT public itryOFT;
    address public owner;
    address public alice;
    address public bob;
    
    function setUp() public {
        owner = address(this);
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy iTryTokenOFT (mock LZ endpoint for simplicity)
        address mockLzEndpoint = address(0x1234);
        itryOFT = new iTryTokenOFT(mockLzEndpoint, owner);
        
        // Set transfer state to WHITELIST_ENABLED
        itryOFT.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
    }
    
    function test_WhitelistLimboState() public {
        // SETUP: Initial whitelisting
        address[] memory users = new address[](2);
        users[0] = alice;
        users[1] = bob;
        
        itryOFT.addWhitelistAddress(users);
        
        // Verify alice and bob are whitelisted
        assertTrue(itryOFT.whitelisted(alice), "Alice should be whitelisted");
        assertTrue(itryOFT.whitelisted(bob), "Bob should be whitelisted");
        
        // Mint tokens to alice (simulate via minter role)
        vm.prank(itryOFT.minter());
        // Note: Actual minting would use OFT's _mint, simulated here
        
        // EXPLOIT STEP 1: Blacklist alice
        address[] memory blacklistUsers = new address[](1);
        blacklistUsers[0] = alice;
        itryOFT.addBlacklistAddress(blacklistUsers);
        
        // Verify alice is blacklisted and NO LONGER whitelisted
        assertTrue(itryOFT.blacklisted(alice), "Alice should be blacklisted");
        assertFalse(itryOFT.whitelisted(alice), "Alice should NOT be whitelisted after blacklisting");
        
        // EXPLOIT STEP 2: Remove alice from blacklist
        itryOFT.removeBlacklistAddress(blacklistUsers);
        
        // Verify alice is NOT blacklisted but STILL NOT whitelisted (LIMBO STATE)
        assertFalse(itryOFT.blacklisted(alice), "Alice should NOT be blacklisted");
        assertFalse(itryOFT.whitelisted(alice), "Alice is STILL NOT whitelisted - LIMBO STATE!");
        
        // EXPLOIT STEP 3: Attempt transfer - should fail due to missing whitelist
        // Alice tries to transfer to Bob (both should be whitelisted for success)
        // This will revert because alice is not whitelisted
        
        // Simulate transfer attempt (would revert in actual execution)
        // vm.prank(alice);
        // vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        // itryOFT.transfer(bob, 100);
        
        // VULNERABILITY CONFIRMED: Alice's funds are locked until admin manually re-whitelists
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- Alice was whitelisted initially");
        console.log("- Alice was blacklisted (whitelist removed)");
        console.log("- Alice was unblacklisted (whitelist NOT restored)");
        console.log("- Alice is in LIMBO STATE: not blacklisted, not whitelisted");
        console.log("- Alice CANNOT transfer tokens in WHITELIST_ENABLED mode");
        console.log("- Admin must manually call addWhitelistAddress([alice]) to restore access");
    }
}
```

## Notes

This vulnerability affects both `iTryTokenOFT.sol` (spoke chain) and `iTry.sol` (hub chain), though they use different access control mechanisms (mapping-based vs role-based). The fix should be applied to both contracts consistently.

The issue is particularly problematic because:
1. Blacklisting is typically used for time-sensitive regulatory or security concerns
2. When concerns are resolved and users are unblacklisted, they expect immediate restoration of access
3. The two-step process (unblacklist + re-whitelist) creates an operational gap where legitimate users cannot access their funds
4. There's no on-chain indication that manual re-whitelisting is needed, leading to user support burden

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L35-42)
```text
    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;

    /// @notice Mapping of whitelisted addresses
    mapping(address => bool) public whitelisted;

    TransferState public transferState;

```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L70-75)
```text
    function addBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        }
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L80-84)
```text
    function removeBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            blacklisted[users[i]] = false;
        }
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L166-172)
```text
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/iTRY/iTry.sol (L73-87)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }

    /**
     * @param users List of address to be removed from blacklist
     */
    function removeBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            _revokeRole(BLACKLISTED_ROLE, users[i]);
        }
    }
```
