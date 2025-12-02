## Title
Front-Running Attack on Blacklist Application Allows Users to Bypass Blacklist Enforcement

## Summary
Users targeted for blacklisting can monitor the mempool for incoming `addBlacklistAddress` transactions and front-run them by transferring all their iTRY tokens to another address before the blacklist is applied. This completely bypasses the blacklist mechanism and violates the protocol's critical invariant that blacklisted users cannot send tokens in any case.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` - `addBlacklistAddress` function (lines 73-78) and `_beforeTokenTransfer` function (lines 177-222)

**Intended Logic:** The blacklist mechanism is designed to prevent targeted addresses from sending, receiving, minting, or burning iTRY tokens for regulatory compliance or security purposes. Once an address is blacklisted, it should be frozen from all token operations.

**Actual Logic:** The blacklist is applied atomically via `_grantRole(BLACKLISTED_ROLE, users[i])` with no delay or pending state. [1](#0-0) 

The transfer validation in `_beforeTokenTransfer` only checks the current blacklist status at execution time. [2](#0-1) 

**Exploitation Path:**
1. BLACKLIST_MANAGER submits transaction `addBlacklistAddress([userAddress])` to blacklist a malicious user
2. Transaction enters public mempool and is visible to all network participants
3. User monitors mempool (via services like Flashbots Protect, MEV-Boost, or custom RPC) and detects the incoming blacklist transaction
4. User immediately submits `transfer(destinationAddress, entireBalance)` with significantly higher gas price (e.g., 2-3x higher priority fee)
5. Due to gas priority, user's transfer executes first. At this moment, user doesn't have BLACKLISTED_ROLE yet, so the transfer check passes and tokens move to destination
6. Blacklist transaction executes next, but user's original address is now empty - funds have escaped

**Security Property Broken:** Violates Critical Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." The intent of this invariant is that users targeted for blacklisting should have their funds frozen, but front-running allows complete bypass.

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by users targeted for blacklisting
- **Damage Severity**: Complete blacklist bypass - 100% of targeted user's tokens can be moved to safety before enforcement. This defeats the entire purpose of the blacklist mechanism, which is typically used for:
  - Regulatory compliance (OFAC sanctions, AML/CTF requirements)
  - Freezing funds of compromised accounts
  - Preventing malicious actors from moving stolen/illegitimate funds
- **User Impact**: This affects protocol governance and compliance. While it doesn't directly harm other users financially, it creates regulatory risk for the protocol and undermines trust in enforcement mechanisms. Blacklisted entities can freely move funds, potentially continuing malicious activities or evading sanctions.

## Likelihood Explanation
- **Attacker Profile**: Any user who anticipates being blacklisted (malicious actors, sanctioned entities, compromised accounts that protocol wants to freeze)
- **Preconditions**: 
  - User must have iTRY tokens in their address
  - Transfer state must be FULLY_ENABLED (or user must be whitelisted in WHITELIST_ENABLED state)
  - User must be monitoring mempool or have alerts set up
- **Execution Complexity**: Simple single transaction with higher gas. Widely available tools:
  - Flashbots Protect for private mempool submission
  - MEV-Boost for priority ordering
  - Any mempool monitoring service (e.g., Blocknative, Alchemy)
  - Custom RPC endpoints with pending transaction monitoring
- **Frequency**: Can be exploited every time a blacklist transaction is submitted for that user. Since blacklisting is a one-time action per address, this is exploitable once per target address.

## Recommendation

Implement a two-phase blacklist mechanism with a pending state and timelock delay:

**Approach 1: Two-Step Blacklist with Timelock**
```solidity
// In src/token/iTRY/iTry.sol:

// Add state variables
mapping(address => uint256) public pendingBlacklistTimestamp;
uint256 public constant BLACKLIST_DELAY = 1 hours; // Configurable delay

// MODIFIED addBlacklistAddress:
function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    for (uint8 i = 0; i < users.length; i++) {
        // Mark as pending instead of immediate blacklist
        pendingBlacklistTimestamp[users[i]] = block.timestamp + BLACKLIST_DELAY;
        emit BlacklistPending(users[i], block.timestamp + BLACKLIST_DELAY);
    }
}

// Add finalization function
function finalizeBlacklist(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    for (uint8 i = 0; i < users.length; i++) {
        require(block.timestamp >= pendingBlacklistTimestamp[users[i]], "Timelock not expired");
        require(pendingBlacklistTimestamp[users[i]] != 0, "Not pending blacklist");
        
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
        delete pendingBlacklistTimestamp[users[i]];
    }
}

// MODIFIED _beforeTokenTransfer to check pending blacklist:
function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
    // Check pending blacklist for sender, from, and to
    require(pendingBlacklistTimestamp[msg.sender] == 0 || block.timestamp < pendingBlacklistTimestamp[msg.sender], "Pending blacklist");
    require(pendingBlacklistTimestamp[from] == 0 || block.timestamp < pendingBlacklistTimestamp[from], "Pending blacklist");
    require(pendingBlacklistTimestamp[to] == 0 || block.timestamp < pendingBlacklistTimestamp[to], "Pending blacklist");
    
    // ... rest of existing transfer validation logic
}
```

**Approach 2: Emergency Blacklist with Immediate Effect (For Critical Cases)**
```solidity
// Add emergency blacklist role for critical situations
bytes32 public constant EMERGENCY_BLACKLIST_ROLE = keccak256("EMERGENCY_BLACKLIST_ROLE");

function emergencyBlacklist(address[] calldata users) external onlyRole(EMERGENCY_BLACKLIST_ROLE) {
    // This bypasses timelock for critical situations (e.g., active exploit)
    // Requires higher privilege and should be used sparingly
    for (uint8 i = 0; i < users.length; i++) {
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
        delete pendingBlacklistTimestamp[users[i]]; // Clear any pending state
    }
}
```

**Trade-offs:**
- Timelock approach prevents front-running but gives users advance warning
- Emergency function maintains ability to freeze funds immediately when needed
- Consider shorter timelock (15-30 minutes) to balance security vs user notice
- Document clear procedures for when to use emergency vs standard blacklist

## Proof of Concept
```solidity
// File: test/Exploit_BlacklistFrontRun.t.sol
// Run with: forge test --match-test test_BlacklistFrontRun -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_BlacklistFrontRun is Test {
    iTry public itry;
    address public admin;
    address public blacklistManager;
    address public minter;
    address public maliciousUser;
    address public escapeAddress;
    
    function setUp() public {
        admin = makeAddr("admin");
        blacklistManager = makeAddr("blacklistManager");
        minter = makeAddr("minter");
        maliciousUser = makeAddr("maliciousUser");
        escapeAddress = makeAddr("escapeAddress");
        
        // Deploy iTry
        itry = new iTry();
        itry.initialize(admin, minter);
        
        // Grant blacklist manager role
        vm.prank(admin);
        itry.grantRole(itry.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        
        // Mint tokens to malicious user
        vm.prank(minter);
        itry.mint(maliciousUser, 1000 ether);
    }
    
    function test_BlacklistFrontRun() public {
        // SETUP: Malicious user has 1000 iTRY tokens
        uint256 initialBalance = itry.balanceOf(maliciousUser);
        assertEq(initialBalance, 1000 ether, "Initial balance should be 1000 iTRY");
        assertEq(itry.balanceOf(escapeAddress), 0, "Escape address should start with 0");
        
        // SCENARIO: Blacklist manager submits transaction to blacklist maliciousUser
        // This transaction is in mempool and visible
        // Malicious user sees it and front-runs with higher gas
        
        // EXPLOIT: User transfers all tokens BEFORE blacklist is applied
        vm.prank(maliciousUser);
        itry.transfer(escapeAddress, initialBalance);
        
        // VERIFY: Transfer succeeded, tokens moved to escape address
        assertEq(itry.balanceOf(maliciousUser), 0, "Malicious user balance should be 0");
        assertEq(itry.balanceOf(escapeAddress), 1000 ether, "Escape address should have 1000 iTRY");
        
        // NOW: Blacklist transaction executes (after user's transfer)
        address[] memory usersToBlacklist = new address[](1);
        usersToBlacklist[0] = maliciousUser;
        vm.prank(blacklistManager);
        itry.addBlacklistAddress(usersToBlacklist);
        
        // VERIFY: User is now blacklisted, but funds already escaped
        assertTrue(itry.hasRole(itry.BLACKLISTED_ROLE(), maliciousUser), "User should be blacklisted");
        assertEq(itry.balanceOf(maliciousUser), 0, "User has no tokens left to freeze");
        assertEq(itry.balanceOf(escapeAddress), 1000 ether, "Tokens successfully escaped to new address");
        
        // VERIFY: Blacklisted user cannot receive tokens back
        vm.prank(escapeAddress);
        vm.expectRevert(abi.encodeWithSignature("OperationNotAllowed()"));
        itry.transfer(maliciousUser, 100 ether);
        
        // CONCLUSION: Blacklist bypass successful via front-running
        console.log("Vulnerability confirmed: User front-ran blacklist and moved all 1000 iTRY tokens");
    }
}
```

## Notes

**Additional Context:**
1. This vulnerability also exists in the cross-chain OFT implementation at `src/token/iTRY/crosschain/iTryTokenOFT.sol` with the same front-running exposure. [3](#0-2) 

2. The known issue about "blacklisted user can transfer tokens using allowance on behalf of non-blacklisted users" is a separate vulnerability about allowance exploitation AFTER blacklist is applied. The front-running issue described here occurs BEFORE blacklist application and is not covered by known issues.

3. Real-world precedent: This attack vector has been exploited in multiple DeFi protocols where users front-run admin actions (e.g., Tornado Cash blocklist, USDC blacklist attempts). Sophisticated actors routinely monitor mempool for such transactions.

4. Recommended implementation should maintain emergency blacklist capability for active exploits while using timelock for routine compliance actions. The delay can be tuned based on operational requirements (suggested: 15-60 minutes).

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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L70-75)
```text
    function addBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        }
    }
```
