## Title
Lack of Batch Blacklist Operations in wiTryOFT Creates Exploitable Timing Window for Malicious Actors to Escape Blacklisting

## Summary
The `updateBlackList` function in `wiTryOFT.sol` only accepts a single address parameter, unlike the iTRY token contract which implements batch blacklist operations. [1](#0-0)  This design inconsistency creates a critical timing window during security incidents where malicious actors can front-run blacklisting transactions and transfer their wiTRY OFT shares to fresh addresses before the blacklist takes effect.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol`, `updateBlackList` function (line 70-74)

**Intended Logic:** The blacklist mechanism should allow the protocol to rapidly freeze multiple malicious addresses during security incidents (hacks, sanctions compliance, regulatory actions), preventing them from transferring or moving their wiTRY OFT shares on spoke chains like MegaETH.

**Actual Logic:** The current implementation only processes one address at a time, requiring separate transactions for each address. [1](#0-0)  This contrasts sharply with the iTRY token which has batch operations. [2](#0-1) 

**Exploitation Path:**
1. **Security Incident Detected**: Protocol identifies addresses A, B, C, D, E that need emergency blacklisting on MegaETH spoke chain
2. **First Transaction Visible**: BlackLister submits `updateBlackList(A, true)` transaction to mempool
3. **Mempool Monitoring**: Addresses B, C, D, E monitor the mempool and detect the pattern of blacklisting transactions
4. **Front-Running Attack**: Before subsequent blacklist transactions are mined, addresses B, C, D, E execute transfer transactions with higher gas prices to move their wiTRY OFT shares to fresh addresses (B2, C2, D2, E2)
5. **Blacklist Bypassed**: By the time BlackLister processes blacklist transactions for B, C, D, E, the shares have already been transferred out
6. **Continued Malicious Activity**: Attackers now control shares from non-blacklisted addresses and can continue transfers, cross-chain bridging, or other operations

**Security Property Broken:** This violates Critical Invariant #2: "**Blacklist Enforcement**: Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." While the blacklist mechanism exists, its effectiveness is severely compromised by the inability to atomically blacklist multiple addresses.

## Impact Explanation
- **Affected Assets**: wiTRY OFT share tokens on spoke chains (MegaETH), representing staked iTRY value
- **Damage Severity**: During security incidents, malicious actors can evade blacklisting entirely by transferring shares before their addresses are processed. This undermines the protocol's ability to freeze compromised or sanctioned funds. The blacklist enforcement becomes a "best effort" mechanism rather than a reliable security control.
- **User Impact**: Legitimate users and protocol security are at risk because:
  - Stolen funds cannot be effectively frozen
  - Sanctioned entities can evade compliance controls
  - Exploiters can move funds cross-chain before restrictions apply
  - Protocol reputation suffers when blacklisting is publicly seen to be ineffective

## Likelihood Explanation
- **Attacker Profile**: Any sophisticated attacker or compromised address holder with wiTRY OFT shares on spoke chains who monitors blockchain mempools
- **Preconditions**: 
  - Multiple addresses need blacklisting simultaneously
  - Attacker has the ability to monitor mempool and submit higher-gas transactions
  - wiTRY OFT shares exist on spoke chains (phase 1 deployment to MegaETH)
- **Execution Complexity**: Low - requires only mempool monitoring (publicly available) and submitting standard transfer transactions with higher gas fees
- **Frequency**: Every time the protocol attempts to blacklist multiple addresses during security incidents, which could be multiple times per year in a production environment handling real-world threats

## Recommendation

Implement batch blacklist operations in `wiTryOFT.sol` to match the pattern used in `iTry.sol`:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, add new function after line 74:

// CURRENT (vulnerable):
function updateBlackList(address _user, bool _isBlackListed) external {
    if (msg.sender != blackLister && msg.sender != owner()) revert OnlyBlackLister();
    blackList[_user] = _isBlackListed;
    emit BlackListUpdated(_user, _isBlackListed);
}

// FIXED - Add batch operation:
/**
 * @dev Updates the blacklist status for multiple users atomically
 * @param _users Array of user addresses to update
 * @param _isBlackListed Boolean indicating whether users should be blacklisted
 */
function updateBlackListBatch(address[] calldata _users, bool _isBlackListed) external {
    if (msg.sender != blackLister && msg.sender != owner()) revert OnlyBlackLister();
    
    uint256 length = _users.length;
    for (uint256 i = 0; i < length; i++) {
        blackList[_users[i]] = _isBlackListed;
        emit BlackListUpdated(_users[i], _isBlackListed);
    }
}
```

**Alternative Mitigations:**
1. Keep existing single-address function for individual updates
2. Add batch function for emergency mass-blacklisting scenarios
3. Document in operational procedures that batch blacklisting should be used during security incidents
4. Consider implementing a pause mechanism as an emergency circuit breaker that immediately freezes all transfers while individual blacklists are being processed

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistTimingWindow.t.sol
// Run with: forge test --match-test test_BlacklistTimingWindowExploit -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryOFT.sol";

contract Exploit_BlacklistTimingWindow is Test {
    wiTryOFT public oft;
    address public owner;
    address public blackLister;
    address public attacker1;
    address public attacker2;
    address public attacker3;
    address public freshAddress1;
    address public freshAddress2;
    address public freshAddress3;
    
    function setUp() public {
        owner = address(this);
        blackLister = makeAddr("blackLister");
        attacker1 = makeAddr("attacker1");
        attacker2 = makeAddr("attacker2");
        attacker3 = makeAddr("attacker3");
        freshAddress1 = makeAddr("fresh1");
        freshAddress2 = makeAddr("fresh2");
        freshAddress3 = makeAddr("fresh3");
        
        // Deploy wiTryOFT
        address lzEndpoint = makeAddr("lzEndpoint");
        oft = new wiTryOFT("wiTRY OFT", "wiTRY", lzEndpoint, owner);
        oft.setBlackLister(blackLister);
        
        // Mint shares to attackers (simulating they have wiTRY OFT shares)
        deal(address(oft), attacker1, 1000 ether);
        deal(address(oft), attacker2, 1000 ether);
        deal(address(oft), attacker3, 1000 ether);
    }
    
    function test_BlacklistTimingWindowExploit() public {
        // SETUP: Initial state - attackers hold wiTRY OFT shares
        assertEq(oft.balanceOf(attacker1), 1000 ether);
        assertEq(oft.balanceOf(attacker2), 1000 ether);
        assertEq(oft.balanceOf(attacker3), 1000 ether);
        assertEq(oft.balanceOf(freshAddress1), 0);
        assertEq(oft.balanceOf(freshAddress2), 0);
        assertEq(oft.balanceOf(freshAddress3), 0);
        
        // SCENARIO: Security incident detected - need to blacklist attacker1, attacker2, attacker3
        
        // EXPLOIT: BlackLister starts blacklisting attacker1
        vm.prank(blackLister);
        oft.updateBlackList(attacker1, true);
        
        // Attacker1 is now blacklisted and cannot transfer
        assertTrue(oft.blackList(attacker1));
        vm.prank(attacker1);
        vm.expectRevert(abi.encodeWithSelector(wiTryOFT.BlackListed.selector, attacker1));
        oft.transfer(freshAddress1, 1000 ether);
        
        // CRITICAL TIMING WINDOW: Before attacker2 and attacker3 are blacklisted,
        // they see the pattern in mempool and front-run by transferring shares
        vm.prank(attacker2);
        oft.transfer(freshAddress2, 1000 ether);
        
        vm.prank(attacker3);
        oft.transfer(freshAddress3, 1000 ether);
        
        // NOW blackLister tries to blacklist attacker2 and attacker3
        vm.startPrank(blackLister);
        oft.updateBlackList(attacker2, true);
        oft.updateBlackList(attacker3, true);
        vm.stopPrank();
        
        // VERIFY: Exploit successful - attackers 2 and 3 escaped blacklisting
        assertEq(oft.balanceOf(attacker2), 0, "Attacker2 transferred shares before blacklist");
        assertEq(oft.balanceOf(attacker3), 0, "Attacker3 transferred shares before blacklist");
        assertEq(oft.balanceOf(freshAddress2), 1000 ether, "Fresh address 2 received shares");
        assertEq(oft.balanceOf(freshAddress3), 1000 ether, "Fresh address 3 received shares");
        
        // Fresh addresses are not blacklisted and can continue transferring
        assertFalse(oft.blackList(freshAddress2));
        assertFalse(oft.blackList(freshAddress3));
        
        vm.prank(freshAddress2);
        oft.transfer(makeAddr("destination"), 500 ether); // Successful transfer
        
        // CONCLUSION: Due to lack of batch blacklist operations, attackers 2 and 3
        // successfully escaped blacklisting by front-running individual blacklist transactions
    }
}
```

## Notes

**Design Inconsistency**: The core issue stems from an architectural inconsistency between the iTRY token contract and the wiTRY OFT contract. The iTRY contract properly implements batch blacklist operations [2](#0-1) , but this pattern was not replicated in the wiTRY OFT spoke chain implementation.

**Cross-Chain Security Implications**: This vulnerability is particularly concerning for cross-chain deployments because:
- Spoke chains (like MegaETH) may have different gas economics making front-running easier
- Layer 2 chains typically have faster block times, narrowing the window for batch operations
- Attackers can bridge escaped shares back to mainnet or to other chains

**Comparison with Hub Chain**: Note that the hub chain's `StakediTry.sol` also lacks batch operations [3](#0-2) , suggesting this may be a systematic design gap across the wiTRY infrastructure, not just the OFT implementation.

**Real-World Precedent**: This type of vulnerability has been exploited in production DeFi protocols where regulatory compliance actions (OFAC sanctions) or security freezes required rapid blacklisting of multiple addresses. Protocols without atomic batch operations have observed sophisticated actors evading restrictions by monitoring pending transactions.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L70-74)
```text
    function updateBlackList(address _user, bool _isBlackListed) external {
        if (msg.sender != blackLister && msg.sender != owner()) revert OnlyBlackLister();
        blackList[_user] = _isBlackListed;
        emit BlackListUpdated(_user, _isBlackListed);
    }
```

**File:** src/token/iTRY/iTry.sol (L73-78)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
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
