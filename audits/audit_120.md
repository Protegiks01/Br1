## Title
Cross-Chain Blacklist Desynchronization Allows Blacklisted Users to Trade on Non-Synchronized Chains

## Summary
The iTRY token system implements independent blacklist mechanisms on each chain with no automatic synchronization. A user blacklisted on the hub chain (Ethereum) can continue trading iTRY tokens on spoke chains (e.g., MegaETH) where they have not yet been manually blacklisted, violating the protocol's core security invariant that "blacklisted users cannot send/receive/mint/burn iTry tokens in ANY case."

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` and `src/token/iTRY/crosschain/iTryTokenOFT.sol`

**Intended Logic:** According to the protocol documentation, blacklisted users should be prevented from sending, receiving, minting, or burning iTRY tokens "in any case." The blacklist mechanism is intended for "rescue operations in case of hacks or similar black swan events" to globally freeze compromised accounts across all chains where iTRY exists.

**Actual Logic:** The protocol implements separate, non-synchronized blacklist systems:

- **Hub Chain (Ethereum)**: Uses AccessControl role-based blacklist (`BLACKLISTED_ROLE`) managed through the `BLACKLIST_MANAGER_ROLE`. [1](#0-0) 

- **Spoke Chains (e.g., MegaETH)**: Uses simple mapping-based blacklist (`mapping(address => bool) public blacklisted`) managed by the owner. [2](#0-1) 

Each chain enforces its blacklist locally through `_beforeTokenTransfer`, but there is **no cross-chain synchronization mechanism** to propagate blacklist updates between chains.

**Exploitation Path:**
1. User bridges 10,000 iTRY tokens from Ethereum to MegaETH using the LayerZero OFT adapter
2. User gets blacklisted on Ethereum for suspicious activity (e.g., compromised private keys)
3. Admin intends to freeze all user's iTRY globally but must manually blacklist on each chain
4. Before admin can blacklist on MegaETH, user freely transfers/trades their 10,000 iTRY on MegaETH
5. User bypasses the intended global freeze, violating the security invariant

**Security Property Broken:** The protocol's critical invariant states: "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case." [3](#0-2)  The phrase "in any case" implies enforcement across all iTRY instances, including cross-chain deployments, which is not currently implemented.

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by users on chains where they have not been blacklisted
- **Damage Severity**: In emergency scenarios (compromised keys, malicious actors), blacklisted users can continue accessing and transferring potentially significant amounts of iTRY on non-synchronized chains, defeating the entire purpose of the emergency blacklist mechanism
- **User Impact**: Affects protocol security during crisis situations. If a user's wallet is compromised and admin blacklists them on Ethereum, the attacker can still extract value by trading iTRY on L2s where the blacklist hasn't propagated

## Likelihood Explanation
- **Attacker Profile**: Any user who bridges iTRY cross-chain before being blacklisted, or malicious actors who exploit the time window between blacklist on one chain and manual propagation to others
- **Preconditions**: iTRY must be deployed on multiple chains with users holding balances across chains
- **Execution Complexity**: Simple - user only needs to have pre-existing balance on a non-blacklisted chain or quickly bridge/trade before manual blacklist propagation
- **Frequency**: Every time a user needs to be blacklisted in an emergency scenario, creating a race condition between admin manual intervention and attacker actions

## Recommendation

Implement a cross-chain blacklist synchronization mechanism using LayerZero messaging:

```solidity
// In src/token/iTRY/iTry.sol, add cross-chain blacklist sync:

// NEW: Add LayerZero messaging for blacklist synchronization
function addBlacklistAddressCrossChain(
    address[] calldata users,
    uint32[] calldata dstEids
) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    // First, blacklist locally
    for (uint8 i = 0; i < users.length; i++) {
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
    }
    
    // Then, send LayerZero messages to all spoke chains
    for (uint8 j = 0; j < dstEids.length; j++) {
        bytes memory payload = abi.encode(SYNC_BLACKLIST, users);
        _sendMessage(dstEids[j], payload);
    }
}
```

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add message handler:

// NEW: Handle incoming blacklist sync messages
function _lzReceive(
    Origin calldata _origin,
    bytes32 _guid,
    bytes calldata _message,
    address _executor,
    bytes calldata _extraData
) internal virtual override {
    (uint8 msgType, address[] memory users) = abi.decode(_message, (uint8, address[]));
    
    if (msgType == SYNC_BLACKLIST) {
        // Automatically update local blacklist
        for (uint8 i = 0; i < users.length; i++) {
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        }
        emit BlacklistSynced(users);
    } else {
        super._lzReceive(_origin, _guid, _message, _executor, _extraData);
    }
}
```

**Alternative mitigation:** If cross-chain messaging is too complex, document clearly that blacklist/whitelist must be manually synchronized across all chains and implement monitoring/alerting systems to ensure rapid propagation during emergency scenarios.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistDesync.t.sol
// Run with: forge test --match-test test_BlacklistDesyncExploit -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_CrossChainBlacklistDesync is Test {
    iTry public hubToken;
    iTryTokenOFT public spokeToken;
    iTryTokenOFTAdapter public adapter;
    
    address public admin = makeAddr("admin");
    address public blacklistManager = makeAddr("blacklistManager");
    address public maliciousUser = makeAddr("maliciousUser");
    address public victim = makeAddr("victim");
    
    address public hubEndpoint = makeAddr("hubEndpoint");
    address public spokeEndpoint = makeAddr("spokeEndpoint");
    
    function setUp() public {
        // Deploy hub chain iTRY token
        vm.startPrank(admin);
        iTry implementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin // minter
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        hubToken = iTry(address(proxy));
        
        // Grant blacklist manager role
        hubToken.grantRole(hubToken.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        
        // Deploy adapter on hub chain
        adapter = new iTryTokenOFTAdapter(address(hubToken), hubEndpoint, admin);
        
        // Deploy OFT on spoke chain
        spokeToken = new iTryTokenOFT(spokeEndpoint, admin);
        vm.stopPrank();
    }
    
    function test_BlacklistDesyncExploit() public {
        // SETUP: Mint tokens to malicious user on hub chain
        vm.prank(admin);
        hubToken.mint(maliciousUser, 10000e18);
        
        // Simulate user bridging tokens to spoke chain (simplified)
        vm.prank(spokeEndpoint);
        spokeToken.lzReceive(
            ITryTokenOFT.Origin(1, bytes32(uint256(uint160(address(adapter)))), 1),
            bytes32(0),
            abi.encodePacked(bytes32(uint256(uint160(maliciousUser))), uint256(10000e18)),
            address(0),
            ""
        );
        
        assertEq(spokeToken.balanceOf(maliciousUser), 10000e18, "User should have tokens on spoke chain");
        
        // EXPLOIT: User gets blacklisted on hub chain
        vm.startPrank(blacklistManager);
        address[] memory usersToBlacklist = new address[](1);
        usersToBlacklist[0] = maliciousUser;
        hubToken.addBlacklistAddress(usersToBlacklist);
        vm.stopPrank();
        
        // Verify user is blacklisted on hub
        assertTrue(hubToken.hasRole(hubToken.BLACKLISTED_ROLE(), maliciousUser), "User should be blacklisted on hub");
        
        // VERIFY: User can still transfer on spoke chain (VULNERABILITY)
        vm.prank(maliciousUser);
        spokeToken.transfer(victim, 5000e18);
        
        assertEq(spokeToken.balanceOf(victim), 5000e18, "Victim received tokens from blacklisted user");
        assertEq(spokeToken.balanceOf(maliciousUser), 5000e18, "Blacklisted user retained remaining tokens");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- User blacklisted on hub chain: TRUE");
        console.log("- User can still trade on spoke chain: TRUE");
        console.log("- Invariant 'blacklisted users cannot transfer in ANY case' VIOLATED");
    }
}
```

## Notes

This vulnerability represents a fundamental architectural issue where the protocol's critical security mechanism (blacklist) operates in silos across different chains. While each chain's local blacklist enforcement works correctly, the lack of cross-chain synchronization creates a window of opportunity for malicious actors or compromised accounts to continue operating on chains where they haven't been manually blacklisted yet.

The severity is HIGH because:
1. It directly violates a documented critical invariant about blacklist enforcement
2. It defeats the stated purpose of the blacklist for "rescue operations in case of hacks or similar black swan events"  
3. The time window between blacklisting on one chain and manual propagation to others can be exploited
4. In emergency scenarios (compromised keys, malicious actors), this delay can result in significant fund movement before the blacklist is fully propagated

The comparison with wiTryOFT is instructive - that contract also has independent blacklist management but includes protective logic in `_credit` to redirect tokens if the recipient is blacklisted [4](#0-3) , showing awareness of cross-chain blacklist issues. However, this is still insufficient as it only handles the receive case, not the broader desynchronization problem.

### Citations

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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L35-84)
```text
    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;

    /// @notice Mapping of whitelisted addresses
    mapping(address => bool) public whitelisted;

    TransferState public transferState;

    /// @notice Emitted when minter address is updated
    event MinterUpdated(address indexed oldMinter, address indexed newMinter);

    /**
     * @notice Constructor for iTryTokenOFT
     * @param _lzEndpoint LayerZero endpoint address for MegaETH
     * @param _owner Address that will own this OFT (typically deployer)
     */
    constructor(address _lzEndpoint, address _owner) OFT("iTry Token", "iTRY", _lzEndpoint, _owner) {
        transferState = TransferState.FULLY_ENABLED;
        minter = _lzEndpoint;
    }

    /**
     * @notice Sets the minter address
     * @param _newMinter The new minter address
     */
    function setMinter(address _newMinter) external onlyOwner {
        address oldMinter = minter;
        minter = _newMinter;
        emit MinterUpdated(oldMinter, _newMinter);
    }

    /**
     * @param users List of address to be blacklisted
     * @notice Owner can blacklist addresses. Blacklisted addresses cannot transfer tokens.
     */
    function addBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        }
    }

    /**
     * @param users List of address to be removed from blacklist
     */
    function removeBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            blacklisted[users[i]] = false;
        }
    }
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L84-97)
```text
    function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
        internal
        virtual
        override
        returns (uint256 amountReceivedLD)
    {
        // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
        if (blackList[_to]) {
            emit RedistributeFunds(_to, _amountLD);
            return super._credit(owner(), _amountLD, _srcEid);
        } else {
            return super._credit(_to, _amountLD, _srcEid);
        }
    }
```
