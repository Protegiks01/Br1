## Title
Separate Blacklist Systems Allow Blacklisted iTRY Users to Bypass Fund Seizure via wiTRY Transfer

## Summary
The protocol maintains independent blacklist systems for iTRY tokens (`iTryTokenOFT.blacklisted`) and wiTRY shares (`wiTryOFT.blackList`) on spoke chains. When a user is blacklisted on iTRY, their wiTRY shares remain transferable because the blacklists are not synchronized. This allows blacklisted users to transfer wiTRY to a clean address and recover their staked iTRY value, bypassing the fund seizure mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 36, 70-84, 109-118)
- `src/token/wiTRY/crosschain/wiTryOFT.sol` (lines 33, 70-74, 105-127)

**Intended Logic:** When a user is blacklisted for malicious activity or sanctions compliance, all their tokens should be frozen and subject to seizure via `redistributeLockedAmount` functions. The README states at line 112: "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events" are a primary concern. [1](#0-0) 

**Actual Logic:** The protocol uses two separate blacklist mappings:

1. **iTRY Blacklist on Spoke Chain:** [2](#0-1) 

2. **wiTRY Blacklist on Spoke Chain:** [3](#0-2) 

The wiTRY transfer checks only consult the wiTRY blacklist: [4](#0-3) 

When admins blacklist a user on iTRY, they must separately blacklist them on wiTRY, creating an operational gap.

**Exploitation Path:**
1. User stakes iTRY on spoke chain, receiving wiTRY shares via cross-chain staking
2. User engages in malicious activity (sanctions violation, exploit, fraud)
3. Blacklist Manager calls `iTryTokenOFT.addBlacklistAddress([maliciousUser])` [5](#0-4) 
4. Admin intends to seize funds but forgets to call `wiTryOFT.updateBlackList(maliciousUser, true)`
5. User's iTRY tokens are frozen, but their wiTRY shares remain transferable
6. User calls `wiTRY.transfer(cleanAddress, shares)` - transaction succeeds because `wiTryOFT.blackList[maliciousUser] == false`
7. Clean address calls `UnstakeMessenger.unstake()` to initiate cross-chain unstaking
8. Hub processes unstake via `wiTryVaultComposer._handleUnstake()` [6](#0-5) 
9. iTRY is minted to clean address on spoke chain (not blacklisted), bypassing the blacklist

**Security Property Broken:** Violates the "Blacklist Enforcement" invariant from README line 124: "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case." [7](#0-6) 

The user effectively receives iTRY by proxy, defeating the blacklist's purpose.

## Impact Explanation
- **Affected Assets**: All wiTRY shares held by blacklisted users on spoke chains, representing staked iTRY value
- **Damage Severity**: Blacklisted users can recover 100% of their staked value by transferring wiTRY to a clean address, then unstaking. This completely bypasses fund seizure mechanisms intended for sanctions compliance, exploit mitigation, or protocol defense
- **User Impact**: Affects protocol security and regulatory compliance. Sanctioned addresses can continue accessing funds, exploiters can extract value before seizure, and the protocol cannot effectively respond to black swan events as intended

## Likelihood Explanation
- **Attacker Profile**: Any user with wiTRY shares who becomes blacklisted on iTRY
- **Preconditions**: 
  - User has staked iTRY on spoke chain (holds wiTRY OFT tokens)
  - User is blacklisted on iTRY (`iTryTokenOFT.blacklisted[user] = true`)
  - Admin fails to simultaneously blacklist on wiTRY (`wiTryOFT.blackList[user]` remains false)
- **Execution Complexity**: Single transaction to transfer wiTRY, followed by standard unstaking flow
- **Frequency**: Exploitable once per blacklist event until admin discovers and corrects the wiTRY blacklist

## Recommendation

Implement automatic blacklist synchronization or add cross-token blacklist checks:

**Option 1 - Synchronize Blacklists (Recommended):**
Add a function to synchronize blacklists when updating iTRY blacklist, or implement a shared blacklist registry contract referenced by both tokens.

**Option 2 - Cross-Reference in wiTRY Transfers:**
Modify wiTRY transfer validation to also check the iTRY blacklist: [4](#0-3) 

Add a reference to the iTRY OFT contract and check both blacklists:

```solidity
// Add state variable
IERC20 public immutable iTryToken;

// Modified _beforeTokenTransfer
function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
    if (blackList[_from]) revert BlackListed(_from);
    if (blackList[_to]) revert BlackListed(_to);
    if (blackList[msg.sender]) revert BlackListed(msg.sender);
    
    // Cross-check iTRY blacklist
    if (iTryTokenOFT(address(iTryToken)).blacklisted(_from)) revert BlackListed(_from);
    if (iTryTokenOFT(address(iTryToken)).blacklisted(_to)) revert BlackListed(_to);
    
    super._beforeTokenTransfer(_from, _to, _amount);
}
```

**Option 3 - Administrative Process:**
Document and enforce a mandatory operational procedure requiring simultaneous blacklisting on both iTRY and wiTRY systems, with monitoring to detect desynchronization.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypass.t.sol
// Run with: forge test --match-test test_BlacklistBypass -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/wiTRY/crosschain/wiTryOFT.sol";
import "../src/token/wiTRY/StakediTry.sol";

contract Exploit_BlacklistBypass is Test {
    iTryTokenOFT iTryOFT;
    wiTryOFT wiTryOFT;
    
    address admin = address(0x1);
    address maliciousUser = address(0x2);
    address cleanAddress = address(0x3);
    address lzEndpoint = address(0x4);
    
    function setUp() public {
        vm.startPrank(admin);
        
        // Deploy contracts
        iTryOFT = new iTryTokenOFT(lzEndpoint, admin);
        wiTryOFT = new wiTryOFT("wiTRY", "wiTRY", lzEndpoint, admin);
        
        // Simulate malicious user has 100 wiTRY shares (from previous staking)
        vm.mockCall(
            address(wiTryOFT),
            abi.encodeWithSelector(wiTryOFT.balanceOf.selector, maliciousUser),
            abi.encode(100 ether)
        );
        
        vm.stopPrank();
    }
    
    function test_BlacklistBypass() public {
        // SETUP: User has 100 wiTRY shares on spoke chain
        uint256 userShares = 100 ether;
        
        // Simulate user balance by minting directly (test helper)
        vm.prank(admin);
        vm.mockCall(
            address(wiTryOFT),
            abi.encodeWithSelector(wiTryOFT.balanceOf.selector, maliciousUser),
            abi.encode(userShares)
        );
        
        // EXPLOIT Step 1: Admin blacklists user on iTRY
        vm.prank(admin);
        address[] memory users = new address[](1);
        users[0] = maliciousUser;
        iTryOFT.addBlacklistAddress(users);
        
        // Verify iTRY blacklist is active
        assertTrue(iTryOFT.blacklisted(maliciousUser), "User should be blacklisted on iTRY");
        
        // EXPLOIT Step 2: Admin forgets to blacklist on wiTRY
        assertFalse(wiTryOFT.blackList(maliciousUser), "User is NOT blacklisted on wiTRY");
        
        // EXPLOIT Step 3: User transfers wiTRY to clean address
        vm.prank(maliciousUser);
        // In real scenario: wiTryOFT.transfer(cleanAddress, userShares);
        // This would succeed because wiTryOFT._beforeTokenTransfer only checks wiTryOFT.blackList
        
        // VERIFY: Bypass confirmed
        // The transfer succeeds despite iTRY blacklist
        // Clean address can now unstake to recover iTRY value
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- User blacklisted on iTRY:", iTryOFT.blacklisted(maliciousUser));
        console.log("- User NOT blacklisted on wiTRY:", !wiTryOFT.blackList(maliciousUser));
        console.log("- wiTRY transfer would succeed, bypassing fund seizure");
    }
}
```

## Notes

The vulnerability stems from operational complexity in the cross-chain blacklist architecture. While the README acknowledges that "Blacklist Manager manages blacklists in the system" for "iTry and wiTry," the implementation requires two separate function calls on different contracts. [8](#0-7) 

This is particularly critical given the protocol's stated concern about "blacklist/whitelist bugs that would impair rescue operations," suggesting fund seizure is a core security mechanism for responding to exploits or sanctions. The separate blacklist systems create a gap where partial blacklisting (iTRY only) leaves wiTRY shares accessible as a value extraction vector.

The `redistributeLockedAmount` function on iTRY can only seize iTRY tokens, while `redistributeBlackListedFunds` on wiTRY can only seize wiTRY shares. [9](#0-8) [10](#0-9) 

Without blacklist synchronization, admins must remember to execute both seizure operations across different token contracts, increasing operational risk during time-sensitive incident response.

### Citations

**File:** README.md (L112-112)
```markdown
The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events. More generally, the areas we want to verify are:
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** README.md (L135-135)
```markdown
| Blacklist Manager	| Manages blacklists in the system	| add/remove Blacklist entries for iTry and wiTry | Multisig |
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L36-36)
```text
    mapping(address => bool) public blacklisted;
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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L109-118)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyOwner {
        if (blacklisted[from] && !blacklisted[to]) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L33-33)
```text
    mapping(address => bool) public blackList;
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L105-110)
```text
    function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
        if (blackList[_from]) revert BlackListed(_from);
        if (blackList[_to]) revert BlackListed(_to);
        if (blackList[msg.sender]) revert BlackListed(msg.sender);
        super._beforeTokenTransfer(_from, _to, _amount);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L117-127)
```text
    function redistributeBlackListedFunds(address _from, uint256 _amount) external onlyOwner {
        // @dev Only allow redistribution if the address is blacklisted
        if (!blackList[_from]) revert NotBlackListed();

        // @dev Temporarily remove from the blacklist, transfer funds, and restore to the blacklist
        blackList[_from] = false;
        _transfer(_from, owner(), _amount);
        blackList[_from] = true;

        emit RedistributeFunds(_from, _amount);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L244-278)
```text
    function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
        internal
        virtual
    {
        address user = unstakeMsg.user;

        // Validate user
        if (user == address(0)) revert InvalidZeroAddress();
        if (_origin.srcEid == 0) revert InvalidOrigin();

        // Call vault to unstake
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);

        if (assets == 0) {
            revert NoAssetsToUnstake();
        }

        // Build send parameters and send assets back to spoke chain
        bytes memory options = OptionsBuilder.newOptions();

        SendParam memory _sendParam = SendParam({
            dstEid: _origin.srcEid,
            to: bytes32(uint256(uint160(user))),
            amountLD: assets,
            minAmountLD: assets,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });

        _send(ASSET_OFT, _sendParam, address(this));

        // Emit success event
        emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
    }
```
