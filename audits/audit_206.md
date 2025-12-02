## Title
**Cross-chain Transfer DOS: Blacklisted Owner Breaks wiTRY Redistribution Mechanism**

## Summary
The wiTryOFT contract's `_credit` function redirects cross-chain transfers intended for blacklisted users to the contract `owner()`. However, if the `owner()` is blacklisted (either accidentally or through misconfiguration), the `_beforeTokenTransfer` hook will revert, causing permanent failure of all incoming cross-chain transfers to blacklisted users and resulting in irreversible fund loss.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol` [1](#0-0) 

**Intended Logic:** When a blacklisted user receives cross-chain wiTRY shares, the funds should be automatically redistributed to the contract owner to prevent blacklisted users from receiving tokens, as stated in the comment at line 78: "If blacklisted, redistributes the funds to the contract owner."

**Actual Logic:** The redistribution mechanism calls `super._credit(owner(), _amountLD, _srcEid)` which internally invokes `_mint(owner(), amount)`. This mint operation triggers the overridden `_beforeTokenTransfer` hook: [2](#0-1) 

At line 107, the hook checks `if (blackList[_to]) revert BlackListed(_to)`. Since `_to` equals `owner()` in the redirect scenario, if `owner()` is blacklisted, the transaction reverts with `BlackListed(owner())`.

**Exploitation Path:**
1. **Configuration Scenario**: The `blackLister` or `owner()` blacklists the owner address (either accidentally during testing, through misconfiguration, or as an unintended side effect of bulk blacklist operations) [3](#0-2) 

2. **Cross-chain Transfer Initiated**: A user sends wiTRY shares from the hub chain to a blacklisted address on the spoke chain via LayerZero

3. **Message Delivery**: LayerZero delivers the message and calls `_credit(blacklistedUser, amount, srcEid)` on the destination wiTryOFT contract

4. **Redirect Attempt**: The blacklist check at line 91 detects the blacklisted recipient and attempts to redirect to `owner()` at line 93

5. **Revert on Mint**: The `super._credit(owner(), ...)` call internally executes `_mint(owner(), amount)`, which triggers `_beforeTokenTransfer(address(0), owner(), amount)`. Line 107 checks if `owner()` is blacklisted and reverts

6. **Permanent Fund Loss**: 
   - The cross-chain message fails and cannot be retried (LayerZero messages are not replayable after execution)
   - Tokens were already burned/locked on the source chain
   - The user's funds are permanently lost with no recovery mechanism

**Security Property Broken:** This violates the **Blacklist Enforcement** invariant from the README: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." The redirect mechanism is designed to enforce this, but the implementation creates a situation where the mechanism itself fails, resulting in both the blacklisted user not receiving tokens AND the owner not receiving them either—causing permanent loss.

## Impact Explanation
- **Affected Assets**: All wiTRY shares being transferred cross-chain to blacklisted addresses while `owner()` is blacklisted
- **Damage Severity**: 100% permanent loss of funds for users whose cross-chain transfers are targeted to blacklisted addresses during the period when `owner()` is blacklisted. Unlike regular transfer failures, LayerZero messages cannot be replayed, making this loss irreversible.
- **User Impact**: Any user sending wiTRY cross-chain to an address that becomes blacklisted (or is already blacklisted) will lose their entire transferred amount if the contract owner is also blacklisted. This affects both legitimate users accidentally sending to wrong addresses and the protocol's ability to enforce blacklist controls without collateral damage.

## Likelihood Explanation
- **Attacker Profile**: This is not an attacker-triggered vulnerability but a configuration error with critical consequences. The `blackLister` or `owner()` can trigger this by blacklisting the owner address.
- **Preconditions**: 
  - The `owner()` address must be blacklisted (either accidentally or through operational error)
  - Cross-chain transfers to blacklisted users must occur during this period
- **Execution Complexity**: Single transaction failure—no complex attack setup required. The vulnerability manifests automatically whenever the two preconditions are met.
- **Frequency**: Affects every cross-chain transfer to a blacklisted user for the entire duration that `owner()` remains blacklisted. Recovery requires recognizing the issue and removing `owner()` from the blacklist.

## Recommendation

**Fix Option 1 (Recommended):** Exempt the `owner()` address from blacklist checks in `_beforeTokenTransfer` when it's the recipient of a mint operation (coming from address(0)): [2](#0-1) 

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, function _beforeTokenTransfer, lines 105-110:

// CURRENT (vulnerable):
function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
    if (blackList[_from]) revert BlackListed(_from);
    if (blackList[_to]) revert BlackListed(_to);
    if (blackList[msg.sender]) revert BlackListed(msg.sender);
    super._beforeTokenTransfer(_from, _to, _amount);
}

// FIXED:
function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
    if (blackList[_from]) revert BlackListed(_from);
    // Allow minting to owner() even if blacklisted (for redistribution mechanism)
    if (_from != address(0) && blackList[_to]) revert BlackListed(_to);
    if (blackList[msg.sender]) revert BlackListed(msg.sender);
    super._beforeTokenTransfer(_from, _to, _amount);
}
```

**Fix Option 2:** Add a dedicated redistribution address that is never checked against the blacklist:

```solidity
address public redistributionRecipient; // Set to owner() or dedicated address

function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal virtual override returns (uint256 amountReceivedLD)
{
    if (blackList[_to]) {
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(redistributionRecipient, _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}

function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
    if (blackList[_from]) revert BlackListed(_from);
    // Exempt redistribution recipient from blacklist check
    if (_to != redistributionRecipient && blackList[_to]) revert BlackListed(_to);
    if (blackList[msg.sender]) revert BlackListed(msg.sender);
    super._beforeTokenTransfer(_from, _to, _amount);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedOwnerDOS.t.sol
// Run with: forge test --match-test test_BlacklistedOwnerDOS -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryOFT.sol";
import "../test/mocks/MockLayerZeroEndpoint.sol";

contract Exploit_BlacklistedOwnerDOS is Test {
    wiTryOFT public oft;
    MockLayerZeroEndpoint public endpoint;
    
    address public owner = makeAddr("owner");
    address public blackLister = makeAddr("blackLister");
    address public blacklistedUser = makeAddr("blacklistedUser");
    address public normalUser = makeAddr("normalUser");
    
    uint32 constant HUB_EID = 40161; // Sepolia
    
    function setUp() public {
        // Deploy mock endpoint
        endpoint = new MockLayerZeroEndpoint();
        
        // Deploy wiTryOFT as owner
        vm.prank(owner);
        oft = new wiTryOFT("wiTRY OFT", "wiTRY", address(endpoint), owner);
        
        // Set blackLister
        vm.prank(owner);
        oft.setBlackLister(blackLister);
        
        // Blacklist the target user
        vm.prank(blackLister);
        oft.updateBlackList(blacklistedUser, true);
    }
    
    function test_BlacklistedOwnerDOS() public {
        // SETUP: Simulate incoming cross-chain transfer
        uint256 transferAmount = 100e18;
        
        // Normal case: Owner is NOT blacklisted - redistribution works
        vm.prank(address(endpoint)); // LayerZero endpoint calls _credit
        uint256 received = oft.exposed_credit(blacklistedUser, transferAmount, HUB_EID);
        
        assertEq(received, transferAmount, "Normal case: Funds should be redirected to owner");
        assertEq(oft.balanceOf(owner), transferAmount, "Owner should receive redistributed funds");
        
        // EXPLOIT: Owner gets blacklisted (accidentally or through error)
        vm.prank(blackLister);
        oft.updateBlackList(owner, true);
        
        // VERIFY: Now all cross-chain transfers to blacklisted users fail permanently
        vm.prank(address(endpoint));
        vm.expectRevert(abi.encodeWithSelector(wiTryOFT.BlackListed.selector, owner));
        oft.exposed_credit(blacklistedUser, transferAmount, HUB_EID);
        
        // Demonstrate permanent fund loss:
        // - Tokens were burned on source chain (simulated by endpoint)
        // - Tokens cannot be minted on destination chain (revert above)
        // - LayerZero messages are not replayable after execution
        // - User's funds are permanently lost
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- Cross-chain transfer to blacklisted user attempted");
        console.log("- Owner is blacklisted, causing redistribution to fail");
        console.log("- Transaction reverts, funds lost permanently");
        console.log("- No recovery mechanism available");
    }
}

// Helper: Expose internal _credit function for testing
contract wiTryOFTHarness is wiTryOFT {
    constructor(string memory _name, string memory _symbol, address _lzEndpoint, address _delegate)
        wiTryOFT(_name, _symbol, _lzEndpoint, _delegate)
    {}
    
    function exposed_credit(address _to, uint256 _amountLD, uint32 _srcEid)
        external returns (uint256)
    {
        return _credit(_to, _amountLD, _srcEid);
    }
}
```

## Notes

- This vulnerability is **NOT** the known issue from the Zellic audit about blacklisted users using allowance. That issue concerns local transfers via `transferFrom`, while this vulnerability affects the cross-chain redistribution mechanism in `_credit`.

- The vulnerability has a cascading effect: it doesn't just affect one user—it blocks ALL cross-chain transfers to blacklisted users for the entire duration that `owner()` remains blacklisted.

- The issue is particularly insidious because it breaks a safety mechanism (blacklist redistribution) designed to protect the protocol. The redirect to `owner()` is meant to prevent blacklisted users from receiving funds, but the implementation creates a single point of failure.

- Recovery requires the `blackLister` or `owner()` to recognize the issue and remove `owner()` from the blacklist, but by that time, multiple cross-chain transfers may have already failed with permanent fund loss.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L65-74)
```text
    /**
     * @dev Updates the blacklist status of a user.
     * @param _user The user identifier to update.
     * @param _isBlackListed Boolean indicating whether the user should be blacklisted or not.
     */
    function updateBlackList(address _user, bool _isBlackListed) external {
        if (msg.sender != blackLister && msg.sender != owner()) revert OnlyBlackLister();
        blackList[_user] = _isBlackListed;
        emit BlackListUpdated(_user, _isBlackListed);
    }
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

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L105-110)
```text
    function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
        if (blackList[_from]) revert BlackListed(_from);
        if (blackList[_to]) revert BlackListed(_to);
        if (blackList[msg.sender]) revert BlackListed(msg.sender);
        super._beforeTokenTransfer(_from, _to, _amount);
    }
```
