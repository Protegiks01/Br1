## Title
Cross-Chain Fund Theft via Blacklist Redirection in wiTryOFT._credit

## Summary
When users send wiTRY shares cross-chain to a blacklisted recipient via `wiTryOFT._credit`, the function silently redirects funds to the protocol owner instead of reverting. This causes permanent loss of user funds because LayerZero considers the message successfully delivered (no refund triggered), and the `RedistributeFunds` event doesn't record the original sender's address for potential recovery. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol` - `_credit` function (lines 84-97)

**Intended Logic:** The `_credit` function is called by LayerZero when cross-chain messages arrive. It should either successfully credit the intended recipient or revert the transaction to trigger LayerZero's refund mechanism (as seen in VaultComposerSync's try-catch pattern). [2](#0-1) 

**Actual Logic:** When the recipient is blacklisted, `_credit` redirects shares to `owner()` and returns success without reverting. This means LayerZero considers the delivery complete, preventing any refund to the original sender. [3](#0-2) 

**Exploitation Path:**
1. User A on Hub Chain (Ethereum) calls `wiTryOFTAdapter.send()` to send 1000 wiTRY shares to User B on Spoke Chain (MegaETH)
2. User A's 1000 shares are locked in wiTryOFTAdapter on Hub Chain [4](#0-3) 
3. LayerZero delivers message to wiTryOFT on Spoke Chain, calling `_credit(User B, 1000, srcEid)`
4. If User B is blacklisted, `_credit` emits `RedistributeFunds(User B, 1000)` and mints 1000 shares to `owner()` instead
5. LayerZero message completes successfully (no revert), so no refund mechanism triggers
6. Result: User A has lost 1000 shares (locked on Hub), User B has 0 shares, owner() has gained 1000 shares on Spoke

**Security Property Broken:** This violates the cross-chain message integrity invariant: "LayerZero messages for unstaking must be delivered to correct user with proper validation." It also causes unauthorized fund redistribution where the original sender loses their assets to the protocol owner.

## Impact Explanation
- **Affected Assets**: wiTRY share tokens sent cross-chain from Hub to Spoke chains
- **Damage Severity**: 100% loss of transferred shares for the sender. All shares sent to blacklisted addresses are permanently redirected to the protocol owner with no recovery mechanism.
- **User Impact**: Any user sending wiTRY shares cross-chain to a blacklisted address (whether accidentally or if the recipient gets blacklisted between send and receive) loses their entire transfer amount. While the `blackList` mapping is public and queryable, users typically don't check blacklist status before cross-chain transfers, and the recipient could be blacklisted mid-flight.

## Likelihood Explanation
- **Attacker Profile**: Not malicious - any legitimate user can accidentally trigger this by sending to a blacklisted address. This can also affect users sending to addresses that become blacklisted during the cross-chain message transit time.
- **Preconditions**: (1) User sends wiTRY shares cross-chain via LayerZero, (2) Recipient address is blacklisted on destination chain
- **Execution Complexity**: Single transaction cross-chain transfer. No special timing or complex setup required.
- **Frequency**: Every cross-chain transfer to a blacklisted address results in fund loss. Given that blacklist status can change dynamically and users rarely check recipient blacklist status before sending, this is a realistic ongoing risk.

## Recommendation

The `_credit` function should revert when the recipient is blacklisted, rather than redirecting to owner(). This allows LayerZero's error handling to trigger refunds to the original sender:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, function _credit, lines 84-97:

// CURRENT (vulnerable):
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    if (blackList[_to]) {
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}

// FIXED:
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // Revert if recipient is blacklisted to trigger refund mechanism
    if (blackList[_to]) {
        revert BlackListed(_to);
    }
    return super._credit(_to, _amountLD, _srcEid);
}
```

**Alternative mitigation:** If the protocol requires automatic redirection for compliance reasons, implement a refund mechanism that records the original sender in the RedistributeFunds event and allows owner to return funds:

```solidity
// Store original sender in event for potential refunds
event RedistributeFunds(address indexed intendedRecipient, address indexed originalSender, uint256 amount);

function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    if (blackList[_to]) {
        // Extract original sender from LayerZero message context if available
        address originalSender = _getOriginalSender(); // Would need implementation
        emit RedistributeFunds(_to, originalSender, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

However, the first solution (reverting) is strongly recommended as it leverages LayerZero's built-in refund mechanism and prevents any fund loss.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistRedirectionFundLoss.t.sol
// Run with: forge test --match-test test_BlacklistRedirectionCausesFundLoss -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryOFT.sol";
import "../src/token/wiTRY/crosschain/wiTryOFTAdapter.sol";
import "../src/token/wiTRY/StakediTry.sol";

contract Exploit_BlacklistRedirection is Test {
    wiTryOFT oftSpoke;
    wiTryOFTAdapter oftHub;
    StakediTry vault;
    
    address userA = address(0x1); // Sender on Hub
    address userB = address(0x2); // Intended recipient on Spoke (will be blacklisted)
    address owner = address(0x3);
    address lzEndpoint = address(0x4);
    
    function setUp() public {
        vm.startPrank(owner);
        
        // Deploy wiTryOFT on spoke chain
        oftSpoke = new wiTryOFT("wiTRY Shares", "wiTRY", lzEndpoint, owner);
        
        // Set up blacklist manager
        oftSpoke.setBlackLister(owner);
        
        vm.stopPrank();
    }
    
    function test_BlacklistRedirectionCausesFundLoss() public {
        uint256 transferAmount = 1000e18;
        
        // SETUP: Blacklist userB on spoke chain
        vm.prank(owner);
        oftSpoke.updateBlackList(userB, true);
        assertTrue(oftSpoke.blackList(userB), "UserB should be blacklisted");
        
        // EXPLOIT: Simulate LayerZero message delivery
        // In real scenario, userA sent shares from Hub to userB on Spoke
        // LayerZero calls _credit on the spoke chain
        vm.prank(lzEndpoint);
        uint256 credited = oftSpoke._credit(userB, transferAmount, uint32(1));
        
        // VERIFY: Funds were redirected to owner instead of userB
        assertEq(oftSpoke.balanceOf(userB), 0, "UserB should have 0 shares (blacklisted)");
        assertEq(oftSpoke.balanceOf(owner), transferAmount, "Owner should have received all shares");
        assertEq(credited, transferAmount, "_credit returned success (no revert)");
        
        // The critical issue: userA on Hub has locked shares, userB got nothing, owner got the shares
        // No refund mechanism triggered because _credit succeeded
        console.log("Fund Loss Confirmed:");
        console.log("- UserA lost shares on Hub (locked in adapter)");
        console.log("- UserB received 0 shares on Spoke (blacklisted)");
        console.log("- Owner gained shares on Spoke:", oftSpoke.balanceOf(owner));
        console.log("- No refund possible (LayerZero message completed successfully)");
    }
}
```

## Notes

**Comparison with iTryTokenOFT:** The sister contract `iTryTokenOFT` does NOT override `_credit`, which means it uses the default LayerZero OFT implementation. When attempting to mint to a blacklisted address in iTryTokenOFT, the `_beforeTokenTransfer` hook would revert, causing the entire `_credit` operation to fail and triggering LayerZero's error handling. [5](#0-4) 

**Why this differs from iTry's behavior:** The main iTry token on Ethereum reverts when attempting to transfer to blacklisted addresses via `_beforeTokenTransfer`. [6](#0-5)  The wiTryOFT contract should follow the same pattern to maintain consistency and prevent fund loss.

**Event insufficient for tracking:** The `RedistributeFunds` event only logs the intended recipient and amount, not the original sender. [7](#0-6)  This makes it impossible for the protocol to identify and refund affected users, even if the owner wanted to manually return misdirected funds.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L38-38)
```text
    event RedistributeFunds(address indexed user, uint256 amount);
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

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L133-147)
```text
        /// @dev try...catch to handle the compose operation. if it fails we refund the user
        try this.handleCompose{value: msg.value}(_composeSender, composeFrom, composeMsg, amount) {
            emit Sent(_guid);
        } catch (bytes memory _err) {
            /// @dev A revert where the msg.value passed is lower than the min expected msg.value is handled separately
            /// This is because it is possible to re-trigger from the endpoint the compose operation with the right msg.value
            if (bytes4(_err) == InsufficientMsgValue.selector) {
                assembly {
                    revert(add(32, _err), mload(_err))
                }
            }

            _refund(_composeSender, _message, amount, tx.origin);
            emit Refunded(_guid);
        }
```

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L26-33)
```text
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-177)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L177-196)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```
