## Title
Cross-Chain totalSupply Discrepancy Due to Failed Minting to Blacklisted Recipients on Spoke Chain

## Summary
When iTRY tokens are bridged from hub to spoke chain via LayerZero, if the recipient is blacklisted on the spoke chain, the minting transaction reverts in `_beforeTokenTransfer`, causing tokens to remain permanently locked on the hub chain without corresponding tokens minted on the spoke chain. This creates an irrecoverable totalSupply discrepancy and permanent loss of user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` - `_beforeTokenTransfer` function [1](#0-0) 

**Intended Logic:** When LayerZero delivers a cross-chain message to mint iTRY tokens on the spoke chain, the minting should succeed regardless of recipient blacklist status (similar to how the hub chain minter can mint), or gracefully handle blacklisted recipients by redirecting funds.

**Actual Logic:** The `_beforeTokenTransfer` hook checks if the recipient is blacklisted at line 145. If the recipient (`to`) is blacklisted, the condition `!blacklisted[to]` evaluates to false, causing none of the allowed conditions (lines 143-152) to match. The transaction falls through to line 154 and reverts with `OperationNotAllowed`, preventing the mint from completing.

**Exploitation Path:**
1. User locks 100 iTRY tokens on hub chain via `iTryTokenOFTAdapter`, specifying Alice's address as the recipient on spoke chain
2. iTryTokenOFTAdapter locks the tokens and LayerZero sends a cross-chain message to spoke chain
3. Alice's address is blacklisted on the spoke chain (either already blacklisted, or blacklisted during message flight via race condition)
4. LayerZero endpoint calls `lzReceive` on spoke chain `iTryTokenOFT`, which internally calls `_credit(Alice, 100 ether)`
5. `_credit` attempts to call `_mint(Alice, 100 ether)`
6. `_mint` triggers `_beforeTokenTransfer(address(0), Alice, 100 ether)`
7. Line 145 check fails because `!blacklisted[Alice]` is false
8. Transaction reverts at line 154 with `OperationNotAllowed`
9. Result: 100 iTRY locked permanently on hub chain, 0 iTRY minted on spoke chain - permanent fund loss

**Security Property Broken:** 
- **Blacklist Enforcement Invariant**: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" is over-enforced, causing fund loss instead of proper handling
- **Cross-chain Message Integrity**: "LayerZero messages for unstaking must be delivered to correct user with proper validation" - messages fail to deliver, violating delivery guarantee

## Impact Explanation
- **Affected Assets**: All iTRY tokens bridged to blacklisted addresses on spoke chain are permanently lost
- **Damage Severity**: 100% loss of bridged amount - tokens locked on hub with no recovery mechanism, no corresponding tokens on spoke
- **User Impact**: 
  - Any user bridging to an address that becomes blacklisted loses all funds
  - Affects legitimate users who get blacklisted mid-flight (race condition)
  - No way to recover locked tokens from hub chain adapter

## Likelihood Explanation
- **Attacker Profile**: 
  - Any unprivileged user can trigger this (even accidentally)
  - Malicious actors can intentionally grief by bridging to addresses they know will be blacklisted
  - Race condition: honest users bridging while admin blacklists destination
- **Preconditions**: 
  - Recipient address must be blacklisted on spoke chain
  - Hub chain doesn't check spoke chain blacklist status before locking
- **Execution Complexity**: Single cross-chain transaction - extremely simple to trigger
- **Frequency**: Can be exploited continuously - every bridge to blacklisted address causes permanent loss

## Recommendation

iTryTokenOFT should implement the same protective pattern as wiTryOFT by overriding `_credit` to handle blacklisted recipients: [2](#0-1) 

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add this function:

/**
 * @dev Override _credit to handle blacklisted recipients
 * @param _to The intended recipient address
 * @param _amountLD The amount to credit
 * @param _srcEid The source endpoint ID
 * @return amountReceivedLD The actual amount credited
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // If the recipient is blacklisted, redirect funds to the owner instead of reverting
    if (blacklisted[_to]) {
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

Alternative mitigation: Remove the blacklist check for minting operations in `_beforeTokenTransfer` when `msg.sender == minter`, allowing LayerZero to complete the mint even for blacklisted addresses (they still won't be able to transfer the tokens).

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedRecipientBridge.t.sol
// Run with: forge test --match-test test_BlacklistedRecipientCausesSupplyDiscrepancy -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_BlacklistedRecipientBridge is Test {
    iTry public hubToken;
    iTryTokenOFTAdapter public adapter;
    iTryTokenOFT public spokeOFT;
    
    address public deployer = address(0x1);
    address public alice = address(0x2);
    address public lzEndpoint = address(0x3);
    
    function setUp() public {
        vm.startPrank(deployer);
        
        // Deploy hub chain token
        hubToken = new iTry();
        hubToken.initialize(deployer, deployer);
        
        // Deploy adapter on hub
        adapter = new iTryTokenOFTAdapter(address(hubToken), lzEndpoint, deployer);
        
        // Deploy OFT on spoke
        spokeOFT = new iTryTokenOFT(lzEndpoint, deployer);
        
        // Mint tokens to alice on hub
        hubToken.mint(alice, 100 ether);
        
        vm.stopPrank();
    }
    
    function test_BlacklistedRecipientCausesSupplyDiscrepancy() public {
        // SETUP: Alice has 100 iTRY on hub, wants to bridge to spoke
        uint256 hubBalanceBefore = hubToken.balanceOf(alice);
        assertEq(hubBalanceBefore, 100 ether, "Alice should have 100 iTRY on hub");
        
        // Admin blacklists Alice on spoke chain (could happen during message flight)
        vm.prank(deployer);
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = alice;
        spokeOFT.addBlacklistAddress(blacklistAddresses);
        
        // EXPLOIT: Simulate LayerZero message delivery attempting to mint to blacklisted Alice
        // In real scenario: alice would call adapter.send() on hub, tokens get locked,
        // LayerZero delivers message to spoke, spoke tries to mint to alice
        
        vm.startPrank(lzEndpoint); // LayerZero endpoint is the minter
        
        // This simulates the _credit -> _mint call that would happen in lzReceive
        vm.expectRevert(abi.encodeWithSignature("OperationNotAllowed()"));
        spokeOFT.mint(alice, 100 ether); // This would be called internally by _credit
        
        vm.stopPrank();
        
        // VERIFY: Alice has 0 iTRY on spoke (mint failed)
        uint256 spokeBalance = spokeOFT.balanceOf(alice);
        assertEq(spokeBalance, 0, "Alice should have 0 iTRY on spoke - mint failed");
        
        // In real scenario, 100 iTRY would be locked in adapter on hub
        // but 0 iTRY minted on spoke = 100 iTRY permanent loss
        
        uint256 spokeTotalSupply = spokeOFT.totalSupply();
        assertEq(spokeTotalSupply, 0, "Spoke totalSupply is 0 despite hub having tokens locked");
        
        // This demonstrates the totalSupply discrepancy:
        // Hub: 100 iTRY locked in adapter (not burned)
        // Spoke: 0 iTRY minted
        // Result: 100 iTRY permanently lost, accounting broken
    }
}
```

## Notes

This vulnerability is particularly severe because:

1. **Comparison to wiTryOFT**: The protocol's own `wiTryOFT` contract already implements the correct pattern by overriding `_credit` to redirect blacklisted recipients to the owner, preventing fund loss. [3](#0-2)  iTryTokenOFT inexplicably lacks this same protection.

2. **No Recovery Mechanism**: Once tokens are locked on the hub chain due to failed spoke-side minting, there is no built-in mechanism to unlock them. The adapter's OFT pattern doesn't provide refund functionality for failed deliveries.

3. **Race Condition Risk**: Even legitimate users can lose funds if an admin blacklists an address between transaction submission and LayerZero message delivery.

4. **Transfer State Vulnerability**: The same issue occurs if `transferState` is set to `FULLY_DISABLED` on the spoke chain. [4](#0-3)  In this state, ALL operations revert, including minting from LayerZero, causing the same permanent fund loss.

5. **Not a Known Issue**: The Zellic audit mentions blacklist bypass via allowances on same-chain transfers, but does not cover this cross-chain blacklist failure mode that causes permanent fund loss.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-155)
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
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L174-176)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
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
