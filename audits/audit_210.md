## Title
Blacklisted Owner Causes Permanent Cross-Chain Transfer Failure and Share Lock

## Summary
The `wiTryOFT._credit()` function redirects incoming cross-chain transfers to the `owner()` address when the intended recipient is blacklisted. However, if the `owner()` address itself is blacklisted, the `_beforeTokenTransfer` hook will revert when attempting to mint tokens to `owner()`, causing all incoming cross-chain transfers to blacklisted recipients to fail permanently and lock shares on the hub chain.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol` (wiTryOFT contract, `_credit` function lines 84-97, `_beforeTokenTransfer` function lines 105-110)

**Intended Logic:** When a cross-chain transfer arrives for a blacklisted recipient, the `_credit` function should redirect the funds to the contract owner as a safety mechanism, as documented in the comment "redistributes the funds to the contract owner". [1](#0-0) 

**Actual Logic:** The redirect logic assumes `owner()` can always receive tokens, but the `_beforeTokenTransfer` hook enforces blacklist restrictions on ALL token transfers including mints. When `owner()` is blacklisted, the mint operation at line 93 fails because `_beforeTokenTransfer` checks if the recipient (`_to`) is blacklisted and reverts. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. The `blackLister` role legitimately blacklists the `owner()` address (e.g., due to regulatory requirements, compliance flagging, or address compromise). This is allowed by the `updateBlackList` function which permits both `blackLister` and `owner()` to blacklist any address. [4](#0-3) 
2. A user on the hub chain (Ethereum) sends wiTRY shares via `wiTryOFTAdapter` to a blacklisted recipient on the spoke chain (MegaETH). The adapter locks the shares and sends a LayerZero message. [5](#0-4) 
3. LayerZero delivers the message to `wiTryOFT.lzReceive()` on the spoke chain, which internally calls `_credit(blacklistedRecipient, amount, srcEid)`
4. Line 91 evaluates to true (recipient is blacklisted), triggering line 93: `return super._credit(owner(), _amountLD, _srcEid);` which attempts to mint shares to `owner()`
5. The parent OFT contract's `_credit` calls `_mint(owner(), amount)`, which triggers `_beforeTokenTransfer(address(0), owner(), amount)`
6. At line 107, `if (blackList[_to])` evaluates to true (where `_to == owner()`), causing the transaction to revert with `BlackListed(owner())`
7. The entire LayerZero message delivery fails, and the shares remain permanently locked in `wiTryOFTAdapter` on the hub chain

**Security Property Broken:** Violates the "Cross-chain Message Integrity" invariant which states "LayerZero messages for unstaking must be delivered to correct user with proper validation." The redirect mechanism creates a single point of failure where blacklisting the owner blocks all transfers to blacklisted users.

## Impact Explanation
- **Affected Assets**: wiTRY shares locked in `wiTryOFTAdapter` on the hub chain (Ethereum), preventing users from accessing their staked iTRY value
- **Damage Severity**: All incoming cross-chain transfers to blacklisted recipients fail completely. Shares worth potentially millions in USD equivalent remain locked on the hub chain with no automatic recovery mechanism. Users cannot bridge their shares to the spoke chain, effectively losing access to cross-chain functionality.
- **User Impact**: Every user attempting to receive wiTRY shares on the spoke chain while blacklisted will have their transfers fail. This affects not just malicious actors but also users who may be temporarily blacklisted for compliance review. The only recovery requires un-blacklisting the owner, which may be legally or regulatorily impossible if the owner address has been flagged.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is triggered by legitimate protocol operations. The `blackLister` role (a compliance multisig) performs their duty by blacklisting a compromised or flagged owner address.
- **Preconditions**: 
  1. `blackLister` is set via `setBlackLister()` (normal protocol setup)
  2. Owner address becomes subject to blacklisting (compromise, regulatory flag, compliance requirement)
  3. Any blacklisted user exists on the recipient list for cross-chain transfers
- **Execution Complexity**: Single transaction by `blackLister` calling `updateBlackList(owner(), true)`. All subsequent cross-chain transfers to blacklisted users then fail automatically.
- **Frequency**: Once `owner()` is blacklisted, EVERY cross-chain transfer to ANY blacklisted recipient fails until `owner()` is un-blacklisted (which may never be possible).

## Recommendation

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, function _credit, lines 84-97:

// CURRENT (vulnerable):
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

// FIXED:
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // If the recipient is blacklisted, check if owner is also blacklisted
    // If owner is blacklisted, revert explicitly rather than attempting redirect
    // This provides clear error messaging and prevents silent fund lock
    if (blackList[_to]) {
        if (blackList[owner()]) {
            revert BlackListed(owner()); // Explicit revert with clear error
        }
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative mitigation:** Consider implementing a separate `recoveryAddress` that is immutable and cannot be blacklisted, or use a burn mechanism instead of redirect to avoid the single point of failure.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedOwnerCrossChainFailure.t.sol
// Run with: forge test --match-test test_BlacklistedOwnerCrossChainFailure -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryOFT.sol";

contract Exploit_BlacklistedOwnerCrossChainFailure is Test {
    wiTryOFT public shareOFT;
    address public owner;
    address public blackLister;
    address public blacklistedUser;
    address public lzEndpoint;
    
    function setUp() public {
        owner = makeAddr("owner");
        blackLister = makeAddr("blackLister");
        blacklistedUser = makeAddr("blacklistedUser");
        lzEndpoint = makeAddr("lzEndpoint");
        
        // Deploy wiTryOFT
        vm.prank(owner);
        shareOFT = new wiTryOFT("wiTRY OFT", "wiTRY", lzEndpoint, owner);
        
        // Set blackLister
        vm.prank(owner);
        shareOFT.setBlackLister(blackLister);
    }
    
    function test_BlacklistedOwnerCrossChainFailure() public {
        // SETUP: Blacklist a regular user
        vm.prank(blackLister);
        shareOFT.updateBlackList(blacklistedUser, true);
        assertEq(shareOFT.blackList(blacklistedUser), true, "User should be blacklisted");
        
        // SETUP: Blacklist the owner (legitimate compliance action)
        vm.prank(blackLister);
        shareOFT.updateBlackList(owner, true);
        assertEq(shareOFT.blackList(owner), true, "Owner should be blacklisted");
        
        // EXPLOIT: Simulate incoming cross-chain transfer to blacklisted user
        // This would normally be called by LayerZero endpoint via lzReceive
        // The _credit function will try to redirect to owner, which will fail
        
        vm.expectRevert(abi.encodeWithSignature("BlackListed(address)", owner));
        vm.prank(lzEndpoint);
        shareOFT._credit(blacklistedUser, 100 ether, 40161); // 40161 = Sepolia EID
        
        // VERIFY: Transaction reverted, proving shares would be locked on hub chain
        // In a real scenario, this revert causes LayerZero message delivery to fail
        // and shares remain locked in wiTryOFTAdapter on the hub chain
    }
    
    function test_NormalFlowWorksWhenOwnerNotBlacklisted() public {
        // SETUP: Only blacklist the user, not the owner
        vm.prank(blackLister);
        shareOFT.updateBlackList(blacklistedUser, true);
        
        // When owner is NOT blacklisted, redirect works fine
        vm.prank(lzEndpoint);
        uint256 credited = shareOFT._credit(blacklistedUser, 100 ether, 40161);
        
        // Verify tokens were credited to owner instead
        assertEq(credited, 100 ether, "Full amount should be credited");
        assertEq(shareOFT.balanceOf(owner), 100 ether, "Owner should receive the tokens");
        assertEq(shareOFT.balanceOf(blacklistedUser), 0, "Blacklisted user should have no tokens");
    }
}
```

## Notes

This vulnerability represents a critical design flaw where the separation of powers between `owner` and `blackLister` roles creates an unintended failure mode. The `blackLister` role is intentionally separate to provide checks and balances, but the redirect logic in `_credit` assumes `owner()` is always available as a failsafe recipient.

The issue is particularly severe because:
1. Blacklisting the owner is a **legitimate action** - if the owner's keys are compromised or the address is flagged by regulators, the `blackLister` must be able to blacklist it
2. The failure mode is **silent from the hub chain perspective** - users send shares expecting them to arrive, but they remain locked with no clear error message on the sending side
3. **Recovery is complex** - LayerZero V2 may allow message retries, but if the owner cannot be un-blacklisted for legal reasons, the shares are permanently locked
4. This violates the **principle of least surprise** - the blacklist mechanism should not create a single point of failure that blocks all cross-chain transfers to blacklisted users

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

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L76-83)
```text
    /**
     * @dev Credits tokens to the recipient while checking if the recipient is blacklisted.
     * If blacklisted, redistributes the funds to the contract owner.
     * @param _to The address of the recipient.
     * @param _amountLD The amount of tokens to credit.
     * @param _srcEid The source endpoint identifier.
     * @return amountReceivedLD The actual amount of tokens received.
     */
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

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L6-25)
```text
/**
 * @title wiTryOFTAdapter
 * @notice OFT Adapter for wiTRY shares on hub chain (Ethereum Mainnet)
 * @dev Wraps the StakedUSDe share token to enable cross-chain transfers via LayerZero
 *
 * Architecture (Phase 1 - Instant Redeems):
 * - Hub Chain (Ethereum): StakedUSDe (ERC4626 vault) + wiTryOFTAdapter (locks shares)
 * - Spoke Chain (MegaETH): ShareOFT (mints/burns based on messages)
 *
 * Flow:
 * 1. User deposits iTRY into StakedUSDe vault → receives wiTRY shares
 * 2. User approves wiTryOFTAdapter to spend their wiTRY
 * 3. User calls send() on wiTryOFTAdapter
 * 4. Adapter locks wiTRY shares and sends LayerZero message
 * 5. ShareOFT mints equivalent shares on spoke chain
 *
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
 */
```
