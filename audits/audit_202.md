## Title
Blacklisted Users Can Permanently Escape Blacklist Due to Missing Revert Handling in redistributeBlackListedFunds

## Summary
The `redistributeBlackListedFunds` function in `wiTryOFT.sol` temporarily removes a user from the blacklist before calling `_transfer`, but fails to restore the blacklist status if the transfer reverts. This allows blacklisted users to permanently escape blacklist restrictions when the owner attempts to redistribute their funds with incorrect parameters.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol` (function `redistributeBlackListedFunds`, lines 117-127) [1](#0-0) 

**Intended Logic:** The function should temporarily remove a user from the blacklist, transfer their funds to the owner, then restore their blacklist status. This allows the owner to recover funds from blacklisted addresses without requiring the user's authorization.

**Actual Logic:** The function sets `blackList[_from] = false` on line 122, then calls `_transfer(_from, owner(), _amount)` on line 123. If `_transfer` reverts for ANY reason (insufficient balance, owner is blacklisted, arithmetic overflow, etc.), line 124 (`blackList[_from] = true`) never executes, leaving the user permanently unblacklisted.

**Exploitation Path:**
1. User is blacklisted (legitimately or wrongly) and holds 100 wiTRY shares on spoke chain
2. Owner calls `redistributeBlackListedFunds(user, 150)` with amount exceeding user's balance
3. Line 122 executes: `blackList[user] = false` - user is temporarily unblacklisted
4. Line 123 attempts: `_transfer(user, owner(), 150)` - reverts due to insufficient balance
5. Line 124 never executes - user remains `blackList[user] = false`
6. User immediately transfers all 100 shares to another address before owner can re-blacklist them
7. Owner's attempt to recover funds has backfired, allowing sanctioned address to move funds

**Security Property Broken:** Violates the **Blacklist Enforcement** invariant: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." The user who should remain blacklisted can now freely transfer tokens.

## Impact Explanation
- **Affected Assets**: wiTRY shares on spoke chains (MegaETH) held by blacklisted addresses
- **Damage Severity**: Blacklisted users (potentially sanctioned addresses or malicious actors) can bypass blacklist restrictions and transfer funds. While this requires an owner error to trigger, it violates a critical security invariant. The owner loses the ability to enforce blacklist restrictions until they manually re-blacklist the user, creating a race condition window.
- **User Impact**: Affects protocol compliance and security. If blacklisted addresses represent sanctioned entities or compromised accounts, their ability to move funds creates legal and security risks for the protocol.

## Likelihood Explanation
- **Attacker Profile**: Blacklisted user (unprivileged, but motivated to escape restrictions)
- **Preconditions**: 
  - User must be blacklisted on wiTryOFT (spoke chain)
  - Owner must attempt to redistribute funds with incorrect parameters (amount > balance, or owner is blacklisted)
  - User must monitor mempool or have system to detect unblacklisting
- **Execution Complexity**: Medium - Requires owner error, but feasible scenarios:
  - Owner miscalculates user's balance
  - Owner is accidentally blacklisted by blackLister before calling redistributeBlackListedFunds
  - Race condition between blackLister and owner actions
- **Frequency**: Once per owner mistake, but creates permanent escape unless owner manually re-blacklists

## Recommendation
Wrap the `_transfer` call in a try-catch block to ensure blacklist status is restored even on revert:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, function redistributeBlackListedFunds, lines 117-127:

// CURRENT (vulnerable):
function redistributeBlackListedFunds(address _from, uint256 _amount) external onlyOwner {
    if (!blackList[_from]) revert NotBlackListed();
    
    blackList[_from] = false;
    _transfer(_from, owner(), _amount);
    blackList[_from] = true;
    
    emit RedistributeFunds(_from, _amount);
}

// FIXED:
function redistributeBlackListedFunds(address _from, uint256 _amount) external onlyOwner {
    if (!blackList[_from]) revert NotBlackListed();
    
    blackList[_from] = false;
    try this._transferWrapper(_from, owner(), _amount) {
        // Transfer succeeded
    } catch {
        // Transfer failed - restore blacklist before reverting
        blackList[_from] = true;
        revert TransferFailed();
    }
    blackList[_from] = true;
    
    emit RedistributeFunds(_from, _amount);
}

// Add helper function to enable try-catch (can't try-catch internal functions):
function _transferWrapper(address from, address to, uint256 amount) external {
    require(msg.sender == address(this), "Only self");
    _transfer(from, to, amount);
}
```

**Alternative mitigation:** Add pre-flight validation checks:

```solidity
function redistributeBlackListedFunds(address _from, uint256 _amount) external onlyOwner {
    if (!blackList[_from]) revert NotBlackListed();
    
    // Validate before state changes
    if (balanceOf(_from) < _amount) revert InsufficientBalance();
    if (blackList[owner()]) revert OwnerBlacklisted();
    
    blackList[_from] = false;
    _transfer(_from, owner(), _amount);
    blackList[_from] = true;
    
    emit RedistributeFunds(_from, _amount);
}
```

## Proof of Concept
```solidity
// File: test/Exploit_BlacklistBypass.t.sol
// Run with: forge test --match-test test_BlacklistBypassViaFailedRedistribution -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryOFT.sol";

contract Exploit_BlacklistBypass is Test {
    wiTryOFT public oft;
    address public owner;
    address public blacklistedUser;
    address public recipient;
    
    function setUp() public {
        owner = address(this);
        blacklistedUser = address(0x1234);
        recipient = address(0x5678);
        
        // Deploy wiTryOFT
        oft = new wiTryOFT("wiTRY", "wiTRY", address(0xdead), owner);
        
        // Mint tokens to blacklisted user
        vm.prank(address(oft)); // Simulate LayerZero message minting
        oft.transfer(blacklistedUser, 100 ether);
    }
    
    function test_BlacklistBypassViaFailedRedistribution() public {
        // SETUP: Blacklist the user
        oft.updateBlackList(blacklistedUser, true);
        
        // Verify user is blacklisted and cannot transfer
        vm.prank(blacklistedUser);
        vm.expectRevert();
        oft.transfer(recipient, 50 ether);
        
        assertTrue(oft.blackList(blacklistedUser), "User should be blacklisted");
        
        // EXPLOIT: Owner tries to redistribute with amount exceeding balance
        uint256 userBalance = oft.balanceOf(blacklistedUser);
        assertEq(userBalance, 100 ether);
        
        // Owner mistakenly tries to redistribute more than user has
        vm.expectRevert(); // _transfer will revert due to insufficient balance
        oft.redistributeBlackListedFunds(blacklistedUser, 150 ether);
        
        // VERIFY: User is now UNBLACKLISTED due to failed redistribution
        assertFalse(oft.blackList(blacklistedUser), "User should be unblacklisted after failed redistribution");
        
        // User can now transfer funds freely
        vm.prank(blacklistedUser);
        oft.transfer(recipient, 100 ether);
        
        assertEq(oft.balanceOf(recipient), 100 ether, "Blacklisted user successfully transferred funds");
        assertEq(oft.balanceOf(blacklistedUser), 0, "Blacklisted user emptied their balance");
    }
}
```

## Notes
This vulnerability answers the security question: **Yes, the owner CAN use `redistributeBlackListedFunds` to recover shares WITHOUT needing the user's private key** (since `_transfer` is an internal function that doesn't require authorization). However, the implementation has a critical flaw where failed transfers permanently unblacklist users.

The issue is distinct from the known Zellic finding about "Blacklisted user can transfer tokens using allowance" - that's about msg.sender validation in `_beforeTokenTransfer`, while this is about incomplete state restoration in `redistributeBlackListedFunds`. [2](#0-1) 

The `_beforeTokenTransfer` hook will not catch this escape because once `blackList[_from]` is set to false on line 122, the user is legitimately unblacklisted from the contract's perspective.

### Citations

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
