## Title
Blacklist Bypass via `redeemFor` Recipient Validation Failure Allows Sanctioned Users to Extract DLF Collateral

## Summary
The `redeemFor` function in `iTryIssuer.sol` validates that the caller (`msg.sender`) is whitelisted but fails to validate the `recipient` parameter against the iTRY blacklist. This allows whitelisted users to redeem iTRY and send the underlying DLF collateral to blacklisted addresses, enabling sanctioned users to extract value from the protocol.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/iTryIssuer.sol` - `redeemFor` function (lines 318-370) [1](#0-0) 

**Intended Logic:** The redemption system should prevent blacklisted users from extracting value from the protocol. The `redeemFor` function is designed to allow whitelisted users to redeem iTRY tokens for DLF collateral, with access control enforced via the `onlyRole(_WHITELISTED_USER_ROLE)` modifier.

**Actual Logic:** The function only validates that `msg.sender` (the caller) is whitelisted, but performs no validation on the `recipient` parameter. The iTRY tokens are burned from `msg.sender`, while DLF collateral is sent to `recipient` without checking if `recipient` is blacklisted on iTRY. [2](#0-1) 

This creates an asymmetry with the `mintFor` function, where the iTRY token's `_beforeTokenTransfer` hook validates that the recipient is not blacklisted: [3](#0-2) 

However, for redemptions, no such check exists in `iTryIssuer`, and the protection relies entirely on the external DLF token's blacklist (if any), which is a separate system from iTRY's blacklist managed by different roles. [4](#0-3) 

**Exploitation Path:**
1. User A (blacklisted on iTRY for sanctions/compliance reasons) wants to extract value from the protocol
2. User A coordinates with User B (whitelisted and owns iTRY tokens)
3. User B calls `issuer.redeemFor(userA_address, iTRY_amount, minOut)`
4. User B's iTRY is burned (valid since User B is whitelisted)
5. DLF collateral is transferred to User A
6. If User A is not blacklisted on the DLF token OR if the DLF blacklist is not synchronized with iTRY's blacklist, the transfer succeeds
7. User A successfully receives valuable DLF assets despite being sanctioned on iTRY

**Security Property Broken:** This violates the protocol's blacklist enforcement intent. While the invariant states "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case," the broader security goal from the README's "Areas of concern" is to prevent "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events." Allowing blacklisted users to receive the underlying collateral defeats the purpose of the sanctioning system. [5](#0-4) 

## Impact Explanation
- **Affected Assets**: DLF collateral tokens held in custody by the protocol
- **Damage Severity**: Blacklisted/sanctioned users can extract value from the protocol by receiving DLF collateral through a whitelisted proxy. The severity depends on whether the DLF token's blacklist is synchronized with iTRY's blacklist - if not synchronized or if DLF has no blacklist in production, the bypass is complete.
- **User Impact**: Any blacklisted user with access to a whitelisted user can extract their proportional share of DLF collateral, circumventing compliance/sanctions controls. This affects the protocol's ability to freeze assets of malicious actors or comply with regulatory requirements.

## Likelihood Explanation
- **Attacker Profile**: A blacklisted user who can coordinate with or coerce a whitelisted user (could be an accomplice, compromised account, or social engineering victim)
- **Preconditions**: 
  - Attacker must be blacklisted on iTRY
  - A whitelisted user must own iTRY tokens
  - Either: (a) DLF token has no blacklist, or (b) DLF blacklist is not synchronized with iTRY blacklist
- **Execution Complexity**: Single transaction - the whitelisted accomplice calls `redeemFor` with the blacklisted user's address as the recipient
- **Frequency**: Can be exploited as many times as the whitelisted user has iTRY to redeem

## Recommendation

Add recipient blacklist validation in the `redeemFor` function before processing the redemption:

```solidity
// In src/protocol/iTryIssuer.sol, function redeemFor, after line 325:

// CURRENT (vulnerable):
// No validation of recipient's blacklist status

// FIXED:
function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
    public
    onlyRole(_WHITELISTED_USER_ROLE)
    nonReentrant
    returns (bool fromBuffer)
{
    // Validate recipient address
    if (recipient == address(0)) revert CommonErrors.ZeroAddress();
    
    // ADD THIS CHECK: Validate recipient is not blacklisted on iTRY
    if (iTryToken.hasRole(iTryToken.BLACKLISTED_ROLE(), recipient)) {
        revert RecipientBlacklisted(recipient);
    }
    
    // ... rest of function logic
}
```

Alternative mitigation: If the protocol intends to allow whitelisted users to redeem on behalf of others, add explicit documentation and consider implementing a separate `redeemToBlacklisted` function that requires additional admin approval for exceptional cases.

## Proof of Concept

```solidity
// File: test/Exploit_RedeemForBlacklistBypass.t.sol
// Run with: forge test --match-test test_RedeemForBlacklistBypass -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/external/DLFToken.sol";

contract Exploit_RedeemForBlacklistBypass is Test {
    iTryIssuer public issuer;
    iTry public iTryToken;
    DLFToken public dlfToken;
    
    address public admin;
    address public whitelistedUser;
    address public blacklistedUser;
    address public blacklistManager;
    
    function setUp() public {
        admin = makeAddr("admin");
        whitelistedUser = makeAddr("whitelistedUser");
        blacklistedUser = makeAddr("blacklistedUser");
        blacklistManager = makeAddr("blacklistManager");
        
        // Deploy and initialize protocol (simplified for PoC)
        // In real test, use full deployment setup from iTryIssuer.base.t.sol
    }
    
    function test_RedeemForBlacklistBypass() public {
        // SETUP: Initial state
        // 1. WhitelistedUser has 1000 iTRY tokens
        // 2. BlacklistedUser is blacklisted on iTRY
        // 3. DLF token's blacklist is not synchronized (BlacklistedUser not blacklisted on DLF)
        
        uint256 redeemAmount = 500e18;
        uint256 initialDlfBalance = dlfToken.balanceOf(blacklistedUser);
        
        vm.startPrank(blacklistManager);
        address[] memory users = new address[](1);
        users[0] = blacklistedUser;
        iTryToken.addBlacklistAddress(users);
        vm.stopPrank();
        
        // Verify blacklistedUser cannot receive iTRY directly
        vm.startPrank(whitelistedUser);
        vm.expectRevert(); // Should revert due to blacklist
        iTryToken.transfer(blacklistedUser, 100e18);
        vm.stopPrank();
        
        // EXPLOIT: WhitelistedUser calls redeemFor to send DLF to blacklistedUser
        vm.startPrank(whitelistedUser);
        bool fromBuffer = issuer.redeemFor(blacklistedUser, redeemAmount, 0);
        vm.stopPrank();
        
        // VERIFY: Confirm exploit success
        uint256 finalDlfBalance = dlfToken.balanceOf(blacklistedUser);
        
        // BlacklistedUser successfully received DLF despite being blacklisted on iTRY
        assertGt(finalDlfBalance, initialDlfBalance, "Vulnerability confirmed: Blacklisted user received DLF through redeemFor");
        
        // This demonstrates that blacklisted users can extract value from the protocol
        // by having whitelisted users redeem on their behalf
    }
}
```

## Notes

This vulnerability exists due to incomplete recipient validation in the `redeemFor` function. While the DLF token (external dependency) has its own blacklist mechanism, this creates a dual-blacklist system where synchronization is not guaranteed. The iTryIssuer should enforce iTRY's blacklist rules when distributing the underlying collateral to maintain consistent sanctions enforcement across the protocol.

The issue is distinct from the known Zellic finding about blacklisted users transferring via allowance - that issue concerns iTRY token transfers themselves, whereas this issue concerns the redemption flow where DLF collateral is distributed to potentially blacklisted recipients without validation.

### Citations

**File:** src/protocol/iTryIssuer.sol (L318-325)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (bool fromBuffer)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
```

**File:** src/protocol/iTryIssuer.sol (L351-370)
```text
        _burn(msg.sender, iTRYAmount);

        // Check if buffer pool has enough DLF balance
        uint256 bufferBalance = liquidityVault.getAvailableBalance();

        if (bufferBalance >= grossDlfAmount) {
            // Buffer has enough - serve from buffer
            _redeemFromVault(recipient, netDlfAmount, feeAmount);

            fromBuffer = true;
        } else {
            // Buffer insufficient - serve from custodian
            _redeemFromCustodian(recipient, netDlfAmount, feeAmount);

            fromBuffer = false;
        }

        // Emit redemption event
        emit ITRYRedeemed(recipient, iTRYAmount, netDlfAmount, fromBuffer, redemptionFeeInBPS);
    }
```

**File:** src/token/iTRY/iTry.sol (L180-183)
```text
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/external/DLFToken.sol (L25-29)
```text
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused {
        require(!_isBlacklisted[from], "ERC20: sender is blacklisted");
        require(!_isBlacklisted[to], "ERC20: recipient is blacklisted");
        super._beforeTokenTransfer(from, to, amount);
    }
```

**File:** README.md (L122-127)
```markdown
- The total issued iTry in the Issuer contract should always be be equal or lower to the total value of the DLF under custody. It should not be possible to mint "unbacked" iTry through the issuer. This does not mean that _totalIssuedITry needs to be equal to iTry.totalSupply(), though: there could be more than one minter contract using different backing assets.
- In the context of this audit, the NAV price queried can be assumed to be correct. The Oracle implementation will perform additional checks on the data feed and revert if it encounters issues.
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
- Only non-blacklisted addresses can send/receive/burn iTry tokens in a FULLY_ENABLED transfer state.
- No adresses can send/receive tokens in a FULLY_DISABLED transfer state.
```
