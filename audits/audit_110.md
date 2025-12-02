## Title
Whitelist Bypass via Minting: Non-Whitelisted Recipients Can Receive iTRY in WHITELIST_ENABLED State

## Summary
The `_beforeTokenTransfer` function in iTry.sol fails to validate that the recipient (`to`) address has the `WHITELISTED_ROLE` during minting operations in `WHITELIST_ENABLED` state. This allows whitelisted users to mint iTRY tokens to any non-blacklisted address, bypassing the whitelist-only transfer invariant and enabling restricted token distribution during the controlled rollout phase.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` - `_beforeTokenTransfer` function, lines 177-222 [1](#0-0) 

**Intended Logic:** In `WHITELIST_ENABLED` state, the protocol should enforce that ONLY whitelisted users can send, receive, or burn iTRY tokens. This is a critical invariant for controlled token distribution during initial rollout or restricted operation phases.

**Actual Logic:** The minting path (lines 201-202) only validates:
- `hasRole(MINTER_CONTRACT, msg.sender)` - caller is the iTryIssuer
- `from == address(0)` - it's a mint operation
- `!hasRole(BLACKLISTED_ROLE, to)` - recipient is not blacklisted

**However, it does NOT check `hasRole(WHITELISTED_ROLE, to)`**, unlike the normal transfer case (lines 210-214) which requires all parties to be whitelisted.

**Exploitation Path:**
1. Protocol admin sets `transferState = TransferState.WHITELIST_ENABLED` to restrict token distribution to vetted participants only
2. Whitelisted user Alice calls `iTryIssuer.mintFor(bob, 1000000e18, minOut)` where Bob is NOT whitelisted but also not blacklisted
3. The iTryIssuer validates Alice has `_WHITELISTED_USER_ROLE` and proceeds with minting [2](#0-1) 

4. The `iTry.mint()` function calls `_mint()` which triggers `_beforeTokenTransfer(address(0), bob, amount)`
5. The check at lines 201-202 passes because Bob is not blacklisted, **even though Bob is not whitelisted**
6. Bob receives iTRY tokens despite not being whitelisted, violating the whitelist-only invariant

**Security Property Broken:** Critical Invariant #3 - "Whitelist Enforcement: In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY." [3](#0-2) 

## Impact Explanation
- **Affected Assets**: iTRY token distribution and protocol access control
- **Damage Severity**: During WHITELIST_ENABLED phase (typically used for controlled rollout, regulatory compliance, or security incidents), any whitelisted user can distribute iTRY to non-vetted parties. This undermines:
  - KYC/AML compliance requirements
  - Gradual rollout strategy
  - Risk management during security incidents
  - Regulatory restrictions on token holder eligibility
- **User Impact**: All non-whitelisted addresses can receive iTRY during supposedly restricted periods. This affects the entire protocol's access control model during critical phases.

## Likelihood Explanation
- **Attacker Profile**: Any whitelisted user with legitimate access to `iTryIssuer.mintFor()` function
- **Preconditions**: 
  - Protocol in `WHITELIST_ENABLED` state (likely during initial rollout or security incident response)
  - Attacker has `_WHITELISTED_USER_ROLE` in iTryIssuer
  - Attacker has DLF collateral to mint iTRY
- **Execution Complexity**: Single transaction calling `iTryIssuer.mintFor(non_whitelisted_address, amount, minOut)`
- **Frequency**: Can be exploited continuously by any whitelisted user until the transfer state changes to `FULLY_ENABLED` or the vulnerability is patched

## Recommendation

Add whitelist validation for the minting recipient in `WHITELIST_ENABLED` state: [4](#0-3) 

```solidity
// In src/token/iTRY/iTry.sol, _beforeTokenTransfer function, lines 201-202:

// CURRENT (vulnerable):
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
    // minting

// FIXED:
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) 
    && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - recipient must be whitelisted in WHITELIST_ENABLED state
```

**Alternative approach:** Add validation in `iTryIssuer.mintFor()` to check recipient whitelist status before minting:

```solidity
// In src/protocol/iTryIssuer.sol, mintFor function, after line 277:

// Validate recipient is whitelisted in iTry token (if in WHITELIST_ENABLED state)
if (iTryToken.transferState() == IiTryDefinitions.TransferState.WHITELIST_ENABLED) {
    require(iTryToken.hasRole(iTryToken.WHITELISTED_ROLE(), recipient), "Recipient must be whitelisted");
}
```

The same issue affects `redistributeLockedAmount()` at lines 205-207, which should also validate the `to` address is whitelisted in `WHITELIST_ENABLED` state.

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistBypass.t.sol
// Run with: forge test --match-test test_WhitelistBypassViaMinting -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_WhitelistBypass is Test {
    iTryIssuer public issuer;
    iTry public itry;
    IERC20 public dlf;
    address public admin;
    address public alice; // whitelisted user
    address public bob;   // non-whitelisted user
    
    function setUp() public {
        admin = makeAddr("admin");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy and initialize iTry token
        vm.startPrank(admin);
        itry = new iTry();
        itry.initialize(admin, address(issuer)); // issuer gets MINTER_CONTRACT role
        
        // Set transfer state to WHITELIST_ENABLED
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Add alice to whitelist (both in iTry and iTryIssuer)
        itry.addWhitelistAddress([alice]);
        issuer.addToWhitelist(alice);
        
        // Bob is NOT whitelisted - this is intentional
        
        vm.stopPrank();
    }
    
    function test_WhitelistBypassViaMinting() public {
        // SETUP: Verify initial state
        assertTrue(itry.transferState() == IiTryDefinitions.TransferState.WHITELIST_ENABLED, 
            "Transfer state should be WHITELIST_ENABLED");
        assertTrue(itry.hasRole(itry.WHITELISTED_ROLE(), alice), 
            "Alice should be whitelisted");
        assertFalse(itry.hasRole(itry.WHITELISTED_ROLE(), bob), 
            "Bob should NOT be whitelisted");
        assertFalse(itry.hasRole(itry.BLACKLISTED_ROLE(), bob), 
            "Bob should NOT be blacklisted");
        
        // EXPLOIT: Alice mints iTRY to non-whitelisted Bob
        vm.startPrank(alice);
        deal(address(dlf), alice, 1000000e18); // Give alice DLF collateral
        dlf.approve(address(issuer), 1000000e18);
        
        // Alice calls mintFor to mint iTRY to Bob (non-whitelisted)
        uint256 mintAmount = 1000000e18;
        issuer.mintFor(bob, mintAmount, 0);
        vm.stopPrank();
        
        // VERIFY: Bob received iTRY despite not being whitelisted
        uint256 bobBalance = itry.balanceOf(bob);
        assertGt(bobBalance, 0, "Vulnerability confirmed: Non-whitelisted Bob received iTRY in WHITELIST_ENABLED state");
        
        console.log("Bob's iTRY balance:", bobBalance);
        console.log("Whitelist bypass successful - invariant violated!");
    }
}
```

## Notes

This vulnerability specifically affects the `WHITELIST_ENABLED` state which is designed for controlled token distribution during:
- Initial protocol rollout
- KYC/AML compliance periods  
- Security incident response (restricting to known safe addresses)
- Regulatory-required restricted access periods

The same inconsistency exists in the `redistributeLockedAmount` minting path (lines 205-207), where admin can mint to non-whitelisted addresses when redistributing blacklisted user funds during `WHITELIST_ENABLED` state.

While this doesn't directly enable fund theft, it violates a critical access control invariant and could have serious regulatory/compliance implications during controlled rollout phases.

### Citations

**File:** src/token/iTRY/iTry.sol (L177-222)
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
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
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

**File:** src/protocol/iTryIssuer.sol (L270-306)
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

        // Emit event
        emit ITRYIssued(recipient, netDlfAmount, iTRYAmount, navPrice, mintFeeInBPS);
    }
```

**File:** src/token/iTRY/IiTryDefinitions.sol (L5-9)
```text
    enum TransferState {
        FULLY_DISABLED,
        WHITELIST_ENABLED,
        FULLY_ENABLED
    }
```
