## Title
FastAccessVault Allows Permanent Loss of Funds Through Unchecked iTryIssuer Receiver Address

## Summary
The `processTransfer` function in `FastAccessVault.sol` fails to validate whether the receiver address is the iTryIssuer contract itself. This allows whitelisted users to call `redeemFor` with the iTryIssuer as the recipient, causing DLF collateral tokens to be permanently locked in the issuer contract, which has no mechanism to transfer them out.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/protocol/FastAccessVault.sol` - `processTransfer` function (lines 144-158)

**Intended Logic:** The `processTransfer` function should only transfer DLF tokens to legitimate recipient addresses that can properly receive and utilize them. The function is designed to prevent circular flows by checking that the receiver is not the FastAccessVault itself. [1](#0-0) 

**Actual Logic:** The function only validates that `_receiver` is not `address(0)` and not `address(this)`, but critically **fails to check** if `_receiver` is the iTryIssuer contract. This allows DLF tokens to be sent to iTryIssuer, where they become permanently stuck since iTryIssuer has no token rescue function and is not designed to hold collateral tokens.

**Exploitation Path:**

1. **User initiates redemption to iTryIssuer**: A whitelisted user calls `iTryIssuer.redeemFor(address(iTryIssuer), iTRYAmount, minAmountOut)` [2](#0-1) 

2. **iTRY burned and accounting updated**: The issuer burns the user's iTRY tokens and decreases `_totalIssuedITry` and `_totalDLFUnderCustody` correctly [3](#0-2) 

3. **Vault transfer called with iTryIssuer as receiver**: The internal `_redeemFromVault` function is invoked, which calls `liquidityVault.processTransfer(address(iTryIssuer), netDlfAmount)` [4](#0-3) 

4. **Tokens transferred to iTryIssuer and permanently locked**: FastAccessVault executes the transfer to iTryIssuer (passes all existing checks) [5](#0-4) . The DLF tokens are now permanently stuck because iTryIssuer has no `rescueToken` function and only uses `collateralToken.transferFrom()` to receive tokens from users, never to send them out [6](#0-5) 

**Security Property Broken:** While the accounting invariant ("Total issued iTRY MUST be equal or lower to total value of DLF under custody") is technically maintained in the accounting variables, the actual DLF tokens are permanently lost to the protocol, breaking the fundamental premise that redeemed collateral should reach the user.

## Impact Explanation

- **Affected Assets**: DLF collateral tokens that should be returned to users during redemption
- **Damage Severity**: Complete and permanent loss of DLF collateral for affected users. The tokens are locked in iTryIssuer with no recovery mechanism. Any amount from 1 wei to the entire vault balance could be lost per transaction.
- **User Impact**: Any whitelisted user who mistakenly specifies `address(iTryIssuer)` as the recipient (whether through UI error, integration contract bug, or malicious intent) loses their collateral permanently. This could also affect integration contracts that programmatically interact with the redemption system.

## Likelihood Explanation

- **Attacker Profile**: Any whitelisted user with iTRY balance to redeem. Could also be triggered accidentally by legitimate users or buggy integration contracts.
- **Preconditions**: 
  - User must be whitelisted (can call `redeemFor`)
  - User must have iTRY balance to redeem
  - FastAccessVault must have sufficient DLF balance to serve the redemption
- **Execution Complexity**: Single transaction - user simply calls `redeemFor(address(iTryIssuer), amount, minOut)`
- **Frequency**: Can be exploited repeatedly by any whitelisted user, limited only by their iTRY balance and vault liquidity

## Recommendation

Add explicit validation in `FastAccessVault.processTransfer` to prevent transfers to the iTryIssuer contract:

```solidity
// In src/protocol/FastAccessVault.sol, function processTransfer, after line 146:

// CURRENT (vulnerable):
function processTransfer(address _receiver, uint256 _amount) external onlyIssuer {
    if (_receiver == address(0)) revert CommonErrors.ZeroAddress();
    if (_receiver == address(this)) revert InvalidReceiver(_receiver);
    if (_amount == 0) revert CommonErrors.ZeroAmount();
    // ... rest of function

// FIXED:
function processTransfer(address _receiver, uint256 _amount) external onlyIssuer {
    if (_receiver == address(0)) revert CommonErrors.ZeroAddress();
    if (_receiver == address(this)) revert InvalidReceiver(_receiver);
    if (_receiver == address(_issuerContract)) revert InvalidReceiver(_receiver); // NEW: Prevent circular flow to issuer
    if (_amount == 0) revert CommonErrors.ZeroAmount();
    // ... rest of function
```

**Alternative mitigation:** Add a `rescueToken` function to iTryIssuer (similar to other contracts in the codebase) to allow recovery of accidentally sent tokens, though prevention is the preferred approach.

## Proof of Concept

```solidity
// File: test/Exploit_FastAccessVault_IssuerLock.t.sol
// Run with: forge test --match-test test_FastAccessVault_IssuerReceiver_LocksTokens -vvv

pragma solidity ^0.8.0;

import "./iTryIssuer.base.t.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_FastAccessVault_IssuerLock is iTryIssuerBaseTest {
    
    function setUp() public override {
        super.setUp();
        
        // Fund the vault with DLF for redemptions
        collateralToken.mint(address(vault), 100_000e18);
    }
    
    function test_FastAccessVault_IssuerReceiver_LocksTokens() public {
        // SETUP: User mints iTRY first
        uint256 mintAmount = 1000e18;
        vm.startPrank(whitelistedUser1);
        collateralToken.approve(address(issuer), mintAmount);
        issuer.mintFor(whitelistedUser1, mintAmount, 0);
        vm.stopPrank();
        
        uint256 iTRYBalance = iTryToken.balanceOf(whitelistedUser1);
        uint256 issuerDLFBefore = collateralToken.balanceOf(address(issuer));
        uint256 vaultDLFBefore = collateralToken.balanceOf(address(vault));
        uint256 userDLFBefore = collateralToken.balanceOf(whitelistedUser1);
        
        // EXPLOIT: User redeems with iTryIssuer as receiver
        vm.startPrank(whitelistedUser1);
        bool fromBuffer = issuer.redeemFor(address(issuer), iTRYBalance, 0);
        vm.stopPrank();
        
        // VERIFY: Tokens are locked in issuer contract
        uint256 issuerDLFAfter = collateralToken.balanceOf(address(issuer));
        uint256 vaultDLFAfter = collateralToken.balanceOf(address(vault));
        uint256 userDLFAfter = collateralToken.balanceOf(whitelistedUser1);
        
        // Calculate expected DLF transfer (accounting for redemption fee)
        uint256 expectedDLF = (iTRYBalance * 1e18) / oracle.price();
        uint256 feeAmount = (expectedDLF * DEFAULT_REDEMPTION_FEE_BPS) / BPS_DENOMINATOR;
        uint256 netDLF = expectedDLF - feeAmount;
        
        // Assertions proving the vulnerability
        assertTrue(fromBuffer, "Should redeem from buffer");
        assertEq(userDLFAfter - userDLFBefore, 0, "User received no DLF (funds lost!)");
        assertGt(issuerDLFAfter - issuerDLFBefore, 0, "DLF locked in issuer contract");
        assertEq(issuerDLFAfter - issuerDLFBefore, netDLF, "Exact redemption amount locked in issuer");
        assertEq(vaultDLFBefore - vaultDLFAfter, expectedDLF, "Full amount (including fee) left vault");
        
        // Additional verification: iTryIssuer has no function to extract these tokens
        // The tokens are permanently locked with no recovery mechanism
        console.log("DLF permanently locked in iTryIssuer:", issuerDLFAfter - issuerDLFBefore);
    }
}
```

## Notes

The vulnerability exists because `FastAccessVault.processTransfer` implements a partial validation strategy - it prevents self-transfers to the vault itself but fails to consider that the iTryIssuer (the only authorized caller via `onlyIssuer` modifier) is equally inappropriate as a receiver. The design pattern in the codebase shows awareness of this risk (the check for `address(this)` at line 146), but the implementation is incomplete.

The severity is **High** because:
1. Results in permanent loss of user funds (DLF collateral)
2. No recovery mechanism exists (iTryIssuer lacks `rescueToken`)
3. Exploitable by any whitelisted user in a single transaction
4. Could affect integration contracts that programmatically call redemption functions

This is distinct from the known issues in the Zellic audit, which do not cover this specific circular transfer vulnerability.

### Citations

**File:** src/protocol/FastAccessVault.sol (L144-158)
```text
    function processTransfer(address _receiver, uint256 _amount) external onlyIssuer {
        if (_receiver == address(0)) revert CommonErrors.ZeroAddress();
        if (_receiver == address(this)) revert InvalidReceiver(_receiver);
        if (_amount == 0) revert CommonErrors.ZeroAmount();

        uint256 currentBalance = _vaultToken.balanceOf(address(this));
        if (currentBalance < _amount) {
            revert InsufficientBufferBalance(_amount, currentBalance);
        }

        if (!_vaultToken.transfer(_receiver, _amount)) {
            revert CommonErrors.TransferFailed();
        }
        emit TransferProcessed(_receiver, _amount, (currentBalance - _amount));
    }
```

**File:** src/protocol/iTryIssuer.sol (L318-323)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (bool fromBuffer)
    {
```

**File:** src/protocol/iTryIssuer.sol (L587-591)
```text
    function _burn(address from, uint256 amount) internal {
        // Burn user's iTRY tokens
        _totalIssuedITry -= amount;
        iTryToken.burnFrom(from, amount);
    }
```

**File:** src/protocol/iTryIssuer.sol (L604-618)
```text
    function _transferIntoVault(address from, uint256 dlfAmount, uint256 feeAmount) internal {
        _totalDLFUnderCustody += dlfAmount;
        // Transfer net DLF amount to buffer pool
        if (!collateralToken.transferFrom(from, address(liquidityVault), dlfAmount)) {
            revert CommonErrors.TransferFailed();
        }

        if (feeAmount > 0) {
            // Transfer fee to treasury
            if (!collateralToken.transferFrom(from, treasury, feeAmount)) {
                revert CommonErrors.TransferFailed();
            }
            emit FeeProcessed(from, treasury, feeAmount);
        }
    }
```

**File:** src/protocol/iTryIssuer.sol (L627-635)
```text
    function _redeemFromVault(address receiver, uint256 receiveAmount, uint256 feeAmount) internal {
        _totalDLFUnderCustody -= (receiveAmount + feeAmount);

        liquidityVault.processTransfer(receiver, receiveAmount);

        if (feeAmount > 0) {
            liquidityVault.processTransfer(treasury, feeAmount);
        }
    }
```
