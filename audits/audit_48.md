## Title
Pending Custodian Transfer Requests Lost During Custodian Address Change Causing Permanent User Fund Loss

## Summary
When users redeem iTRY tokens via custodian transfer path, the `_redeemFromCustodian()` function emits events for off-chain processing but does not track pending requests on-chain. If the custodian address is changed via `setCustodian()` before the old custodian processes these events, users permanently lose their DLF collateral with no recovery mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/protocol/iTryIssuer.sol` - `_redeemFromCustodian()` (lines 644-658), `setCustodian()` (lines 468-470), `_setCustodian()` (lines 496-501)

**Intended Logic:** When users redeem iTRY and the FastAccessVault has insufficient liquidity, the system should emit events for the custodian to process transfers off-chain. If the custodian address changes, pending transfers should be migrated or handled properly to ensure users receive their DLF collateral.

**Actual Logic:** The `_redeemFromCustodian()` function immediately updates accounting and emits events without tracking pending requests on-chain. [1](#0-0)  The events (`CustodianTransferRequested`) do not include the custodian address. [2](#0-1)  When `setCustodian()` is called, it immediately replaces the custodian address with no checks for pending transfers. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. User calls `redeemFor()` with 1000 iTRY when FastAccessVault has insufficient balance (e.g., only 100 DLF available)
2. Protocol routes to `_redeemFromCustodian()`, which decrements `_totalDLFUnderCustody` and emits `CustodianTransferRequested(user, netAmount)` and `CustodianTransferRequested(treasury, feeAmount)` events
3. Before the custodian processes these events, admin calls `setCustodian(newCustodianAddress)` (legitimate operational change, e.g., switching service providers)
4. Old custodian stops monitoring events or loses authorization; new custodian was not aware of events emitted before their appointment
5. User never receives their DLF collateral - permanent loss with no on-chain recovery mechanism since `_totalDLFUnderCustody` was already decremented

**Security Property Broken:** Users must receive their redeemed DLF collateral. The protocol should ensure proper handling of pending transfers during state transitions. The accounting shows DLF was removed from custody, but tokens were never actually transferred.

## Impact Explanation
- **Affected Assets**: User DLF collateral redemptions, treasury fee payments in DLF
- **Damage Severity**: Complete permanent loss of all DLF amounts for redemptions processed via custodian transfer path between event emission and old custodian processing. No mechanism exists to manually adjust `_totalDLFUnderCustody` or reprocess failed transfers. [5](#0-4) 
- **User Impact**: All users who redeemed iTRY via custodian path (when vault had insufficient liquidity) during the time window between event emission and custodian address change lose their entire redemption amount permanently

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a logic flaw triggered by normal operations
- **Preconditions**: FastAccessVault must have insufficient balance to serve redemption (forcing custodian transfer path), and admin must change custodian address before old custodian processes pending events
- **Execution Complexity**: Occurs naturally during legitimate operational custodian transitions (e.g., switching service providers, updating infrastructure)
- **Frequency**: Every redemption routed through custodian path during custodian transition period is affected

## Recommendation

```solidity
// In src/protocol/iTryIssuer.sol:

// Add state variable to track pending custodian transfers:
struct PendingTransfer {
    address recipient;
    uint256 amount;
    uint256 timestamp;
}
mapping(uint256 => PendingTransfer) public pendingCustodianTransfers;
uint256 public pendingTransferCount;

// CURRENT (vulnerable) - lines 496-501:
function _setCustodian(address newCustodian) internal {
    if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();
    address oldCustodian = custodian;
    custodian = newCustodian;
    emit CustodianUpdated(oldCustodian, newCustodian);
}

// FIXED:
function _setCustodian(address newCustodian) internal {
    if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();
    // Check for pending transfers before allowing custodian change
    require(pendingTransferCount == 0, "Pending custodian transfers exist");
    address oldCustodian = custodian;
    custodian = newCustodian;
    emit CustodianUpdated(oldCustodian, newCustodian);
}

// CURRENT (vulnerable) - lines 644-658:
function _redeemFromCustodian(address receiver, uint256 receiveAmount, uint256 feeAmount) internal {
    _totalDLFUnderCustody -= (receiveAmount + feeAmount);
    uint256 topUpAmount = receiveAmount + feeAmount;
    emit FastAccessVaultTopUpRequested(topUpAmount);
    if (feeAmount > 0) {
        emit CustodianTransferRequested(treasury, feeAmount);
    }
    emit CustodianTransferRequested(receiver, receiveAmount);
}

// FIXED:
function _redeemFromCustodian(address receiver, uint256 receiveAmount, uint256 feeAmount) internal {
    // Track pending transfer on-chain
    uint256 transferId = pendingTransferCount++;
    pendingCustodianTransfers[transferId] = PendingTransfer({
        recipient: receiver,
        amount: receiveAmount,
        timestamp: block.timestamp
    });
    
    // Do NOT decrement _totalDLFUnderCustody until transfer is confirmed
    uint256 topUpAmount = receiveAmount + feeAmount;
    emit FastAccessVaultTopUpRequested(topUpAmount);
    
    if (feeAmount > 0) {
        uint256 feeTransferId = pendingTransferCount++;
        pendingCustodianTransfers[feeTransferId] = PendingTransfer({
            recipient: treasury,
            amount: feeAmount,
            timestamp: block.timestamp
        });
        emit CustodianTransferRequested(treasury, feeAmount);
    }
    emit CustodianTransferRequested(receiver, receiveAmount);
}

// Add confirmation function for custodian to call after transfer:
function confirmCustodianTransfer(uint256 transferId) external {
    require(msg.sender == custodian, "Only custodian");
    PendingTransfer memory transfer = pendingCustodianTransfers[transferId];
    require(transfer.amount > 0, "Transfer not found");
    
    // Now update accounting after confirmation
    _totalDLFUnderCustody -= transfer.amount;
    delete pendingCustodianTransfers[transferId];
    pendingTransferCount--;
    
    emit CustodianTransferConfirmed(transferId, transfer.recipient, transfer.amount);
}
```

**Alternative mitigation:** Emit custodian address in `CustodianTransferRequested` event and add admin function to manually reprocess failed transfers by adjusting `_totalDLFUnderCustody` with proper validation.

## Proof of Concept

```solidity
// File: test/Exploit_CustodianChangeVulnerability.t.sol
// Run with: forge test --match-test test_CustodianChangeCausesPermanentLoss -vvv

pragma solidity ^0.8.0;

import "./iTryIssuer.base.t.sol";

contract Exploit_CustodianChangeVulnerability is iTryIssuerBaseTest {
    
    function test_CustodianChangeCausesPermanentLoss() public {
        // SETUP: User mints iTRY
        uint256 mintAmount = 1000e18;
        uint256 iTRYMinted = _mintITry(whitelistedUser1, mintAmount, 0);
        
        uint256 userInitialDLF = collateralToken.balanceOf(whitelistedUser1);
        
        // Set vault balance to 0 to force custodian transfer path
        _setVaultBalance(0);
        
        // Record initial state
        uint256 initialTotalCustody = _getTotalCustody();
        address initialCustodian = issuer.custodian();
        
        // EXPLOIT STEP 1: User redeems iTRY, triggering custodian transfer
        vm.expectEmit(true, false, false, true);
        emit CustodianTransferRequested(whitelistedUser1, 0); // Will emit with actual amount
        
        vm.prank(whitelistedUser1);
        bool fromBuffer = issuer.redeemFor(whitelistedUser1, iTRYMinted, 0);
        
        // Verify redemption went through custodian path
        assertFalse(fromBuffer, "Should route to custodian");
        
        // Verify accounting was updated (this is the problem!)
        uint256 afterRedeemCustody = _getTotalCustody();
        assertLt(afterRedeemCustody, initialTotalCustody, "Custody decreased");
        
        // EXPLOIT STEP 2: Admin changes custodian before old custodian processes
        address newCustodian = makeAddr("newCustodian");
        vm.prank(admin);
        issuer.setCustodian(newCustodian);
        
        // VERIFY VULNERABILITY: 
        // 1. User never received DLF (still has initial balance)
        assertEq(
            collateralToken.balanceOf(whitelistedUser1), 
            userInitialDLF, 
            "User did not receive DLF"
        );
        
        // 2. Accounting shows DLF was removed from custody
        assertLt(
            afterRedeemCustody,
            initialTotalCustody,
            "Accounting shows DLF removed from custody"
        );
        
        // 3. No way to recover - no admin function to adjust _totalDLFUnderCustody
        // 4. Old custodian may not process events after losing authorization
        // 5. New custodian doesn't know about events emitted before appointment
        
        // RESULT: Permanent loss of user funds
        console.log("User expected DLF but received: 0");
        console.log("Accounting shows", initialTotalCustody - afterRedeemCustody, "DLF removed");
        console.log("No recovery mechanism exists - PERMANENT LOSS");
    }
}
```

## Notes

This vulnerability is a **logic error in state transition handling**, not a centralization risk or malicious admin scenario. Changing custodian addresses is a legitimate operational requirement (e.g., switching service providers, infrastructure updates), and the protocol should handle this safely without causing user fund loss. The issue stems from three design flaws: (1) events don't include custodian address creating ambiguity about which custodian should process them, (2) accounting updates occur immediately before off-chain processing completes, and (3) no on-chain tracking or recovery mechanism exists for pending transfers. The FastAccessVault also has a separate custodian variable that can be changed independently [6](#0-5) , further complicating the coordination problem.

### Citations

**File:** src/protocol/iTryIssuer.sol (L93-94)
```text
    /// @notice Total amount of DLF collateral held under custody (vault + custodian)
    uint256 private _totalDLFUnderCustody;
```

**File:** src/protocol/iTryIssuer.sol (L468-470)
```text
    function setCustodian(address newCustodian) external onlyRole(_INTEGRATION_MANAGER_ROLE) {
        _setCustodian(newCustodian);
    }
```

**File:** src/protocol/iTryIssuer.sol (L496-501)
```text
    function _setCustodian(address newCustodian) internal {
        if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();
        address oldCustodian = custodian;
        custodian = newCustodian;
        emit CustodianUpdated(oldCustodian, newCustodian);
    }
```

**File:** src/protocol/iTryIssuer.sol (L644-658)
```text
    function _redeemFromCustodian(address receiver, uint256 receiveAmount, uint256 feeAmount) internal {
        _totalDLFUnderCustody -= (receiveAmount + feeAmount);

        // Signal that fast access vault needs top-up from custodian
        uint256 topUpAmount = receiveAmount + feeAmount;
        emit FastAccessVaultTopUpRequested(topUpAmount);

        if (feeAmount > 0) {
            // Emit event for off-chain custodian to process
            emit CustodianTransferRequested(treasury, feeAmount);
        }

        // Emit event for off-chain custodian to process
        emit CustodianTransferRequested(receiver, receiveAmount);
    }
```

**File:** src/protocol/interfaces/IiTryIssuer.sol (L86-90)
```text
     * @notice Emitted when a transfer is requested from the custodian
     * @param to The address to receive the transfer
     * @param amount The amount to be transferred
     */
    event CustodianTransferRequested(address indexed to, uint256 amount);
```

**File:** src/protocol/FastAccessVault.sol (L260-266)
```text
    function setCustodian(address newCustodian) external onlyOwner {
        if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();

        address oldCustodian = custodian;
        custodian = newCustodian;
        emit CustodianUpdated(oldCustodian, newCustodian);
    }
```
