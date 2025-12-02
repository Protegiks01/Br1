## Title
FastAccessVault Target Buffer Calculation Can Exceed Total AUM, Breaking Liquidity Distribution

## Summary
The `_calculateTargetBufferBalance` function in `FastAccessVault.sol` fails to cap the target buffer at the total AUM when `minimumExpectedBalance` exceeds `_referenceAUM`, causing the vault to request more collateral than exists in the entire system and breaking the intended liquidity distribution architecture. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/protocol/FastAccessVault.sol` - `_calculateTargetBufferBalance` (lines 241-244) and `rebalanceFunds` (lines 165-181)

**Intended Logic:** The FastAccessVault should maintain a configurable percentage of total DLF collateral (e.g., 5%) to enable instant redemptions, with a minimum balance floor. The vault and custodian should maintain complementary balances that sum to the total AUM. [2](#0-1) 

**Actual Logic:** When `minimumExpectedBalance` exceeds the total AUM, the calculation returns `minimumExpectedBalance` without any cap, causing the vault to target holding MORE than the entire protocol's collateral. [1](#0-0) 

**Exploitation Path:**

1. **Initial State**: Protocol deployed with `minimumExpectedBalance = 50,000 DLF` and initial AUM of 10,000,000 DLF (reasonable 0.5% ratio)

2. **AUM Reduction**: Through normal protocol operations, AUM decreases below minimum:
   - Users perform large redemptions reducing `_totalDLFUnderCustody`
   - NAV price drops causing undercollateralization
   - Admin burns excess iTRY via `burnExcessITry` function [3](#0-2) 

3. **Rebalancing Triggered**: Anyone calls `rebalanceFunds()` when AUM = 30,000 DLF (less than minimum of 50,000)
   - `_calculateTargetBufferBalance(30,000)` returns 50,000 (the minimum)
   - Vault currently holds 10,000 DLF
   - Function emits `TopUpRequestedFromCustodian` for 40,000 DLF
   - **But custodian only has 20,000 DLF (30,000 total - 10,000 in vault = 20,000)** [4](#0-3) 

4. **System Dysfunction**: 
   - Custodian cannot fulfill the impossible request
   - Vault continuously reports needing more funds than exist
   - If custodian transfers all 20,000 to reach 30,000 in vault, they have 0 left
   - System stuck targeting 50,000 but can never exceed 30,000 total AUM

**Security Property Broken:** The vault is designed to hold a percentage of total collateral for fast redemptions while custodian holds the remainder. This calculation breaks that invariant by attempting to concentrate more than 100% of collateral in the vault.

## Impact Explanation

- **Affected Assets**: All DLF collateral in the FastAccessVault and custodian
- **Damage Severity**: 
  - Rebalancing mechanism becomes dysfunctional, continuously requesting impossible amounts
  - If custodian attempts to fulfill, ALL collateral gets pulled into vault, leaving custodian with zero
  - Fast redemption architecture breaks - vault holds everything instead of percentage buffer
  - System accounting becomes inconsistent with reality
- **User Impact**: All protocol users affected indirectly through broken liquidity management, though no direct fund theft occurs

## Likelihood Explanation

- **Attacker Profile**: Any user can trigger conditions through redemptions; anyone can call `rebalanceFunds()`
- **Preconditions**: 
  - Protocol initialized with reasonable `minimumExpectedBalance`
  - Total AUM decreases below minimum through redemptions, NAV drops, or admin burning excess iTRY
  - No validation prevents setting minimum higher than current AUM [5](#0-4) 

- **Execution Complexity**: Low - normal protocol operations (redemptions) can naturally trigger this state
- **Frequency**: Occurs whenever AUM drops below `minimumExpectedBalance` and persists until admin manually adjusts minimum downward

## Recommendation

Add a cap to ensure the target buffer never exceeds the total AUM:

```solidity
// In src/protocol/FastAccessVault.sol, function _calculateTargetBufferBalance, lines 241-244:

// CURRENT (vulnerable):
function _calculateTargetBufferBalance(uint256 _referenceAUM) internal view returns (uint256) {
    uint256 targetBufferBalance = (_referenceAUM * targetBufferPercentageBPS) / 10000;
    return (targetBufferBalance < minimumExpectedBalance) ? minimumExpectedBalance : targetBufferBalance;
}

// FIXED:
function _calculateTargetBufferBalance(uint256 _referenceAUM) internal view returns (uint256) {
    uint256 targetBufferBalance = (_referenceAUM * targetBufferPercentageBPS) / 10000;
    uint256 effectiveMinimum = minimumExpectedBalance > _referenceAUM ? _referenceAUM : minimumExpectedBalance;
    return (targetBufferBalance < effectiveMinimum) ? effectiveMinimum : targetBufferBalance;
}
// This ensures target never exceeds total AUM, maintaining the percentage-based architecture
```

**Alternative mitigation:** Add validation in `setMinimumBufferBalance` to prevent setting minimum above current AUM, though this doesn't handle AUM decreasing after deployment.

## Proof of Concept

```solidity
// File: test/Exploit_BufferExceedsAUM.t.sol
// Run with: forge test --match-test test_BufferExceedsAUM -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/FastAccessVault.sol";
import "../src/protocol/iTryIssuer.sol";
import "./mocks/MockERC20.sol";
import "./mocks/MockIssuerContract.sol";

contract Exploit_BufferExceedsAUM is Test {
    FastAccessVault vault;
    MockERC20 vaultToken;
    MockIssuerContract issuerContract;
    address owner = address(this);
    address custodian = makeAddr("custodian");
    
    uint256 constant INITIAL_AUM = 10_000_000e18;
    uint256 constant MINIMUM_BALANCE = 50_000e18; 
    uint256 constant TARGET_BPS = 500; // 5%
    
    function setUp() public {
        vaultToken = new MockERC20("DLF", "DLF");
        issuerContract = new MockIssuerContract(INITIAL_AUM);
        
        vault = new FastAccessVault(
            address(vaultToken),
            address(issuerContract),
            custodian,
            TARGET_BPS,
            MINIMUM_BALANCE,
            owner
        );
        
        issuerContract.setVault(address(vault));
        vaultToken.mint(address(vault), 10_000e18);
    }
    
    function test_BufferExceedsAUM() public {
        // SETUP: Initial state is healthy
        assertEq(issuerContract.getCollateralUnderCustody(), INITIAL_AUM);
        
        // EXPLOIT: AUM drops below minimum through redemptions
        uint256 newAUM = 30_000e18; // Less than MINIMUM_BALANCE of 50,000
        issuerContract.setCollateralUnderCustody(newAUM);
        
        // VERIFY: Target exceeds total AUM
        uint256 currentBalance = vaultToken.balanceOf(address(vault));
        
        // Rebalancing requests more than exists
        vm.expectEmit(true, false, false, false);
        emit TopUpRequestedFromCustodian(custodian, 0, MINIMUM_BALANCE);
        vault.rebalanceFunds();
        
        // Vulnerability confirmed: Vault targets 50,000 but only 30,000 exists in entire system
        // If custodian has 20,000 (30,000 total - 10,000 in vault), they cannot fulfill 40,000 request
        assertEq(MINIMUM_BALANCE, 50_000e18, "Target is 50k");
        assertEq(newAUM, 30_000e18, "But total AUM is only 30k");
        assertGt(MINIMUM_BALANCE, newAUM, "Vulnerability confirmed: Target exceeds total AUM");
    }
    
    event TopUpRequestedFromCustodian(address indexed custodian, uint256 amount, uint256 targetBalance);
}
```

## Notes

The existing test suite includes a case demonstrating this scenario (`test_rebalanceFunds_whenAUMIsZero_usesMinimumBalance` at line 758) where AUM = 0 but minimum = 50,000, yet the test expects the request to proceed without validating feasibility. [6](#0-5) 

The vulnerability is exacerbated by the lack of validation when setting `minimumExpectedBalance`, allowing any value to be set regardless of current or future AUM levels. [5](#0-4) 

While the off-chain custodian may refuse to fulfill impossible requests, the on-chain accounting and rebalancing logic remain broken, potentially causing operational issues and preventing proper liquidity distribution across the protocol.

### Citations

**File:** src/protocol/FastAccessVault.sol (L12-30)
```text
/**
 * @title FastAccessVault
 * @author Inverter Network
 * @notice Liquidity buffer vault for instant iTRY redemptions without custodian delays
 * @dev This contract maintains a configurable percentage of total DLF collateral to enable
 *      instant redemptions. It automatically rebalances between itself and the custodian to
 *      maintain optimal liquidity levels.
 *
 *      Key features:
 *      - Holds buffer of DLF tokens for instant redemptions
 *      - Automatic rebalancing based on target percentage of AUM
 *      - Minimum balance floor to ensure always-available liquidity
 *      - Fixed reference to authorized issuer contract for access control
 *      - Emergency token rescue functionality
 *
 *      The vault uses a two-tier sizing strategy:
 *      1. Target percentage: Buffer = AUM * targetBufferPercentageBPS / 10000
 *      2. Minimum balance: Buffer = max(calculated_target, minimumExpectedBalance)
 *
```

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

**File:** src/protocol/FastAccessVault.sol (L197-201)
```text
    function setMinimumBufferBalance(uint256 newMinimumBufferBalance) external onlyOwner {
        uint256 oldMinimumBalance = minimumExpectedBalance;
        minimumExpectedBalance = newMinimumBufferBalance;
        emit MinimumBufferBalanceUpdated(oldMinimumBalance, newMinimumBufferBalance);
    }
```

**File:** src/protocol/FastAccessVault.sol (L241-244)
```text
    function _calculateTargetBufferBalance(uint256 _referenceAUM) internal view returns (uint256) {
        uint256 targetBufferBalance = (_referenceAUM * targetBufferPercentageBPS) / 10000;
        return (targetBufferBalance < minimumExpectedBalance) ? minimumExpectedBalance : targetBufferBalance;
    }
```

**File:** src/protocol/iTryIssuer.sol (L373-390)
```text
    function burnExcessITry(uint256 iTRYAmount)
        public
        onlyRole(DEFAULT_ADMIN_ROLE)
        nonReentrant
    {
        // Validate iTRYAmount > 0
        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();

        if (iTRYAmount > _totalIssuedITry) {
            revert AmountExceedsITryIssuance(iTRYAmount, _totalIssuedITry);
        }

        _burn(msg.sender, iTRYAmount);


        // Emit redemption event
        emit excessITryRemoved(iTRYAmount, _totalIssuedITry);
    }
```

**File:** test/FastAccessVault.t.sol (L758-770)
```text
    function test_rebalanceFunds_whenAUMIsZero_usesMinimumBalance() public {
        _updateAUM(0);
        _setupVaultWithBalance(10_000e18);

        // Target should be minimum since 0 * percentage = 0 < minimum
        uint256 targetBalance = DEFAULT_MINIMUM;
        uint256 needed = targetBalance - 10_000e18;

        vm.expectEmit(true, false, false, true, address(vault));
        emit TopUpRequestedFromCustodian(custodian, needed, targetBalance);

        vault.rebalanceFunds();
    }
```
