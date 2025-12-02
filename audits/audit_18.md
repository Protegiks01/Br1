## Title
FastAccessVault Perpetual Under-Buffering Due to Unvalidated Minimum Balance Against Total Collateral

## Summary
The `rebalanceFunds()` function in `FastAccessVault.sol` can enter a perpetual under-buffering state when `minimumExpectedBalance` exceeds the total available collateral (`_totalDLFUnderCustody`). The function emits top-up requests to the custodian without validating that the custodian has sufficient balance to fulfill them, causing the vault to remain indefinitely underfunded and breaking fast redemption functionality.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `rebalanceFunds()` function should maintain the vault's buffer at an optimal level by requesting the custodian to top up when underfunded. The target balance is calculated as the maximum of either a percentage of total AUM or the `minimumExpectedBalance`.

**Actual Logic:** The function calculates target balance without validating that it's achievable given total available collateral. When `minimumExpectedBalance` is set higher than `_totalDLFUnderCustody`, the target becomes mathematically impossible to reach. The custodian cannot fulfill top-up requests because the requested amount exceeds their actual holdings.

**Exploitation Path:**
1. Owner sets `minimumExpectedBalance` to 100e18 DLF tokens via `setMinimumBufferBalance()` [2](#0-1) 
2. Total collateral under custody drops to 70e18 DLF (e.g., after multiple redemptions reduce `_totalDLFUnderCustody`)
3. Current vault balance is 20e18 DLF, meaning custodian effectively holds 50e18 DLF (70 - 20)
4. User calls `rebalanceFunds()`:
   - `aumReferenceValue = 70e18` (from `getCollateralUnderCustody()`) [3](#0-2) 
   - `targetBalance = max((70e18 * 500) / 10000, 100e18) = 100e18` [4](#0-3) 
   - `needed = 100e18 - 20e18 = 80e18`
   - Event `TopUpRequestedFromCustodian` emitted requesting 80e18 DLF
5. Custodian only has 50e18 DLF available, cannot fulfill the 80e18 request
6. Vault remains at 20e18 DLF (well below the 100e18 target)
7. Subsequent calls to `rebalanceFunds()` continue emitting the same unfulfillable request

**Security Property Broken:** The FastAccessVault's core function of providing immediate liquidity for fast redemptions is broken. The vault cannot serve redemptions requiring more than 20e18 DLF when it should maintain 100e18 DLF buffer.

## Impact Explanation
- **Affected Assets**: DLF tokens in FastAccessVault, iTRY redemption functionality
- **Damage Severity**: Users cannot perform fast redemptions when vault is perpetually under-buffered. All redemptions requiring more than current vault balance (20e18 in example) must use the slow custodian redemption path, defeating the purpose of the FastAccessVault. The system operates in a degraded state until admin manually reduces `minimumExpectedBalance` to an achievable level.
- **User Impact**: All users attempting fast redemptions above vault's actual balance are affected. This can occur through legitimate admin configuration or when total collateral drops below a previously reasonable minimum (e.g., due to large redemptions or NAV changes affecting collateral value).

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a systemic issue. Can be triggered by any user calling `rebalanceFunds()` after owner sets `minimumExpectedBalance` too high or after collateral drops below the minimum.
- **Preconditions**: 
  - Owner sets `minimumExpectedBalance` higher than total collateral (can happen legitimately during configuration or market stress)
  - OR: Total collateral drops below previously set `minimumExpectedBalance` due to redemptions
- **Execution Complexity**: Single transaction calling `rebalanceFunds()` (permissionless function)
- **Frequency**: Occurs whenever `minimumExpectedBalance > _totalDLFUnderCustody`, and persists until admin intervention

## Recommendation
Add validation in `setMinimumBufferBalance()` to ensure the minimum never exceeds total available collateral, and add a check in `rebalanceFunds()` to cap the target at total available collateral:

```solidity
// In src/protocol/FastAccessVault.sol, function setMinimumBufferBalance, line 197-201:

// CURRENT (vulnerable):
function setMinimumBufferBalance(uint256 newMinimumBufferBalance) external onlyOwner {
    uint256 oldMinimumBalance = minimumExpectedBalance;
    minimumExpectedBalance = newMinimumBufferBalance;
    emit MinimumBufferBalanceUpdated(oldMinimumBalance, newMinimumBufferBalance);
}

// FIXED:
function setMinimumBufferBalance(uint256 newMinimumBufferBalance) external onlyOwner {
    uint256 totalCollateral = _issuerContract.getCollateralUnderCustody();
    if (newMinimumBufferBalance > totalCollateral) {
        revert MinimumExceedsTotalCollateral(newMinimumBufferBalance, totalCollateral);
    }
    uint256 oldMinimumBalance = minimumExpectedBalance;
    minimumExpectedBalance = newMinimumBufferBalance;
    emit MinimumBufferBalanceUpdated(oldMinimumBalance, newMinimumBufferBalance);
}
```

Additionally, modify `_calculateTargetBufferBalance()` to cap at total collateral:

```solidity
// In src/protocol/FastAccessVault.sol, function _calculateTargetBufferBalance, line 241-243:

// CURRENT (vulnerable):
function _calculateTargetBufferBalance(uint256 _referenceAUM) internal view returns (uint256) {
    uint256 targetBufferBalance = (_referenceAUM * targetBufferPercentageBPS) / 10000;
    return (targetBufferBalance < minimumExpectedBalance) ? minimumExpectedBalance : targetBufferBalance;
}

// FIXED:
function _calculateTargetBufferBalance(uint256 _referenceAUM) internal view returns (uint256) {
    uint256 targetBufferBalance = (_referenceAUM * targetBufferPercentageBPS) / 10000;
    uint256 targetWithMinimum = (targetBufferBalance < minimumExpectedBalance) ? minimumExpectedBalance : targetBufferBalance;
    // Cap target at total available collateral to ensure it's achievable
    return targetWithMinimum > _referenceAUM ? _referenceAUM : targetWithMinimum;
}
```

## Proof of Concept
```solidity
// File: test/Exploit_PerpetualUnderBuffering.t.sol
// Run with: forge test --match-test test_perpetualUnderBuffering -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/FastAccessVault.sol";
import "../src/protocol/iTryIssuer.sol";
import "./mocks/MockERC20.sol";
import "./mocks/MockIssuerContract.sol";

contract Exploit_PerpetualUnderBuffering is Test {
    FastAccessVault vault;
    MockERC20 dlfToken;
    MockIssuerContract issuer;
    address owner;
    address custodian;
    
    function setUp() public {
        owner = address(this);
        custodian = makeAddr("custodian");
        
        // Deploy DLF token and issuer
        dlfToken = new MockERC20("DLF", "DLF");
        issuer = new MockIssuerContract(70e18); // Total collateral = 70 DLF
        
        // Deploy vault with 5% target (500 BPS) and 50 DLF minimum
        vault = new FastAccessVault(
            address(dlfToken),
            address(issuer),
            custodian,
            500, // 5%
            50e18, // Initial minimum
            owner
        );
        
        issuer.setVault(address(vault));
        
        // Give vault 20 DLF (leaving custodian with 50 DLF)
        dlfToken.mint(address(vault), 20e18);
        dlfToken.mint(custodian, 50e18);
    }
    
    function test_perpetualUnderBuffering() public {
        // SETUP: Owner sets minimum balance to 100 DLF (exceeds total 70 DLF)
        vault.setMinimumBufferBalance(100e18);
        
        uint256 vaultBalanceBefore = dlfToken.balanceOf(address(vault));
        uint256 totalCollateral = issuer.getCollateralUnderCustody();
        
        assertEq(vaultBalanceBefore, 20e18, "Vault starts with 20 DLF");
        assertEq(totalCollateral, 70e18, "Total collateral is 70 DLF");
        
        // EXPLOIT: Call rebalanceFunds - will request 80 DLF but custodian only has 50
        vm.expectEmit(true, false, false, true, address(vault));
        emit IFastAccessVault.TopUpRequestedFromCustodian(
            custodian,
            80e18, // Requesting 80 DLF (100 - 20)
            100e18  // Target is 100 DLF
        );
        
        vault.rebalanceFunds();
        
        // VERIFY: Vault remains at 20 DLF since custodian cannot fulfill
        // (In real scenario, custodian would not be able to send 80 DLF as they only have 50)
        assertEq(dlfToken.balanceOf(address(vault)), 20e18, 
            "Vault still at 20 DLF - perpetually under-buffered");
        
        // Even if custodian sends all their 50 DLF:
        vm.prank(custodian);
        dlfToken.transfer(address(vault), 50e18);
        
        // Vault is now at 70 DLF but still below the impossible 100 DLF target
        assertEq(dlfToken.balanceOf(address(vault)), 70e18, 
            "Even with all custodian funds, vault cannot reach 100 DLF target");
        
        // Subsequent rebalance calls continue to emit unfulfillable requests
        vm.expectEmit(true, false, false, true, address(vault));
        emit IFastAccessVault.TopUpRequestedFromCustodian(
            custodian,
            30e18, // Still requesting more (100 - 70)
            100e18  // Target remains impossible
        );
        
        vault.rebalanceFunds();
        
        // Vault remains under-buffered, fast redemptions limited to 70 DLF instead of target 100 DLF
        assertTrue(dlfToken.balanceOf(address(vault)) < vault.getMinimumBufferBalance(),
            "Vulnerability confirmed: Perpetual under-buffering due to impossible target");
    }
}
```

## Notes

The vulnerability stems from the lack of validation when setting `minimumExpectedBalance` and the failure to cap calculated targets at total available collateral. While the custodian is a trusted role, the issue doesn't require custodian malice—it occurs when the minimum is legitimately set too high or when market conditions (redemptions, NAV changes) cause total collateral to drop below a previously reasonable minimum.

This is distinct from the known issue about iTRY backing falling below 1:1 on NAV drops. That issue concerns the collateral value versus iTRY issuance ratio, whereas this vulnerability concerns the vault's inability to maintain its liquidity buffer due to impossible target calculations. The impact is degraded fast redemption service, not insolvency.

The fix ensures that both the configuration phase (setting minimum) and the operational phase (rebalancing) validate that targets are mathematically achievable given actual collateral availability.

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

**File:** src/protocol/FastAccessVault.sol (L197-201)
```text
    function setMinimumBufferBalance(uint256 newMinimumBufferBalance) external onlyOwner {
        uint256 oldMinimumBalance = minimumExpectedBalance;
        minimumExpectedBalance = newMinimumBufferBalance;
        emit MinimumBufferBalanceUpdated(oldMinimumBalance, newMinimumBufferBalance);
    }
```

**File:** src/protocol/FastAccessVault.sol (L241-243)
```text
    function _calculateTargetBufferBalance(uint256 _referenceAUM) internal view returns (uint256) {
        uint256 targetBufferBalance = (_referenceAUM * targetBufferPercentageBPS) / 10000;
        return (targetBufferBalance < minimumExpectedBalance) ? minimumExpectedBalance : targetBufferBalance;
```

**File:** src/protocol/iTryIssuer.sol (L251-253)
```text
    function getCollateralUnderCustody() external view returns (uint256) {
        return _totalDLFUnderCustody;
    }
```
