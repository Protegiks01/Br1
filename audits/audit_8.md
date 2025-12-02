## Title
Missing Self-Transfer Validation in rebalanceFunds Allows Broken Rebalancing Logic

## Summary
The `rebalanceFunds` function in FastAccessVault.sol does not verify that the custodian address is not the vault itself before transferring excess funds, unlike the `processTransfer` function which explicitly checks for and prevents self-transfers. [1](#0-0)  This inconsistency allows the vault to be configured with itself as the custodian, breaking the rebalancing mechanism and creating false accounting.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/FastAccessVault.sol`, function `rebalanceFunds` (lines 165-181) and `setCustodian` (lines 260-266)

**Intended Logic:** The rebalancing function should transfer excess funds from the vault to an external custodian address to maintain optimal liquidity levels. The custodian should be a separate address that holds DLF tokens not needed for immediate redemptions.

**Actual Logic:** The function transfers to the custodian address without validating it's not the vault itself. [2](#0-1)  If custodian equals `address(this)`, the vault performs a self-transfer that appears successful but doesn't actually move funds out of the vault. The event `ExcessFundsTransferredToCustodian` is emitted with misleading information, suggesting funds were transferred when they remain in the vault.

**Exploitation Path:**
1. Owner deploys FastAccessVault with custodian set to the vault's own address in constructor, or later calls `setCustodian(address(vault))` [3](#0-2) 
2. Neither the constructor [4](#0-3)  nor `setCustodian` validates that `custodian != address(this)` [3](#0-2) 
3. When `rebalanceFunds()` executes and vault has excess funds, it calls `_vaultToken.transfer(custodian, excess)` where custodian is the vault itself [5](#0-4) 
4. The ERC20 transfer succeeds (self-transfers are valid), but vault balance remains unchanged - no funds actually leave the vault
5. Event claims excess funds were transferred to custodian, creating false accounting in off-chain systems

**Security Property Broken:** The protocol's liquidity management invariant is violated. The FastAccessVault should maintain only a target percentage of total AUM for instant redemptions, with excess funds held by the external custodian. [6](#0-5)  When custodian is the vault itself, excess funds cannot be moved out, permanently breaking the rebalancing mechanism.

## Impact Explanation
- **Affected Assets**: DLF tokens held in FastAccessVault that should be transferred to custodian during rebalancing
- **Damage Severity**: The vault permanently holds excess liquidity that should be with the custodian. This creates capital inefficiency - funds that could be deployed elsewhere remain idle in the vault. Off-chain monitoring systems tracking the `ExcessFundsTransferredToCustodian` event will show incorrect balances, believing funds were moved when they weren't.
- **User Impact**: All protocol users are affected indirectly through suboptimal capital allocation. The rebalancing mechanism that ensures proper liquidity distribution is completely broken.

## Likelihood Explanation
- **Attacker Profile**: This requires the Owner role to misconfigure the custodian address, either during deployment or via `setCustodian`. This is not exploitable by unprivileged attackers but represents an operational risk from configuration mistakes.
- **Preconditions**: Owner must set custodian to the vault's own address. No other validation prevents this.
- **Execution Complexity**: Single transaction by Owner to set misconfigured custodian address
- **Frequency**: One-time misconfiguration permanently breaks rebalancing until corrected

## Recommendation
Add validation to prevent the custodian from being set to the vault's own address, matching the defensive pattern used in `processTransfer`: [7](#0-6) 

```solidity
// In src/protocol/FastAccessVault.sol, constructor, line 100:

// CURRENT (vulnerable):
if (_custodian == address(0)) revert CommonErrors.ZeroAddress();

// FIXED:
if (_custodian == address(0)) revert CommonErrors.ZeroAddress();
if (_custodian == address(this)) revert InvalidReceiver(_custodian); // Prevent self-custodian

// In src/protocol/FastAccessVault.sol, function setCustodian, line 261:

// CURRENT (vulnerable):
if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();

// FIXED:
if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();
if (newCustodian == address(this)) revert InvalidReceiver(newCustodian); // Prevent self-custodian
```

This reuses the existing `InvalidReceiver` error already defined for the same purpose in `processTransfer`.

## Proof of Concept
```solidity
// File: test/Exploit_SelfCustodianRebalance.t.sol
// Run with: forge test --match-test test_SelfCustodianBreaksRebalancing -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/FastAccessVault.sol";
import "../src/protocol/interfaces/IFastAccessVault.sol";

contract Exploit_SelfCustodianRebalance is Test {
    FastAccessVault vault;
    IERC20 dlfToken;
    address issuerContract;
    address owner;
    
    function setUp() public {
        owner = address(this);
        issuerContract = address(0x123); // Mock issuer
        dlfToken = IERC20(address(new MockERC20()));
        
        // Deploy vault with itself as custodian (simulating misconfiguration)
        vault = new FastAccessVault(
            address(dlfToken),
            issuerContract,
            address(0), // Will set to vault address after deployment
            500, // 5% target
            1000e18, // minimum balance
            owner
        );
        
        // Misconfigure custodian to be vault itself
        vault.setCustodian(address(vault));
    }
    
    function test_SelfCustodianBreaksRebalancing() public {
        // SETUP: Give vault excess funds (more than target buffer)
        deal(address(dlfToken), address(vault), 10000e18);
        
        // Mock issuer's getCollateralUnderCustody to return 100k
        // Target should be 5% = 5000, vault has 10000 = 5000 excess
        vm.mockCall(
            issuerContract,
            abi.encodeWithSelector(bytes4(keccak256("getCollateralUnderCustody()"))),
            abi.encode(100000e18)
        );
        
        uint256 balanceBefore = dlfToken.balanceOf(address(vault));
        
        // EXPLOIT: Call rebalanceFunds - should transfer excess to custodian
        // but custodian IS the vault, so it's a no-op self-transfer
        vm.expectEmit(true, false, false, true);
        emit IFastAccessVault.ExcessFundsTransferredToCustodian(
            address(vault), // custodian is vault itself
            5000e18, // claimed excess transferred
            5000e18  // claimed target balance
        );
        vault.rebalanceFunds();
        
        // VERIFY: Vault balance unchanged - funds weren't actually moved
        uint256 balanceAfter = dlfToken.balanceOf(address(vault));
        assertEq(balanceAfter, balanceBefore, "Vulnerability confirmed: Self-transfer didn't move funds");
        assertEq(balanceAfter, 10000e18, "Vault still holds all excess funds");
        
        // The event claimed funds were transferred, but they weren't
        // This creates false accounting - off-chain systems think funds moved
    }
}

contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
```

## Notes

This finding represents a **defensive programming gap and code inconsistency** rather than a direct exploit by unprivileged attackers. The `processTransfer` function explicitly validates against self-transfers with `if (_receiver == address(this)) revert InvalidReceiver(_receiver);` [8](#0-7)  but the same check is absent in both the constructor, `setCustodian`, and `rebalanceFunds` functions.

While this requires Owner misconfiguration to manifest, it violates the principle of fail-safe defaults and creates operational risk. The impact is broken liquidity management and false event emissions rather than direct fund theft, justifying Medium severity under the Code4rena framework.

### Citations

**File:** src/protocol/FastAccessVault.sol (L12-32)
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
 * @custom:security-contact security@inverter.network
 */
```

**File:** src/protocol/FastAccessVault.sol (L90-113)
```text
    constructor(
        address __vaultToken,
        address __issuerContract,
        address _custodian,
        uint256 _initialTargetPercentageBPS,
        uint256 _minimumExpectedBalance,
        address _initialAdmin
    ) {
        if (__vaultToken == address(0)) revert CommonErrors.ZeroAddress();
        if (__issuerContract == address(0)) revert CommonErrors.ZeroAddress();
        if (_custodian == address(0)) revert CommonErrors.ZeroAddress();
        if (_initialAdmin == address(0)) revert CommonErrors.ZeroAddress();

        _validateBufferPercentageBPS(_initialTargetPercentageBPS);

        _vaultToken = IERC20(__vaultToken);
        _issuerContract = IiTryIssuer(__issuerContract);
        custodian = _custodian;
        targetBufferPercentageBPS = _initialTargetPercentageBPS;
        minimumExpectedBalance = _minimumExpectedBalance;

        // Transfer ownership to the initial admin
        transferOwnership(_initialAdmin);
    }
```

**File:** src/protocol/FastAccessVault.sol (L144-148)
```text
    function processTransfer(address _receiver, uint256 _amount) external onlyIssuer {
        if (_receiver == address(0)) revert CommonErrors.ZeroAddress();
        if (_receiver == address(this)) revert InvalidReceiver(_receiver);
        if (_amount == 0) revert CommonErrors.ZeroAmount();

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

**File:** src/protocol/FastAccessVault.sol (L260-266)
```text
    function setCustodian(address newCustodian) external onlyOwner {
        if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();

        address oldCustodian = custodian;
        custodian = newCustodian;
        emit CustodianUpdated(oldCustodian, newCustodian);
    }
```
