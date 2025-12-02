## Title
Lack of Parameter Uniqueness Validation in FastAccessVault Constructor Enables Permanent Fund Lock via Rebalancing

## Summary
The FastAccessVault constructor does not validate that `__vaultToken` and `_custodian` parameters are distinct addresses. [1](#0-0)  If both parameters are set to the same address during deployment, the permissionless `rebalanceFunds()` function will transfer excess DLF tokens to the token contract itself, permanently locking collateral and breaking the protocol's backing invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/protocol/FastAccessVault.sol` - constructor (lines 90-113) and `rebalanceFunds()` function (lines 165-181)

**Intended Logic:** The constructor should initialize the vault with:
- `_vaultToken`: The DLF ERC20 token address for collateral storage
- `custodian`: A separate custodian address to receive excess funds during rebalancing

The `rebalanceFunds()` function should transfer excess funds to the legitimate custodian for off-chain management. [2](#0-1) 

**Actual Logic:** The constructor only validates that addresses are non-zero, with no uniqueness checks. [3](#0-2)  If `__vaultToken == _custodian`, the rebalancing mechanism transfers tokens to the token contract itself at line 176, permanently locking them.

**Exploitation Path:**
1. **Deployment Misconfiguration**: FastAccessVault is deployed (via iTryIssuer constructor) with `_collateralToken == _custodian`, causing `_vaultToken` and `custodian` to be the same address. [4](#0-3) 
2. **Normal Operations**: Users mint iTRY, depositing DLF into the FastAccessVault. The vault accumulates collateral beyond the target buffer percentage.
3. **Attacker Triggers Rebalancing**: Any user calls the permissionless `rebalanceFunds()` function. [5](#0-4) 
4. **Fund Lock**: The function calculates excess and executes `_vaultToken.transfer(custodian, excess)` where both are the same address, sending DLF tokens to the DLF token contract itself. [6](#0-5) 
5. **Permanent Loss**: The tokens are locked in the token contract (standard ERC20 tokens accept self-transfers but provide no recovery mechanism). The FastAccessVault's `rescueToken` function cannot recover them as they are not held by the vault contract. [7](#0-6) 

**Security Property Broken:** Violates the iTRY Backing invariant: "Total issued iTRY in iTryIssuer MUST ALWAYS be equal or lower to total value of DLF under custody." The locked DLF tokens reduce effective collateral while `_totalDLFUnderCustody` in iTryIssuer still counts them as available. [8](#0-7) 

## Impact Explanation
- **Affected Assets**: DLF collateral tokens backing iTRY stablecoin, FastAccessVault redemption capacity
- **Damage Severity**: 
  - Permanent loss of DLF tokens transferred to the token contract
  - Each rebalancing call can lock `(currentBalance - targetBalance)` tokens
  - With 5% target buffer on 100M DLF, up to 95M DLF could be locked
  - Protocol becomes undercollateralized as iTryIssuer still counts locked tokens in `_totalDLFUnderCustody`
  - Users unable to redeem iTRY for full DLF value
- **User Impact**: All iTRY holders affected as redeemable collateral decreases; fast redemptions fail when vault is drained

## Likelihood Explanation
- **Attacker Profile**: Any user (attacker, legitimate user, or even protocol participants) can trigger the exploit
- **Preconditions**: 
  - FastAccessVault deployed with `__vaultToken == _custodian` (deployment-time misconfiguration)
  - Vault has excess funds beyond target buffer (normal operation)
  - Standard ERC20 token implementation that accepts self-transfers
- **Execution Complexity**: Single transaction calling `rebalanceFunds()` - no special timing or complex setup required
- **Frequency**: Can be exploited repeatedly whenever vault exceeds target balance; attacker could even deposit DLF to create excess and immediately rebalance to lock funds

## Recommendation

Add parameter uniqueness validation in the FastAccessVault constructor:

```solidity
// In src/protocol/FastAccessVault.sol, constructor, after line 101:

// CURRENT (vulnerable):
// No validation for parameter uniqueness

// FIXED:
if (__vaultToken == address(0)) revert CommonErrors.ZeroAddress();
if (__issuerContract == address(0)) revert CommonErrors.ZeroAddress();
if (_custodian == address(0)) revert CommonErrors.ZeroAddress();
if (_initialAdmin == address(0)) revert CommonErrors.ZeroAddress();

// Add these uniqueness checks:
if (__vaultToken == _custodian) revert InvalidConfiguration("vaultToken cannot be custodian");
if (__vaultToken == __issuerContract) revert InvalidConfiguration("vaultToken cannot be issuer");
if (__issuerContract == _custodian) revert InvalidConfiguration("issuer cannot be custodian");
```

Alternative mitigation: Add a check in `rebalanceFunds()` to prevent transfers to the vault token address:

```solidity
// In src/protocol/FastAccessVault.sol, function rebalanceFunds, line 175:

// CURRENT:
if (currentBalance > targetBalance) {
    uint256 excess = currentBalance - targetBalance;
    if (!_vaultToken.transfer(custodian, excess)) {
        revert CommonErrors.TransferFailed();
    }

// FIXED:
if (currentBalance > targetBalance) {
    uint256 excess = currentBalance - targetBalance;
    if (custodian == address(_vaultToken)) {
        revert InvalidReceiver(custodian); // Prevent self-transfer
    }
    if (!_vaultToken.transfer(custodian, excess)) {
        revert CommonErrors.TransferFailed();
    }
```

## Proof of Concept

```solidity
// File: test/Exploit_VaultTokenCustodianCollision.t.sol
// Run with: forge test --match-test test_VaultTokenCustodianCollision_LocksCollateral -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/protocol/FastAccessVault.sol";
import "../src/protocol/iTryIssuer.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockDLF is ERC20 {
    constructor() ERC20("DLF", "DLF") {
        _mint(msg.sender, 1000000e18);
    }
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract MockIssuer {
    uint256 public collateral = 1000000e18;
    
    function getCollateralUnderCustody() external view returns (uint256) {
        return collateral;
    }
}

contract Exploit_VaultTokenCustodianCollision is Test {
    MockDLF public dlf;
    MockIssuer public issuer;
    FastAccessVault public vault;
    
    address public attacker = address(0x1337);
    address public admin = address(0x9999);
    
    function setUp() public {
        // Deploy mock DLF token
        dlf = new MockDLF();
        issuer = new MockIssuer();
        
        // Deploy vault with MISCONFIGURED parameters: vaultToken == custodian
        // This simulates the deployment bug where same address is used for both
        vault = new FastAccessVault(
            address(dlf),           // __vaultToken (DLF token)
            address(issuer),        // __issuerContract  
            address(dlf),           // _custodian (SAME AS VAULT TOKEN!)
            500,                    // 5% target buffer
            10000e18,               // minimum balance
            admin                   // admin
        );
        
        // Fund vault with DLF tokens (simulating normal operations)
        dlf.transfer(address(vault), 100000e18);
    }
    
    function test_VaultTokenCustodianCollision_LocksCollateral() public {
        // SETUP: Check initial state
        uint256 vaultBalanceBefore = dlf.balanceOf(address(vault));
        uint256 dlfTokenContractBalanceBefore = dlf.balanceOf(address(dlf));
        
        console.log("Vault balance before:", vaultBalanceBefore);
        console.log("DLF token contract balance before:", dlfTokenContractBalanceBefore);
        
        // EXPLOIT: Attacker (or anyone) calls rebalanceFunds
        // This will transfer excess to custodian, but custodian == vaultToken!
        vm.prank(attacker);
        vault.rebalanceFunds();
        
        // VERIFY: Tokens are now locked in DLF token contract
        uint256 vaultBalanceAfter = dlf.balanceOf(address(vault));
        uint256 dlfTokenContractBalanceAfter = dlf.balanceOf(address(dlf));
        
        console.log("Vault balance after:", vaultBalanceAfter);
        console.log("DLF token contract balance after:", dlfTokenContractBalanceAfter);
        
        // Assert that tokens moved from vault to DLF token contract itself
        assertLt(vaultBalanceAfter, vaultBalanceBefore, "Vault balance should decrease");
        assertGt(dlfTokenContractBalanceAfter, dlfTokenContractBalanceBefore, "DLF contract balance should increase");
        
        uint256 lockedAmount = dlfTokenContractBalanceAfter - dlfTokenContractBalanceBefore;
        console.log("Permanently locked DLF tokens:", lockedAmount);
        
        // These tokens are now PERMANENTLY LOCKED in the DLF token contract
        // They cannot be rescued because rescueToken only works for tokens held by the vault
        // The vault's rescueToken function cannot retrieve tokens from external addresses
        assertGt(lockedAmount, 0, "Vulnerability confirmed: Tokens permanently locked in DLF contract");
    }
}
```

## Notes

This vulnerability represents a critical deployment validation gap. The constructor validates addresses are non-zero but fails to ensure they serve distinct roles. While the misconfiguration must occur at deployment time, the resulting vulnerability is immediately exploitable by any unprivileged actor through the permissionless `rebalanceFunds()` function.

The issue is particularly severe because:
1. The test suite explicitly confirms `rebalanceFunds()` is intended to be permissionless
2. Standard ERC20 tokens accept self-transfers without reverting
3. The vault's `rescueToken` function cannot recover tokens sent to external addresses
4. The iTryIssuer's accounting (`_totalDLFUnderCustody`) becomes incorrect, violating the backing invariant
5. The locked funds reduce redemption capacity, potentially causing bank-run scenarios

This differs from typical admin misconfiguration issues because the exploit requires no privileged access after deployment and causes immediate, irreversible fund loss.

### Citations

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

**File:** src/protocol/FastAccessVault.sol (L164-181)
```text
    /// @inheritdoc IFastAccessVault
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

**File:** src/protocol/FastAccessVault.sol (L215-229)
```text
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        if (token == address(0)) {
            // Rescue ETH
            (bool success,) = to.call{value: amount}("");
            if (!success) revert CommonErrors.TransferFailed();
        } else {
            // Rescue ERC20 tokens
            IERC20(token).safeTransfer(to, amount);
        }

        emit TokenRescued(token, to, amount);
    }
```

**File:** src/protocol/iTryIssuer.sol (L148-159)
```text
        liquidityVault = IFastAccessVault(
            address(
                new FastAccessVault(
                    _collateralToken,
                    address(this), // Issuer is this contract
                    _custodian,
                    _vaultTargetPercentageBPS,
                    _vaultMinimumBalance,
                    _initialAdmin // Admin for vault ownership
                )
            )
        );
```

**File:** src/protocol/iTryIssuer.sol (L250-253)
```text
    /// @inheritdoc IiTryIssuer
    function getCollateralUnderCustody() external view returns (uint256) {
        return _totalDLFUnderCustody;
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
