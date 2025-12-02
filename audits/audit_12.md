## Title
Insufficient Input Validation in `setCustodian` Allows Setting Burn Address, Enabling Permanent Loss of Protocol Collateral

## Summary
The `setCustodian` function in `FastAccessVault.sol` only validates against `address(0)` but fails to prevent setting the custodian to known burn addresses (e.g., `0x000000000000000000000000000000000000dEaD`) or other problematic addresses. Since `rebalanceFunds()` automatically transfers excess DLF collateral to the custodian and is callable by anyone, a misconfigured custodian would result in permanent loss of protocol collateral backing the iTRY stablecoin.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/FastAccessVault.sol` (function `setCustodian`, lines 260-266; function `rebalanceFunds`, lines 165-181)

**Intended Logic:** The custodian address should be a valid, operational address capable of receiving and managing DLF tokens for the protocol's liquidity rebalancing operations.

**Actual Logic:** The `setCustodian` function only validates that the new custodian is not `address(0)`, allowing the owner to accidentally set the custodian to burn addresses or other non-operational addresses that cannot return funds. [1](#0-0) 

**Exploitation Path:**
1. Owner accidentally sets custodian to a burn address like `0x000000000000000000000000000000000000dEaD` (common burn address used in many protocols) or the vault's own address `address(this)`
2. The vault accumulates DLF tokens above the target buffer threshold
3. Any unprivileged user calls `rebalanceFunds()` (no access control on this function)
4. The excess DLF tokens are automatically transferred to the burn address/problematic address at line 176, permanently locking them [2](#0-1) 

**Security Property Broken:** Violates the critical invariant that "Total issued iTRY in iTryIssuer MUST ALWAYS be equal or lower to total value of DLF under custody" - losing DLF collateral reduces the backing ratio of the stablecoin.

## Impact Explanation
- **Affected Assets**: DLF tokens (Digital Liquidity Fund tokens serving as collateral for iTRY stablecoin)
- **Damage Severity**: All excess DLF tokens held in FastAccessVault above the target buffer would be permanently lost if rebalancing occurs while custodian is set to a burn address. This directly reduces the collateral backing the iTRY stablecoin system.
- **User Impact**: All iTRY holders are affected as the collateral backing their stablecoin is reduced, potentially leading to undercollateralization. The protocol would need to acquire additional DLF to restore proper backing.

## Likelihood Explanation
- **Attacker Profile**: Requires owner misconfiguration (not malicious intent), then any unprivileged user can trigger the loss by calling `rebalanceFunds()`
- **Preconditions**: Owner must accidentally set custodian to a problematic address, and vault balance must exceed target buffer threshold
- **Execution Complexity**: Single transaction call to `rebalanceFunds()` after misconfiguration
- **Frequency**: Can occur any time vault is over-buffered after misconfiguration

## Recommendation

Add validation to prevent setting custodian to known problematic addresses:

```solidity
// In src/protocol/FastAccessVault.sol, function setCustodian, lines 260-266:

// CURRENT (vulnerable):
// Only checks for address(0)

// FIXED:
function setCustodian(address newCustodian) external onlyOwner {
    if (newCustodian == address(0)) revert CommonErrors.ZeroAddress();
    // Prevent setting custodian to this contract (would lock funds)
    if (newCustodian == address(this)) revert InvalidReceiver(newCustodian);
    // Prevent common burn addresses
    if (newCustodian == 0x000000000000000000000000000000000000dEaD) {
        revert InvalidReceiver(newCustodian);
    }
    
    address oldCustodian = custodian;
    custodian = newCustodian;
    emit CustodianUpdated(oldCustodian, newCustodian);
}
```

Alternative mitigation: Add access control to `rebalanceFunds()` to make it owner-only, which would allow the owner to correct the custodian address before funds are lost. Note that the interface documentation claims "Only callable by owner" but the implementation lacks the `onlyOwner` modifier. [3](#0-2) 

## Proof of Concept

```solidity
// File: test/Exploit_CustodianBurnAddress.t.sol
// Run with: forge test --match-test test_CustodianBurnAddress_PermanentLoss -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/FastAccessVault.sol";
import "./mocks/MockERC20.sol";
import "./mocks/MockIssuerContract.sol";

contract Exploit_CustodianBurnAddress is Test {
    FastAccessVault public vault;
    MockERC20 public vaultToken;
    MockIssuerContract public issuerContract;
    
    address public owner;
    address public burnAddress = 0x000000000000000000000000000000000000dEaD;
    address public anyUser;
    
    uint256 constant INITIAL_VAULT_BALANCE = 1_000_000e18;
    uint256 constant INITIAL_AUM = 10_000_000e18;
    uint256 constant DEFAULT_TARGET_BPS = 500; // 5%
    uint256 constant DEFAULT_MINIMUM = 50_000e18;
    
    function setUp() public {
        owner = address(this);
        anyUser = makeAddr("anyUser");
        
        // Deploy mock contracts
        vaultToken = new MockERC20("Digital Liquidity Fund", "DLF");
        issuerContract = new MockIssuerContract(INITIAL_AUM);
        
        // Deploy vault with legitimate custodian initially
        vault = new FastAccessVault(
            address(vaultToken),
            address(issuerContract),
            makeAddr("legitimateCustodian"),
            DEFAULT_TARGET_BPS,
            DEFAULT_MINIMUM,
            owner
        );
        
        issuerContract.setVault(address(vault));
        
        // Give vault excess balance (above target)
        vaultToken.mint(address(vault), INITIAL_VAULT_BALANCE);
    }
    
    function test_CustodianBurnAddress_PermanentLoss() public {
        // SETUP: Initial state
        uint256 targetBalance = (INITIAL_AUM * DEFAULT_TARGET_BPS) / 10000; // 5% of 10M = 500K
        uint256 vaultBalance = vaultToken.balanceOf(address(vault)); // 1M
        uint256 expectedExcess = vaultBalance - targetBalance; // 500K excess
        
        assertGt(vaultBalance, targetBalance, "Vault should have excess balance");
        assertEq(vaultToken.balanceOf(burnAddress), 0, "Burn address starts with 0 balance");
        
        // EXPLOIT STEP 1: Owner accidentally sets custodian to burn address
        // (This could happen due to copy-paste error, address confusion, etc.)
        vault.setCustodian(burnAddress);
        assertEq(vault.custodian(), burnAddress, "Custodian set to burn address");
        
        // EXPLOIT STEP 2: Any unprivileged user triggers rebalancing
        vm.prank(anyUser);
        vault.rebalanceFunds();
        
        // VERIFY: Excess funds are permanently lost to burn address
        uint256 burnAddressBalance = vaultToken.balanceOf(burnAddress);
        uint256 vaultBalanceAfter = vaultToken.balanceOf(address(vault));
        
        assertEq(burnAddressBalance, expectedExcess, "Excess funds sent to burn address");
        assertEq(vaultBalanceAfter, targetBalance, "Vault now at target balance");
        
        // These funds are now PERMANENTLY INACCESSIBLE
        // Protocol collateral is reduced by 500K DLF tokens
        // iTRY backing ratio is compromised
        console.log("DLF tokens permanently lost:", burnAddressBalance);
        console.log("This reduces iTRY collateral backing");
    }
}
```

## Notes

This vulnerability also exists in `iTryIssuer.sol` with the same pattern - the `_setCustodian` function only validates against `address(0)`: [4](#0-3) 

The key insight is that this is not about assuming malicious admin behavior, but rather about **insufficient input validation** that fails to protect against obvious configuration errors. Input validation for admin functions is a standard security practice, as evidenced by the existing `address(0)` check. The validation is simply incomplete, missing other clearly problematic addresses that would result in permanent loss of protocol funds.

### Citations

**File:** src/protocol/FastAccessVault.sol (L174-179)
```text
        } else if (currentBalance > targetBalance) {
            uint256 excess = currentBalance - targetBalance;
            if (!_vaultToken.transfer(custodian, excess)) {
                revert CommonErrors.TransferFailed();
            }
            emit ExcessFundsTransferredToCustodian(address(custodian), excess, targetBalance);
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

**File:** src/protocol/interfaces/IFastAccessVault.sol (L140-145)
```text
     * @notice Rebalance the vault to match target buffer levels
     * @dev Only callable by owner. Requests top-up from custodian if under target,
     *      or transfers excess to custodian if over target
     *
     */
    function rebalanceFunds() external;
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
