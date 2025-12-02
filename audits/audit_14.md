## Title
FastAccessVault.rescueToken Can Drain Operational DLF Balance Creating Unbacked iTRY Tokens

## Summary
The `rescueToken` function in FastAccessVault.sol lacks validation to prevent rescuing the vault's operational DLF token balance. This allows the owner to withdraw DLF tokens that back issued iTRY tokens without updating the accounting in iTryIssuer, directly violating the protocol's core invariant that "Total issued iTRY MUST ALWAYS be equal or lower to total value of DLF under custody." [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/protocol/FastAccessVault.sol` (FastAccessVault contract, `rescueToken` function, lines 215-229)

**Intended Logic:** The `rescueToken` function is documented as an emergency function to "rescue tokens accidentally sent to this contract." It should only allow rescuing tokens that were mistakenly sent to the vault, not the operational DLF balance that backs issued iTRY tokens. [2](#0-1) 

**Actual Logic:** The function allows rescuing ANY ERC20 token including the vault's operational token (`_vaultToken`, which is DLF). There is no validation check like `if (token == address(_vaultToken)) revert InvalidToken();` that would prevent this. [1](#0-0) 

**Exploitation Path:**
1. Users mint iTRY by depositing DLF tokens to the FastAccessVault, which updates `_totalDLFUnderCustody` in iTryIssuer [3](#0-2) 

2. Owner calls `FastAccessVault.rescueToken(address(_vaultToken), recipient, amount)` to withdraw DLF tokens from the vault [1](#0-0) 

3. The DLF tokens are transferred out, but `_totalDLFUnderCustody` in iTryIssuer is NOT decreased (unlike proper redemptions which update this value) [4](#0-3) 

4. The protocol now has unbacked iTRY in circulation - the accounting shows more DLF under custody than actually exists, violating the core invariant

**Security Property Broken:** Critical Invariant #1 from README: "The total issued iTRY in the Issuer contract should always be equal or lower to the total value of the DLF under custody. It should not be possible to mint 'unbacked' iTRY through the issuer." [5](#0-4) 

## Impact Explanation
- **Affected Assets**: All DLF tokens held in FastAccessVault, all issued iTRY tokens
- **Damage Severity**: Complete loss of iTRY backing. If owner rescues substantial DLF amounts, users attempting redemptions will fail due to insufficient vault balance, while the protocol still believes sufficient collateral exists. This creates unbacked stablecoin tokens and protocol insolvency.
- **User Impact**: All iTRY holders are affected. When users attempt to redeem their iTRY for DLF, the vault will have insufficient balance, causing redemptions to fail or require custodian intervention. The protocol's solvency guarantee is broken.

## Likelihood Explanation
- **Attacker Profile**: Requires owner privileges (multisig), but represents a critical code defect rather than intentional malicious action
- **Preconditions**: FastAccessVault must hold operational DLF tokens (normal operating state after any minting activity)
- **Execution Complexity**: Single transaction calling `rescueToken` with vault token address
- **Frequency**: Can be executed at any time the vault holds DLF tokens

## Recommendation

The FastAccessVault should follow the same pattern as StakediTry, which explicitly prevents rescuing operational assets: [6](#0-5) 

Apply the same protection to FastAccessVault:

```solidity
// In src/protocol/FastAccessVault.sol, function rescueToken, add validation after line 217:

function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
    if (to == address(0)) revert CommonErrors.ZeroAddress();
    if (amount == 0) revert CommonErrors.ZeroAmount();
    
    // ADDED: Prevent rescuing operational vault token
    if (token == address(_vaultToken)) revert InvalidToken();
    
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

Add the error definition:
```solidity
error InvalidToken();
```

This ensures `rescueToken` can only rescue accidentally sent tokens, not the vault's operational DLF balance that backs issued iTRY.

## Proof of Concept

```solidity
// File: test/Exploit_RescueOperationalDLF.t.sol
// Run with: forge test --match-test test_RescueOperationalDLF_CreatesUnbackedITRY -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/protocol/FastAccessVault.sol";
import "./mocks/MockERC20.sol";
import "./iTryIssuer.base.t.sol";

contract Exploit_RescueOperationalDLF is iTryIssuerBaseTest {
    
    function test_RescueOperationalDLF_CreatesUnbackedITRY() public {
        // SETUP: User mints iTRY with DLF collateral
        uint256 mintAmount = 1000e18;
        
        vm.startPrank(whitelistedUser1);
        collateralToken.approve(address(issuer), mintAmount);
        issuer.mintFor(whitelistedUser1, mintAmount, 0);
        vm.stopPrank();
        
        // Verify initial state: iTRY is fully backed
        uint256 issuedITRY = issuer.getTotalIssuedITry();
        uint256 dlfUnderCustody = issuer.getCollateralUnderCustody();
        uint256 vaultBalance = vault.getAvailableBalance();
        
        console.log("Initial issued iTRY:", issuedITRY);
        console.log("Initial DLF under custody:", dlfUnderCustody);
        console.log("Initial vault DLF balance:", vaultBalance);
        
        assertGt(issuedITRY, 0, "iTRY should be minted");
        assertEq(dlfUnderCustody, vaultBalance, "Custody accounting should match vault balance");
        assertTrue(issuedITRY <= dlfUnderCustody, "Invariant: iTRY must be backed by DLF");
        
        // EXPLOIT: Owner rescues operational DLF tokens from vault
        address recipient = makeAddr("recipient");
        uint256 rescueAmount = vaultBalance / 2; // Rescue 50% of operational balance
        
        vm.prank(admin);
        FastAccessVault(address(vault)).rescueToken(
            address(collateralToken), 
            recipient, 
            rescueAmount
        );
        
        // VERIFY: Accounting mismatch - unbacked iTRY created
        uint256 finalIssuedITRY = issuer.getTotalIssuedITry();
        uint256 finalDlfUnderCustody = issuer.getCollateralUnderCustody();
        uint256 finalVaultBalance = vault.getAvailableBalance();
        uint256 recipientBalance = collateralToken.balanceOf(recipient);
        
        console.log("\nAfter rescue:");
        console.log("Final issued iTRY:", finalIssuedITRY);
        console.log("Final DLF under custody (accounting):", finalDlfUnderCustody);
        console.log("Final vault DLF balance (actual):", finalVaultBalance);
        console.log("Rescued to recipient:", recipientBalance);
        
        // CRITICAL: Accounting shows full backing, but actual balance is reduced
        assertEq(finalIssuedITRY, issuedITRY, "Issued iTRY unchanged");
        assertEq(finalDlfUnderCustody, dlfUnderCustody, "Custody accounting NOT updated");
        assertEq(finalVaultBalance, vaultBalance - rescueAmount, "Vault balance reduced");
        assertEq(recipientBalance, rescueAmount, "DLF successfully rescued");
        
        // INVARIANT VIOLATED: iTRY is no longer fully backed
        assertGt(finalDlfUnderCustody, finalVaultBalance, 
            "VULNERABILITY: Accounting shows more DLF than actually exists");
        
        // IMPACT: Users cannot redeem because vault has insufficient balance
        vm.startPrank(whitelistedUser1);
        uint256 redeemAmount = finalIssuedITRY;
        
        // This will fail because vault doesn't have enough DLF
        vm.expectRevert();
        issuer.redeemFor(whitelistedUser1, redeemAmount, 0);
        vm.stopPrank();
        
        console.log("\n[!] CRITICAL: Protocol believes it has", finalDlfUnderCustody, "DLF");
        console.log("[!] CRITICAL: Vault actually has", finalVaultBalance, "DLF");
        console.log("[!] CRITICAL: iTRY is now UNBACKED by", finalDlfUnderCustody - finalVaultBalance, "DLF");
    }
}
```

## Notes

**Why this is NOT a centralization risk:** While the vulnerability requires owner privileges to exploit, it represents a fundamental code defect that violates the protocol's core invariant. The codebase itself demonstrates awareness of this issue:

- StakediTry explicitly prevents rescuing operational assets with validation [7](#0-6) 

- The comment in StakediTry states: "the owner cannot rescue iTry tokens because they functionally sit here and belong to stakers" [8](#0-7) 

This same principle should apply to FastAccessVault's DLF tokens - they functionally belong to iTRY holders as backing collateral and should not be rescuable. The test claiming this is an "intentional design feature" conflicts with the protocol's documented invariants. [9](#0-8) 

The proper design pattern exists in the codebase but was not consistently applied to FastAccessVault, creating a critical vulnerability that enables unbacked stablecoin minting.

### Citations

**File:** src/protocol/FastAccessVault.sol (L207-214)
```text
    /**
     * @notice Rescue tokens accidentally sent to this contract
     * @dev Only callable by owner. Can rescue both ERC20 tokens and native ETH
     *      Use address(0) for rescuing ETH
     * @param token The token address to rescue (use address(0) for ETH)
     * @param to The address to send rescued tokens to
     * @param amount The amount to rescue
     */
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

**File:** README.md (L122-122)
```markdown
- The total issued iTry in the Issuer contract should always be be equal or lower to the total value of the DLF under custody. It should not be possible to mint "unbacked" iTry through the issuer. This does not mean that _totalIssuedITry needs to be equal to iTry.totalSupply(), though: there could be more than one minter contract using different backing assets.
```

**File:** src/token/wiTRY/StakediTry.sol (L145-161)
```text
    /**
     * @notice Allows the owner to rescue tokens accidentally sent to the contract.
     * Note that the owner cannot rescue iTry tokens because they functionally sit here
     * and belong to stakers but can rescue staked iTry as they should never actually
     * sit in this contract and a staker may well transfer them here by accident.
     * @param token The token to be rescued.
     * @param amount The amount of tokens to be rescued.
     * @param to Where to send rescued tokens
     */
    function rescueTokens(address token, uint256 amount, address to)
        external
        nonReentrant
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (address(token) == asset()) revert InvalidToken();
        IERC20(token).safeTransfer(to, amount);
    }
```

**File:** test/FastAccessVault.t.sol (L1199-1207)
```text
    /// @dev Intentional design feature
    function test_rescueToken_whenRescuingVaultToken_succeeds() public {
        uint256 rescueAmount = 500_000e18;

        vault.rescueToken(address(vaultToken), user1, rescueAmount);

        assertEq(vaultToken.balanceOf(user1), rescueAmount, "Should be able to rescue vault token");
        assertEq(vault.getAvailableBalance(), INITIAL_VAULT_BALANCE - rescueAmount, "Vault balance decreased");
    }
```
