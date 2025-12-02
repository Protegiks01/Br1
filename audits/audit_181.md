# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the wiTryOFTAdapter.sol share bridging mechanism and its interaction with the StakediTry ERC4626 vault, I found no exploitable sandwich attack vulnerability.

**Key Technical Findings:**

**1. Share Bridging Mechanism**

The wiTryOFTAdapter uses LayerZero's OFTAdapter with a lock/unlock pattern. [1](#0-0) 

During bridging:
- Shares are transferred as ERC20 tokens via `safeTransferFrom` (LayerZero's `_debit` function)
- The same number of shares are locked on L1 and minted on L2
- **No conversion between shares and assets occurs**

The test suite confirms this behavior. [2](#0-1) 

**2. Share-to-Asset Ratio Calculation**

The vault's share value is determined by: [3](#0-2) 

While this ratio can change due to deposits/withdrawals, it doesn't affect the bridging process because:
- Shares are locked as ERC20 tokens, not converted based on the ratio
- The bridging user sends X shares and receives X shares on the destination chain
- Any ratio changes affect all shareholders proportionally, not specifically the bridging user

**3. Why MEV Sandwich Attacks Don't Work**

A hypothetical MEV attack would involve:
1. Front-running the bridge transaction with a large deposit/withdraw
2. User's shares get locked (but as an ERC20 transfer, unaffected by the ratio)
3. Back-running to restore the vault state

This fails because:
- The number of shares transferred is fixed at transaction execution time
- Share quantity is preserved across chains (not recalculated based on ratio)
- No asymmetric profit opportunity exists for the MEV bot

**4. Distinction from Composer Flow**

The VaultComposerSync does perform asset-to-share conversions with slippage protection, but this is a different flow for depositing assets cross-chain. [4](#0-3) 

The question specifically asks about share bridging via wiTryOFTAdapter, which operates on shares directly without conversion.

## Notes

The wiTryOFTAdapter's design choice to use lock/unlock rather than mint/burn is explicitly to preserve the vault's share-to-asset accounting integrity. This same design property ensures that share bridging is immune to ratio manipulation attacks, as the bridging process operates on the share token level (ERC20 transfers) rather than the vault accounting level (asset-to-share conversions).

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L22-25)
```text
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
 */
```

**File:** test/crosschainTests/crosschain/Step8_ShareBridging.t.sol (L119-128)
```text
        // Verify shares locked on Sepolia
        uint256 userSharesAfterSend = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesAfterSend = sepoliaVault.balanceOf(address(sepoliaShareAdapter));

        console.log("\nAfter Send (Sepolia):");
        console.log("  userL1 shares:", userSharesAfterSend);
        console.log("  adapter shares (locked):", adapterSharesAfterSend);

        assertEq(userSharesAfterSend, INITIAL_DEPOSIT - SHARES_TO_BRIDGE, "User should have 50 shares remaining");
        assertEq(adapterSharesAfterSend, SHARES_TO_BRIDGE, "Adapter should have locked 50 shares");
```

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L212-213)
```text
        uint256 shareAmount = _deposit(_depositor, _assetAmount);
        _assertSlippage(shareAmount, _sendParam.minAmountLD);
```
