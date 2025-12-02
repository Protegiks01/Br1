# NoVulnerability found for this question.

## Validation Summary

After thorough code review and analysis, I confirm the security claim is **correct**: there is **no sandwich attack vulnerability** in direct share bridging via `wiTryOFTAdapter`.

## Technical Validation

### 1. Share Bridging Mechanism Confirmed

The `wiTryOFTAdapter` indeed uses LayerZero's lock/unlock pattern as documented: [1](#0-0) 

This design choice explicitly preserves the vault's share-to-asset accounting by keeping `totalSupply` constant on the hub chain.

### 2. No Conversion During Bridging

The bridging flow operates purely at the ERC20 token level:
- LayerZero's `OFTAdapter` base contract handles `_debit()` which performs standard ERC20 `transferFrom()` 
- Shares are locked in the adapter contract (not burned)
- On the destination chain, `wiTryOFT` mints equivalent share tokens via `_credit()`
- **No conversion between shares and assets occurs** - if user bridges X shares, exactly X shares are locked on L1 and X shares are minted on L2

### 3. Share-to-Asset Ratio Immaterial

While the vault's share value is calculated dynamically: [2](#0-1) 

This ratio affects the VALUE of all shares proportionally, not the NUMBER of shares transferred during bridging. Any ratio changes between transaction submission and execution affect all shareholders equally, providing no asymmetric profit opportunity for MEV bots.

### 4. Key Distinction Correctly Identified

The analyst correctly distinguished between:
- **Direct share bridging** (wiTryOFTAdapter): Transfers shares as ERC20 tokens without conversion
- **Composer flow** (VaultComposerSync): Performs asset-to-share conversions with slippage protection

The question specifically addresses direct share bridging, which is immune to sandwich attacks.

## Notes

The analysis is technically sound. The wiTryOFTAdapter's architectural decision to use lock/unlock (rather than mint/burn) serves dual purposes:
1. Preserves vault accounting integrity (intended design goal)
2. Makes share bridging immune to ratio manipulation attacks (security property)

This is not a vulnerability - it's correct-by-design behavior where the bridging mechanism operates at the token level rather than the accounting level.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L22-24)
```text
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
```

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```
