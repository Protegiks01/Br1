# NoVulnerability found for this question.

## Validation Confirmed

After thorough code analysis, I **confirm the security claim is correct**: there is **no sandwich attack vulnerability** in direct share bridging via `wiTryOFTAdapter`.

## Technical Validation

### 1. Lock/Unlock Pattern Confirmed

The `wiTryOFTAdapter` explicitly uses LayerZero's lock/unlock pattern, as documented in the code comments. [1](#0-0) 

This architectural decision preserves the vault's share-to-asset accounting by keeping `totalSupply` constant on the hub chain.

### 2. No Conversion During Bridging

The bridging flow operates purely at the ERC20 token level:

- **Hub to Spoke**: Shares are locked on hub chain via the adapter, LayerZero sends a message, and the OFT contract mints equivalent shares on the spoke chain. [2](#0-1) 

- **Spoke to Hub**: The reverse process occurs - OFT burns shares, message is sent, and adapter unlocks native shares. [3](#0-2) 

**Critical Point**: If a user bridges X shares, exactly X shares are locked on L1 and X shares are minted on L2. No share-to-asset conversion occurs.

### 3. Share-to-Asset Ratio Immaterial for Bridging

While the vault's share value is calculated dynamically based on total assets, [4](#0-3)  this ratio affects the **VALUE** of all shares proportionally, not the **NUMBER** of shares transferred during bridging. 

Any ratio changes between transaction submission and execution affect all shareholders equally, providing no asymmetric profit opportunity for MEV bots.

### 4. Correct Distinction from Composer Flow

The analyst correctly distinguished between:

- **Direct share bridging** (wiTryOFTAdapter): Pure token transfer without conversion
- **Composer flow** (VaultComposerSync): Performs asset-to-share conversions

The composer flow explicitly includes slippage protection because it performs conversions that CAN be sandwiched: [5](#0-4) 

And for redemptions: [6](#0-5) 

The slippage protection in the composer flow exists precisely because those operations involve conversions at the vault's current ratio.

## Conclusion

The analysis is technically sound. The `wiTryOFTAdapter`'s architectural decision to use lock/unlock serves dual purposes:
1. Preserves vault accounting integrity (intended design goal)
2. Makes share bridging immune to sandwich attacks (security property)

This is **correct-by-design behavior** where the bridging mechanism operates at the token level rather than the accounting level. Direct share bridging via `wiTryOFTAdapter` is indeed immune to sandwich attacks.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L22-24)
```text
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L15-19)
```text
 * Flow from Hub to Spoke:
 * 1. Hub adapter locks native wiTRY shares
 * 2. LayerZero message sent to this contract
 * 3. This contract mints equivalent OFT share tokens
 *
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L20-23)
```text
 * Flow from Spoke to Hub:
 * 1. This contract burns OFT share tokens
 * 2. LayerZero message sent to hub adapter
 * 3. Hub adapter unlocks native wiTRY shares
```

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L206-220)
```text
    function _depositAndSend(
        bytes32 _depositor,
        uint256 _assetAmount,
        SendParam memory _sendParam,
        address _refundAddress
    ) internal virtual {
        uint256 shareAmount = _deposit(_depositor, _assetAmount);
        _assertSlippage(shareAmount, _sendParam.minAmountLD);

        _sendParam.amountLD = shareAmount;
        _sendParam.minAmountLD = 0;

        _send(SHARE_OFT, _sendParam, _refundAddress);
        emit Deposited(_depositor, _sendParam.to, _sendParam.dstEid, _assetAmount, shareAmount);
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L268-282)
```text
    function _redeemAndSend(
        bytes32 _redeemer,
        uint256 _shareAmount,
        SendParam memory _sendParam,
        address _refundAddress
    ) internal virtual {
        uint256 assetAmount = _redeem(_redeemer, _shareAmount);
        _assertSlippage(assetAmount, _sendParam.minAmountLD);

        _sendParam.amountLD = assetAmount;
        _sendParam.minAmountLD = 0;

        _send(ASSET_OFT, _sendParam, _refundAddress);
        emit Redeemed(_redeemer, _sendParam.to, _sendParam.dstEid, _shareAmount, assetAmount);
    }
```
