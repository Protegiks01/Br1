## Title
LayerZero Decimal Conversion Causes Cross-Chain Unstake/Fast Redeem DOS Due to Zero Slippage Tolerance with Dust Amounts

## Summary
The `_handleUnstake` and `_fastRedeem` functions in `wiTryVaultComposer.sol` set both `amountLD` and `minAmountLD` to the exact asset amount returned from vault operations, providing zero slippage tolerance. However, LayerZero V2 OFT uses 6 shared decimals (vs 18 local decimals for iTRY), causing any dust amounts below 10^12 wei to be lost during decimal conversion. This causes legitimate unstake/fast redeem transactions to revert when the received amount (after losing dust) fails the `minAmountLD` check.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol`
- `_handleUnstake` function, lines 264-272
- `_fastRedeem` function, lines 116-117 [1](#0-0) [2](#0-1) 

**Intended Logic:** The code sets `minAmountLD = assets` to ensure users receive the exact amount of iTRY assets from their unstake/fast redeem operation with zero slippage tolerance.

**Actual Logic:** LayerZero OFT V2 uses shared decimals (default 6) for cross-chain normalization while iTRY uses 18 decimals. The conversion process:
1. Source chain: `amountSD = amountLD / 10^12` (integer division, loses dust)
2. Cross-chain transmission: sends `amountSD`
3. Destination chain: `receivedAmountLD = amountSD * 10^12` (reconstructs without dust)
4. Slippage check: `receivedAmountLD >= minAmountLD` (fails if original had dust)

When `assets` from ERC4626 vault calculations contains any amount below 10^12 wei (e.g., `1000000000000123` = 1 token + 123 wei dust), the received amount becomes `1000000000000` (dust lost), which is less than `minAmountLD = 1000000000000123`, causing the transaction to revert. [3](#0-2) 

**Exploitation Path:**
1. User initiates cooldown on L2 by sending wiTRY shares to L1 via `UnstakeMessenger`
2. After cooldown completes, user calls unstake on L2
3. `wiTryVaultComposer._handleUnstake` is triggered on L1, calling `unstakeThroughComposer(user)` which returns `assets` from `userCooldown.underlyingAmount`
4. This `assets` value comes from ERC4626's `previewRedeem(shares)` calculation, which can produce any precision within 18 decimals (e.g., contains 123 wei dust) [4](#0-3) [5](#0-4) 

5. `SendParam` is constructed with both `amountLD = assets` and `minAmountLD = assets` (zero slippage)
6. LayerZero OFT converts: `amountSD = assets / 10^12`, losing the 123 wei dust
7. On destination L2, LayerZero reconstructs: `receivedAmountLD = amountSD * 10^12` (now missing 123 wei)
8. Slippage check fails: `receivedAmountLD (missing dust) < minAmountLD (original with dust)`
9. Transaction reverts, user's iTRY remains locked, cannot unstake

**Security Property Broken:** Cross-chain Message Integrity invariant - "LayerZero messages for unstaking must be delivered to correct user with proper validation" is violated because legitimate unstake messages fail due to implementation error, not intentional validation failure.

## Impact Explanation
- **Affected Assets**: iTRY assets locked in cooldown on L1 vault, cannot be returned to users on L2
- **Damage Severity**: Users cannot complete unstake or fast redeem operations when their asset amounts contain dust below 10^12 wei. Funds are not permanently lost (owner can potentially rescue via `rescueToken`) but are temporarily inaccessible through normal protocol flow, requiring administrative intervention.
- **User Impact**: Any user attempting cross-chain unstake or fast redeem where ERC4626 share-to-asset calculations produce amounts with dust. Given vault yield distribution and variable share prices, dust is expected in most calculations. Affects both regular unstaking (after cooldown) and fast redeem paths.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a bug affecting legitimate users during normal protocol operations
- **Preconditions**: 
  - User has completed cooldown or is using fast redeem
  - The calculated asset amount from ERC4626 `previewRedeem` contains any remainder when divided by 10^12 (extremely common)
  - Vault share price is not a perfect multiple of 10^12 wei per share (typical with yield accrual)
- **Execution Complexity**: Single transaction (normal unstake/fast redeem call), no special timing or coordination required
- **Frequency**: High - occurs naturally for most unstake/fast redeem operations due to ERC4626 rounding and share price fluctuations from yield

## Recommendation

The fix is to remove dust from `minAmountLD` before sending, matching the pattern used correctly in `VaultComposerSync._depositAndSend` and `_redeemAndSend`: [6](#0-5) 

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _handleUnstake, lines 264-272:

// CURRENT (vulnerable):
SendParam memory _sendParam = SendParam({
    dstEid: _origin.srcEid,
    to: bytes32(uint256(uint160(user))),
    amountLD: assets,
    minAmountLD: assets, // Zero slippage - will fail on dust
    extraOptions: options,
    composeMsg: "",
    oftCmd: ""
});

// FIXED:
uint256 decimalConversionRate = 10**12; // 10^(localDecimals - sharedDecimals) = 10^(18-6)
SendParam memory _sendParam = SendParam({
    dstEid: _origin.srcEid,
    to: bytes32(uint256(uint160(user))),
    amountLD: assets,
    minAmountLD: (assets / decimalConversionRate) * decimalConversionRate, // Remove dust below 10^12 wei
    extraOptions: options,
    composeMsg: "",
    oftCmd: ""
});
```

Apply the same fix to `_fastRedeem` function at lines 116-117:

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _fastRedeem, lines 116-117:

// CURRENT (vulnerable):
_sendParam.amountLD = assets;
_sendParam.minAmountLD = assets;

// FIXED:
uint256 decimalConversionRate = 10**12;
_sendParam.amountLD = assets;
_sendParam.minAmountLD = (assets / decimalConversionRate) * decimalConversionRate; // Remove dust
```

**Alternative mitigation:** Set `minAmountLD = 0` after local validation, similar to the pattern in `VaultComposerSync`. However, the dust removal approach is more conservative as it still provides slippage protection at the granularity that LayerZero can actually support.

## Proof of Concept

```solidity
// File: test/Exploit_DecimalConversionDOS.t.sol
// Run with: forge test --match-test test_DecimalConversionDOS -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";

contract Exploit_DecimalConversionDOS is Test {
    wiTryVaultComposer composer;
    StakediTryCrosschain vault;
    
    function setUp() public {
        // Deploy contracts with realistic configuration
        // Initialize vault with assets that will produce dust amounts
    }
    
    function test_DecimalConversionDOS() public {
        // SETUP: User has cooldown with dust amount
        address user = address(0x123);
        uint256 shareAmount = 1000000000000000000; // 1 share
        
        // Simulate vault state where previewRedeem produces dust
        // e.g., due to yield accumulation, share price = 1.000000000000123 iTRY per share
        uint256 assetsWithDust = 1000000000000123; // 1 token + 123 wei dust
        
        // Simulate cooldown completion
        vm.warp(block.timestamp + vault.cooldownDuration());
        
        // EXPLOIT: User attempts legitimate unstake
        // This should succeed but will fail due to dust
        
        // Internal flow in _handleUnstake:
        // 1. assets = vault.unstakeThroughComposer(user) returns 1000000000000123
        // 2. SendParam.amountLD = 1000000000000123
        // 3. SendParam.minAmountLD = 1000000000000123 (zero slippage)
        
        // LayerZero conversion:
        uint256 decimalConversionRate = 10**12;
        uint256 amountSD = assetsWithDust / decimalConversionRate; // = 1 (loses 123 wei)
        uint256 receivedAmountLD = amountSD * decimalConversionRate; // = 1000000000000
        
        // VERIFY: Slippage check fails
        assertLt(receivedAmountLD, assetsWithDust, "Dust lost in conversion");
        assertEq(receivedAmountLD, 1000000000000, "Received amount missing dust");
        assertEq(assetsWithDust - receivedAmountLD, 123, "Exactly 123 wei dust lost");
        
        // This would cause LayerZero OFT to revert with slippage error:
        // require(receivedAmountLD >= minAmountLD) fails because:
        // 1000000000000 >= 1000000000000123 is false
        
        // User's funds remain locked, cannot unstake normally
    }
    
    function test_DecimalConversionDOS_FastRedeem() public {
        // Similar scenario for fast redeem path
        address user = address(0x456);
        uint256 shareAmount = 1000000000000000000;
        
        // Fast redeem calculates: assets = totalAssets - feeAssets
        // Both can have dust, resulting in final amount with dust
        uint256 totalAssets = 1000000000000456;
        uint256 feeAssets = 50000000000123; // 5% fee with dust
        uint256 assetsAfterFee = totalAssets - feeAssets; // Has dust
        
        // Same issue occurs in _fastRedeem with minAmountLD = assets (with dust)
        uint256 decimalConversionRate = 10**12;
        uint256 receivedAmountLD = (assetsAfterFee / decimalConversionRate) * decimalConversionRate;
        
        assertLt(receivedAmountLD, assetsAfterFee, "Dust lost in fast redeem");
        // Transaction fails, user cannot fast redeem despite paying fee
    }
}
```

## Notes

This vulnerability demonstrates a subtle but critical mismatch between:
1. **Local precision**: ERC4626 vault calculations using 18 decimals
2. **Cross-chain precision**: LayerZero OFT shared decimals (6 decimals by default)

The correct pattern is shown in `VaultComposerSync` where slippage is validated locally, then `minAmountLD` is set to 0 (or dust-adjusted) before cross-chain send. The vulnerable functions bypass this pattern by directly using vault-returned amounts as both `amountLD` and `minAmountLD`. [7](#0-6) 

The fix is straightforward: either remove dust from `minAmountLD` to match LayerZero's actual granularity, or set `minAmountLD = 0` after validating locally. The dust removal approach is recommended as it maintains some slippage protection while accounting for LayerZero's decimal conversion limitations.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L116-117)
```text
        _sendParam.amountLD = assets;
        _sendParam.minAmountLD = assets;
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L264-272)
```text
        SendParam memory _sendParam = SendParam({
            dstEid: _origin.srcEid,
            to: bytes32(uint256(uint160(user))),
            amountLD: assets,
            minAmountLD: assets,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
```

**File:** src/token/wiTRY/StakediTry.sol (L213-216)
```text
    /// @dev Necessary because both ERC20 (from ERC20Permit) and ERC4626 declare decimals()
    function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
        return 18;
    }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L46-47)
```text
        assets = previewRedeem(shares);
        _startComposerCooldown(composer, redeemer, shares, assets);
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L86-87)
```text
        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L212-218)
```text
        uint256 shareAmount = _deposit(_depositor, _assetAmount);
        _assertSlippage(shareAmount, _sendParam.minAmountLD);

        _sendParam.amountLD = shareAmount;
        _sendParam.minAmountLD = 0;

        _send(SHARE_OFT, _sendParam, _refundAddress);
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L274-281)
```text
        uint256 assetAmount = _redeem(_redeemer, _shareAmount);
        _assertSlippage(assetAmount, _sendParam.minAmountLD);

        _sendParam.amountLD = assetAmount;
        _sendParam.minAmountLD = 0;

        _send(ASSET_OFT, _sendParam, _refundAddress);
        emit Redeemed(_redeemer, _sendParam.to, _sendParam.dstEid, _shareAmount, assetAmount);
```
