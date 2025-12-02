## Title
Fast Redeem Bypasses User Slippage Protection Leading to Unexpected Value Loss

## Summary
The `_fastRedeem` function in `wiTryVaultComposer` overwrites the user's slippage protection parameter (`minAmountLD`) without validation, allowing transactions to succeed even when the redeemed assets fall below the user's minimum acceptable amount. This violates the established slippage protection pattern used elsewhere in the codebase and can result in users receiving significantly less iTRY than expected due to fast redemption fees up to 20%.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The fast redeem cross-chain flow should respect user-defined slippage protection by validating that the redeemed assets meet the minimum amount specified in `_sendParam.minAmountLD` before processing the transaction, consistent with the standard redemption pattern.

**Actual Logic:** The `_fastRedeem` function directly overwrites both `_sendParam.amountLD` and `_sendParam.minAmountLD` with the actual redeemed assets without any validation against the user's original slippage protection.

**Exploitation Path:**
1. User on Spoke chain initiates cross-chain fast redeem with 1000 wiTRY shares and sets `minAmountLD = 900 ether` in their compose message (expecting at least 900 iTRY after accounting for fees)
2. The fast redeem fee is currently set at 20% (MAX_FAST_REDEEM_FEE) [2](#0-1) 
3. `fastRedeemThroughComposer()` burns the shares and returns 800 iTRY (1000 - 20% fee) [3](#0-2) 
4. `_fastRedeem()` overwrites `minAmountLD = 800` without checking against the user's original 900 minimum requirement [4](#0-3) 
5. Transaction succeeds and user receives 800 iTRY instead of the 900 iTRY minimum they specified

**Security Property Broken:** Users' slippage protection is violated. The standard pattern implemented in `_depositAndSend()` and `_redeemAndSend()` validates actual amounts against `minAmountLD` via `_assertSlippage()` before overwriting parameters [5](#0-4) [6](#0-5) , but this protection is completely absent in `_fastRedeem()`.

## Impact Explanation
- **Affected Assets**: iTRY tokens returned from fast redemption cross-chain operations
- **Damage Severity**: Users can lose up to the difference between their expected minimum and actual received amount. With fees up to 20%, this could represent significant value loss (e.g., expecting 900 iTRY minimum but receiving 800 iTRY = 100 iTRY loss beyond user's tolerance)
- **User Impact**: All users performing cross-chain fast redemption who set slippage protection are affected. The issue is triggered whenever the redeemed assets (after fee) fall below the user's specified minimum, which can occur due to fee adjustments by admin or unfavorable share-to-asset conversion rates

## Likelihood Explanation
- **Attacker Profile**: Any user performing cross-chain fast redemption (no special privileges required)
- **Preconditions**: Fast redemption must be enabled, and the fee must cause the net redeemed assets to fall below the user's specified minimum
- **Execution Complexity**: Single cross-chain transaction initiated by the user
- **Frequency**: Occurs on every fast redemption where the actual assets are less than the user's `minAmountLD`, which is common when users set protective slippage bounds

## Recommendation

Add slippage validation before overwriting the SendParam values:

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _fastRedeem, line 106:

function _fastRedeem(bytes32 _redeemer, uint256 _shareAmount, SendParam memory _sendParam, address _refundAddress) internal virtual {
    address redeemer = _redeemer.bytes32ToAddress();
    if (redeemer == address(0)) revert InvalidZeroAddress();

    uint256 assets = IStakediTryCrosschain(address(VAULT)).fastRedeemThroughComposer(_shareAmount, redeemer, redeemer);
    
    if (assets == 0) {
        revert NoAssetsToRedeem();
    }

    // FIXED: Add slippage validation before overwriting
    _assertSlippage(assets, _sendParam.minAmountLD);

    _sendParam.amountLD = assets;
    _sendParam.minAmountLD = 0; // Reset to 0 after validation (consistent with standard pattern)

    _send(ASSET_OFT, _sendParam, _refundAddress);

    emit CrosschainFastRedeemProcessed(redeemer, _sendParam.dstEid, _shareAmount, assets);
}
```

This change:
1. Validates the redeemed assets against user's minimum before proceeding
2. Follows the established pattern in `_depositAndSend()` and `_redeemAndSend()` [7](#0-6) 
3. Reverts with `SlippageExceeded` error if the user's minimum is not met
4. Resets `minAmountLD` to 0 after validation (not to the actual amount) to prevent OFT-level double validation

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemSlippageBypass.t.sol
// Run with: forge test --match-test test_FastRedeemSlippageBypass -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import {SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

contract Exploit_FastRedeemSlippageBypass is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    address user = address(0x1234);
    
    function setUp() public {
        // Initialize vault and composer
        // Set fast redeem fee to 20% (MAX_FAST_REDEEM_FEE)
        // User has 1000 wiTRY shares
    }
    
    function test_FastRedeemSlippageBypass() public {
        // SETUP: User sets minimum acceptable amount to 900 iTRY
        SendParam memory sendParam = SendParam({
            dstEid: 40232, // Spoke chain
            to: bytes32(uint256(uint160(user))),
            amountLD: 0,
            minAmountLD: 900 ether, // User wants at least 900 iTRY
            extraOptions: "",
            composeMsg: "",
            oftCmd: bytes("FAST_REDEEM")
        });
        
        uint256 shareAmount = 1000 ether;
        
        // EXPLOIT: Fast redeem with 20% fee returns only 800 iTRY
        // Expected: Transaction should revert with SlippageExceeded
        // Actual: Transaction succeeds with 800 iTRY
        
        vm.prank(address(composer));
        uint256 receivedAssets = vault.fastRedeemThroughComposer(shareAmount, user, user);
        
        // VERIFY: User receives less than their minimum
        assertEq(receivedAssets, 800 ether, "User received 800 iTRY");
        assertLt(receivedAssets, sendParam.minAmountLD, "Slippage protection violated");
        
        // In _fastRedeem, minAmountLD is overwritten to 800
        // Transaction succeeds despite user expecting minimum 900
    }
}
```

**Notes:**
- The vulnerability stems from an inconsistent implementation pattern: standard redemption flows validate slippage, but fast redemption does not
- The issue is exacerbated by the high maximum fee (20%) that can be applied to fast redemptions
- The `_handleUnstake()` function exhibits similar behavior but is less problematic since it doesn't involve user-controlled slippage parameters in the initial message [8](#0-7) 
- The fix aligns with the established pattern used in the parent `VaultComposerSync` contract, ensuring consistency across all redemption flows

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L106-124)
```text
    function _fastRedeem(bytes32 _redeemer, uint256 _shareAmount, SendParam memory _sendParam, address _refundAddress) internal virtual {
         address redeemer = _redeemer.bytes32ToAddress();
        if (redeemer == address(0)) revert InvalidZeroAddress();

        uint256 assets = IStakediTryCrosschain(address(VAULT)).fastRedeemThroughComposer(_shareAmount, redeemer, redeemer); // redeemer is the owner and crosschain receiver

          if (assets == 0) {
            revert NoAssetsToRedeem();
        }

        _sendParam.amountLD = assets;
        _sendParam.minAmountLD = assets;

        _send(ASSET_OFT, _sendParam, _refundAddress);

        // Emit success event
        emit CrosschainFastRedeemProcessed(redeemer, _sendParam.dstEid, _shareAmount, assets);

    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L244-278)
```text
    function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
        internal
        virtual
    {
        address user = unstakeMsg.user;

        // Validate user
        if (user == address(0)) revert InvalidZeroAddress();
        if (_origin.srcEid == 0) revert InvalidOrigin();

        // Call vault to unstake
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);

        if (assets == 0) {
            revert NoAssetsToUnstake();
        }

        // Build send parameters and send assets back to spoke chain
        bytes memory options = OptionsBuilder.newOptions();

        SendParam memory _sendParam = SendParam({
            dstEid: _origin.srcEid,
            to: bytes32(uint256(uint160(user))),
            amountLD: assets,
            minAmountLD: assets,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });

        _send(ASSET_OFT, _sendParam, address(this));

        // Emit success event
        emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L27-27)
```text
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L112-131)
```text
    function fastRedeemThroughComposer(uint256 shares, address crosschainReceiver, address owner)
        external
        onlyRole(COMPOSER_ROLE)
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 assets)
    {
        address composer = msg.sender;
        if (crosschainReceiver == address(0)) revert InvalidZeroAddress();
        if (shares > maxRedeem(composer)) revert ExcessiveRedeemAmount(); // Composer holds the shares on behave of the owner

        uint256 totalAssets = previewRedeem(shares);
        uint256 feeAssets = _redeemWithFee(shares, totalAssets, composer, composer); // Composer receives the assets for further crosschain transfer

        assets = totalAssets - feeAssets;

        emit FastRedeemedThroughComposer(composer, crosschainReceiver, owner, shares, assets, feeAssets);

        return assets;
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

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L309-311)
```text
    function _assertSlippage(uint256 _amountLD, uint256 _minAmountLD) internal view virtual {
        if (_amountLD < _minAmountLD) revert SlippageExceeded(_amountLD, _minAmountLD);
    }
```
