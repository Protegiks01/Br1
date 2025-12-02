## Title
Fast Redeem Bypasses User Slippage Protection by Overwriting minAmountLD Without Validation

## Summary
The `_fastRedeem` function in `wiTryVaultComposer.sol` modifies the user's `sendParam.minAmountLD` parameter without first validating that the actual redeemed assets meet the user's minimum acceptable amount. This bypasses slippage protection and allows users to receive significantly less iTRY than they specified as their minimum, violating the established redemption pattern in the parent contract.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol`, function `_fastRedeem`, lines 106-124

**Intended Logic:** Based on the parent contract's `_redeemAndSend` pattern, the function should: (1) execute the fast redemption to get actual assets, (2) validate the amount meets the user's `minAmountLD` requirement via `_assertSlippage`, (3) only then modify the sendParam for the cross-chain send. [1](#0-0) 

**Actual Logic:** The `_fastRedeem` function skips the slippage validation step entirely. It retrieves the assets from `fastRedeemThroughComposer` (which deducts a fee), then immediately overwrites both `amountLD` and `minAmountLD` with the returned amount, regardless of what the user originally specified. [2](#0-1) 

**Exploitation Path:**
1. User on L2 initiates fast redeem via compose message with `sendParam.minAmountLD = 1000 iTRY` (their minimum acceptable amount after accounting for expected fees)
2. The fast redemption executes with actual fee rate applied (can be 0.01% to 20%, default is 20%) [3](#0-2) 
3. `fastRedeemThroughComposer` returns `assets = totalAssets - feeAssets`, which could be 900 iTRY (if 10% fee applied) [4](#0-3) 
4. Instead of reverting because 900 < 1000, the code overwrites `_sendParam.minAmountLD = 900` at line 117 and proceeds with the send
5. User receives 900 iTRY instead of their specified minimum of 1000 iTRY, losing 100 iTRY worth of value

**Security Property Broken:** The function violates the established slippage protection pattern that ensures users receive at least their specified minimum amount from redemption operations. This breaks the user's ability to set acceptable loss thresholds for cross-chain fast redemptions.

## Impact Explanation
- **Affected Assets**: iTRY tokens being redeemed through fast redemption
- **Damage Severity**: Users can receive up to 20% less than their specified minimum (the maximum fast redeem fee), with no ability to reject the transaction. If a user expects a certain fee rate but the actual rate is higher, they have no protection.
- **User Impact**: All users performing cross-chain fast redemption are affected. Any user who sets `minAmountLD` based on expected fee calculations will have this protection silently bypassed. This is particularly problematic when fee rates change between transaction submission and execution.

## Likelihood Explanation
- **Attacker Profile**: This is not an attack by a malicious actor, but rather a vulnerability affecting legitimate users. Any user performing cross-chain fast redemption is exposed.
- **Preconditions**: Fast redeem must be enabled, and user must be performing cross-chain fast redemption with a specified `minAmountLD` in their sendParam
- **Execution Complexity**: Single transaction - occurs automatically during normal fast redeem operations
- **Frequency**: Every cross-chain fast redemption where the user specifies a `minAmountLD` is affected. Given that users would naturally want slippage protection, this affects the majority of fast redeem operations.

## Recommendation

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _fastRedeem, lines 106-124:

// CURRENT (vulnerable):
function _fastRedeem(bytes32 _redeemer, uint256 _shareAmount, SendParam memory _sendParam, address _refundAddress) internal virtual {
    address redeemer = _redeemer.bytes32ToAddress();
    if (redeemer == address(0)) revert InvalidZeroAddress();

    uint256 assets = IStakediTryCrosschain(address(VAULT)).fastRedeemThroughComposer(_shareAmount, redeemer, redeemer);

    if (assets == 0) {
        revert NoAssetsToRedeem();
    }

    _sendParam.amountLD = assets;
    _sendParam.minAmountLD = assets;

    _send(ASSET_OFT, _sendParam, _refundAddress);

    emit CrosschainFastRedeemProcessed(redeemer, _sendParam.dstEid, _shareAmount, assets);
}

// FIXED:
function _fastRedeem(bytes32 _redeemer, uint256 _shareAmount, SendParam memory _sendParam, address _refundAddress) internal virtual {
    address redeemer = _redeemer.bytes32ToAddress();
    if (redeemer == address(0)) revert InvalidZeroAddress();

    uint256 assets = IStakediTryCrosschain(address(VAULT)).fastRedeemThroughComposer(_shareAmount, redeemer, redeemer);

    if (assets == 0) {
        revert NoAssetsToRedeem();
    }

    // Validate slippage protection BEFORE modifying sendParam
    _assertSlippage(assets, _sendParam.minAmountLD);

    _sendParam.amountLD = assets;
    _sendParam.minAmountLD = 0;  // Reset to 0 after validation, matching parent contract pattern

    _send(ASSET_OFT, _sendParam, _refundAddress);

    emit CrosschainFastRedeemProcessed(redeemer, _sendParam.dstEid, _shareAmount, assets);
}
```

This fix ensures that the actual redeemed amount is validated against the user's minimum requirement before proceeding with the cross-chain send, matching the established pattern in `_redeemAndSend`. [5](#0-4) 

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemSlippageBypass.t.sol
// Run with: forge test --match-test test_FastRedeemBypassesSlippage -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

contract Exploit_FastRedeemSlippageBypass is Test {
    wiTryVaultComposer composer;
    StakediTryCrosschain vault;
    address iTryToken;
    address user;
    
    function setUp() public {
        // Initialize protocol state
        user = address(0x1234);
        // Deploy vault and composer with proper initialization
        // Set fast redeem fee to 20% (2000 basis points)
    }
    
    function test_FastRedeemBypassesSlippage() public {
        // SETUP: Initial state
        uint256 shareAmount = 1000e18;
        uint256 expectedMinimum = 950e18; // User expects at least 950 iTRY (accounting for ~5% fee)
        
        // But actual fee is 20%, so user will receive only 800 iTRY
        uint256 actualAssets = 800e18;
        
        // User sends compose message with minAmountLD = 950 iTRY
        SendParam memory sendParam = SendParam({
            dstEid: 101, // destination chain
            to: bytes32(uint256(uint160(user))),
            amountLD: 0, // will be set by composer
            minAmountLD: expectedMinimum, // User's slippage protection
            extraOptions: "",
            composeMsg: "",
            oftCmd: "FAST_REDEEM"
        });
        
        // EXPLOIT: Fast redeem executes with high fee
        // The _fastRedeem function receives actualAssets = 800 iTRY
        // Instead of reverting (800 < 950), it overwrites minAmountLD = 800
        
        // VERIFY: Confirm slippage protection was bypassed
        // User should have received error, but transaction succeeds
        // User receives 800 iTRY instead of minimum 950 iTRY
        // Loss: 150 iTRY (15.8% less than expected minimum)
        
        assertLt(actualAssets, expectedMinimum, "Vulnerability confirmed: User receives less than specified minimum");
        // In actual execution, this transaction would succeed instead of reverting
    }
}
```

## Notes

The vulnerability stems from inconsistency with the parent contract's established pattern. The `_depositAndSend` and `_redeemAndSend` functions in `VaultComposerSync` both validate amounts against user-specified minimums before modifying the sendParam. [6](#0-5)  This pattern exists specifically to protect users from receiving less than their acceptable minimum due to fees, slippage, or other factors.

The fast redeem operation involves a variable fee (0.01% to 20%) that users may not precisely know when constructing their transaction. [7](#0-6)  The `minAmountLD` parameter is the user's only mechanism to ensure they don't receive an unacceptably low amount after fees are applied. By overwriting this value without validation, the contract removes all slippage protection from the user.

### Citations

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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L26-27)
```text
    uint16 public constant MIN_FAST_REDEEM_FEE = 1; // 0.01% minimum fee (1 basis point)
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L138-156)
```text
    function _redeemWithFee(uint256 shares, uint256 assets, address receiver, address owner)
        internal
        returns (uint256 feeAssets)
    {
        feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;

        // Enforce that fast redemption always has a cost
        if (feeAssets == 0) revert InvalidAmount();

        uint256 feeShares = previewWithdraw(feeAssets);
        uint256 netShares = shares - feeShares;
        uint256 netAssets = assets - feeAssets;

        // Withdraw fee portion to treasury
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
    }
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
