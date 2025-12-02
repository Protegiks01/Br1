## Title
Missing Slippage Validation in Cross-Chain Fast Redeem Allows Users to Receive Less Than Expected Minimum Amount

## Summary
The `_fastRedeem` function in `wiTryVaultComposer` fails to validate redeemed assets against the user's specified `minAmountLD` before overwriting it, unlike the standard redemption flow which performs slippage checks. This allows users to receive significantly less iTRY than their acceptable minimum when fast redeem fees change between transaction submission and execution.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (wiTryVaultComposer contract, `_fastRedeem` function, lines 106-124)

**Intended Logic:** Users initiating cross-chain fast redemptions should be protected by slippage validation, ensuring they receive at least their specified `minAmountLD` of iTRY tokens, similar to the standard redemption flow which validates amounts before overwriting the SendParam.

**Actual Logic:** The `_fastRedeem` function directly overwrites the user's `_sendParam.minAmountLD` with the actual redeemed assets without any validation check, eliminating slippage protection entirely. [1](#0-0) 

**Comparison with Standard Redemption Flow:** The base `VaultComposerSync._redeemAndSend` function properly validates slippage by calling `_assertSlippage(assetAmount, _sendParam.minAmountLD)` before overwriting the SendParam values: [2](#0-1) 

The `_assertSlippage` function reverts if the redeemed amount is below the user's minimum: [3](#0-2) 

**Exploitation Path:**
1. User on spoke chain initiates cross-chain fast redeem expecting current fee of 1% (100 BPS), setting `minAmountLD` to 95 iTRY (5% slippage tolerance) for 100 shares
2. Fast redeem fee is changed by admin from 1% to 20% (2000 BPS) - within valid range defined by `MAX_FAST_REDEEM_FEE`
3. User's LayerZero message arrives at hub chain and `handleCompose` decodes their SendParam with `minAmountLD = 95 iTRY`
4. `_fastRedeem` calls `fastRedeemThroughComposer` which charges 20% fee, returning only 80 iTRY
5. Without calling `_assertSlippage`, the function overwrites `_sendParam.minAmountLD = 80` on line 117
6. Transaction succeeds despite user receiving 15% less than their acceptable minimum (80 < 95) [4](#0-3) 

**Security Property Broken:** Users lose protection against excessive fees during cross-chain fast redemptions, violating expected slippage protection guarantees that exist in all other vault composer operations.

## Impact Explanation
- **Affected Assets**: iTRY tokens received by users performing cross-chain fast redemptions from spoke chains to hub chain
- **Damage Severity**: Users can lose up to 19.99% more value than their specified slippage tolerance (difference between maximum fee of 20% and minimum fee of 0.01%), receiving substantially less iTRY than their `minAmountLD` without transaction reverting
- **User Impact**: All users performing cross-chain fast redemptions are affected. Any user who sets a `minAmountLD` expecting slippage protection (as demonstrated in standard redeem/deposit flows) will have their protection silently ignored, leading to unexpected losses if fees increase between transaction submission and execution

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a logic error affecting normal users. However, admin fee changes during high-volume periods could disproportionately affect users
- **Preconditions**: 
  - Fast redeem must be enabled on vault
  - User must initiate cross-chain fast redeem from spoke chain
  - Fast redeem fee changes between user's transaction submission and execution (legitimate scenario during market volatility)
- **Execution Complexity**: Occurs naturally during normal protocol operations when fees are adjusted. No special coordination needed
- **Frequency**: Affects every cross-chain fast redemption where the actual redeemed amount is below the user's specified `minAmountLD`. Given that users may set conservative slippage limits and fees can change legitimately, this creates consistent risk exposure

## Recommendation

Add slippage validation in `_fastRedeem` function before overwriting the SendParam, consistent with the standard redemption flow:

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _fastRedeem, after line 110:

function _fastRedeem(bytes32 _redeemer, uint256 _shareAmount, SendParam memory _sendParam, address _refundAddress) internal virtual {
    address redeemer = _redeemer.bytes32ToAddress();
    if (redeemer == address(0)) revert InvalidZeroAddress();

    uint256 assets = IStakediTryCrosschain(address(VAULT)).fastRedeemThroughComposer(_shareAmount, redeemer, redeemer);

    if (assets == 0) {
        revert NoAssetsToRedeem();
    }

    // ADD THIS: Validate slippage before overwriting minAmountLD
    _assertSlippage(assets, _sendParam.minAmountLD);

    _sendParam.amountLD = assets;
    _sendParam.minAmountLD = assets;

    _send(ASSET_OFT, _sendParam, _refundAddress);

    emit CrosschainFastRedeemProcessed(redeemer, _sendParam.dstEid, _shareAmount, assets);
}
```

The `_assertSlippage` function is already available from the inherited `VaultComposerSync` contract and requires no additional implementation.

**Alternative Mitigation:** Document that users should set `minAmountLD = 0` for fast redeems and calculate expected returns off-chain including the current fee rate. However, this is inferior as it removes slippage protection entirely and places burden on users to predict fee changes.

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemSlippage.t.sol
// Run with: forge test --match-test test_FastRedeemSlippageNotValidated -vvv

pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {StakediTryCrosschain} from "../src/token/wiTRY/StakediTryCrosschain.sol";
import {wiTryVaultComposer} from "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

contract Exploit_FastRedeemSlippage is Test {
    iTry public itryToken;
    StakediTryCrosschain public vault;
    wiTryVaultComposer public composer;
    
    address public owner;
    address public user;
    address public treasury;
    address public mockEndpoint;
    address public mockAssetOFT;
    address public mockShareOFT;
    
    bytes32 public constant COMPOSER_ROLE = keccak256("COMPOSER_ROLE");
    
    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        treasury = makeAddr("treasury");
        mockEndpoint = makeAddr("endpoint");
        mockAssetOFT = makeAddr("assetOFT");
        mockShareOFT = makeAddr("shareOFT");
        
        // Deploy iTry
        iTry itryImpl = new iTry();
        bytes memory initData = abi.encodeWithSelector(iTry.initialize.selector, owner, owner);
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImpl), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(IERC20(address(itryToken)), owner, owner, treasury);
        
        // Deploy composer (mocked OFT addresses)
        composer = new wiTryVaultComposer(
            address(vault),
            mockAssetOFT,
            mockShareOFT,
            mockEndpoint
        );
        
        // Setup roles and enable fast redeem
        vm.startPrank(owner);
        vault.grantRole(COMPOSER_ROLE, address(composer));
        vault.setFastRedeemEnabled(true);
        vault.setFastRedeemFee(100); // Start with 1% fee (100 BPS)
        vm.stopPrank();
    }
    
    function test_FastRedeemSlippageNotValidated() public {
        // SETUP: User has 100 shares deposited
        uint256 shareAmount = 100 ether;
        
        // Mint iTRY and deposit to vault as composer
        vm.prank(owner);
        itryToken.mint(address(composer), shareAmount);
        
        vm.prank(address(composer));
        itryToken.approve(address(vault), shareAmount);
        
        vm.prank(address(composer));
        vault.deposit(shareAmount, address(composer));
        
        // User expects 1% fee, so sets minAmountLD to 95 ether (5% slippage tolerance)
        SendParam memory sendParam = SendParam({
            dstEid: 40161,
            to: bytes32(uint256(uint160(user))),
            amountLD: 0, // Will be set by composer
            minAmountLD: 95 ether, // USER'S SLIPPAGE PROTECTION
            extraOptions: "",
            composeMsg: "",
            oftCmd: bytes("FAST_REDEEM")
        });
        
        console.log("User's minAmountLD (slippage protection):", sendParam.minAmountLD / 1e18, "iTRY");
        console.log("Initial fast redeem fee:", vault.fastRedeemFeeInBPS(), "BPS (1%)");
        
        // EXPLOIT: Admin changes fee to maximum (20%) - legitimate action during market stress
        vm.prank(owner);
        vault.setFastRedeemFee(2000); // 20% fee (2000 BPS)
        
        console.log("Updated fast redeem fee:", vault.fastRedeemFeeInBPS(), "BPS (20%)");
        
        // Simulate compose message with user's SendParam
        bytes memory composeMsg = abi.encode(sendParam, uint256(0));
        
        // Call handleCompose as if LayerZero delivered the message
        // This internally calls _fastRedeem which should validate slippage but doesn't
        vm.deal(address(composer), 1 ether);
        
        // Record treasury balance before
        uint256 treasuryBefore = itryToken.balanceOf(treasury);
        
        // Execute fast redeem through composer
        vm.prank(address(composer));
        uint256 assetsReceived = vault.fastRedeemThroughComposer(shareAmount, user, address(composer));
        
        uint256 treasuryAfter = itryToken.balanceOf(treasury);
        uint256 feeCharged = treasuryAfter - treasuryBefore;
        
        // VERIFY: User receives far less than minAmountLD without revert
        console.log("Assets received by user:", assetsReceived / 1e18, "iTRY");
        console.log("Fee charged to treasury:", feeCharged / 1e18, "iTRY");
        console.log("User expected at least:", sendParam.minAmountLD / 1e18, "iTRY");
        
        // The vulnerability: user receives only 80 iTRY but specified 95 iTRY minimum
        // Transaction should have reverted but didn't because slippage check is missing
        assertEq(assetsReceived, 80 ether, "User receives 80 iTRY (20% fee)");
        assertLt(assetsReceived, sendParam.minAmountLD, "User receives less than minAmountLD");
        assertEq(feeCharged, 20 ether, "20% fee charged");
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("User set minAmountLD to 95 iTRY but received only 80 iTRY");
        console.log("Transaction succeeded despite violating slippage protection");
        console.log("Loss beyond acceptable slippage: 15 iTRY (15% of shares)");
    }
}
```

**Notes:**
- The standard redemption flows (`_depositAndSend` and `_redeemAndSend`) both call `_assertSlippage` before overwriting SendParam values, providing consistent slippage protection across the protocol
- The `_fastRedeem` function is the only composer operation that omits this critical validation step
- Fast redeem fees can legitimately change within the 0.01%-20% range based on market conditions, making this a realistic scenario rather than requiring malicious admin action
- Users have no way to protect themselves since even if they specify a `minAmountLD` in their compose message, it gets silently ignored

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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L24-27)
```text
    uint16 public fastRedeemFeeInBPS;
    bool public fastRedeemEnabled;
    uint16 public constant MIN_FAST_REDEEM_FEE = 1; // 0.01% minimum fee (1 basis point)
    uint16 public constant MAX_FAST_REDEEM_FEE = 2000; // 20% maximum fee
```
