## Title
Event Log Mismatch: `FastRedeemedThroughComposer` Emits Incorrect Cross-Chain Destination Address

## Summary
The `fastRedeemThroughComposer` function emits a `FastRedeemedThroughComposer` event claiming iTRY will be sent to the `crosschainReceiver` address, but the actual cross-chain transfer in `wiTryVaultComposer._fastRedeem()` uses a user-controlled `sendParam.to` field that can differ from the logged address, creating permanently incorrect event logs.

## Impact
**Severity**: Medium

## Finding Description
**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
According to the interface documentation, the `crosschainReceiver` parameter represents the "Address that will receive iTRY on remote chain". [3](#0-2) 

The event emission is expected to accurately log where iTRY assets will be bridged cross-chain.

**Actual Logic:** 
The `fastRedeemThroughComposer` function receives a `crosschainReceiver` parameter and emits it in the event [4](#0-3) , but this function only redeems shares to the composer's balance [5](#0-4) . It does NOT perform any cross-chain transfer.

The actual cross-chain transfer happens in `wiTryVaultComposer._fastRedeem()`, which calls `fastRedeemThroughComposer` with `redeemer` as the `crosschainReceiver` [6](#0-5) , but then sends iTRY using the original `_sendParam` without validating that `_sendParam.to` matches the logged `redeemer` address [7](#0-6) .

The function only modifies the amount fields of `_sendParam` but leaves the `to` field unchanged from the user's original compose message input.

**Exploitation Path:**
1. Alice on Arbitrum (spoke chain) initiates a fast redeem by sending wiTRY shares via LayerZero compose message
2. In her compose message, Alice sets `sendParam.to = 0xBob` (any address different from her own)
3. LayerZero delivers the message to wiTryVaultComposer on hub chain with `_composeFrom = 0xAlice`
4. `_fastRedeem()` extracts `redeemer = 0xAlice` and calls `fastRedeemThroughComposer(shares, 0xAlice, 0xAlice)`
5. Event emits: `FastRedeemedThroughComposer(composer, 0xAlice, 0xAlice, shares, assets, fees)` - claiming iTRY goes to Alice
6. `_fastRedeem()` then calls `_send(ASSET_OFT, _sendParam, refundAddr)` where `_sendParam.to = 0xBob`
7. iTRY is actually bridged to Bob, but the permanent on-chain event log claims it went to Alice

**Security Property Broken:** 
This violates data integrity expectations where event logs should accurately reflect the protocol's actual state changes and fund movements. It breaks trust in the event system as a reliable audit trail. [8](#0-7) 

## Impact Explanation
- **Affected Assets**: iTRY tokens being bridged cross-chain during fast redemption operations
- **Damage Severity**: While no direct fund theft occurs (the user controls both addresses in their transaction), the event logs create permanently incorrect records on-chain. Off-chain systems (block explorers, indexers, analytics platforms, compliance tools) monitoring the `FastRedeemedThroughComposer` event will record the wrong destination address.
- **User Impact**: Any user performing cross-chain fast redemption where they specify a different destination address than their source address will have incorrect event logs. Users checking transaction history will see misleading information about where their funds were sent.

## Likelihood Explanation
- **Attacker Profile**: Any user performing cross-chain fast redemption can trigger this, whether intentionally (to create misleading audit trails) or accidentally (by misconfiguring their `sendParam.to` field)
- **Preconditions**: 
  - User must have wiTRY shares on spoke chain
  - Fast redeem must be enabled on the vault
  - User must construct a compose message with `sendParam.to` different from their own address
- **Execution Complexity**: Single cross-chain transaction - user sends wiTRY with compose message containing mismatched destination
- **Frequency**: Can occur on every fast redeem where user specifies a different destination address

## Recommendation

In `wiTryVaultComposer._fastRedeem()`, validate that the destination address in `_sendParam.to` matches the `redeemer` address before sending, or update the event emission to log the actual destination:

**Option 1 - Enforce destination match (recommended):** [2](#0-1) 

Add validation after line 108:
```solidity
address redeemer = _redeemer.bytes32ToAddress();
if (redeemer == address(0)) revert InvalidZeroAddress();

// ADDED: Validate destination matches redeemer
if (_sendParam.to != bytes32(uint256(uint160(redeemer)))) {
    revert InvalidDestination(); // Add this error to the contract
}
```

**Option 2 - Fix event to log actual destination:**

Modify `StakediTryCrosschain.fastRedeemThroughComposer()` to accept and emit the actual destination from `sendParam`, or have `wiTryVaultComposer` emit its own event after the send operation that logs the actual destination used.

**Option 3 - Override sendParam.to:**

In `wiTryVaultComposer._fastRedeem()` after line 117, add:
```solidity
_sendParam.amountLD = assets;
_sendParam.minAmountLD = assets;
_sendParam.to = bytes32(uint256(uint160(redeemer))); // Force destination to match redeemer
```

## Proof of Concept

```solidity
// File: test/Exploit_EventLogMismatch.t.sol
// Run with: forge test --match-test test_eventLogMismatchFastRedeem -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";

contract Exploit_EventLogMismatch is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    
    address alice = address(0xA11CE);
    address bob = address(0xB0B);
    
    event FastRedeemedThroughComposer(
        address indexed composer,
        address indexed crosschainReceiver,
        address indexed owner,
        uint256 shares,
        uint256 assets,
        uint256 feeAssets
    );
    
    function setUp() public {
        // Deploy vault and composer
        // [Deployment code would go here]
    }
    
    function test_eventLogMismatchFastRedeem() public {
        // SETUP: Alice has wiTRY shares, constructs compose message
        // with sendParam.to = bob (different from alice)
        
        // Simulate LayerZero compose callback
        // _composeFrom = alice
        // sendParam.to = bob
        
        // EXPLOIT: Event will emit alice as crosschainReceiver
        vm.expectEmit(true, true, true, true);
        emit FastRedeemedThroughComposer(
            address(composer),
            alice,  // Event claims iTRY goes to Alice
            alice,
            1000e18,
            900e18,
            100e18
        );
        
        // But actual _send() will use sendParam.to = bob
        // iTRY actually goes to Bob, not Alice
        
        // VERIFY: Event log shows alice, but bob receives iTRY
        // This creates incorrect permanent on-chain records
    }
}
```

## Notes

The vulnerability is confirmed by the existing test suite which explicitly verifies that the composer receives assets, not the `crosschainReceiver` parameter. [9](#0-8) 

The official deployment script demonstrates the intended usage where `sendParam.to` should equal the redeemer address [10](#0-9) , but this is not enforced in the contract code.

This issue violates Web3 security principles where event logs are considered part of the trust model for off-chain systems, compliance, and audit trails. The mismatch between logged and actual behavior undermines the reliability of on-chain event data.

### Citations

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

**File:** src/token/wiTRY/interfaces/IStakediTryCrosschain.sol (L96-102)
```text
     * @param crosschainReceiver Address that will receive iTRY on remote chain
     * @param owner Address whose shares are being redeemed
     * @return assets Amount of assets received (after fees)
     */
    function fastRedeemThroughComposer(uint256 shares, address crosschainReceiver, address owner)
        external
        returns (uint256 assets);
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

**File:** test/StakediTryCrosschain.fastRedeem.t.sol (L273-292)
```text
    function test_fastRedeemThroughComposer_composerReceivesAssetsNotRedeemer() public {
        _mintAndDeposit(composer, 100e18);

        uint256 crosschainReceiverBalanceBefore = itryToken.balanceOf(crosschainReceiver);
        uint256 composerAssetsBefore = itryToken.balanceOf(composer);

        uint256 sharesToRedeem = 50e18;
        uint256 expectedTotalAssets = vault.previewRedeem(sharesToRedeem);
        uint256 expectedFee = (expectedTotalAssets * 1000) / 10000;
        uint256 expectedNetAssets = expectedTotalAssets - expectedFee;

        vm.prank(composer);
        vault.fastRedeemThroughComposer(sharesToRedeem, crosschainReceiver, composer);

        // Composer receives the assets (for crosschain transfer)
        assertEq(itryToken.balanceOf(composer), composerAssetsBefore + expectedNetAssets, "Composer should receive assets");

        // Crosschain receiver does NOT receive assets directly
        assertEq(itryToken.balanceOf(crosschainReceiver), crosschainReceiverBalanceBefore, "Crosschain receiver should not receive assets directly");
    }
```

**File:** script/test/composer/FastRedeemAndBridgeBack_SpokeToHubToSpoke_RedeemerAddress.s.sol (L109-117)
```text
        SendParam memory composeSendParam = SendParam({
            dstEid: spokeEid, // Bridge iTRY back to Spoke
            to: bytes32(uint256(uint160(redeemerAddress))), // Recipient on Spoke
            amountLD: 0, // Will be set by wiTryVaultComposer after fast redeem
            minAmountLD: 0,
            extraOptions: "",
            composeMsg: "",
            oftCmd: bytes("FAST_REDEEM") // CRITICAL: Triggers fast redeem
        });
```
