## Title
Cross-Chain Fast Redeem Burns Shares Before Validating Destination Blacklist Status

## Summary
The `_fastRedeem` function in `wiTryVaultComposer` immediately burns user shares through `fastRedeemThroughComposer` before validating whether the destination redeemer address can receive iTRY on the spoke chain. If the redeemer is blacklisted on the destination chain, the shares are permanently burned but the iTRY mint fails, causing permanent loss of user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (lines 106-124, specifically line 110)
- `src/token/wiTRY/StakediTryCrosschain.sol` (lines 112-131, specifically line 124)
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 140-155, specifically line 145)

**Intended Logic:** The fast redeem mechanism should allow users to bypass the cooldown period by paying a fee, receiving their iTRY immediately on the destination chain. The process should be atomic or have proper validation to prevent loss of user funds.

**Actual Logic:** The implementation burns shares first, then attempts the cross-chain transfer. The shares are burned via `_redeemWithFee` in step 1 [1](#0-0) , but the cross-chain transfer to the redeemer happens asynchronously in step 2 [2](#0-1) . If the redeemer is blacklisted on the destination spoke chain, the mint will fail [3](#0-2) , but the shares are already burned with no recovery mechanism.

**Exploitation Path:**
1. User on spoke chain sends wiTRY with "FAST_REDEEM" command to hub chain via LayerZero
2. Hub chain `wiTryVaultComposer._fastRedeem` receives the message and calls `fastRedeemThroughComposer(_shareAmount, redeemer, redeemer)`
3. Inside `fastRedeemThroughComposer`, the function calls `_redeemWithFee(shares, totalAssets, composer, composer)` which immediately burns ALL shares from the composer's balance through two `_withdraw` calls [4](#0-3) 
4. Control returns to `_fastRedeem` which then calls `_send(ASSET_OFT, _sendParam, _refundAddress)` to send iTRY cross-chain
5. Hub chain transaction completes successfully - iTRY is locked in the OFT adapter, shares are burned
6. LayerZero message arrives on spoke chain and attempts to mint iTRY to the redeemer address
7. The `_beforeTokenTransfer` hook in `iTryTokenOFT` checks if the destination address is blacklisted - if `blacklisted[to]` is true, the transaction reverts [5](#0-4) 
8. Result: Shares permanently burned on hub chain, iTRY locked in adapter, redeemer receives nothing

**Security Property Broken:** Violates Blacklist Enforcement invariant (#2) - "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - and causes permanent loss of user funds through a cross-chain race condition where shares are destroyed before destination address validation.

## Impact Explanation
- **Affected Assets**: User's wiTRY shares (permanently burned) and equivalent iTRY tokens (locked in OFT adapter on hub chain, undeliverable on spoke chain)
- **Damage Severity**: 100% loss of the fast-redeemed amount for any user who becomes blacklisted on the destination chain between initiating the fast redeem and the message delivery. The iTRY remains locked in the adapter with no recovery mechanism.
- **User Impact**: Any user performing cross-chain fast redemption who is blacklisted on the destination spoke chain. This includes users who were legitimately using the protocol but were later blacklisted, users blacklisted on only one chain due to multi-chain blacklist sync delays, or users targeted by blacklist managers between transaction initiation and execution.

## Likelihood Explanation
- **Attacker Profile**: This affects any legitimate user who is blacklisted on the destination chain. No malicious intent required - can occur through normal protocol operations.
- **Preconditions**: 
  - Fast redeem must be enabled on the vault
  - User must have wiTRY shares on spoke chain
  - User must be blacklisted on the destination spoke chain's `iTryTokenOFT` contract
  - Crucially, there is NO validation in `fastRedeemThroughComposer` that checks the blacklist status [6](#0-5)  - only checks for zero address
- **Execution Complexity**: Single transaction initiated by user on spoke chain, LayerZero handles cross-chain delivery automatically
- **Frequency**: Can occur on every fast redeem attempt by a blacklisted user until they are removed from the blacklist

## Recommendation

Add blacklist validation in the `fastRedeemThroughComposer` function before burning shares:

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function fastRedeemThroughComposer, before line 124:

// CURRENT (vulnerable):
// No validation of crosschainReceiver's blacklist status before burning shares

// FIXED:
function fastRedeemThroughComposer(uint256 shares, address crosschainReceiver, address owner)
    external
    onlyRole(COMPOSER_ROLE)
    ensureCooldownOn
    ensureFastRedeemEnabled
    returns (uint256 assets)
{
    address composer = msg.sender;
    if (crosschainReceiver == address(0)) revert InvalidZeroAddress();
    
    // ADD THIS: Validate that the crosschainReceiver can receive iTRY on destination chain
    // Option 1: Query the destination chain's iTryTokenOFT blacklist status via LayerZero
    // Option 2: Maintain a synchronized blacklist mapping on hub chain
    // Option 3: Revert with a clear error message that blacklisted users cannot fast redeem
    
    // Simplified implementation (requires blacklist sync mechanism):
    // if (isBlacklistedOnDestination[crosschainReceiver][destinationChainId]) {
    //     revert ReceiverBlacklistedOnDestination();
    // }
    
    if (shares > maxRedeem(composer)) revert ExcessiveRedeemAmount();

    uint256 totalAssets = previewRedeem(shares);
    uint256 feeAssets = _redeemWithFee(shares, totalAssets, composer, composer);

    assets = totalAssets - feeAssets;

    emit FastRedeemedThroughComposer(composer, crosschainReceiver, owner, shares, assets, feeAssets);

    return assets;
}
```

**Alternative mitigations:**
1. **Refund mechanism**: Implement a fallback in `wiTryVaultComposer.lzReceive` that detects failed destination mints and allows users to reclaim their funds by re-minting shares
2. **Two-step process**: Lock shares in cooldown instead of burning them immediately, only burn after successful cross-chain delivery confirmation
3. **Pre-flight validation**: Require users to prove they are not blacklisted on destination chain before initiating fast redeem

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemBlacklistLoss.t.sol
// Run with: forge test --match-test test_FastRedeemBlacklistLoss -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";

contract Exploit_FastRedeemBlacklistLoss is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    iTry hubITry;
    iTryTokenOFT spokeITry;
    address alice = address(0x123);
    
    function setUp() public {
        // Deploy hub chain contracts
        hubITry = new iTry();
        vault = new StakediTryCrosschain(IERC20(address(hubITry)), address(this), address(this), address(this));
        composer = new wiTryVaultComposer(address(vault), address(hubITry), address(vault), address(this));
        
        // Deploy spoke chain iTryTokenOFT
        spokeITry = new iTryTokenOFT(address(this), address(this));
        
        // Setup: Alice has wiTRY shares on spoke chain (bridged earlier)
        // Grant composer role to wiTryVaultComposer
        vault.grantRole(vault.COMPOSER_ROLE(), address(composer));
        
        // Enable fast redeem
        vault.setFastRedeemEnabled(true);
    }
    
    function test_FastRedeemBlacklistLoss() public {
        // SETUP: Alice has 1000 wiTRY shares in the composer (already bridged from spoke chain)
        uint256 initialShares = 1000 ether;
        deal(address(vault), address(composer), initialShares);
        
        // SETUP: Alice is blacklisted on SPOKE chain (destination)
        address[] memory blacklistUsers = new address[](1);
        blacklistUsers[0] = alice;
        spokeITry.addBlacklistAddress(blacklistUsers);
        
        // Verify Alice is blacklisted on spoke chain
        assertTrue(spokeITry.blacklisted(alice), "Alice should be blacklisted on spoke chain");
        
        // EXPLOIT: Alice initiates fast redeem (or LayerZero message arrives)
        // This simulates the composer receiving a cross-chain fast redeem request
        vm.prank(address(composer));
        uint256 assetsReturned = vault.fastRedeemThroughComposer(initialShares, alice, alice);
        
        // VERIFY: Shares are BURNED from composer
        assertEq(vault.balanceOf(address(composer)), 0, "Shares should be burned");
        
        // VERIFY: Composer received iTRY assets
        assertGt(assetsReturned, 0, "Composer should have received assets");
        
        // VERIFY: When LayerZero tries to mint to Alice on spoke chain, it will FAIL
        // Simulating the mint that would happen on spoke chain:
        vm.expectRevert(); // Will revert due to blacklist check
        vm.prank(spokeITry.minter());
        spokeITry.transfer(alice, assetsReturned); // This represents the mint attempt
        
        // RESULT: Alice's shares are permanently burned, iTRY is locked in adapter
        // Alice receives nothing and has no recovery mechanism
        console.log("Shares burned:", initialShares);
        console.log("iTRY amount that failed to mint:", assetsReturned);
        console.log("Alice's loss: 100% of fast-redeemed amount");
    }
}
```

## Notes

The vulnerability stems from the asynchronous nature of cross-chain operations combined with insufficient pre-validation. The shares are burned atomically on the hub chain, but the destination mint happens in a separate, later transaction on the spoke chain. LayerZero V2 provides message delivery guarantees, but cannot guarantee successful execution of the destination transaction if it reverts due to application logic (like blacklist checks).

This is distinct from the known Zellic issue about "Native fee loss on failed lzReceive" - that issue is about gas payment, while this is about permanent loss of principal (shares burned but tokens undeliverable). The root cause is that `fastRedeemThroughComposer` only validates `crosschainReceiver != address(0)` [6](#0-5)  but never validates blacklist status before committing the irreversible action of burning shares [1](#0-0) .

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L120-120)
```text
        if (crosschainReceiver == address(0)) revert InvalidZeroAddress();
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L124-124)
```text
        uint256 feeAssets = _redeemWithFee(shares, totalAssets, composer, composer); // Composer receives the assets for further crosschain transfer
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L110-119)
```text
        uint256 assets = IStakediTryCrosschain(address(VAULT)).fastRedeemThroughComposer(_shareAmount, redeemer, redeemer); // redeemer is the owner and crosschain receiver

          if (assets == 0) {
            revert NoAssetsToRedeem();
        }

        _sendParam.amountLD = assets;
        _sendParam.minAmountLD = assets;

        _send(ASSET_OFT, _sendParam, _refundAddress);
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L145-154)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L152-155)
```text
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
```
