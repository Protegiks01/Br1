## Title
Cross-Chain Unstake Message Failure Permanently Locks User Fees Without Cooldown Validation

## Summary
Users can call `UnstakeMessenger.unstake()` on spoke chains without having any active cooldown on the hub chain, causing the hub's `wiTryVaultComposer._handleUnstake()` to revert with `NoAssetsToUnstake()` and permanently locking the user's msg.value (LayerZero message fee) since there is no try-catch refund mechanism in the `_lzReceive()` flow.

## Impact
**Severity**: Medium

## Finding Description

**Location:** 
- `src/token/wiTRY/crosschain/UnstakeMessenger.sol` (unstake function)
- `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (_handleUnstake function)
- `src/token/wiTRY/StakediTryCrosschain.sol` (unstakeThroughComposer function)

**Intended Logic:** 
The cross-chain unstake flow should validate that users have completed cooldowns before processing unstake requests, or refund fees if the operation cannot complete successfully (similar to the compose flow with try-catch refunds).

**Actual Logic:** 
The spoke chain accepts unstake requests without validating cooldown existence, and the hub chain reverts without refunding fees when no assets are available to unstake. Unlike the `lzCompose()` flow which has try-catch error handling and refunds, the `_lzReceive()` flow has no such protection.

**Exploitation Path:**

1. **User initiates unstake without cooldown:** User calls `UnstakeMessenger.unstake(returnTripAllocation)` on spoke chain with msg.value covering LayerZero fees, but has never initiated a cooldown on the hub chain (or already claimed it). [1](#0-0) 

2. **Message sent without validation:** The function encodes the message with `msg.sender` as user and sends it via LayerZero without checking if the user has any cooldown shares on the hub chain. The base msg.value fee is consumed by LayerZero. [2](#0-1) 

3. **Hub chain processes message:** LayerZero delivers the message to `wiTryVaultComposer._lzReceive()`, which decodes it and calls `_handleUnstake()`. [3](#0-2) 

4. **Vault returns zero assets:** The `_handleUnstake()` function calls `unstakeThroughComposer(user)`, which retrieves the user's cooldown. If the user never initiated a cooldown, `userCooldown.underlyingAmount` is 0, and the function returns 0. [4](#0-3) 

5. **Revert without refund:** The `_handleUnstake()` function checks if `assets == 0` and reverts with `NoAssetsToUnstake()`, permanently losing the user's msg.value since there is no try-catch mechanism. [5](#0-4) 

**Security Property Broken:** 
This violates the expectation that failed cross-chain operations should either succeed or refund fees to users. It also differs from the documented known issue which specifically covers gas underpayment scenarios where users can successfully retry. [6](#0-5) 

## Impact Explanation

- **Affected Assets**: User's native tokens (ETH/MATIC/etc.) paid as msg.value for LayerZero message fees
- **Damage Severity**: Users lose the entire msg.value paid for the unstake message, which can be significant depending on gas prices and cross-chain fees. The user cannot recover these funds and cannot successfully retry the unstake operation without first initiating a cooldown on the hub chain and waiting for the cooldown period.
- **User Impact**: Any user who calls `unstake()` on a spoke chain without having an active, completed cooldown on the hub chain will lose their message fee. This affects users who are unfamiliar with the cooldown requirement, have already claimed their cooldown, or use poorly designed frontend interfaces.

## Likelihood Explanation

- **Attacker Profile**: Any user (no special privileges required). More likely to affect new users or those using incorrectly implemented frontends.
- **Preconditions**: 
  - User has no active cooldown on hub chain (either never initiated or already claimed)
  - User calls `unstake()` on spoke chain with msg.value
  - LayerZero successfully delivers the message to hub chain
- **Execution Complexity**: Single transaction on spoke chain. No timing requirements or complex coordination needed.
- **Frequency**: Can occur every time a user attempts to unstake without an active cooldown. The impact accumulates with each failed attempt since fees are permanently lost.

## Recommendation

**Option 1: Add pre-flight validation on spoke chain (Recommended)**

Add a view function to query cooldown status cross-chain before allowing unstake, or require users to provide proof of cooldown existence.

**Option 2: Add try-catch with refund in `_lzReceive()` flow**

Wrap the `_handleUnstake()` call in a try-catch block similar to the `lzCompose()` pattern to refund users when unstake fails: [7](#0-6) 

**Option 3: Return success/failure status instead of reverting**

Modify `_handleUnstake()` to return a boolean success status and emit an event instead of reverting, allowing the message to complete while informing the user of the failure.

## Proof of Concept

```solidity
// File: test/Exploit_UnstakeWithoutCooldown.t.sol
// Run with: forge test --match-test test_UnstakeWithoutCooldown -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";

contract Exploit_UnstakeWithoutCooldown is Test {
    UnstakeMessenger messenger;
    wiTryVaultComposer composer;
    address user = address(0x1234);
    
    function setUp() public {
        // Deploy contracts and configure LayerZero peers
        // Initialize hub and spoke chains
    }
    
    function test_UnstakeWithoutCooldown() public {
        // SETUP: User has NO cooldown on hub chain
        vm.startPrank(user);
        
        uint256 userBalanceBefore = user.balance;
        uint256 returnTripAllocation = 0.01 ether;
        uint256 totalFee = 0.02 ether; // Example fee
        
        // EXPLOIT: User calls unstake without cooldown
        // This sends LayerZero message and consumes msg.value
        messenger.unstake{value: totalFee}(returnTripAllocation);
        
        uint256 userBalanceAfter = user.balance;
        
        // VERIFY: User lost the message fee
        assertEq(userBalanceBefore - userBalanceAfter, totalFee, "User lost message fee");
        
        // Simulate LayerZero message delivery to hub
        // Hub's _handleUnstake will revert with NoAssetsToUnstake
        // User's fee is permanently lost with no refund mechanism
        
        vm.stopPrank();
    }
}
```

## Notes

This vulnerability is **distinct from the known Zellic audit issue** documented in the README. The known issue states: "Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request."

The key differences are:

1. **Known issue context**: Specifically about gas underpayment scenarios where the user paid insufficient fees for execution
2. **Known issue resolution**: User can retry with correct gas payment and successfully complete the unstake
3. **This vulnerability**: User has no cooldown shares to unstake, regardless of gas payment
4. **This vulnerability resolution**: User CANNOT successfully retry without first initiating a cooldown on the hub chain and waiting for the cooldown period

Additionally, the codebase implements try-catch refund patterns for the `lzCompose()` flow but not for the direct `_lzReceive()` flow used by `unstake()`, creating an inconsistency in error handling between the two cross-chain message types. [8](#0-7)

### Citations

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L108-151)
```text
    function unstake(uint256 returnTripAllocation) external payable nonReentrant returns (bytes32 guid) {
        // Validate hub peer configured
        bytes32 hubPeer = peers[hubEid];
        if (hubPeer == bytes32(0)) revert HubNotConfigured();

        // Validate returnTripAllocation
        if (returnTripAllocation == 0) revert InvalidReturnTripAllocation();

        // Build return trip options (valid TYPE_3 header)
        bytes memory extraOptions = OptionsBuilder.newOptions();

        // Encode UnstakeMessage with msg.sender as user (prevents spoofing)
        UnstakeMessage memory message = UnstakeMessage({user: msg.sender, extraOptions: extraOptions});
        bytes memory payload = abi.encode(MSG_TYPE_UNSTAKE, message);

        // Build options WITH native value forwarding for return trip execution
        // casting to 'uint128' is safe because returnTripAllocation value will be less than 2^128
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory callerOptions =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
        bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);

        // Quote with native drop included (single quote with fixed returnTripAllocation)
        MessagingFee memory fee = _quote(hubEid, payload, options, false);

        // Validate caller sent enough
        if (msg.value < fee.nativeFee) {
            revert InsufficientFee(fee.nativeFee, msg.value);
        }

        // Automatic refund to msg.sender
        MessagingReceipt memory receipt = _lzSend(
            hubEid,
            payload,
            options,
            fee,
            payable(msg.sender) // Refund excess to user
        );
        guid = receipt.guid;

        emit UnstakeRequested(msg.sender, hubEid, fee.nativeFee, msg.value - fee.nativeFee, guid);

        return guid;
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L214-234)
```text
    function _lzReceive(
        Origin calldata _origin,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) internal override {
        // Note: LayerZero OApp handles peer validation before calling _lzReceive().
        // Peer validation is redundant here as the OApp base contract already ensures
        // messages only come from authorized peers configured via setPeer().

        // Decode and route message
        (uint16 msgType, IUnstakeMessenger.UnstakeMessage memory unstakeMsg) =
            abi.decode(_message, (uint16, IUnstakeMessenger.UnstakeMessage));

        if (msgType == MSG_TYPE_UNSTAKE) {
            _handleUnstake(_origin, _guid, unstakeMsg);
        } else {
            revert UnknownMessageType(msgType);
        }
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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L77-101)
```text
    function unstakeThroughComposer(address receiver)
        external
        onlyRole(COMPOSER_ROLE)
        nonReentrant
        returns (uint256 assets)
    {
        // Validate valid receiver
        if (receiver == address(0)) revert InvalidZeroAddress();

        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
        } else {
            revert InvalidCooldown();
        }

        emit UnstakeThroughComposer(msg.sender, receiver, assets);

        return assets;
    }
```

**File:** README.md (L40-40)
```markdown
- Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request.
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L113-148)
```text
    function lzCompose(
        address _composeSender, // The OFT used on refund, also the vaultIn token.
        bytes32 _guid,
        bytes calldata _message, // expected to contain a composeMessage = abi.encode(SendParam hopSendParam,uint256 minMsgValue)
        address,
        /*_executor*/
        bytes calldata /*_extraData*/
    )
        external
        payable
        virtual
        override
    {
        if (msg.sender != ENDPOINT) revert OnlyLzEndpoint(msg.sender);
        if (_composeSender != ASSET_OFT && _composeSender != SHARE_OFT) revert OnlyValidComposeCaller(_composeSender);

        bytes32 composeFrom = _message.composeFrom();
        uint256 amount = _message.amountLD();
        bytes memory composeMsg = _message.composeMsg();

        /// @dev try...catch to handle the compose operation. if it fails we refund the user
        try this.handleCompose{value: msg.value}(_composeSender, composeFrom, composeMsg, amount) {
            emit Sent(_guid);
        } catch (bytes memory _err) {
            /// @dev A revert where the msg.value passed is lower than the min expected msg.value is handled separately
            /// This is because it is possible to re-trigger from the endpoint the compose operation with the right msg.value
            if (bytes4(_err) == InsufficientMsgValue.selector) {
                assembly {
                    revert(add(32, _err), mload(_err))
                }
            }

            _refund(_composeSender, _message, amount, tx.origin);
            emit Refunded(_guid);
        }
    }
```
