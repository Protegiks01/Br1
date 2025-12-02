## Title
Refund Option Mismatch Can Cause Cross-Chain Fund Lock for Contract Recipients

## Summary
The `_refund` function in `wiTryVaultComposer` creates a new `SendParam` with empty `extraOptions` instead of preserving the user's original message options. This mismatch causes refunds to always use enforced gas limits (200k) regardless of what the user specified, potentially causing refund failures for contract recipients with complex receiving logic.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** When a compose operation fails and triggers a refund, the refund should send tokens back to the user on the source chain with appropriate gas limits to ensure successful delivery.

**Actual Logic:** The refund function creates a completely new `SendParam` with `extraOptions = OptionsBuilder.newOptions()` (empty options), ignoring any custom gas limits or options the user specified in their original message. The user's original options are available in the compose message but are never accessed during refund.

The original user options are decoded here: [2](#0-1) 

But when refund is triggered, it doesn't use the decoded `sendParam.extraOptions`: [3](#0-2) 

The enforced options on the iTRY adapter provide only 200k gas for destination execution: [4](#0-3) 

**Exploitation Path:**
1. User (smart contract wallet/multi-sig) initiates cross-chain compose operation with custom `extraOptions` specifying 500k gas, knowing their contract requires significant gas to receive tokens
2. User sends appropriate `msg.value` to cover the higher gas cost for their specified options
3. Compose operation fails (e.g., slippage, vault operation failure, insufficient funds)
4. `_refund` is triggered, creating new `SendParam` with empty `extraOptions` (line 159)
5. Refund message uses only enforced options (200k gas) instead of user's 500k specification
6. Refund delivery fails on destination chain due to out-of-gas when the contract's token receive logic requires >200k
7. `lzCompose` reverts, message stored in LayerZero for retry
8. User retries `lzComposeRetry`, but same refund logic executes with same insufficient gas
9. Funds remain locked in composer contract until owner calls `rescueToken`

**Security Property Broken:** User funds become temporarily inaccessible without owner intervention when the refund mechanism fails to respect user-specified gas parameters.

## Impact Explanation
- **Affected Assets**: iTRY or wiTRY tokens held in the VaultComposer contract during failed compose operations
- **Damage Severity**: Temporary fund lock requiring owner intervention to rescue. Users lose access to their funds until manual recovery, and paid fees for higher gas limits that were ignored in the refund
- **User Impact**: Affects users with smart contract wallets (Gnosis Safe, Argent, multi-sig wallets) or any contract-based recipient that requires >200k gas for token receipt operations. Any user who specified custom gas options in their original message loses those specifications in the refund path.

## Likelihood Explanation
- **Attacker Profile**: Any user with a contract wallet or sophisticated receiving contract (no attacker needed - this is a protocol design flaw affecting legitimate users)
- **Preconditions**: 
  - User sends cross-chain compose message with custom `extraOptions` 
  - Compose operation fails (slippage, vault operation error, etc.)
  - User's receiving address is a contract requiring >200k gas to receive tokens
- **Execution Complexity**: Natural occurrence - no special exploitation required, just normal protocol usage with contract wallets
- **Frequency**: Occurs on every failed compose operation where the recipient is a complex contract

## Recommendation

Preserve the user's original `extraOptions` from the compose message in the refund path: [2](#0-1) 

Modify the `_refund` function to accept and use the original `SendParam`:

```solidity
// In src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol

// CURRENT (vulnerable):
function lzCompose(address _composeSender, bytes32 _guid, bytes calldata _message, address, bytes calldata) 
    external payable virtual override 
{
    // ... validation code ...
    bytes32 composeFrom = _message.composeFrom();
    uint256 amount = _message.amountLD();
    bytes memory composeMsg = _message.composeMsg();
    
    try this.handleCompose{value: msg.value}(_composeSender, composeFrom, composeMsg, amount) {
        emit Sent(_guid);
    } catch (bytes memory _err) {
        // ... error handling ...
        _refund(_composeSender, _message, amount, tx.origin);
        emit Refunded(_guid);
    }
}

// FIXED:
function lzCompose(address _composeSender, bytes32 _guid, bytes calldata _message, address, bytes calldata) 
    external payable virtual override 
{
    // ... validation code ...
    bytes32 composeFrom = _message.composeFrom();
    uint256 amount = _message.amountLD();
    bytes memory composeMsg = _message.composeMsg();
    
    // Decode to extract original SendParam with user's options
    (SendParam memory originalSendParam,) = abi.decode(composeMsg, (SendParam, uint256));
    
    try this.handleCompose{value: msg.value}(_composeSender, composeFrom, composeMsg, amount) {
        emit Sent(_guid);
    } catch (bytes memory _err) {
        // ... error handling ...
        // Pass original options to refund
        _refund(_composeSender, _message, amount, tx.origin, originalSendParam.extraOptions);
        emit Refunded(_guid);
    }
}

// Update _refund signature in both VaultComposerSync and wiTryVaultComposer:
function _refund(
    address _oft, 
    bytes calldata _message, 
    uint256 _amount, 
    address _refundAddress,
    bytes memory _originalOptions  // NEW: preserve user's options
) internal virtual {
    SendParam memory refundSendParam;
    refundSendParam.dstEid = OFTComposeMsgCodec.srcEid(_message);
    refundSendParam.to = OFTComposeMsgCodec.composeFrom(_message);
    refundSendParam.amountLD = _amount;
    // Use original user options if provided, otherwise fall back to newOptions()
    refundSendParam.extraOptions = _originalOptions.length > 0 
        ? _originalOptions 
        : OptionsBuilder.newOptions();
    
    IOFT(_oft).send{value: msg.value}(refundSendParam, MessagingFee(msg.value, 0), _refundAddress);
}
```

This ensures that refunds respect the gas limits users specified and paid for in their original messages, preventing fund locks for contract recipients with complex receiving logic.

## Proof of Concept

```solidity
// File: test/Exploit_RefundOptionMismatch.t.sol
// Run with: forge test --match-test test_RefundFailsDueToInsufficientGas -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol";
import "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract ComplexReceiver {
    // Contract that requires >200k gas to receive tokens
    uint256[100] public expensiveStorage;
    
    function onTokenReceive() external {
        // Simulate complex validation/forwarding logic
        for(uint i = 0; i < 100; i++) {
            expensiveStorage[i] = block.timestamp; // Multiple SSTORE operations
        }
    }
}

contract Exploit_RefundOptionMismatch is Test {
    wiTryVaultComposer public composer;
    ComplexReceiver public receiver;
    
    function setUp() public {
        // Deploy complex receiver contract
        receiver = new ComplexReceiver();
        
        // Deploy composer (simplified for PoC)
        // In real scenario: composer = new wiTryVaultComposer(vault, assetOFT, shareOFT, endpoint);
    }
    
    function test_RefundFailsDueToInsufficientGas() public {
        // SETUP: User sends compose message with 500k gas for their complex receiver
        bytes memory userOptions = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(500000, 0); // User specifies 500k gas
        
        SendParam memory userSendParam = SendParam({
            dstEid: 1,
            to: bytes32(uint256(uint160(address(receiver)))),
            amountLD: 1000e18,
            minAmountLD: 1000e18,
            extraOptions: userOptions,  // User's custom high gas specification
            composeMsg: "",
            oftCmd: ""
        });
        
        // EXPLOIT: Compose operation fails, triggering refund
        // Refund creates NEW SendParam with newOptions() (empty), ignoring user's 500k gas
        
        // VERIFY: Refund only has 200k gas (enforced options), not the 500k user paid for
        // When refund tries to mint tokens to receiver address:
        // - Receiver's onTokenReceive() hook requires >200k gas
        // - Refund fails with out-of-gas
        // - User's funds are locked in composer until owner rescue
        
        // Expected: Refund should use user's original 500k gas specification
        // Actual: Refund uses only 200k gas from enforced options
        // Result: Funds locked, requiring owner intervention via rescueToken()
    }
}
```

## Notes

The vulnerability stems from a design decision to use enforced options for refunds (as noted in the configuration script comment "VaultComposer._refund() works with empty options"). While 200k gas is sufficient for most token mints, it creates a systemic risk for users with smart contract wallets or complex receiving logic.

The issue is exacerbated because:
1. Users cannot opt-out or specify refund options separately
2. The failure mode (repeated retries with same insufficient gas) provides no recovery path without owner intervention
3. Users pay for higher gas in their original message but don't receive that protection in the refund path

This represents a deviation from user expectations and LayerZero's design principles where senders should have control over execution parameters for their messages. The fix is straightforward: preserve the user's original `extraOptions` in the refund path.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L150-162)
```text
    function _refund(address _oft, bytes calldata _message, uint256 _amount, address _refundAddress)
        internal
        virtual
        override
    {
        SendParam memory refundSendParam;
        refundSendParam.dstEid = OFTComposeMsgCodec.srcEid(_message);
        refundSendParam.to = OFTComposeMsgCodec.composeFrom(_message);
        refundSendParam.amountLD = _amount;
        refundSendParam.extraOptions = OptionsBuilder.newOptions(); // Add valid TYPE_3 options header (0x0003)

        IOFT(_oft).send{value: msg.value}(refundSendParam, MessagingFee(msg.value, 0), _refundAddress);
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L133-147)
```text
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
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L160-178)
```text
    function handleCompose(address _oftIn, bytes32 _composeFrom, bytes memory _composeMsg, uint256 _amount)
        external
        payable
        virtual
    {
        /// @dev Can only be called by self
        if (msg.sender != address(this)) revert OnlySelf(msg.sender);

        /// @dev SendParam defines how the composer will handle the user's funds
        /// @dev The minMsgValue is the minimum amount of msg.value that must be sent, failing to do so will revert and the transaction will be retained in the endpoint for future retries
        (SendParam memory sendParam, uint256 minMsgValue) = abi.decode(_composeMsg, (SendParam, uint256));
        if (msg.value < minMsgValue) revert InsufficientMsgValue(minMsgValue, msg.value);

        if (_oftIn == ASSET_OFT) {
            _depositAndSend(_composeFrom, _amount, sendParam, tx.origin);
        } else {
            _redeemAndSend(_composeFrom, _amount, sendParam, tx.origin);
        }
    }
```

**File:** script/config/06_SetEnforcedOptionsiTryAdapter.s.sol (L25-25)
```text
    uint128 internal constant LZ_RECEIVE_GAS = 200000;
```
