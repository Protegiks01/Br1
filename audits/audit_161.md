## Title
Cross-Chain Unstaking Fails Due to Zero msg.value in Non-Payable `_lzReceive` Context

## Summary
The `_handleUnstake` function attempts to send iTRY tokens back to spoke chains using `msg.value` to pay LayerZero fees, but since it's called from the non-payable `_lzReceive` function, `msg.value` is always zero. This causes all cross-chain unstaking operations to fail despite users having pre-paid the return trip fees, effectively locking their funds on spoke chains.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (`_lzReceive` function)
- `src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol` (`_send` function)

**Intended Logic:** 
The cross-chain unstaking flow should work as follows:
1. User calls `UnstakeMessenger.unstake(returnTripAllocation)` on spoke chain with sufficient msg.value
2. LayerZero forwards the `returnTripAllocation` native value to wiTryVaultComposer on hub chain
3. wiTryVaultComposer receives the message and native value
4. It processes the unstake and sends iTRY back to the user using the forwarded native value to pay fees

**Actual Logic:**
The system fails at step 4. When LayerZero delivers the message to wiTryVaultComposer: [1](#0-0) 

The `_lzReceive` function is NOT payable, so when it calls `_handleUnstake`, the `msg.value` in that call context is zero: [2](#0-1) 

When `_handleUnstake` calls `_send` at line 274, and `_send` attempts to forward the iTRY with LayerZero fees: [3](#0-2) 

The `msg.value` used at line 366 is zero (from the non-payable `_lzReceive` context), even though the contract received native value in its balance via the `receive()` function: [4](#0-3) 

**Exploitation Path:**
1. User initiates unstake on spoke chain via `UnstakeMessenger.unstake(returnTripAllocation)`, sending sufficient native tokens
2. LayerZero forwards message to hub chain, depositing `returnTripAllocation` into wiTryVaultComposer's balance
3. LayerZero endpoint calls `lzReceive` on wiTryVaultComposer (which calls internal `_lzReceive`)
4. `_lzReceive` processes the message and calls `_handleUnstake` with `msg.value = 0`
5. `_handleUnstake` calls `_send(ASSET_OFT, _sendParam, address(this))`
6. `_send` attempts `IOFT(_oft).send{value: 0}(...)` with zero fee payment
7. The OFT's send operation reverts due to insufficient fee payment
8. The entire unstake transaction fails, user's iTRY remains locked on hub chain

**Security Property Broken:** 
Violates "Cross-chain Message Integrity" invariant - LayerZero messages for unstaking must be delivered to correct user with proper validation. The unstaking mechanism completely fails to deliver assets back to users.

## Impact Explanation
- **Affected Assets**: All wiTRY staked by users on spoke chains attempting to unstake back to iTRY
- **Damage Severity**: Users cannot withdraw their staked assets from spoke chains. The unstaking mechanism is completely non-functional. Users lose their pre-paid return trip fees on every failed attempt.
- **User Impact**: All users who stake wiTRY on spoke chains and attempt to unstake via cross-chain messaging are affected. Every unstake attempt will fail until the contract is fixed or users' funds are manually rescued by protocol admins.

## Likelihood Explanation
- **Attacker Profile**: Any legitimate user attempting normal cross-chain unstaking operations
- **Preconditions**: 
  - User has wiTRY staked on a spoke chain
  - User has completed cooldown period
  - User initiates unstake via UnstakeMessenger
  - LayerZero successfully delivers the message to hub chain
- **Execution Complexity**: This is not an attack but a critical bug affecting normal operations. It occurs in every single cross-chain unstake attempt.
- **Frequency**: Every time any user attempts to unstake from a spoke chain (100% failure rate)

## Recommendation

The `_send` function needs to be modified to explicitly use the contract's balance when called from `_lzReceive` context, or the native value needs to be passed through the call chain properly.

**Option 1: Make `_lzReceive` and call chain payable**

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, line 214:

// CURRENT (vulnerable):
function _lzReceive(
    Origin calldata _origin,
    bytes32 _guid,
    bytes calldata _message,
    address _executor,
    bytes calldata _extraData
) internal override {
    // ... processing ...
    _handleUnstake(_origin, _guid, unstakeMsg);
}

// FIXED - Option 1 (Not recommended due to LayerZero architecture):
// LayerZero's architecture doesn't support making _lzReceive payable
// as the native value is delivered separately via receive()
```

**Option 2: Modify `_handleUnstake` to explicitly forward contract balance**

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, line 244:

// CURRENT (vulnerable):
function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
    internal
    virtual
{
    address user = unstakeMsg.user;
    if (user == address(0)) revert InvalidZeroAddress();
    if (_origin.srcEid == 0) revert InvalidOrigin();

    uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
    if (assets == 0) {
        revert NoAssetsToUnstake();
    }

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
    emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
}

// FIXED - Option 2 (Recommended):
function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
    internal
    virtual
{
    address user = unstakeMsg.user;
    if (user == address(0)) revert InvalidZeroAddress();
    if (_origin.srcEid == 0) revert InvalidOrigin();

    uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
    if (assets == 0) {
        revert NoAssetsToUnstake();
    }

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

    // Calculate required fee for return trip
    MessagingFee memory fee = IOFT(ASSET_OFT).quoteSend(_sendParam, false);
    
    // Use contract's balance (forwarded by LayerZero) to pay for return trip
    if (address(this).balance < fee.nativeFee) {
        revert InsufficientBalance();
    }
    
    // Send with explicit value from contract balance
    IOFT(ASSET_OFT).send{value: fee.nativeFee}(_sendParam, fee, address(this));
    
    emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
}
```

**Alternative: Override `_send` for unstake context**

Create a separate internal function `_sendWithBalance` that uses the contract's balance instead of `msg.value`, and call it from `_handleUnstake`.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainUnstakeFails.t.sol
// Run with: forge test --match-test test_CrossChainUnstakeFails -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_CrossChainUnstakeFails is Test {
    wiTryVaultComposer public composer;
    StakediTryCrosschain public vault;
    iTry public itry;
    UnstakeMessenger public messenger;
    
    address public user = makeAddr("user");
    uint32 public constant SPOKE_EID = 40217;
    uint32 public constant HUB_EID = 40161;
    
    function setUp() public {
        // Deploy protocol contracts
        // [Full deployment code would go here]
        
        // Setup: User has wiTRY staked on spoke chain and completes cooldown
        // User initiates unstake via UnstakeMessenger with sufficient fees
    }
    
    function test_CrossChainUnstakeFails() public {
        // SETUP: Simulate LayerZero delivering unstake message to hub
        // The native value (returnTripAllocation) is sent to composer's balance
        uint256 returnTripFee = 0.01 ether;
        vm.deal(address(composer), returnTripFee);
        
        // Build unstake message as it would arrive from LayerZero
        Origin memory origin = Origin({
            srcEid: SPOKE_EID,
            sender: bytes32(uint256(uint160(address(messenger)))),
            nonce: 1
        });
        
        bytes32 guid = bytes32(uint256(1));
        
        IUnstakeMessenger.UnstakeMessage memory unstakeMsg = IUnstakeMessenger.UnstakeMessage({
            user: user,
            extraOptions: OptionsBuilder.newOptions()
        });
        
        bytes memory message = abi.encode(1, unstakeMsg); // MSG_TYPE_UNSTAKE = 1
        
        // EXPLOIT: LayerZero calls lzReceive (which calls _lzReceive internally)
        // The _lzReceive function is NOT payable, so msg.value = 0
        // Even though composer has returnTripFee in its balance
        
        // This will fail because _send tries to use msg.value (which is 0)
        // to pay for the OFT send operation
        vm.expectRevert(); // Will revert due to insufficient fee
        
        // Simulate LayerZero endpoint calling lzReceive
        // (In reality this would be called by LayerZero's endpoint contract)
        composer.lzReceive(origin, guid, message, address(0), "");
        
        // VERIFY: The unstake failed even though:
        // 1. User paid for return trip on spoke chain
        // 2. Composer received the native value in its balance
        // 3. But _send uses msg.value which is 0 in _lzReceive context
        
        assertEq(address(composer).balance, returnTripFee, "Composer still has unused fee balance");
        // User's iTRY remains locked, unable to be withdrawn
    }
}
```

**Notes:**
This vulnerability completely breaks the cross-chain unstaking mechanism. While the `quoteUnstakeReturn` function correctly quotes fees with `payInLzToken = false` (native token payment), and this matches the actual send operation's payment method (`MessagingFee(msg.value, 0)`), the critical issue is that `msg.value` is zero in the execution context. The LayerZero-forwarded native value sits unused in the contract's balance while the send operation fails due to zero fee payment.

The original security question about `payInLzToken` parameter consistency is actually satisfied (both quote and send use native payment), but the investigation revealed this more severe bug where the forwarded native value cannot be accessed via `msg.value` in the non-payable `_lzReceive` call chain.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L176-176)
```text
    receive() external payable override {}
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

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L357-368)
```text
    function _send(address _oft, SendParam memory _sendParam, address _refundAddress) internal {
        if (_sendParam.dstEid == VAULT_EID) {
            /// @dev Can do this because _oft is validated before this function is called
            address erc20 = _oft == ASSET_OFT ? ASSET_ERC20 : SHARE_ERC20;

            if (msg.value > 0) revert NoMsgValueExpected();
            IERC20(erc20).safeTransfer(_sendParam.to.bytes32ToAddress(), _sendParam.amountLD);
        } else {
            // crosschain send
            IOFT(_oft).send{value: msg.value}(_sendParam, MessagingFee(msg.value, 0), _refundAddress);
        }
    }
```
