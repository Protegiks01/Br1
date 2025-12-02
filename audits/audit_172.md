## Title
Cross-Chain Unstake Assets Permanently Trapped on _send Failure Due to Non-Atomic State Clearing

## Summary
The `wiTryVaultComposer._handleUnstake()` function violates atomic transaction integrity by clearing user cooldown state and withdrawing iTRY assets to the composer contract BEFORE attempting the cross-chain `_send()` operation. If `_send()` reverts due to insufficient msg.value or LayerZero errors, the LayerZero message becomes permanently un-retryable because the cooldown state has already been cleared, trapping user funds in the composer contract until admin rescue.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (`_handleUnstake` function, lines 244-278)

**Intended Logic:** The function should atomically unstake iTRY from the vault and send it back to the user on the spoke chain. If any step fails, the entire operation should revert cleanly, allowing LayerZero to retry the message.

**Actual Logic:** The function executes state-modifying operations in a non-atomic sequence:

1. First, it calls `unstakeThroughComposer(user)` which irreversibly clears the user's cooldown state and withdraws assets to the composer [1](#0-0) 

2. Inside `unstakeThroughComposer`, the cooldown state is permanently cleared and assets are withdrawn [2](#0-1) 

3. Then it attempts `_send()` which can revert due to insufficient native value or LayerZero errors [3](#0-2) 

4. When `_send()` reverts, the entire `_lzReceive` reverts, but the cooldown state modification from step 2 has already occurred (the revert happens at the LayerZero level, not at the vault state level)

**Exploitation Path:**
1. User initiates cross-chain unstake on spoke chain via `UnstakeMessenger.unstake()` with insufficient `returnTripAllocation` due to gas price increase [4](#0-3) 

2. LayerZero delivers message to hub chain, calling `wiTryVaultComposer._lzReceive()` [5](#0-4) 

3. `_handleUnstake()` calls `unstakeThroughComposer()` which clears cooldown state (sets `underlyingAmount = 0`) and withdraws iTRY to composer [6](#0-5) 

4. `_send()` reverts due to insufficient msg.value, causing `_lzReceive` to revert and LayerZero to store the message for retry [7](#0-6) 

5. On retry attempt, `unstakeThroughComposer()` reads `userCooldown.underlyingAmount` which is now 0, returns 0 assets, and triggers `NoAssetsToUnstake()` revert [8](#0-7) 

6. User's iTRY remains trapped in composer contract, recoverable only via owner's `rescueToken()` function [9](#0-8) 

**Security Property Broken:** Violates the "Cross-chain Message Integrity" invariant - LayerZero messages for unstaking should be delivered to correct user with proper validation, but the non-atomic state clearing makes message retry impossible.

## Impact Explanation
- **Affected Assets**: All iTRY tokens being unstaked cross-chain from spoke to hub
- **Damage Severity**: Users lose temporary access to their unstaked iTRY (funds trapped in composer contract). Requires manual admin intervention via `rescueToken()` to recover. In worst case with malicious or unavailable admin, funds could be permanently lost.
- **User Impact**: Any user performing cross-chain unstaking during periods of gas price volatility or insufficient fee payment. Affects every failed unstake attempt where `_send()` reverts.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a protocol design flaw. Any legitimate user can trigger this by underestimating the `returnTripAllocation` parameter.
- **Preconditions**: 
  - User has completed cooldown period on hub chain
  - User initiates cross-chain unstake with insufficient native value for return trip
  - Gas prices increase between quote time and execution time
  - LayerZero enforced options misconfigured
- **Execution Complexity**: Single transaction on spoke chain. User only needs to call `UnstakeMessenger.unstake()` with insufficient msg.value.
- **Frequency**: Can occur on every cross-chain unstake where fee estimation is incorrect or gas prices fluctuate. The known Zellic issue mentions "users will have to pay twice" but doesn't capture that assets become trapped.

## Recommendation

**FIXED Implementation:**

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _handleUnstake, lines 244-278:

// CURRENT (vulnerable):
// State is cleared before _send() is attempted, making retries impossible

// FIXED:
function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
    internal
    virtual
{
    address user = unstakeMsg.user;

    // Validate user
    if (user == address(0)) revert InvalidZeroAddress();
    if (_origin.srcEid == 0) revert InvalidOrigin();

    // CRITICAL FIX: Pre-validate that assets exist BEFORE calling unstakeThroughComposer
    UserCooldown memory cooldown = IStakediTryCrosschain(address(VAULT)).getCooldown(user);
    if (cooldown.underlyingAmount == 0 || block.timestamp < cooldown.cooldownEnd) {
        revert NoAssetsToUnstake();
    }

    // Build send parameters FIRST (before state changes)
    bytes memory options = OptionsBuilder.newOptions();
    SendParam memory _sendParam = SendParam({
        dstEid: _origin.srcEid,
        to: bytes32(uint256(uint160(user))),
        amountLD: cooldown.underlyingAmount, // Use pre-checked amount
        minAmountLD: cooldown.underlyingAmount,
        extraOptions: options,
        composeMsg: "",
        oftCmd: ""
    });

    // Pre-validate that _send will succeed (check msg.value is sufficient)
    MessagingFee memory fee = IOFT(ASSET_OFT).quoteSend(_sendParam, false);
    if (msg.value < fee.nativeFee) {
        revert InsufficientMsgValue(fee.nativeFee, msg.value);
    }

    // NOW perform state changes (only after validations pass)
    uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);

    // Send with validated parameters
    _send(ASSET_OFT, _sendParam, address(this));

    // Emit success event
    emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
}
```

**Alternative Mitigation 1:** Implement a "pending unstake" mapping that tracks assets withdrawn but not yet sent, with a separate `claimFailedUnstake()` function allowing users to retry sending their trapped assets.

**Alternative Mitigation 2:** Add a `retryUnstakeSend()` function that reads trapped asset balances and allows users to provide additional msg.value to complete the send operation without calling `unstakeThroughComposer` again.

**Alternative Mitigation 3:** Move the cooldown state clearing to AFTER successful `_send()` completion, or implement a two-phase commit pattern where state is only finalized after cross-chain delivery confirmation.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainUnstakeAssetTrap.t.sol
// Run with: forge test --match-test test_CrossChainUnstakeAssetTrap -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/token/iTRY/iTry.sol";
import "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/interfaces/IOAppReceiver.sol";

contract Exploit_CrossChainUnstakeAssetTrap is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    iTry itry;
    address user = address(0x1234);
    uint32 spokeEid = 40232;
    
    function setUp() public {
        // Deploy protocol contracts (simplified)
        itry = new iTry(address(this));
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            address(0), // rewarder
            address(this), // owner
            address(0) // treasury
        );
        
        // Deploy composer (would need proper OFT adapters in real setup)
        composer = new wiTryVaultComposer(
            address(vault),
            address(itry), // asset OFT
            address(vault), // share OFT
            address(0) // endpoint (mock)
        );
        
        // Grant COMPOSER_ROLE to composer
        vault.grantRole(vault.COMPOSER_ROLE(), address(composer));
        
        // Setup: User has completed cooldown
        vm.startPrank(user);
        // ... (user would have staked, initiated cooldown, waited)
        vm.stopPrank();
    }
    
    function test_CrossChainUnstakeAssetTrap() public {
        // SETUP: User has 1000 iTRY in cooldown, ready to unstake
        uint256 cooledAmount = 1000e18;
        
        // Manually set cooldown state for testing
        vm.store(
            address(vault),
            keccak256(abi.encode(user, 0)), // cooldowns mapping slot
            bytes32(uint256(cooledAmount)) // underlyingAmount
        );
        
        // Mint iTRY to silo for withdrawal
        itry.mint(address(vault.silo()), cooledAmount);
        
        // Verify user has cooldown ready
        uint256 initialCooldownAmount = vault.cooldowns(user).underlyingAmount;
        assertEq(initialCooldownAmount, cooledAmount, "Initial cooldown should be set");
        
        // EXPLOIT STEP 1: Simulate _lzReceive call with insufficient msg.value
        Origin memory origin = Origin({
            srcEid: spokeEid,
            sender: bytes32(uint256(uint160(user))),
            nonce: 1
        });
        
        bytes memory message = abi.encode(
            uint16(1), // MSG_TYPE_UNSTAKE
            IUnstakeMessenger.UnstakeMessage({
                user: user,
                extraOptions: ""
            })
        );
        
        // First attempt with insufficient value - this will partially execute
        vm.expectRevert(); // _send will revert due to insufficient value
        composer._lzReceive{value: 0}( // No value provided for return trip
            origin,
            bytes32(0),
            message,
            address(0),
            ""
        );
        
        // VERIFY EXPLOIT: Cooldown is cleared, but assets trapped in composer
        uint256 finalCooldownAmount = vault.cooldowns(user).underlyingAmount;
        assertEq(finalCooldownAmount, 0, "Cooldown cleared on first attempt");
        
        uint256 composerBalance = itry.balanceOf(address(composer));
        assertEq(composerBalance, cooledAmount, "Assets trapped in composer");
        
        uint256 userBalance = itry.balanceOf(user);
        assertEq(userBalance, 0, "User received nothing");
        
        // VERIFY RETRY FAILS: Second attempt will always fail with NoAssetsToUnstake
        vm.expectRevert(); // Will revert with NoAssetsToUnstake
        composer._lzReceive{value: 1 ether}( // Even with sufficient value now
            origin,
            bytes32(0),
            message,
            address(0),
            ""
        );
        
        // Assets remain trapped, only owner can rescue via rescueToken()
        assertEq(
            itry.balanceOf(address(composer)), 
            cooledAmount, 
            "Assets permanently trapped until admin rescue"
        );
    }
}
```

## Notes

This vulnerability is distinct from the Zellic-identified "Native fee loss on failed wiTryVaultComposer.lzReceive" issue. The Zellic finding states users must "pay twice" for fees, but does NOT identify that the actual unstaked iTRY assets become trapped in the composer contract with no user-accessible recovery mechanism. This represents a more severe impact as it involves principal loss rather than just fee loss.

The root cause is a violation of the Checks-Effects-Interactions pattern at the cross-contract level. The `unstakeThroughComposer()` call modifies critical state in `StakediTryCrosschain` (clearing cooldown) before the `_send()` interaction that can revert, creating an unrecoverable state divergence between the vault's accounting and the composer's asset custody.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L186-200)
```text
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert InvalidZeroAddress();
        if (amount == 0) revert InvalidAmount();

        if (token == address(0)) {
            // Rescue ETH
            (bool success,) = to.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            // Rescue ERC20 tokens
            IERC20(token).safeTransfer(to, amount);
        }

        emit TokenRescued(token, to, amount);
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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L255-255)
```text
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L257-259)
```text
        if (assets == 0) {
            revert NoAssetsToUnstake();
        }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L274-274)
```text
        _send(ASSET_OFT, _sendParam, address(this));
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L86-93)
```text
        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L108-150)
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
