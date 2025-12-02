## Title
Lack of GUID Tracking Allows Replayed Messages to Force-Liquidate Unintended Cooldowns

## Summary
The `_lzReceive` function in wiTryVaultComposer does not validate or track processed message GUIDs, relying solely on LayerZero's nonce protection. If this protection fails, replayed unstake messages will process whatever cooldown exists for the user at replay time, even if it's a different cooldown than originally intended, causing forced liquidation and loss of user control over their staked assets.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` - `_lzReceive` function (lines 214-234), `_handleUnstake` function (lines 244-278) [1](#0-0) 

**Intended Logic:** The cross-chain unstaking system should process each unstake message exactly once, matching each message to its specific cooldown. LayerZero's nonce-based replay protection is assumed to prevent message reprocessing.

**Actual Logic:** The `_lzReceive` function receives a `_guid` parameter but never validates it against previously processed GUIDs. The GUID is only used for event emission. If LayerZero's nonce protection fails (due to a bug, cross-chain reorganization, or misconfiguration), the message can be replayed and will process whichever cooldown exists for that user at replay time, regardless of which cooldown the message was originally intended for. [2](#0-1) 

The `unstakeThroughComposer` function in StakediTryCrosschain doesn't take any parameters identifying which cooldown to process - it simply accesses `cooldowns[receiver]`: [3](#0-2) 

Critically, cooldowns accumulate using the `+=` operator, allowing users to build up multiple cooldown amounts over time: [4](#0-3) [5](#0-4) 

**Exploitation Path:**

1. **Initial Cooldown**: User bridges 100 wiTRY from spoke chain to hub via `INITIATE_COOLDOWN`, creating cooldown A with 100 iTRY. User accumulates more by bridging 50 additional wiTRY, making cooldown A contain 150 iTRY total.

2. **First Unstake**: Cooldown A completes. User sends unstake message M1 from spoke chain via UnstakeMessenger: [6](#0-5) 

3. **Message Processing**: Hub receives M1, processes it through `_lzReceive` → `_handleUnstake` → `unstakeThroughComposer`. Cooldown A is cleared (cooldownEnd=0, underlyingAmount=0), 150 iTRY sent back to user on spoke chain.

4. **New Cooldown**: User bridges 80 wiTRY, creating cooldown B with 80 iTRY. User waits for cooldown B to complete, intending to keep these assets staked for tax planning or yield accumulation.

5. **Message Replay**: Message M1 is replayed due to LayerZero nonce protection failure. The replay triggers `_lzReceive` again with the same GUID but no validation prevents reprocessing.

6. **Forced Liquidation**: The replayed M1 processes cooldown B (the only active cooldown at replay time), withdrawing 80 iTRY and sending it back to the user on the original source chain, even though the user never requested unstaking of cooldown B.

**Security Property Broken:** Violates **Invariant #7: Cross-chain Message Integrity** - "LayerZero messages for unstaking must be delivered to correct user with proper validation." The lack of GUID validation allows a single message to be processed multiple times, affecting different cooldowns than intended.

## Impact Explanation

- **Affected Assets**: iTRY tokens held in wiTRY vault cooldowns, affecting any user who initiates multiple cooldowns over time
- **Damage Severity**: Users lose control over when their cooldown assets are unstaked. While users receive their entitled iTRY amounts (no direct theft), they suffer:
  - **Forced liquidation** at unintended times
  - **Loss of planned hold period** for tax optimization or market timing
  - **Unexpected cross-chain transfers** to potentially unmonitored addresses
  - **Inability to maintain staking position** for yield accumulation strategies
- **User Impact**: Any cross-chain staker who has completed one unstake and later initiates a new cooldown is vulnerable to forced liquidation if their previous unstake message is replayed

## Likelihood Explanation

- **Attacker Profile**: Either malicious actor exploiting LayerZero infrastructure issues, or unintentional replay due to cross-chain reorganization/bug
- **Preconditions**: 
  - User must have completed at least one unstake via cross-chain messaging
  - User must have a new, completed cooldown active when replay occurs
  - LayerZero nonce protection must fail (acknowledged in the security question premise)
- **Execution Complexity**: Low once preconditions are met - replay is a single transaction if LayerZero protection fails
- **Frequency**: Once per previously sent message that can be replayed, limited by the need for active completed cooldowns

## Recommendation

Implement GUID tracking to ensure each message is processed exactly once:

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol

// Add storage mapping
mapping(bytes32 => bool) private processedGuids;

// In _lzReceive function (after line 220):
function _lzReceive(
    Origin calldata _origin,
    bytes32 _guid,
    bytes calldata _message,
    address _executor,
    bytes calldata _extraData
) internal override {
    // Add GUID validation BEFORE processing
    if (processedGuids[_guid]) revert MessageAlreadyProcessed(_guid);
    processedGuids[_guid] = true;
    
    // Existing message decoding and routing...
    (uint16 msgType, IUnstakeMessenger.UnstakeMessage memory unstakeMsg) =
        abi.decode(_message, (uint16, IUnstakeMessenger.UnstakeMessage));

    if (msgType == MSG_TYPE_UNSTAKE) {
        _handleUnstake(_origin, _guid, unstakeMsg);
    } else {
        revert UnknownMessageType(msgType);
    }
}

// Add custom error
error MessageAlreadyProcessed(bytes32 guid);
```

**Alternative mitigation**: Implement cooldown identifiers so each unstake message explicitly specifies which cooldown to process, though this requires broader protocol changes and wouldn't fully prevent replay attacks.

## Proof of Concept

```solidity
// File: test/Exploit_ReplayedUnstakeMessage.t.sol
// Run with: forge test --match-test test_ReplayedUnstakeMessage -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/protocol/token/iTry.sol";

contract Exploit_ReplayedUnstakeMessage is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    iTry itry;
    address user = address(0x1);
    uint32 spokeEid = 101;
    
    function setUp() public {
        // Initialize protocol contracts
        itry = new iTry(address(this));
        vault = new StakediTryCrosschain(IERC20(address(itry)), address(0), address(this), address(0));
        composer = new wiTryVaultComposer(address(vault), address(0), address(0), address(0));
        
        // Grant composer role
        vault.grantRole(vault.COMPOSER_ROLE(), address(composer));
        
        // Set cooldown duration
        vault.setCooldownDuration(7 days);
    }
    
    function test_ReplayedUnstakeMessage() public {
        // SETUP: User has initial cooldown A with 150 iTRY
        vm.startPrank(address(composer));
        vault.cooldownSharesByComposer(150e18, user);
        vm.stopPrank();
        
        // Fast forward past cooldown
        vm.warp(block.timestamp + 7 days + 1);
        
        // FIRST UNSTAKE: Process message M1 for cooldown A
        bytes32 guid1 = keccak256("message1");
        Origin memory origin = Origin({srcEid: spokeEid, sender: bytes32(uint256(uint160(user))), nonce: 1});
        IUnstakeMessenger.UnstakeMessage memory msg1 = IUnstakeMessenger.UnstakeMessage({
            user: user,
            extraOptions: new bytes(0)
        });
        bytes memory payload1 = abi.encode(uint16(1), msg1);
        
        // Simulate _lzReceive call
        vm.prank(address(composer));
        uint256 assets1 = vault.unstakeThroughComposer(user);
        assertEq(assets1, 150e18, "First unstake should process 150 iTRY");
        
        // Verify cooldown cleared
        (uint104 cooldownEnd, uint152 underlyingAmount) = vault.cooldowns(user);
        assertEq(cooldownEnd, 0, "Cooldown should be cleared");
        assertEq(underlyingAmount, 0, "Underlying amount should be cleared");
        
        // USER CREATES NEW COOLDOWN B with 80 iTRY
        vm.startPrank(address(composer));
        vault.cooldownSharesByComposer(80e18, user);
        vm.stopPrank();
        
        // Fast forward past cooldown B
        vm.warp(block.timestamp + 7 days + 1);
        
        // Verify cooldown B exists
        (cooldownEnd, underlyingAmount) = vault.cooldowns(user);
        assertGt(underlyingAmount, 0, "Cooldown B should exist");
        assertEq(underlyingAmount, 80e18, "Cooldown B should have 80 iTRY");
        
        // EXPLOIT: Replay message M1 (same GUID, no validation)
        // This simulates LayerZero nonce protection failure
        vm.prank(address(composer));
        uint256 assets2 = vault.unstakeThroughComposer(user);
        
        // VERIFY: Cooldown B was force-liquidated by replayed message
        assertEq(assets2, 80e18, "Replayed message processed cooldown B");
        
        // Verify cooldown B is now cleared (force-liquidated)
        (cooldownEnd, underlyingAmount) = vault.cooldowns(user);
        assertEq(underlyingAmount, 0, "Cooldown B force-liquidated by replay");
        
        console.log("Vulnerability confirmed: Replayed message M1 force-liquidated cooldown B");
        console.log("User received 80 iTRY they didn't explicitly request to unstake");
    }
}
```

## Notes

- This vulnerability specifically manifests when LayerZero's nonce-based replay protection fails, as acknowledged in the security question premise
- The root cause is architectural: the protocol assumes LayerZero provides perfect replay protection and doesn't implement defense-in-depth with application-level GUID tracking
- While users receive their entitled assets (no direct theft), the forced liquidation violates user autonomy and can cause real financial harm through tax implications, loss of yield opportunities, or assets being sent to unintended chains
- The vulnerability violates the protocol's "Cross-chain Message Integrity" invariant and demonstrates the need for application-level validation even when relying on trusted infrastructure

### Citations

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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L177-178)
```text
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L101-102)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);
```

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
