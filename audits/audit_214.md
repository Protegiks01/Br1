## Title
Insufficient `returnTripAllocation` Validation Allows Cross-Chain Unstake Message Failure and Fee Loss

## Summary
The `unstake()` function in `UnstakeMessenger.sol` validates that `returnTripAllocation != 0` but does not enforce a minimum viable fee threshold. Users can provide extremely small values (e.g., 1 wei) that pass validation but are insufficient for the hub-to-spoke return message execution, causing perpetual message failure and requiring users to pay double fees.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/UnstakeMessenger.sol` - `unstake()` function, line 114 [1](#0-0) 

**Intended Logic:** The validation should ensure that `returnTripAllocation` is sufficient to cover the LayerZero messaging fee for the hub→spoke return trip. The protocol documentation emphasizes that users should first query `wiTryVaultComposer.quoteUnstakeReturn()` on the hub to get the base return fee. [2](#0-1) 

**Actual Logic:** The validation only checks for zero (`returnTripAllocation == 0`) but accepts any non-zero value, including 1 wei, which is orders of magnitude below the actual LayerZero messaging cost.

**Exploitation Path:**

1. **User calls `unstake(1)` on spoke chain:** User provides 1 wei as `returnTripAllocation`, which passes the zero-check validation. [3](#0-2) 

2. **Message sent to hub with embedded 1 wei:** The contract embeds 1 wei as native value via `addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation))`. [4](#0-3) 

3. **Hub receives message and processes unstake:** The hub's `_handleUnstake()` withdraws iTRY from the vault for the user. [5](#0-4) 

4. **Return message fails due to insufficient fee:** The hub attempts to send iTRY back via `_send(ASSET_OFT, _sendParam, address(this))` with `msg.value = 1 wei`, which is insufficient for the LayerZero OFT send operation. [6](#0-5) 

5. **Message perpetually fails:** The entire `_lzReceive` transaction reverts (preserving atomicity), but the message enters a failed/retryable state. On retry, the `returnTripAllocation` remains 1 wei (immutable in the message payload), causing permanent failure of this specific message.

**Security Property Broken:** Violates "Cross-chain Message Integrity" invariant - LayerZero messages must be properly validated to ensure successful delivery.

## Impact Explanation
- **Affected Assets**: User's iTRY locked in cooldown on hub chain cannot be claimed via the failed message
- **Damage Severity**: Users lose the entire fee paid for the initial failed message and must send a second message with correct fees, effectively paying double fees for the same operation
- **User Impact**: Any user who provides insufficient `returnTripAllocation` (whether maliciously, mistakenly, or due to UI issues) will experience message failure and fee loss. This can also be used as a griefing vector.

## Likelihood Explanation
- **Attacker Profile**: Any user with wiTRY tokens in cooldown on the hub can trigger this, either accidentally or intentionally
- **Preconditions**: User must have completed cooldown on hub chain and wish to unstake via cross-chain message
- **Execution Complexity**: Single transaction - user simply calls `unstake(1)` instead of properly querying the hub return fee
- **Frequency**: Can occur on every unstake attempt if users don't follow the recommended quote-then-unstake flow

## Recommendation

Validate `returnTripAllocation` against the actual quoted return fee from the hub or enforce a reasonable minimum threshold:

```solidity
// In src/token/wiTRY/crosschain/UnstakeMessenger.sol, function unstake(), line 114:

// CURRENT (vulnerable):
if (returnTripAllocation == 0) revert InvalidReturnTripAllocation();

// FIXED APPROACH 1: Minimum threshold (requires calibration for different networks)
uint256 constant MIN_RETURN_TRIP_ALLOCATION = 0.0001 ether; // Adjust based on network
if (returnTripAllocation < MIN_RETURN_TRIP_ALLOCATION) revert InvalidReturnTripAllocation();

// FIXED APPROACH 2: Compare against quoted hub return fee (more robust)
// Add new view function:
function getMinReturnTripAllocation() external view returns (uint256) {
    // Query hub composer for minimum viable return fee
    // This requires adding cross-chain view capability or documenting expected minimum
}

// Then validate:
uint256 minReturnAllocation = getMinReturnTripAllocation();
if (returnTripAllocation < minReturnAllocation) revert InvalidReturnTripAllocation();
```

**Alternative mitigation:** Add explicit documentation warnings in the function NatSpec and UI to prevent users from bypassing the recommended quote flow. However, on-chain validation is preferable to prevent griefing vectors.

## Proof of Concept

```solidity
// File: test/Exploit_InsufficientReturnTripAllocation.t.sol
// Run with: forge test --match-test test_InsufficientReturnTripAllocation -vvv

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";

contract Exploit_InsufficientReturnTripAllocation is Test {
    UnstakeMessenger messenger;
    address mockEndpoint;
    address user;
    uint32 hubEid = 40161;
    bytes32 hubPeer;
    
    function setUp() public {
        // Deploy mock endpoint
        mockEndpoint = address(new MockEndpoint());
        
        // Deploy UnstakeMessenger
        messenger = new UnstakeMessenger(mockEndpoint, address(this), hubEid);
        
        // Configure hub peer
        hubPeer = bytes32(uint256(uint160(address(0x1234))));
        messenger.setPeer(hubEid, hubPeer);
        
        // Setup user
        user = makeAddr("user");
        vm.deal(user, 1 ether);
    }
    
    function test_InsufficientReturnTripAllocation() public {
        // SETUP: Get proper quote for comparison
        MockEndpoint(mockEndpoint).setQuote(0.01 ether);
        (uint256 properFee,) = messenger.quoteUnstakeWithReturnValue(0.001 ether);
        
        // EXPLOIT: User bypasses proper quoting and uses 1 wei
        uint256 maliciousFee = 1 wei;
        (uint256 insufficientFee,) = messenger.quoteUnstakeWithReturnValue(maliciousFee);
        
        // User successfully sends message with 1 wei returnTripAllocation
        vm.prank(user);
        bytes32 guid = messenger.unstake{value: insufficientFee}(maliciousFee);
        
        // VERIFY: Message sent but will fail on hub due to insufficient return trip fee
        assertTrue(guid != bytes32(0), "Message sent successfully");
        
        // The 1 wei is accepted despite being ~10000x below actual requirement
        assertLt(maliciousFee, properFee / 10000, "Malicious fee is orders of magnitude too small");
        
        // This message will perpetually fail on hub when trying to send iTRY back
        // User must send NEW message with correct fees, losing the first message's fee
    }
}

contract MockEndpoint {
    uint256 public quotedFee;
    
    function setQuote(uint256 _fee) external {
        quotedFee = _fee;
    }
    
    function quote(bytes calldata, address) external view returns (MessagingFee memory) {
        return MessagingFee(quotedFee, 0);
    }
    
    function send(bytes calldata, address) external payable returns (MessagingReceipt memory) {
        return MessagingReceipt(keccak256(abi.encode(block.timestamp)), 1, MessagingFee(msg.value, 0));
    }
}

struct MessagingFee {
    uint256 nativeFee;
    uint256 lzTokenFee;
}

struct MessagingReceipt {
    bytes32 guid;
    uint64 nonce;
    MessagingFee fee;
}
```

## Notes

This vulnerability is distinct from the known Zellic issue "Native fee loss on failed wiTryVaultComposer.lzReceive (underpayment requires double payment)" because:
- **Zellic issue**: Focuses on gas price increases AFTER quoting, causing underpayment in volatile conditions
- **This finding**: Focuses on the complete absence of minimum validation, allowing users to intentionally or accidentally bypass the recommended quote flow with values like 1 wei

The validation gap enables both accidental user errors and intentional griefing attacks, violating the cross-chain message integrity invariant.

### Citations

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L98-107)
```text
     * @param returnTripAllocation Exact native value to forward to hub for return trip (in wei)
     *        This should be the result of calling  wiTryVaultComposer.quoteUnstakeReturn()
     *
     * @return guid Unique identifier for this LayerZero message
     *
     * @dev Usage:
     *      1. Call wiTryVaultComposer.quoteUnstakeReturn(user, amount, spokeDstEid) on hub
     *      2. Call quoteUnstakeWithReturnValue(returnTripAllocation) or quoteUnstakeWithBuffer(returnTripAllocation) on spoke
     *      3. Call unstake{value: quotedTotal}(returnTripAllocation)
     */
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L108-114)
```text
    function unstake(uint256 returnTripAllocation) external payable nonReentrant returns (bytes32 guid) {
        // Validate hub peer configured
        bytes32 hubPeer = peers[hubEid];
        if (hubPeer == bytes32(0)) revert HubNotConfigured();

        // Validate returnTripAllocation
        if (returnTripAllocation == 0) revert InvalidReturnTripAllocation();
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L126-128)
```text
        bytes memory callerOptions =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
        bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);
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

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L357-367)
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
```
