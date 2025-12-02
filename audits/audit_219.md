## Title
Cross-Chain Unstake Transactions Revert Due to Stale Fee Quotes from Gas Price Fluctuations

## Summary
The `UnstakeMessenger.unstake()` function performs a fresh LayerZero fee quote at execution time rather than trusting the user's pre-quoted value. When gas prices increase between the user's quote call and transaction execution, the validation check at line 134 reverts even when users send the exact amount returned by `quoteUnstakeWithReturnValue()`, causing wasted gas and forcing multiple retry attempts.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/UnstakeMessenger.sol` - `unstake()` function (lines 108-151), specifically the fee validation at line 134 and the re-quote at line 131. [1](#0-0) 

**Intended Logic:** Users should call `quoteUnstakeWithReturnValue()` to get the required fee, then send that exact amount as `msg.value` to the `unstake()` function for successful execution. [2](#0-1) 

**Actual Logic:** The contract performs TWO separate quotes:
1. **Quote time** (lines 167-187): User calls `quoteUnstakeWithReturnValue()` which invokes `_quote()` at line 184, returning fee based on CURRENT gas prices
2. **Execution time** (line 131): The `unstake()` function calls `_quote()` AGAIN, returning fee based on NEW gas prices
3. **Validation** (line 134): Checks if `msg.value >= fee.nativeFee` using the execution-time quote

If gas prices increase between these two moments, the execution-time fee exceeds the quote-time fee, causing the validation to fail. [3](#0-2) 

**Exploitation Path:**
1. User calls `quoteUnstakeWithReturnValue(0.0001 ether)` at block N when gas price is 20 gwei → receives quote of `0.01 ETH`
2. User submits transaction `unstake{value: 0.01 ETH}(0.0001 ether)` which enters mempool
3. Network congestion causes gas prices to spike to 25 gwei (25% increase) before transaction is mined at block N+5
4. At execution, line 131 calls `_quote()` which now returns `0.0125 ETH` based on current 25 gwei gas price
5. Line 134 check fails: `0.01 ETH < 0.0125 ETH` → transaction reverts with `InsufficientFee`
6. User loses gas costs for the reverted transaction and must retry with higher payment

**Security Property Broken:** This violates the principle that users following protocol-provided quote functions should have predictable transaction outcomes. The cross-chain message integrity is compromised by unpredictable reverts.

## Impact Explanation
- **Affected Assets**: User ETH on spoke chains (wasted gas), cross-chain unstaking functionality
- **Damage Severity**: Users waste gas on reverted transactions (potentially 0.001-0.01 ETH per failed attempt on L1, or equivalent on L2s). In volatile gas markets, users may need multiple retry attempts, compounding losses. On networks with high gas volatility (Ethereum mainnet during NFT drops, major DeFi events), gas can spike >50% within minutes, exceeding even the maximum 50% buffer.
- **User Impact**: ALL users attempting cross-chain unstaking are affected. The official deployment script demonstrates this exact pattern by using `quoteUnstakeWithReturnValue()` for the exact fee without applying a buffer to the spoke→hub leg. [4](#0-3) 

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this affects all legitimate users. No malicious action required.
- **Preconditions**: 
  - User has completed cooldown on hub chain
  - Network experiences gas price fluctuations between quote and execution (common on congested networks)
  - Time gap exists between quote call and transaction execution (always true due to mempool waiting)
- **Execution Complexity**: Occurs naturally during normal protocol usage. The vulnerability triggers automatically when gas prices increase during the quote→execution window (seconds to minutes depending on network).
- **Frequency**: Affects every unstake operation during periods of gas volatility. On Ethereum mainnet, gas prices can fluctuate 20-50% within 5-10 blocks, making this a frequent occurrence during peak usage.

## Recommendation

Remove the re-quote at execution time and instead validate that the user's `msg.value` is reasonable using a tolerance threshold:

```solidity
// In src/token/wiTRY/crosschain/UnstakeMessenger.sol, function unstake, lines 126-136:

// CURRENT (vulnerable):
bytes memory callerOptions =
    OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);

// Quote with native drop included (single quote with fixed returnTripAllocation)
MessagingFee memory fee = _quote(hubEid, payload, options, false);

// Validate caller sent enough
if (msg.value < fee.nativeFee) {
    revert InsufficientFee(fee.nativeFee, msg.value);
}

// FIXED:
bytes memory callerOptions =
    OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);

// Use msg.value as the fee instead of re-quoting
// LayerZero endpoint will validate sufficiency and refund excess
MessagingFee memory fee = MessagingFee({
    nativeFee: msg.value,
    lzTokenFee: 0
});

// Optional: Add minimum sanity check to prevent dust amounts
if (msg.value < returnTripAllocation) {
    revert InsufficientFee(returnTripAllocation, msg.value);
}
```

**Alternative Mitigation:** Implement a time-bounded quote cache that accepts quotes made within the last N blocks (e.g., 20 blocks ≈ 4 minutes on Ethereum), with users signing the quoted value and timestamp. This allows the contract to verify the quote was recent while eliminating re-quote timing issues.

**Alternative Mitigation 2:** Make `quoteUnstakeWithBuffer()` mandatory by removing `quoteUnstakeWithReturnValue()` from the public interface, and enforce a minimum buffer percentage directly in the `unstake()` function:

```solidity
// Calculate expected minimum with buffer applied
MessagingFee memory expectedFee = _quote(hubEid, payload, options, false);
uint256 minRequired = (expectedFee.nativeFee * (BPS_DENOMINATOR - MAX_SLIPPAGE_BPS)) / BPS_DENOMINATOR;

if (msg.value < minRequired) {
    revert InsufficientFee(minRequired, msg.value);
}

// Use msg.value as fee (LayerZero handles actual costs)
MessagingFee memory fee = MessagingFee({nativeFee: msg.value, lzTokenFee: 0});
```

## Proof of Concept

```solidity
// File: test/Exploit_StaleQuoteRevert.t.sol
// Run with: forge test --match-test test_StaleQuoteRevert -vvv

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import {MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/OAppSender.sol";
import {ILayerZeroEndpointV2} from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";

contract MockEndpoint {
    uint256 public currentFee;
    
    function setFee(uint256 _fee) external {
        currentFee = _fee;
    }
    
    function quote(MessagingParams calldata, address) external view returns (MessagingFee memory) {
        return MessagingFee(currentFee, 0);
    }
    
    function send(MessagingParams calldata, address) external payable returns (MessagingReceipt memory) {
        return MessagingReceipt(bytes32(uint256(1)), 1, MessagingFee(msg.value, 0));
    }
}

contract Exploit_StaleQuoteRevert is Test {
    UnstakeMessenger messenger;
    MockEndpoint endpoint;
    address user = address(0x1234);
    uint32 hubEid = 40161;
    bytes32 hubPeer = bytes32(uint256(uint160(address(0x5678))));
    
    function setUp() public {
        endpoint = new MockEndpoint();
        messenger = new UnstakeMessenger(address(endpoint), address(this), hubEid);
        messenger.setPeer(hubEid, hubPeer);
        
        vm.deal(user, 10 ether);
    }
    
    function test_StaleQuoteRevert() public {
        // SETUP: User gets quote when gas is 20 gwei equivalent
        endpoint.setFee(0.01 ether);
        
        vm.prank(user);
        (uint256 quotedFee,) = messenger.quoteUnstakeWithReturnValue(0.0001 ether);
        assertEq(quotedFee, 0.01 ether, "Initial quote should be 0.01 ETH");
        
        // SIMULATE GAS SPIKE: Gas increases to 25 gwei equivalent (25% increase)
        // This simulates network congestion between quote and execution
        endpoint.setFee(0.0125 ether);
        
        // EXPLOIT: User sends transaction with previously quoted amount
        // Transaction will REVERT even though user followed protocol correctly
        vm.prank(user);
        vm.expectRevert(
            abi.encodeWithSelector(
                IUnstakeMessenger.InsufficientFee.selector,
                0.0125 ether,  // new required fee
                0.01 ether     // user's msg.value (old quote)
            )
        );
        messenger.unstake{value: quotedFee}(0.0001 ether);
        
        // VERIFY: Transaction fails, user wastes gas
        // In real scenario, user would need to retry with higher amount
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("User quoted fee at 20 gwei: %s", quotedFee);
        console.log("Execution requires fee at 25 gwei: %s", 0.0125 ether);
        console.log("Transaction REVERTS despite user following protocol");
        console.log("User must retry and overpay to account for volatility");
    }
}
```

## Notes

The protocol documentation explicitly acknowledges gas price fluctuations as a concern by implementing `feeBufferBPS` (line 70) and providing `quoteUnstakeWithBuffer()`. [5](#0-4)  However, this mitigation is:

1. **Optional**: Users can still call `quoteUnstakeWithReturnValue()` directly (lines 167-187)
2. **Insufficient**: The maximum 50% buffer (line 251) can be exceeded during extreme volatility [6](#0-5) 
3. **Not enforced**: The contract doesn't mandate buffer usage or validate that `msg.value` includes reasonable headroom

The official deployment script demonstrates the exact vulnerable pattern by calling `quoteUnstakeWithReturnValue()` and immediately broadcasting without additional buffer protection on the spoke→hub leg. [7](#0-6) 

This issue is distinct from the known "Native fee loss on failed wiTryVaultComposer.lzReceive" issue, which concerns underpayment causing failures on the hub chain after the spoke transaction succeeds. This vulnerability prevents the spoke transaction from succeeding in the first place.

### Citations

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L66-70)
```text

    /// @notice Fee buffer in basis points to protect against gas price fluctuations
    /// @dev Configurable to adapt to different network conditions
    /// @dev Default 10% (1000 bps) follows LayerZero team guidance
    uint256 public feeBufferBPS = 1000;
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

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L167-187)
```text
    function quoteUnstakeWithReturnValue(uint256 returnTripValue)
        external
        view
        returns (uint256 nativeFee, uint256 lzTokenFee)
    {
        // Build dummy UnstakeMessage for quoting
        UnstakeMessage memory dummyMessage =
            UnstakeMessage({user: address(0), extraOptions: OptionsBuilder.newOptions()});

        bytes memory payload = abi.encode(MSG_TYPE_UNSTAKE, dummyMessage);

        // Build options WITH specified native value
        // This matches what unstake() will do when msg.value = total
        bytes memory callerOptions = OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripValue));
        bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);

        // Quote with native value included
        MessagingFee memory fee = _quote(hubEid, payload, options, false);

        return (fee.nativeFee, fee.lzTokenFee);
    }
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L249-251)
```text
    function setFeeBufferBPS(uint256 newBufferBPS) external onlyOwner {
        require(newBufferBPS >= 500, "Buffer too low (min 5%)");
        require(newBufferBPS <= 5000, "Buffer too high (max 50%)");
```

**File:** script/test/composer/CrosschainUnstake_SpokeToHubToSpoke_RedeemerAddress.s.sol (L86-94)
```text
 * ===== FEE QUOTING =====
 *
 * The script now quotes both legs inline to keep LayerZero fees fresh:
 *   1. Quote wiTryVaultComposer.quoteUnstakeReturn() on Sepolia (hub) to get the base return-leg fee.
 *   2. Apply UnstakeMessenger.feeBufferBPS to that number locally to build the exact returnTripAllocation.
 *   3. Call UnstakeMessenger.quoteUnstakeWithReturnValue(returnTripAllocation) on OP Sepolia (spoke) to get
 *      the EXACT msg.value required for leg1 (no buffer - OApp requires exact fee).
 *   4. Immediately broadcast unstake{value: quotedFee}(returnTripAllocation).
 *
```

**File:** script/test/composer/CrosschainUnstake_SpokeToHubToSpoke_RedeemerAddress.s.sol (L249-251)
```text
        (totalRequired, lzTokenFee) =
            IUnstakeMessenger(unstakeMessenger).quoteUnstakeWithReturnValue(returnTripAllocation);

```
