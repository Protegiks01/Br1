## Title
Contract Callers Cannot Unstake Due to Failed ETH Refund in UnstakeMessenger

## Summary
The `unstake()` function in `UnstakeMessenger.sol` hardcodes the refund address as `payable(msg.sender)`. When a contract without a `receive()` or `fallback()` payable function calls this function using the recommended buffered fee quote, LayerZero's endpoint will attempt to refund excess ETH to the non-payable contract, causing the entire transaction to revert and permanently blocking contract-based unstaking operations.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/UnstakeMessenger.sol` - `unstake()` function, line 144 [1](#0-0) 

**Intended Logic:** The function should allow any caller (including smart contracts) to initiate cross-chain unstaking by sending sufficient native tokens for LayerZero messaging fees, with excess amounts refunded to the caller. [2](#0-1) 

**Actual Logic:** When `msg.sender` is a contract without ETH-receiving capabilities and sends more than the exact fee (as recommended by the protocol), the LayerZero endpoint's refund mechanism fails when attempting to send excess ETH back to the non-payable contract, reverting the entire transaction.

**Exploitation Path:**
1. A smart contract wallet (e.g., Gnosis Safe without ETH-receiving module) or protocol integrator calls `quoteUnstakeWithBuffer(returnTripValue)` to get the recommended fee with safety buffer [3](#0-2) 

2. The contract calls `unstake{value: recommendedFee}(returnTripValue)` following the documented usage pattern [4](#0-3) 

3. The function validates sufficient payment and calls `_lzSend()` with `payable(msg.sender)` as the refund address [5](#0-4) 

4. LayerZero's endpoint attempts to refund the buffer excess to the non-payable contract, the refund fails, and the entire unstake transaction reverts

**Security Property Broken:** Cross-chain Message Integrity - "LayerZero messages for unstaking must be delivered to correct user with proper validation" is violated as contract users cannot initiate unstaking operations at all.

## Impact Explanation
- **Affected Assets**: wiTRY shares held by contracts on spoke chains remain locked and cannot be unstaked through the cross-chain mechanism
- **Damage Severity**: Complete DoS for contract-based callers - they cannot unstake their wiTRY shares at all when following the recommended fee payment pattern. While funds aren't permanently lost (they still own the shares), they cannot access the underlying iTRY assets.
- **User Impact**: All smart contract wallets, multi-signature wallets without ETH-receiving modules, and protocol integrators on spoke chains that lack `receive()` or payable `fallback()` functions are affected. Any attempt to unstake results in transaction reversion.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a design flaw affecting legitimate contract-based users
- **Preconditions**: 
  1. Caller must be a contract without `receive()` or payable `fallback()` function
  2. Caller follows the recommended pattern of using `quoteUnstakeWithBuffer()` which adds a 10% fee buffer by default [6](#0-5) 
  
  3. Even with exact quotes, gas price fluctuations between quote and execution could create refundable excess
- **Execution Complexity**: Single transaction - contract calls `unstake()` with buffered fee
- **Frequency**: Occurs every time affected contracts attempt to unstake, making the functionality completely unusable for this user category

## Recommendation

Add a `refundAddress` parameter to the `unstake()` function to allow contract callers to specify an ETH-capable address for refunds:

```solidity
// In src/token/wiTRY/crosschain/UnstakeMessenger.sol:

// CURRENT (vulnerable) - Line 108:
function unstake(uint256 returnTripAllocation) external payable nonReentrant returns (bytes32 guid)

// FIXED:
function unstake(uint256 returnTripAllocation, address payable refundAddress) external payable nonReentrant returns (bytes32 guid) {
    // Validate hub peer configured
    bytes32 hubPeer = peers[hubEid];
    if (hubPeer == bytes32(0)) revert HubNotConfigured();
    
    // Validate returnTripAllocation
    if (returnTripAllocation == 0) revert InvalidReturnTripAllocation();
    
    // Validate refundAddress (use msg.sender if zero address provided for backward compatibility)
    address payable actualRefundAddress = refundAddress == address(0) ? payable(msg.sender) : refundAddress;
    
    // ... rest of function logic ...
    
    // Automatic refund to specified address
    MessagingReceipt memory receipt = _lzSend(
        hubEid,
        payload,
        options,
        fee,
        actualRefundAddress // Refund to specified address or msg.sender
    );
    
    // ... rest of function ...
}
```

**Alternative Mitigation:** Add a helper function that allows contract callers to query the exact fee and documentation warning to always send exactly the quoted amount without buffer if the caller cannot receive ETH. However, this is less robust as gas price volatility could still create small refunds.

## Proof of Concept

```solidity
// File: test/Exploit_ContractUnstakeRefundDOS.t.sol
// Run with: forge test --match-test test_ContractCannotUnstakeWithBuffer -vvv

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import {MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/OAppSender.sol";

// Mock LayerZero Endpoint that simulates real refund behavior
contract MockEndpointWithRefund {
    function quote(MessagingParams calldata, address) external pure returns (MessagingFee memory) {
        return MessagingFee(0.01 ether, 0);
    }
    
    function send(MessagingParams calldata, address _refundAddress)
        external
        payable
        returns (MessagingReceipt memory)
    {
        uint256 actualFee = 0.01 ether;
        require(msg.value >= actualFee, "Insufficient fee");
        
        // Simulate LayerZero's refund mechanism
        if (msg.value > actualFee) {
            uint256 refund = msg.value - actualFee;
            (bool success, ) = _refundAddress.call{value: refund}("");
            require(success, "Refund failed"); // This is what causes the revert
        }
        
        return MessagingReceipt(bytes32(uint256(1)), 1, MessagingFee(actualFee, 0));
    }
    
    function setDelegate(address) external {}
}

// Non-payable contract trying to unstake
contract NonPayableUnstaker {
    UnstakeMessenger public messenger;
    
    constructor(address _messenger) {
        messenger = UnstakeMessenger(_messenger);
    }
    
    function attemptUnstake(uint256 returnTripAllocation, uint256 value) external {
        messenger.unstake{value: value}(returnTripAllocation);
    }
    
    // No receive() or fallback() - cannot accept ETH refunds
}

contract Exploit_ContractUnstakeRefundDOS is Test {
    UnstakeMessenger public messenger;
    MockEndpointWithRefund public endpoint;
    NonPayableUnstaker public contractUser;
    
    address public owner = makeAddr("owner");
    uint32 public hubEid = 40161;
    bytes32 public hubPeer = bytes32(uint256(uint160(makeAddr("hub"))));
    
    function setUp() public {
        endpoint = new MockEndpointWithRefund();
        
        vm.prank(owner);
        messenger = new UnstakeMessenger(address(endpoint), owner, hubEid);
        
        vm.prank(owner);
        messenger.setPeer(hubEid, hubPeer);
        
        contractUser = new NonPayableUnstaker(address(messenger));
        vm.deal(address(contractUser), 100 ether);
    }
    
    function test_ContractCannotUnstakeWithBuffer() public {
        // Get recommended fee with buffer (10% extra)
        (uint256 recommendedFee, ) = messenger.quoteUnstakeWithBuffer(0.001 ether);
        
        // Recommended fee should be higher than exact fee
        (uint256 exactFee, ) = messenger.quoteUnstakeWithReturnValue(0.001 ether);
        assertGt(recommendedFee, exactFee, "Buffer should add to fee");
        
        // Contract attempts to unstake with recommended buffered fee
        vm.expectRevert("Refund failed");
        contractUser.attemptUnstake(0.001 ether, recommendedFee);
        
        // Vulnerability confirmed: Contract cannot unstake when following recommended pattern
    }
    
    function test_EOACanUnstakeWithBuffer() public {
        address eoaUser = makeAddr("eoa");
        vm.deal(eoaUser, 100 ether);
        
        vm.prank(owner);
        messenger.setPeer(hubEid, hubPeer);
        
        (uint256 recommendedFee, ) = messenger.quoteUnstakeWithBuffer(0.001 ether);
        
        // EOA can successfully unstake with buffer (refund succeeds)
        vm.prank(eoaUser);
        messenger.unstake{value: recommendedFee}(0.001 ether);
        
        // EOA receives refund and transaction succeeds
    }
}
```

## Notes

This vulnerability specifically affects smart contract integrators, including:
- Gnosis Safe multisigs without ETH-receiving modules
- Protocol-owned accounts that integrate wiTRY staking
- DAO treasuries holding wiTRY shares
- Any contract-based wallet systems

The issue arises because the documentation explicitly recommends using `quoteUnstakeWithBuffer()` for safety against gas price fluctuations [7](#0-6) , but this recommended pattern is incompatible with non-payable contract callers. The 10% default buffer [8](#0-7)  creates excess ETH that must be refunded, and LayerZero V2 endpoints typically require successful refund delivery.

While EOA users are unaffected, the growing adoption of smart contract wallets (especially account abstraction and multi-signature systems) makes this a significant usability and accessibility issue that blocks an entire category of legitimate users from accessing core protocol functionality.

### Citations

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L25-33)
```text
 * @dev User Flow:
 *      1. Client queries wiTryVaultComposer.quoteUnstakeReturn() on hub to get hub→spoke return fee
 *      2. Client queries quoteUnstakeWithBuffer() (recommended) or quoteUnstakeWithReturnValue() (exact)
 *         - quoteUnstakeWithBuffer(): Applies feeBufferBPS safety margin (e.g., 10%) for gas fluctuations
 *         - quoteUnstakeWithReturnValue(): Returns exact fee without buffer
 *      3. User calls unstake(returnTripAllocation) with quoted total as msg.value
 *      4. Contract calculates spoke→hub fee with embedded returnTripAllocation
 *      5. Contract validates msg.value ≥ total fee, dispatches message, refunds excess to user
 *      6. Hub receives returnTripAllocation as native value for return trip execution
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L70-70)
```text
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

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L189-198)
```text
    /**
     * @notice Quote recommended fee for unstake WITH buffer applied
     * @dev Recommended for standard integrations. Automatically applies feeBufferBPS
     *      safety buffer to protect against gas price fluctuations between quote and execution.
     *
     * @dev Usage pattern:
     *      1. Call wiTryVaultComposer.quoteUnstakeReturn() to get hub→spoke return fee
     *      2. Call this function with that fee as returnTripValue
     *      3. Send the returned recommendedFee as msg.value to unstake()
     *      4. Contract uses exact fees; excess buffer refunded to user
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L204-218)
```text
    function quoteUnstakeWithBuffer(uint256 returnTripValue)
        external
        view
        returns (uint256 recommendedFee, uint256 lzTokenFee)
    {
        // Get exact fee with return trip value
        (uint256 nativeFee, uint256 lzTokenFeeExact) = this.quoteUnstakeWithReturnValue(returnTripValue);

        // Apply buffer: fee * (10000 + bufferBPS) / 10000
        // Example: 1 ETH fee with 1000 BPS (10%) = 1.1 ETH recommended
        recommendedFee = (nativeFee * (BPS_DENOMINATOR + feeBufferBPS)) / BPS_DENOMINATOR;
        lzTokenFee = lzTokenFeeExact;

        return (recommendedFee, lzTokenFee);
    }
```
