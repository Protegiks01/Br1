# NoVulnerability found for this question.

## Analysis Summary

After thoroughly investigating the code duplication between `quoteFastRedeemReturn` and `quoteUnstakeReturn` in `wiTryVaultComposer.sol`, I found that while these functions are indeed identical, this duplication does **not** create a currently exploitable vulnerability.

## Key Findings

**1. Identical Implementation - By Design:**

Both functions correctly implement the same fee estimation logic because both operations use the same underlying mechanism: [1](#0-0) [2](#0-1) 

**2. Actual Execution Matches Quotes:**

Both operations send iTRY back to the spoke chain using `ASSET_OFT` with `OptionsBuilder.newOptions()`:
- Unstake execution: [3](#0-2) 
- Fast redeem execution: [4](#0-3) 

**3. Enforced Options Provide Consistency:**

The iTRY adapter has enforced options (200k gas) that are automatically added to all quotes, ensuring consistency across both operations: [5](#0-4) 

**4. Failure Handling Prevents Loss:**

Incorrect fee estimates cannot cause loss of funds:
- Compose flow has try-catch with refund mechanism: [6](#0-5) 
- Unstake flow fee validation prevents underpayment: [7](#0-6) 
- Failed `lzReceive` requiring double payment is already a known issue (see KNOWN ISSUES list)

## Notes

**Documentation Error Identified (Non-Security):**
The NatSpec comment at line 326 incorrectly states "spoke→hub" when it should indicate "hub→spoke" for the fast redeem return leg. However, this is purely a documentation issue - the implementation correctly handles hub→spoke transfers.

**Code Quality Concern (Not a Vulnerability):**
The code duplication is a maintenance risk that could lead to future inconsistencies if one function is updated without the other. However, this is a code quality issue, not an exploitable security vulnerability. Currently, both functions work as intended and provide accurate fee estimates for their respective operations.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L116-119)
```text
        _sendParam.amountLD = assets;
        _sendParam.minAmountLD = assets;

        _send(ASSET_OFT, _sendParam, _refundAddress);
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L262-274)
```text
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
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L295-322)
```text
    function quoteUnstakeReturn(address to, uint256 amount, uint32 dstEid)
        external
        view
        returns (uint256 nativeFee, uint256 lzTokenFee)
    {
        // Validate inputs
        if (to == address(0)) revert InvalidZeroAddress();
        if (amount == 0) revert InvalidAmount();
        if (dstEid == 0) revert InvalidDestination();

        // Build send parameters for vault composer's _send() function
        SendParam memory sendParam = SendParam({
            dstEid: dstEid,
            to: bytes32(uint256(uint160(to))),
            amountLD: amount,
            minAmountLD: amount,
            extraOptions: OptionsBuilder.newOptions(), // Adapter enforced options provide gas
            composeMsg: "",
            oftCmd: ""
        });

        // Quote the fee from the adapter
        // Note: This uses the adapter's quoteSend (OFT), not wiTryVaultComposer's _quote (OApp)
        // The adapter already has enforced options with 200k gas set
        MessagingFee memory fee = IOFT(ASSET_OFT).quoteSend(sendParam, false);

        return (fee.nativeFee, fee.lzTokenFee);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L334-361)
```text
    function quoteFastRedeemReturn(address to, uint256 amount, uint32 dstEid)
        external
        view
        returns (uint256 nativeFee, uint256 lzTokenFee)
    {
        // Validate inputs
        if (to == address(0)) revert InvalidZeroAddress();
        if (amount == 0) revert InvalidAmount();
        if (dstEid == 0) revert InvalidDestination();

        // Build send parameters for vault composer's _send() function
        SendParam memory sendParam = SendParam({
            dstEid: dstEid,
            to: bytes32(uint256(uint160(to))),
            amountLD: amount,
            minAmountLD: amount,
            extraOptions: OptionsBuilder.newOptions(), // Adapter enforced options provide gas
            composeMsg: "",
            oftCmd: ""
        });

        // Quote the fee from the adapter
        // Note: This uses the adapter's quoteSend (OFT), not wiTryVaultComposer's _quote (OApp)
        // The adapter already has enforced options with 200k gas set
        MessagingFee memory fee = IOFT(ASSET_OFT).quoteSend(sendParam, false);

        return (fee.nativeFee, fee.lzTokenFee);
    }
```

**File:** script/config/06_SetEnforcedOptionsiTryAdapter.s.sol (L44-45)
```text
        bytes memory enforcedOptions = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(LZ_RECEIVE_GAS, 0);
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

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L130-136)
```text
        // Quote with native drop included (single quote with fixed returnTripAllocation)
        MessagingFee memory fee = _quote(hubEid, payload, options, false);

        // Validate caller sent enough
        if (msg.value < fee.nativeFee) {
            revert InsufficientFee(fee.nativeFee, msg.value);
        }
```
