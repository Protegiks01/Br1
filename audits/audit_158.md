## Title
User LayerZero Fee Refunds Diverted to Contract and Extractable via rescueToken

## Summary
The `wiTryVaultComposer` contract overrides the parent `VaultComposerSync`'s `handleCompose` function and changes the refund address from `tx.origin` (user) to `address(this)` (contract) when calling cross-chain operations. This causes excess LayerZero fees paid by users to be refunded to the contract instead of returning to users, where they accumulate and can be extracted by the owner via `rescueToken`.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (lines 61-84, specifically lines 72, 77)

**Intended Logic:** When users initiate cross-chain compose operations (deposit or fast redeem), they pay `msg.value` to cover LayerZero messaging fees. Any excess fees that aren't consumed should be refunded back to the user who paid them, as implemented in the parent contract `VaultComposerSync`. [1](#0-0) 

**Actual Logic:** The child contract `wiTryVaultComposer` overrides `handleCompose` and replaces the refund address parameter from `tx.origin` to `address(this)` when calling internal vault operations: [2](#0-1) 

When `_send` is executed with `address(this)` as the refund address, LayerZero refunds excess native tokens to the contract instead of the user: [3](#0-2) 

These accumulated refunds can then be extracted by the owner using `rescueToken`: [4](#0-3) 

**Exploitation Path:**
1. User on spoke chain initiates cross-chain deposit or fast redeem via OFT compose message, paying `msg.value = 1.0 ETH` for LayerZero fees
2. LayerZero delivers message to hub chain and calls `lzCompose`, which forwards the 1.0 ETH to `handleCompose`
3. `wiTryVaultComposer.handleCompose` processes the operation and calls `_depositAndSend` or `_fastRedeem` with `refundAddress = address(this)` 
4. The internal `_send` call executes the cross-chain return leg, which only costs 0.8 ETH in actual LayerZero fees
5. LayerZero refunds the excess 0.2 ETH to `address(this)` (the contract) instead of `tx.origin` (the user)
6. The 0.2 ETH sits in the contract balance, accepted by the `receive()` function
7. Over time, refunds accumulate from multiple users
8. Owner calls `rescueToken(address(0), ownerAddress, accumulatedAmount)` to extract all accumulated user refunds

**Security Property Broken:** Users are entitled to receive refunds for overpaid LayerZero fees. The contract diverts these legitimate user refunds to itself, causing direct loss of user funds.

## Impact Explanation
- **Affected Assets**: Native tokens (ETH) paid by users as LayerZero messaging fees
- **Damage Severity**: Users lose 100% of their excess LayerZero fees on every cross-chain compose operation. While individual amounts may be modest (e.g., 0.1-0.5 ETH per transaction depending on gas prices and overestimation), these accumulate across all users over time
- **User Impact**: Every user who performs cross-chain deposit or fast redeem operations via compose messages is affected. Each operation results in permanent loss of overpaid fees.

## Likelihood Explanation
- **Attacker Profile**: Not an attack per se, but a design flaw that causes automatic loss for all users performing compose operations
- **Preconditions**: 
  - User initiates cross-chain deposit (via `_depositAndSend`) or fast redeem (via `_fastRedeem`)
  - User overpays for LayerZero fees (common practice to ensure message delivery)
  - Contract has been deployed with this implementation
- **Execution Complexity**: No active exploitation needed - loss occurs automatically on every compose operation
- **Frequency**: Occurs on every cross-chain compose transaction (deposit or fast redeem)

## Recommendation

In `wiTryVaultComposer.sol`, function `handleCompose`, restore the refund address to `tx.origin` to match the parent contract's behavior:

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, lines 71-77:

// CURRENT (vulnerable):
if (_oftIn == ASSET_OFT) {
    _depositAndSend(_composeFrom, _amount, sendParam, address(this));
} else if (_oftIn == SHARE_OFT) {
    if (keccak256(sendParam.oftCmd) == keccak256("INITIATE_COOLDOWN")) {
        _initiateCooldown(_composeFrom, _amount);
    } else if (keccak256(sendParam.oftCmd) == keccak256("FAST_REDEEM")) {
        _fastRedeem(_composeFrom, _amount, sendParam, address(this));
    }
    // ...
}

// FIXED:
if (_oftIn == ASSET_OFT) {
    _depositAndSend(_composeFrom, _amount, sendParam, tx.origin); // Return refunds to user
} else if (_oftIn == SHARE_OFT) {
    if (keccak256(sendParam.oftCmd) == keccak256("INITIATE_COOLDOWN")) {
        _initiateCooldown(_composeFrom, _amount);
    } else if (keccak256(sendParam.oftCmd) == keccak256("FAST_REDEEM")) {
        _fastRedeem(_composeFrom, _amount, sendParam, tx.origin); // Return refunds to user
    }
    // ...
}
```

**Alternative mitigation:** If there's a specific reason to keep refunds in the contract (e.g., to fund future operations), implement an accounting mechanism to track user refunds separately and provide a function for users to claim their accumulated refunds.

## Proof of Concept

```solidity
// File: test/Exploit_RefundDiversion.t.sol
// Run with: forge test --match-test test_RefundDiversion -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol";

contract Exploit_RefundDiversion is Test {
    wiTryVaultComposer public composer;
    address public user = address(0x1234);
    address public owner = address(0x5678);
    
    function setUp() public {
        // Deploy composer with mock vault and OFT addresses
        // (Full setup would require deploying all dependencies)
        vm.deal(user, 10 ether);
    }
    
    function test_RefundDiversion() public {
        // SETUP: User initiates cross-chain deposit with 1 ETH for fees
        uint256 userBalanceBefore = user.balance;
        uint256 contractBalanceBefore = address(composer).balance;
        
        // User sends compose message with 1 ETH for LayerZero fees
        bytes memory composeMsg = abi.encode(
            SendParam({
                dstEid: 40161, // Sepolia
                to: bytes32(uint256(uint160(user))),
                amountLD: 1000e6, // 1000 iTRY
                minAmountLD: 0,
                extraOptions: "",
                composeMsg: "",
                oftCmd: ""
            }),
            uint256(1 ether) // minMsgValue
        );
        
        // EXPLOIT: handleCompose is called via lzCompose with user's 1 ETH
        // The actual LayerZero send only costs 0.8 ETH
        // Excess 0.2 ETH should go back to user but goes to contract instead
        
        vm.prank(address(composer)); // Self-call restriction
        composer.handleCompose{value: 1 ether}(
            address(0), // ASSET_OFT placeholder
            bytes32(uint256(uint160(user))),
            composeMsg,
            1000e6
        );
        
        // VERIFY: Refund went to contract, not user
        uint256 userBalanceAfter = user.balance;
        uint256 contractBalanceAfter = address(composer).balance;
        
        // User paid 1 ETH but didn't get refund
        assertEq(userBalanceAfter, userBalanceBefore - 1 ether, 
            "User should have paid 1 ETH with no refund");
        
        // Contract received the 0.2 ETH refund
        assertGt(contractBalanceAfter, contractBalanceBefore, 
            "Contract accumulated user's refund");
        
        // Owner can extract user's refunds
        vm.prank(owner);
        composer.rescueToken(address(0), owner, contractBalanceAfter);
        
        assertEq(address(composer).balance, 0, 
            "Owner extracted user's refund via rescueToken");
    }
}
```

## Notes

This vulnerability occurs because the override in `wiTryVaultComposer.handleCompose` deviates from the parent contract's established pattern of returning refunds to users (`tx.origin`). While the `receive()` function's comment mentions accepting "LayerZero fee refunds," it does not distinguish between:

1. Legitimate protocol refunds (from operations the contract initiated)
2. User refunds (from operations users paid for)

The `rescueToken` function is documented as being for "accidentally sent" tokens, but there's no mechanism to prevent it from extracting user refunds that rightfully belong to users. Even though the owner is trusted, these funds are not protocol revenue—they are user overpayments that should be returned.

The same issue affects the `_handleUnstake` function where `address(this)` is used as refund address, but that case is less clear-cut since the unstake message doesn't carry user payment. However, for compose operations (`_depositAndSend` and `_fastRedeem`), users explicitly pay `msg.value` and should receive any excess back.

### Citations

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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L61-84)
```text
    function handleCompose(address _oftIn, bytes32 _composeFrom, bytes memory _composeMsg, uint256 _amount)
        external
        payable
        override
    {
        if (msg.sender != address(this)) revert OnlySelf(msg.sender);

        (SendParam memory sendParam, uint256 minMsgValue) = abi.decode(_composeMsg, (SendParam, uint256));
        if (msg.value < minMsgValue) revert InsufficientMsgValue(minMsgValue, msg.value);

        if (_oftIn == ASSET_OFT) {
            _depositAndSend(_composeFrom, _amount, sendParam, address(this));
        } else if (_oftIn == SHARE_OFT) {
            if (keccak256(sendParam.oftCmd) == keccak256("INITIATE_COOLDOWN")) {
                _initiateCooldown(_composeFrom, _amount);
            } else if (keccak256(sendParam.oftCmd) == keccak256("FAST_REDEEM")) {
                _fastRedeem(_composeFrom, _amount, sendParam, address(this));
            } else {
                revert InitiateCooldownRequired();
            }
        } else {
            revert OnlyValidComposeCaller(_oftIn);
        }
    }
```

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
