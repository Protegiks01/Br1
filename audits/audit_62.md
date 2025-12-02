## Title
Cross-Chain Transfer Failure Due to FULLY_DISABLED State Change Locks User Funds in Adapter

## Summary
The owner can update `transferState` to `FULLY_DISABLED` while users have cross-chain transfers in flight, causing LayerZero message delivery to fail on the destination chain. This leaves user funds locked in the `iTryTokenOFTAdapter` on the source chain with no automatic recovery mechanism, requiring manual owner intervention to restore transfers.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `updateTransferState` function allows the owner to control transfer permissions across three states (FULLY_DISABLED, WHITELIST_ENABLED, FULLY_ENABLED) to manage protocol security during emergencies or regulatory requirements.

**Actual Logic:** When `transferState` is set to `FULLY_DISABLED`, the `_beforeTokenTransfer` hook [2](#0-1)  unconditionally reverts ALL transfer operations with no exceptions—including minting operations from LayerZero cross-chain messages. Unlike the `FULLY_ENABLED` and `WHITELIST_ENABLED` states which explicitly allow minting when `msg.sender == minter` [3](#0-2) , the `FULLY_DISABLED` state blocks even the LayerZero endpoint from minting tokens.

**Exploitation Path:**
1. User initiates cross-chain transfer from Hub (Ethereum) to Spoke (MegaETH) by calling `send()` on `iTryTokenOFTAdapter`, which locks their iTRY tokens in the adapter [4](#0-3) 
2. LayerZero message is transmitted cross-chain but not yet delivered
3. Owner calls `updateTransferState(TransferState.FULLY_DISABLED)` on the destination `iTryTokenOFT` contract [1](#0-0) 
4. LayerZero delivers message to destination and attempts to mint tokens to recipient
5. The `_credit` function calls `_mint`, which triggers `_beforeTokenTransfer` 
6. `_beforeTokenTransfer` reverts because `transferState == FULLY_DISABLED` [2](#0-1) 
7. The entire `lzReceive` transaction reverts, causing LayerZero to store the message as "failed"
8. User's iTRY tokens remain locked in `iTryTokenOFTAdapter` on source chain indefinitely
9. User cannot complete transfer until owner changes `transferState` back to enabled state
10. No automatic refund mechanism exists (unlike the `wiTryVaultComposer` pattern which has refund logic [5](#0-4) )

**Security Property Broken:** Violates the expected atomicity of cross-chain transfers where users should either receive their tokens on the destination or have them automatically returned to source. The current implementation can trap funds in an intermediate locked state controlled solely by owner timing decisions.

## Impact Explanation
- **Affected Assets**: All iTRY tokens that are in cross-chain transit when `transferState` changes to `FULLY_DISABLED`. These tokens are locked in the `iTryTokenOFTAdapter` contract on the Hub chain.
- **Damage Severity**: Users experience temporary to indefinite fund locking. While not permanent theft, funds are inaccessible until the owner changes state back. If the protocol enters a prolonged emergency pause or regulatory freeze, user funds could be locked for extended periods (days, weeks, or longer). In a worst-case scenario where the protocol is abandoned or cannot re-enable transfers, the lock becomes permanent.
- **User Impact**: Any user with a cross-chain transfer in flight during the state change is affected. Given LayerZero message delivery times (seconds to minutes) and the instantaneous nature of `updateTransferState`, even a small window creates risk. Multiple users could be affected simultaneously if the owner changes state during high cross-chain activity periods.

## Likelihood Explanation
- **Attacker Profile**: This is not a malicious attack but an unintended consequence of legitimate administrative action. The owner (assumed to be a trusted multisig) may change `transferState` to `FULLY_DISABLED` during emergencies, security incidents, or regulatory requirements without realizing that in-flight messages will fail.
- **Preconditions**: (1) `transferState` is currently `FULLY_ENABLED` or `WHITELIST_ENABLED`, (2) One or more users have initiated cross-chain transfers via `iTryTokenOFTAdapter.send()`, (3) LayerZero messages have not yet been delivered to destination, (4) Owner calls `updateTransferState(FULLY_DISABLED)` before message delivery.
- **Execution Complexity**: Low complexity—this naturally occurs during normal protocol operations when the owner pauses transfers for any reason while cross-chain activity is ongoing. No coordination or specific timing required from attacker perspective.
- **Frequency**: Could occur during every emergency pause or transfer restriction event. Given LayerZero delivery times of several seconds to minutes, any `updateTransferState` call creates a window where in-flight transfers will fail.

## Recommendation
Add an exception in the `FULLY_DISABLED` state to allow the minter (LayerZero endpoint) to complete cross-chain minting operations: [2](#0-1) 

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, function _beforeTokenTransfer, line 174:

// CURRENT (vulnerable):
} else if (transferState == TransferState.FULLY_DISABLED) {
    revert OperationNotAllowed();
}

// FIXED:
} else if (transferState == TransferState.FULLY_DISABLED) {
    // Allow LayerZero endpoint to complete cross-chain minting for in-flight messages
    if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
        // Cross-chain minting from LayerZero - allowed to complete in-flight transfers
    } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
        // Allow owner to redistribute blacklisted funds even when fully disabled
    } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
        // Allow owner to mint for redistribution even when fully disabled
    } else {
        revert OperationNotAllowed();
    }
}
```

**Alternative Mitigation:** Implement a two-step state change process where `updateTransferState` to `FULLY_DISABLED` includes a grace period (e.g., 5 minutes) during which cross-chain messages can still complete minting. This requires adding a timestamp field and checking elapsed time in `_beforeTokenTransfer`.

**Additional Safety Measure:** Add a function for the owner to manually complete stuck cross-chain transfers by temporarily allowing minting for specific recipients, then immediately re-disabling transfers. This provides a recovery path without fully enabling the protocol.

## Proof of Concept
```solidity
// File: test/Exploit_CrossChainTransferStateLocking.t.sol
// Run with: forge test --match-test test_CrossChainTransferFailsOnFullyDisabled -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";
import {IiTryDefinitions} from "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_CrossChainTransferStateLocking is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
        console.log("\n=== PoC: Cross-Chain Transfer State Locking ===");
    }

    function test_CrossChainTransferFailsOnFullyDisabled() public {
        // SETUP: Mint iTRY to user on L1 (Hub)
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, TRANSFER_AMOUNT);
        
        uint256 userBalanceBefore = sepoliaITryToken.balanceOf(userL1);
        uint256 adapterBalanceBefore = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        
        console.log("\nInitial State (Sepolia):");
        console.log("  User balance:", userBalanceBefore);
        console.log("  Adapter balance:", adapterBalanceBefore);
        
        // EXPLOIT Step 1: User initiates cross-chain transfer
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaAdapter), TRANSFER_AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL1))),
            amountLD: TRANSFER_AMOUNT,
            minAmountLD: TRANSFER_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        vm.recordLogs();
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        console.log("\nUser sent cross-chain transfer - tokens locked in adapter");
        uint256 adapterBalanceAfterSend = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("  Adapter now holds:", adapterBalanceAfterSend);
        assertEq(adapterBalanceAfterSend, TRANSFER_AMOUNT, "Tokens should be locked in adapter");
        
        // EXPLOIT Step 2: Owner changes state to FULLY_DISABLED before message arrives
        vm.selectFork(opSepoliaForkId);
        vm.prank(deployer); // deployer is owner
        opSepoliaOFT.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        console.log("\nOwner set transferState to FULLY_DISABLED on destination");
        
        // EXPLOIT Step 3: Try to relay message - it will fail
        vm.selectFork(sepoliaForkId);
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        
        vm.selectFork(opSepoliaForkId);
        console.log("\nAttempting to relay message...");
        
        // This will revert because _beforeTokenTransfer blocks ALL operations in FULLY_DISABLED
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        relayMessage(message);
        
        console.log("Message delivery FAILED - reverted with OperationNotAllowed");
        
        // VERIFY: Tokens are stuck in adapter, user has nothing on L2
        vm.selectFork(opSepoliaForkId);
        uint256 userBalanceL2 = opSepoliaOFT.balanceOf(userL1);
        console.log("\nFinal State:");
        console.log("  User balance on L2:", userBalanceL2);
        
        vm.selectFork(sepoliaForkId);
        uint256 adapterBalanceFinal = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("  Tokens locked in adapter:", adapterBalanceFinal);
        
        assertEq(userBalanceL2, 0, "User received nothing on L2");
        assertEq(adapterBalanceFinal, TRANSFER_AMOUNT, "Tokens permanently locked in adapter");
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("  User's 100 iTRY is locked in adapter on L1");
        console.log("  Message cannot be delivered due to FULLY_DISABLED state on L2");
        console.log("  User must wait for owner to re-enable transfers (no guarantee of timing)");
        console.log("  No automatic refund mechanism exists");
    }
}
```

## Notes

This vulnerability differs from the known Zellic issues because it specifically involves the interaction between cross-chain LayerZero messages and the transfer state mechanism. The `FULLY_DISABLED` state's blanket revert creates an unintended denial-of-service for in-flight cross-chain transfers.

The issue is particularly concerning because:
1. The owner cannot detect in-flight messages before changing state (no visibility into pending LayerZero messages)
2. No grace period exists for completing in-flight operations
3. Unlike the `wiTryVaultComposer` which implements try-catch refund logic, the base OFT pattern has no such protection
4. Users have no recourse except waiting for owner action

The recommended fix aligns with how `FULLY_ENABLED` and `WHITELIST_ENABLED` states explicitly allow minting from the LayerZero endpoint, creating consistency across all transfer states.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L134-138)
```text
    function updateTransferState(TransferState code) external onlyOwner {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L143-146)
```text
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L174-176)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L1-29)
```text
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {OFTAdapter} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFTAdapter.sol";

/**
 * @title iTryTokenAdapter
 * @notice OFT Adapter for existing iTRY token on hub chain (Ethereum Mainnet)
 * @dev Wraps the existing iTryToken to enable cross-chain transfers via LayerZero
 *
 * Architecture:
 * - Hub Chain (Ethereum): iTryToken (native) + iTryTokenAdapter (locks tokens)
 * - Spoke Chain (MegaETH): iTryTokenOFT (mints/burns based on messages)
 *
 * Flow:
 * 1. User approves iTryTokenAdapter to spend their iTRY
 * 2. User calls send() on iTryTokenAdapter
 * 3. Adapter locks iTRY and sends LayerZero message to spoke chain
 * 4. iTryTokenOFT mints equivalent amount on spoke chain
 */
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
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
