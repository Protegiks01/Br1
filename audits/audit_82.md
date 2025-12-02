## Title
Users' Tokens Become Permanently Locked on Spoke Chain When Transfer State Changes to FULLY_DISABLED

## Summary
When the `transferState` in `iTryTokenOFT.sol` (spoke chain) is updated to `FULLY_DISABLED`, users holding iTRY tokens on that chain become completely unable to bridge their tokens back to the hub chain. The `_beforeTokenTransfer` function unconditionally reverts all token operations in FULLY_DISABLED state, including the burns required for cross-chain bridging via LayerZero OFT, effectively locking user funds until admin intervention.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` - `_beforeTokenTransfer` function, lines 174-176

**Intended Logic:** The `FULLY_DISABLED` transfer state is intended to temporarily pause all token transfers on the spoke chain. According to the protocol's cross-chain architecture documented in the contract comments, users should always be able to bridge tokens between chains via LayerZero. [1](#0-0) 

**Actual Logic:** When `transferState` is set to `FULLY_DISABLED`, the `_beforeTokenTransfer` function implements a blanket revert that blocks ALL token operations without any exceptions: [2](#0-1) 

This differs critically from the `WHITELIST_ENABLED` and `FULLY_ENABLED` states, which include explicit exceptions for minter operations (burning for cross-chain transfers): [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. User bridges iTRY tokens from hub (Ethereum) to spoke chain (MegaETH) via LayerZero OFT when `transferState` is `WHITELIST_ENABLED` or `FULLY_ENABLED`
2. Admin updates `transferState` to `FULLY_DISABLED` via `updateTransferState()`: [5](#0-4) 

3. User attempts to bridge tokens back to hub by calling LayerZero OFT's `send()` function
4. The OFT internally calls `_debit()` which executes `_burn(user, amount)` to burn tokens on spoke chain
5. `_burn()` triggers `_beforeTokenTransfer(user, address(0), amount)` where `to == address(0)` indicates a burn operation
6. `_beforeTokenTransfer` encounters `transferState == FULLY_DISABLED` and unconditionally reverts
7. User's bridging transaction fails, tokens remain locked on spoke chain

**Security Property Broken:** This violates the protocol's cross-chain architecture design where tokens should be bridgeable between chains. It also violates user expectations that administrative transfer restrictions should not prevent escape mechanisms like bridging to the main chain.

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by users on the spoke chain (MegaETH) when `transferState` is `FULLY_DISABLED`
- **Damage Severity**: Complete loss of liquidity for affected users. Tokens cannot be transferred locally OR bridged back to hub chain. Users are entirely dependent on admin re-enabling transfers.
- **User Impact**: Every user holding iTRY on the spoke chain is affected. This could include hundreds or thousands of users if the spoke chain has significant adoption. The lock persists indefinitely until admin changes the state.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is an administrative action with unintended consequences
- **Preconditions**: 
  - Users have bridged iTRY tokens to spoke chain
  - Admin updates `transferState` from `WHITELIST_ENABLED` to `FULLY_DISABLED` (legitimate admin action)
- **Execution Complexity**: Single admin transaction to change state. User attempts to bridge immediately fail.
- **Frequency**: Occurs every time `FULLY_DISABLED` state is activated while users hold tokens on spoke chain

## Recommendation

The `FULLY_DISABLED` state should include the same exceptions for minter operations (cross-chain burns) that exist in other states:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, function _beforeTokenTransfer, lines 174-176:

// CURRENT (vulnerable):
} else if (transferState == TransferState.FULLY_DISABLED) {
    revert OperationNotAllowed();
}

// FIXED:
} else if (transferState == TransferState.FULLY_DISABLED) {
    // Allow minter to burn tokens for cross-chain bridging back to hub
    // This ensures users can always exit the spoke chain
    if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
        // Cross-chain burn - allow to enable bridging to hub
    } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
        // redistributing - burn
    } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
        // redistributing - mint
    } else {
        revert OperationNotAllowed();
    }
}
```

**Alternative mitigation:** Document clearly that `FULLY_DISABLED` should only be used in extreme emergencies and should never be enabled while users have tokens on the spoke chain. However, the code fix above is strongly preferred as it prevents the footgun.

## Proof of Concept

```solidity
// File: test/Exploit_FullyDisabledTokenLock.t.sol
// Run with: forge test --match-test test_FullyDisabledLocksTokensOnSpokeChain -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";
import {IiTryDefinitions} from "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_FullyDisabledTokenLock is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_FullyDisabledLocksTokensOnSpokeChain() public {
        console.log("\n=== PoC: FULLY_DISABLED Prevents Bridging Back to Hub ===");
        
        // STEP 1: User bridges iTRY from L1 to L2
        vm.selectFork(sepoliaForkId);
        currentChainName = "Sepolia";
        
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, TRANSFER_AMOUNT);
        
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
        
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        // STEP 2: Verify user has tokens on L2
        vm.selectFork(opSepoliaForkId);
        currentChainName = "OP Sepolia";
        
        uint256 userBalanceL2 = opSepoliaOFT.balanceOf(userL1);
        console.log("User balance on L2:", userBalanceL2);
        assertEq(userBalanceL2, TRANSFER_AMOUNT, "User should have tokens on L2");
        
        // STEP 3: Admin changes transferState to FULLY_DISABLED
        vm.prank(deployer);
        opSepoliaOFT.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        console.log("Transfer state changed to FULLY_DISABLED");
        
        // STEP 4: User tries to bridge back to L1 - THIS WILL FAIL
        vm.startPrank(userL1);
        
        SendParam memory returnParam = SendParam({
            dstEid: SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL1))),
            amountLD: TRANSFER_AMOUNT,
            minAmountLD: TRANSFER_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory returnFee = opSepoliaOFT.quoteSend(returnParam, false);
        
        console.log("\nAttempting to bridge back to L1...");
        
        // This should revert with OperationNotAllowed
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        opSepoliaOFT.send{value: returnFee.nativeFee}(returnParam, returnFee, payable(userL1));
        
        vm.stopPrank();
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("User's tokens are LOCKED on L2");
        console.log("Cannot transfer locally OR bridge back to hub");
        console.log("Tokens remain locked until admin changes state");
        
        // Verify tokens are still on L2
        assertEq(opSepoliaOFT.balanceOf(userL1), TRANSFER_AMOUNT, "Tokens locked on L2");
    }
}
```

## Notes

The vulnerability exists because the `FULLY_DISABLED` state was implemented as a complete lockdown without considering that cross-chain bridging operations require token burns. The hub chain implementation in `iTry.sol` has the same issue at lines 219-221: [6](#0-5) 

However, the spoke chain (`iTryTokenOFT.sol`) is the critical location because users who bridge to spoke chains need to be able to bridge back regardless of local transfer restrictions. The hub chain issue is less severe since users can always receive newly minted tokens from `iTryIssuer` on the hub.

This is NOT the known "blacklist transfer via allowance" issue from the Zellic audit - this is a separate architectural flaw where administrative state changes inadvertently disable critical cross-chain functionality.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L10-28)
```text
/**
 * @title iTryTokenOFT
 * @notice OFT representation of iTRY on spoke chains (MegaETH)
 * @dev This contract mints/burns tokens based on LayerZero messages from the hub chain
 *
 * Architecture:
 * - Hub Chain (Ethereum): iTryToken (native) + iTryTokenAdapter (locks tokens)
 * - Spoke Chain (MegaETH): iTryTokenOFT (mints/burns based on messages)
 *
 * Flow from Hub to Spoke:
 * 1. Hub adapter locks native iTRY
 * 2. LayerZero message sent to this contract
 * 3. This contract mints equivalent OFT tokens
 *
 * Flow from Spoke to Hub:
 * 1. This contract burns OFT tokens
 * 2. LayerZero message sent to hub adapter
 * 3. Hub adapter unlocks native iTRY tokens
 */
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L134-138)
```text
    function updateTransferState(TransferState code) external onlyOwner {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L142-155)
```text
        if (transferState == TransferState.FULLY_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L157-172)
```text
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L174-176)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/iTRY/iTry.sol (L219-221)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```
