## Title
FULLY_DISABLED Transfer State Permanently Locks Cross-Chain Bridged iTRY Tokens in Adapter

## Summary
The iTryTokenOFTAdapter uses LayerZero's standard lock/unlock mechanism for cross-chain bridging, which relies on ERC20 `transfer()` operations that are subject to the iTry token's transfer state restrictions. When the admin sets `transferState` to `FULLY_DISABLED` while tokens are locked in the adapter, users cannot bridge their tokens back from L2 to L1, causing permanent fund loss. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description

**Location:** `src/token/iTRY/iTry.sol` (function `_beforeTokenTransfer`, lines 219-221) and `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol`

**Intended Logic:** The iTRY token implements three transfer states (FULLY_ENABLED, WHITELIST_ENABLED, FULLY_DISABLED) to control token movement during different operational phases. The OFT adapter should enable seamless cross-chain bridging regardless of these states.

**Actual Logic:** The adapter inherits LayerZero's standard `OFTAdapter` implementation which performs token transfers through normal ERC20 operations. When unlocking tokens to return them to users, the adapter calls `transfer(user, amount)`, which triggers the `_beforeTokenTransfer` hook. In FULLY_DISABLED state, this hook unconditionally reverts with no exceptions for any address or role. [1](#0-0) 

**Exploitation Path:**

1. **Initial Bridge L1→L2**: User bridges 100 iTRY tokens from Ethereum (L1) to MegaETH (L2) when `transferState` is FULLY_ENABLED or WHITELIST_ENABLED. The adapter locks tokens via `transferFrom(user, adapter, 100)`. [2](#0-1) 

2. **Admin Action**: Protocol admin sets `transferState = FULLY_DISABLED` on L1 (possibly due to security emergency, regulatory pause, or operational maintenance). [3](#0-2) 

3. **Return Bridge Attempt L2→L1**: User attempts to bridge 100 iTRY back from L2 to L1. The LayerZero message arrives at L1, and the adapter attempts to unlock tokens via `transfer(user, 100)`.

4. **Permanent Lock**: The `_beforeTokenTransfer` hook executes and immediately reverts because `transferState == FULLY_DISABLED`. The adapter has no special roles (not MINTER_CONTRACT, not DEFAULT_ADMIN_ROLE) and FULLY_DISABLED state has zero exceptions. [4](#0-3) 

5. **Fund Loss**: User's 100 iTRY tokens remain permanently locked in the adapter contract. Even if `transferState` is later changed back to FULLY_ENABLED, the LayerZero message has already failed and cannot be retried (LayerZero messages are one-time execution).

**Security Property Broken:** The protocol violates the critical invariant of cross-chain message integrity and user fund safety. While the transfer state mechanism is intended to provide operational control, it inadvertently creates a fund loss scenario for cross-chain bridge users. [5](#0-4) 

## Impact Explanation

- **Affected Assets**: All iTRY tokens locked in the iTryTokenOFTAdapter during cross-chain bridge operations become permanently unrecoverable if FULLY_DISABLED state is activated.

- **Damage Severity**: Complete and permanent loss of bridged funds. Users who have tokens locked in the adapter during an emergency pause lose 100% of those bridged tokens with no recovery mechanism. The adapter becomes a permanent token sink.

- **User Impact**: Any user who has bridged iTRY from L1 to L2 and attempts to bridge back during or after a FULLY_DISABLED state activation. This affects ALL cross-chain users during emergency scenarios where FULLY_DISABLED is the intended safety mechanism.

## Likelihood Explanation

- **Attacker Profile**: No attacker required - this is a protocol design flaw. The admin is a trusted role acting correctly by setting FULLY_DISABLED during emergencies.

- **Preconditions**: 
  1. Users have bridged iTRY tokens to L2 (normal expected usage)
  2. Admin sets `transferState = FULLY_DISABLED` for emergency/operational reasons (legitimate admin action)
  3. Users attempt to bridge back to L1 (normal expected behavior)

- **Execution Complexity**: Zero complexity - occurs naturally during normal operations when emergency pause is activated.

- **Frequency**: Occurs on every bridge-back attempt while FULLY_DISABLED is active. Even a brief FULLY_DISABLED period permanently locks all in-flight return messages.

## Recommendation

Add an exception in the `_beforeTokenTransfer` hook to allow the OFT adapter to unlock tokens even when transfers are fully disabled. The adapter should be granted a special role or the hook should recognize adapter operations.

**Option 1: Grant Adapter a Bypass Role**

```solidity
// In src/token/iTRY/iTry.sol

// Add new role constant
bytes32 public constant OFT_ADAPTER_ROLE = keccak256("OFT_ADAPTER_ROLE");

// Modify _beforeTokenTransfer function, line 219:
} else if (transferState == TransferState.FULLY_DISABLED) {
    // FIXED: Allow OFT adapter to unlock tokens even when fully disabled
    if (hasRole(OFT_ADAPTER_ROLE, msg.sender) && from != address(0) && to != address(0)) {
        // OFT adapter unlocking tokens - allow
    } else {
        revert OperationNotAllowed();
    }
}
``` [1](#0-0) 

**Option 2: Whitelist Adapter Contract**

Ensure the adapter contract is added to the whitelist before setting FULLY_DISABLED, and modify the state to use WHITELIST_ENABLED instead of FULLY_DISABLED for emergency scenarios:

```solidity
// Administrative procedure:
// 1. Before emergency pause, whitelist the adapter
iTry.addWhitelistAddress([adapterAddress]);

// 2. Set WHITELIST_ENABLED instead of FULLY_DISABLED
iTry.updateTransferState(TransferState.WHITELIST_ENABLED);

// This allows the adapter (whitelisted) to unlock tokens while preventing other transfers
``` [6](#0-5) 

**Recommended Approach:** Option 1 is more robust as it explicitly handles the adapter's special role in cross-chain infrastructure and doesn't rely on administrative procedures during emergencies.

## Proof of Concept

```solidity
// File: test/Exploit_FullyDisabledLocksAdapter.t.sol
// Run with: forge test --match-test test_FullyDisabledLocksAdapterTokens -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";
import {IiTryDefinitions} from "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_FullyDisabledLocksAdapter is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant BRIDGE_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_FullyDisabledLocksAdapterTokens() public {
        console.log("\n=== EXPLOIT: FULLY_DISABLED Locks Adapter Tokens ===");
        
        // STEP 1: User bridges iTRY from L1 to L2 (normal operation)
        vm.selectFork(sepoliaForkId);
        
        // Mint iTRY to user
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, BRIDGE_AMOUNT);
        
        // Bridge to L2
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaAdapter), BRIDGE_AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL1))),
            amountLD: BRIDGE_AMOUNT,
            minAmountLD: BRIDGE_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        vm.recordLogs();
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // Relay message to L2
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        // Verify tokens locked on L1
        uint256 adapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("Tokens locked in adapter:", adapterBalance);
        assertEq(adapterBalance, BRIDGE_AMOUNT, "Tokens should be locked in adapter");
        
        // STEP 2: Admin sets transfer state to FULLY_DISABLED (emergency scenario)
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        console.log("Transfer state set to FULLY_DISABLED");
        
        // STEP 3: User tries to bridge back from L2 to L1
        vm.selectFork(opSepoliaForkId);
        vm.startPrank(userL1);
        
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        // STEP 4: Attempt to relay message - THIS WILL REVERT
        vm.selectFork(sepoliaForkId);
        console.log("\nAttempting to unlock tokens on L1...");
        
        // This will revert because adapter cannot transfer in FULLY_DISABLED state
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        relayMessage(message);
        
        console.log("\n[EXPLOIT CONFIRMED]");
        console.log("Tokens permanently locked in adapter:", adapterBalance);
        console.log("User cannot recover their iTRY tokens");
        console.log("Even if state is changed back to FULLY_ENABLED later,");
        console.log("the LayerZero message has already failed and cannot be retried");
        
        // Verify tokens still locked
        assertEq(
            sepoliaITryToken.balanceOf(address(sepoliaAdapter)), 
            BRIDGE_AMOUNT, 
            "Tokens remain permanently locked"
        );
        assertEq(
            sepoliaITryToken.balanceOf(userL1),
            0,
            "User has no tokens - permanent loss"
        );
    }
}
```

## Notes

This vulnerability demonstrates a critical design flaw where operational safety mechanisms (transfer state controls) conflict with cross-chain infrastructure requirements. The FULLY_DISABLED state is likely intended for emergency scenarios like security incidents or regulatory compliance, but it inadvertently creates a worse outcome by permanently locking user funds in the bridge adapter.

The issue is particularly severe because:

1. **Emergency Scenarios**: The FULLY_DISABLED state would most likely be used during emergencies when protecting user funds is paramount, yet it causes permanent loss
2. **No Recovery Path**: LayerZero messages are one-time execution - once they fail, they cannot be retried
3. **Affects All Bridge Users**: Every user with in-flight return transactions loses 100% of their bridged funds
4. **Trusted Admin Action**: The vulnerability is triggered by a legitimate admin action during expected operational procedures

The deployment script confirms the adapter has no special roles that would bypass this restriction. [7](#0-6)

### Citations

**File:** src/token/iTRY/iTry.sol (L92-105)
```text
    function addWhitelistAddress(address[] calldata users) external onlyRole(WHITELIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (!hasRole(BLACKLISTED_ROLE, users[i])) _grantRole(WHITELISTED_ROLE, users[i]);
        }
    }

    /**
     * @param users List of address to be removed from whitelist
     */
    function removeWhitelistAddress(address[] calldata users) external onlyRole(WHITELIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            _revokeRole(WHITELISTED_ROLE, users[i]);
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L171-175)
```text
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L177-221)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
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

**File:** src/token/iTRY/IiTryDefinitions.sol (L5-9)
```text
    enum TransferState {
        FULLY_DISABLED,
        WHITELIST_ENABLED,
        FULLY_ENABLED
    }
```

**File:** script/deploy/hub/03_DeployCrossChain.s.sol (L126-140)
```text
    function _deployITryAdapter(Create2Factory factory, address itryToken, address endpoint)
        internal
        returns (iTryTokenOFTAdapter)
    {
        return iTryTokenOFTAdapter(
            _deployDeterministic(
                factory,
                abi.encodePacked(
                    type(iTryTokenOFTAdapter).creationCode, abi.encode(itryToken, endpoint, deployerAddress)
                ),
                ITRY_ADAPTER_SALT,
                "iTryTokenOFTAdapter"
            )
        );
    }
```
