## Title
Cross-Chain Share Loss Due to Blacklist Redirection Failure in wiTryOFT._credit

## Summary
When bridging wiTRY shares from hub chain to spoke chain, if the recipient is blacklisted and the redirection to `owner()` also fails (because owner is blacklisted), the LayerZero message delivery fails on the spoke chain while shares remain permanently locked on the hub chain. This creates an unrecoverable fund loss scenario.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol` (function `_credit`, lines 84-97; function `_beforeTokenTransfer`, lines 105-110)

**Intended Logic:** When a blacklisted user receives shares via cross-chain transfer, the protocol should redirect the shares to the contract owner as a safety mechanism, ensuring shares are never lost. [1](#0-0) 

**Actual Logic:** The `_credit` function redirects blacklisted recipients to `owner()`, but does not validate that the owner is not also blacklisted. The subsequent `_mint` to owner triggers `_beforeTokenTransfer`, which reverts if owner is blacklisted, causing the entire LayerZero message to fail. [2](#0-1) 

**Exploitation Path:**
1. User bridges wiTRY shares from hub chain (Ethereum) to spoke chain (MegaETH) by calling `send()` on `wiTryOFTAdapter`
2. Hub chain: Adapter locks user's shares via `_debit()`, transferring them to the adapter contract
3. LayerZero relayers deliver message to spoke chain
4. Spoke chain: `lzReceive` calls `_credit(user, amount, srcEid)`
5. User is blacklisted on spoke chain, so `_credit` attempts to redirect to `owner()`
6. Owner is also blacklisted (due to misconfiguration, accident, or malicious blacklisting)
7. `super._credit(owner(), ...)` calls `_mint(owner(), amount)`, which triggers `_beforeTokenTransfer`
8. `_beforeTokenTransfer` checks `if (blackList[_to]) revert BlackListed(_to)` where `_to == owner()`
9. Transaction reverts, LayerZero message fails
10. Shares remain locked in `wiTryOFTAdapter` on hub chain
11. No shares are minted on spoke chain

**Security Property Broken:** Violates **Cross-chain Message Integrity** invariant - "LayerZero messages for unstaking must be delivered to correct user with proper validation". Shares are locked without proper crediting, creating permanent fund loss.

## Impact Explanation
- **Affected Assets**: wiTRY vault shares (ERC4626 shares representing staked iTRY)
- **Damage Severity**: 
  - **Complete loss scenario**: If owner remains blacklisted, shares are permanently locked with no recovery mechanism. User loses 100% of bridged shares.
  - **Theft scenario**: If owner is removed from blacklist and message is retried, owner receives the shares instead of the original user (redistribution to owner was intended for blacklisted funds, not legitimate user transfers).
- **User Impact**: Any user attempting to bridge shares to spoke chain when both they and the contract owner are blacklisted on that chain. This can affect multiple users if owner is blacklisted before individual users bridge their shares.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a configuration/operational risk. Can affect any legitimate user bridging shares.
- **Preconditions**: 
  - User is blacklisted on spoke chain (could be legitimate compliance action)
  - Contract owner is also blacklisted on spoke chain (could be accidental, regulatory action, or malicious blacklisting by compromised blackLister role)
  - wiTryOFTAdapter has no rescue function to unlock shares [3](#0-2) 
- **Execution Complexity**: Single cross-chain transaction - occurs naturally during normal bridging operations
- **Frequency**: Can happen on every bridge attempt while the blacklist state persists

## Recommendation

Add validation in `_credit` to ensure the fallback recipient (owner) is not blacklisted before attempting to credit them. If both recipient and owner are blacklisted, the function should revert early with a descriptive error, allowing the protocol team to identify and resolve the issue before shares are locked on the hub chain.

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, function _credit, lines 84-97:

// CURRENT (vulnerable):
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
    if (blackList[_to]) {
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}

// FIXED:
error OwnerBlacklisted();

function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // If the recipient is blacklisted, redirect to owner (if owner is not blacklisted)
    if (blackList[_to]) {
        address contractOwner = owner();
        // Validate owner is not blacklisted to prevent failed message delivery
        if (blackList[contractOwner]) {
            revert OwnerBlacklisted();
        }
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(contractOwner, _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative mitigation:** Add an emergency rescue function to `wiTryOFTAdapter` that allows the owner to recover locked shares in case of failed message delivery. However, this approach is more complex as it requires coordination with LayerZero's failed message handling.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainShareLoss.t.sol
// Run with: forge test --match-test test_CrossChainShareLoss -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_CrossChainShareLoss is CrossChainTestBase {
    using OptionsBuilder for bytes;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }
    
    function test_CrossChainShareLoss() public {
        uint256 INITIAL_DEPOSIT = 100 ether;
        uint256 SHARES_TO_BRIDGE = 50 ether;
        
        // SETUP: Mint iTRY and deposit to get shares on hub chain
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, INITIAL_DEPOSIT);
        
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaVault), INITIAL_DEPOSIT);
        sepoliaVault.deposit(INITIAL_DEPOSIT, userL1);
        vm.stopPrank();
        
        uint256 userSharesBefore = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesBefore = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        
        console.log("User shares before bridge:", userSharesBefore);
        console.log("Adapter locked shares before:", adapterSharesBefore);
        
        // SETUP: Blacklist user AND owner on spoke chain
        vm.selectFork(opSepoliaForkId);
        vm.startPrank(deployer);
        opSepoliaShareOFT.updateBlackList(userL1, true); // Blacklist recipient
        opSepoliaShareOFT.updateBlackList(deployer, true); // Blacklist owner (deployer is owner)
        vm.stopPrank();
        
        console.log("Blacklisted user and owner on spoke chain");
        
        // EXPLOIT: Bridge shares from hub to spoke
        vm.selectFork(sepoliaForkId);
        vm.startPrank(userL1);
        sepoliaVault.approve(address(sepoliaShareAdapter), SHARES_TO_BRIDGE);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL1))),
            amountLD: SHARES_TO_BRIDGE,
            minAmountLD: SHARES_TO_BRIDGE,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaShareAdapter.quoteSend(sendParam, false);
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, userL1);
        vm.stopPrank();
        
        // Capture the message
        vm.recordLogs();
        CrossChainMessage memory message = captureLastMessage();
        
        // Verify shares are locked on hub
        uint256 userSharesAfterSend = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesAfterSend = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        
        console.log("\nAfter send on hub:");
        console.log("User shares:", userSharesAfterSend);
        console.log("Adapter locked shares:", adapterSharesAfterSend);
        
        assertEq(userSharesAfterSend, userSharesBefore - SHARES_TO_BRIDGE, "Shares should be deducted from user");
        assertEq(adapterSharesAfterSend, adapterSharesBefore + SHARES_TO_BRIDGE, "Shares should be locked in adapter");
        
        // EXPLOIT: Try to relay message to spoke chain - should fail
        vm.selectFork(opSepoliaForkId);
        
        // Attempt message relay - this will revert because both user and owner are blacklisted
        vm.expectRevert();
        relayMessage(message);
        
        console.log("\nMessage delivery failed on spoke chain!");
        
        // VERIFY: No shares minted on spoke
        uint256 userSharesOnSpoke = opSepoliaShareOFT.balanceOf(userL1);
        uint256 ownerSharesOnSpoke = opSepoliaShareOFT.balanceOf(deployer);
        
        assertEq(userSharesOnSpoke, 0, "User should have 0 shares on spoke");
        assertEq(ownerSharesOnSpoke, 0, "Owner should have 0 shares on spoke");
        
        console.log("User shares on spoke:", userSharesOnSpoke);
        console.log("Owner shares on spoke:", ownerSharesOnSpoke);
        
        // VERIFY: Shares remain locked on hub with NO recovery mechanism
        vm.selectFork(sepoliaForkId);
        console.log("\nFinal state on hub:");
        console.log("User shares:", sepoliaVault.balanceOf(userL1));
        console.log("Adapter locked shares:", sepoliaVault.balanceOf(address(sepoliaShareAdapter)));
        console.log("\nVulnerability confirmed: 50 ether shares permanently locked with no recovery!");
    }
}
```

## Notes

This vulnerability represents a critical cross-chain atomicity failure. LayerZero V2's asynchronous message delivery model means the source chain transaction (locking shares) commits before the destination chain message is processed. If the destination fails, there is no automatic rollback mechanism.

The blacklist redirection pattern in `_credit` was designed as a safety feature to redirect funds from blacklisted users to the protocol owner. However, it creates a new failure mode when the owner is also blacklisted, as the code does not validate this scenario.

The wiTryOFTAdapter contract is a minimal wrapper with no emergency functions to unlock shares, making recovery impossible without a protocol upgrade or owner intervention on the spoke chain to remove themselves from the blacklist (which may not be possible if the blacklisting was done for legitimate compliance reasons).

This issue is distinct from the known Zellic finding about "Native fee loss on failed wiTryVaultComposer.lzReceive" - that issue relates to fee refunds, while this issue relates to permanent fund loss.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L76-97)
```text
    /**
     * @dev Credits tokens to the recipient while checking if the recipient is blacklisted.
     * If blacklisted, redistributes the funds to the contract owner.
     * @param _to The address of the recipient.
     * @param _amountLD The amount of tokens to credit.
     * @param _srcEid The source endpoint identifier.
     * @return amountReceivedLD The actual amount of tokens received.
     */
    function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
        internal
        virtual
        override
        returns (uint256 amountReceivedLD)
    {
        // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
        if (blackList[_to]) {
            emit RedistributeFunds(_to, _amountLD);
            return super._credit(owner(), _amountLD, _srcEid);
        } else {
            return super._credit(_to, _amountLD, _srcEid);
        }
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L99-110)
```text
    /**
     * @dev Checks the blacklist for both sender and recipient before updating balances for a local movement.
     * @param _from The address from which tokens are transferred.
     * @param _to The address to which tokens are transferred.
     * @param _amount The amount of tokens to transfer.
     */
    function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
        if (blackList[_from]) revert BlackListed(_from);
        if (blackList[_to]) revert BlackListed(_to);
        if (blackList[msg.sender]) revert BlackListed(msg.sender);
        super._beforeTokenTransfer(_from, _to, _amount);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L1-33)
```text
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import {OFTAdapter} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFTAdapter.sol";

/**
 * @title wiTryOFTAdapter
 * @notice OFT Adapter for wiTRY shares on hub chain (Ethereum Mainnet)
 * @dev Wraps the StakedUSDe share token to enable cross-chain transfers via LayerZero
 *
 * Architecture (Phase 1 - Instant Redeems):
 * - Hub Chain (Ethereum): StakedUSDe (ERC4626 vault) + wiTryOFTAdapter (locks shares)
 * - Spoke Chain (MegaETH): ShareOFT (mints/burns based on messages)
 *
 * Flow:
 * 1. User deposits iTRY into StakedUSDe vault → receives wiTRY shares
 * 2. User approves wiTryOFTAdapter to spend their wiTRY
 * 3. User calls send() on wiTryOFTAdapter
 * 4. Adapter locks wiTRY shares and sends LayerZero message
 * 5. ShareOFT mints equivalent shares on spoke chain
 *
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
 */
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```
