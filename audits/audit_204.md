## Title
Missing `address(0)` Validation in `wiTryOFT._credit` Causes Permanent Cross-Chain Token Lock

## Summary
The `wiTryOFT._credit` function does not validate whether the recipient address `_to` is `address(0)` before calling `super._credit()`. Since `address(0)` is not blacklisted by default, cross-chain messages with `_to == address(0)` pass the blacklist check but revert during minting, causing permanent token loss on the source chain with no recovery mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol`, function `_credit`, lines 84-97 [1](#0-0) 

**Intended Logic:** The `_credit` function should safely handle all cross-chain token receipts by redirecting blacklisted recipients to the contract owner, ensuring no tokens are lost or sent to invalid addresses.

**Actual Logic:** When `_to == address(0)` and `address(0)` is not explicitly blacklisted, the function proceeds to line 95 and calls `super._credit(address(0), _amountLD, _srcEid)`, which attempts to mint tokens to `address(0)`. OpenZeppelin's ERC20 `_mint` function reverts when the recipient is `address(0)`, causing the entire `lzReceive` transaction to fail. The tokens burned/locked on the source chain cannot be recovered since the LayerZero message payload cannot be modified on retry.

**Exploitation Path:**
1. User (or contract) calls `send()` on `wiTryOFTAdapter` (hub chain) or `wiTryOFT` (spoke chain) with `SendParam.to = bytes32(uint256(uint160(address(0))))`
2. Source chain burns tokens (OFT) or locks tokens (OFTAdapter) and sends LayerZero message
3. Destination chain receives message and calls `wiTryOFT._credit(address(0), amount, srcEid)`
4. Line 91 checks `blackList[address(0)]` which returns `false` (not blacklisted)
5. Line 95 executes `super._credit(address(0), amount, srcEid)`
6. OFT's `_credit` internally calls `_mint(address(0), amount)`
7. `_beforeTokenTransfer(address(0), address(0), amount)` is triggered [2](#0-1) 
8. Blacklist checks pass since `address(0)` is not blacklisted
9. OpenZeppelin ERC20's `_mint` reverts with `ERC20InvalidReceiver(address(0))`
10. LayerZero message fails and tokens remain permanently locked on source chain

**Security Property Broken:** Violates cross-chain message integrity and causes permanent loss of user funds. The protocol fails to ensure that cross-chain transfers either complete successfully or provide a recovery mechanism.

## Impact Explanation
- **Affected Assets**: wiTRY shares and any tokens sent via the `wiTryOFT` cross-chain bridge
- **Damage Severity**: 100% permanent loss of tokens sent to `address(0)`. Tokens are burned/locked on source chain but never minted on destination chain, with no recovery path.
- **User Impact**: Any user who sends tokens cross-chain to `address(0)` (accidentally through UI bug, malicious contract interaction, or integration error) permanently loses their funds. This affects both individual users and potentially integrated protocols that might construct `SendParam` with invalid recipient addresses.

## Likelihood Explanation
- **Attacker Profile**: Any user with wiTRY shares, or malicious contracts that accept user deposits and construct cross-chain messages
- **Preconditions**: None - only requires calling OFT `send()` function with `to = address(0)`
- **Execution Complexity**: Single transaction - user calls `send()` with invalid recipient address
- **Frequency**: Can occur multiple times as there's no protection against repeated attempts

## Recommendation

Add explicit `address(0)` validation in the `_credit` function to redirect zero address recipients to the contract owner, matching the blacklist handling: [1](#0-0) 

**FIXED:**
```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // Treat address(0) same as blacklisted addresses - redirect to owner
    if (_to == address(0)) {
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    
    // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
    if (blackList[_to]) {
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative mitigation:** Blacklist `address(0)` by default in the constructor:
```solidity
constructor(string memory _name, string memory _symbol, address _lzEndpoint, address _delegate)
    OFT(_name, _symbol, _lzEndpoint, _delegate)
{
    blackList[address(0)] = true;
    emit BlackListUpdated(address(0), true);
}
```

## Proof of Concept
```solidity
// File: test/Exploit_AddressZeroLock.t.sol
// Run with: forge test --match-test test_AddressZeroLock -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_AddressZeroLock is CrossChainTestBase {
    using OptionsBuilder for bytes;
    
    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;
    
    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }
    
    function test_AddressZeroLock() public {
        // SETUP: Mint wiTRY shares to user on hub chain
        vm.selectFork(sepoliaForkId);
        
        // Mint some shares to userL1
        vm.prank(deployer);
        sepoliaShareToken.mint(userL1, TRANSFER_AMOUNT);
        
        uint256 userBalanceBefore = sepoliaShareToken.balanceOf(userL1);
        uint256 adapterBalanceBefore = sepoliaShareToken.balanceOf(address(sepoliaShareAdapter));
        
        console.log("Initial balances:");
        console.log("  User:", userBalanceBefore);
        console.log("  Adapter:", adapterBalanceBefore);
        
        // EXPLOIT: Send tokens to address(0) cross-chain
        vm.startPrank(userL1);
        sepoliaShareToken.approve(address(sepoliaShareAdapter), TRANSFER_AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(0), // Sending to address(0)!
            amountLD: TRANSFER_AMOUNT,
            minAmountLD: TRANSFER_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaShareAdapter.quoteSend(sendParam, false);
        
        vm.recordLogs();
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // VERIFY: Tokens locked on source chain
        uint256 userBalanceAfter = sepoliaShareToken.balanceOf(userL1);
        uint256 adapterBalanceAfter = sepoliaShareToken.balanceOf(address(sepoliaShareAdapter));
        
        console.log("\nAfter send:");
        console.log("  User:", userBalanceAfter);
        console.log("  Adapter (locked):", adapterBalanceAfter);
        
        assertEq(userBalanceAfter, 0, "User should have 0 shares after send");
        assertEq(adapterBalanceAfter, adapterBalanceBefore + TRANSFER_AMOUNT, "Tokens locked in adapter");
        
        // Try to relay message - this will fail
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        
        vm.selectFork(opSepoliaForkId);
        
        // This should revert when trying to mint to address(0)
        vm.expectRevert(); // ERC20InvalidReceiver(address(0))
        relayMessage(message);
        
        // VERIFY: No tokens minted on destination, tokens permanently locked on source
        uint256 destTotalSupply = opSepoliaShareOFT.totalSupply();
        assertEq(destTotalSupply, 0, "No tokens minted on destination");
        
        // Tokens are permanently locked - user lost 100 ether worth of shares
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("  Tokens locked on source:", TRANSFER_AMOUNT);
        console.log("  Tokens minted on destination:", 0);
        console.log("  User loss:", TRANSFER_AMOUNT);
    }
}
```

## Notes

This vulnerability is particularly dangerous because:

1. **No Recovery Mechanism**: Unlike the composer's `lzCompose` flow which has refund logic for failed operations [3](#0-2) , the standard OFT `lzReceive` flow has no such protection.

2. **Silent Failure**: Users might not immediately realize their tokens are permanently lost, especially if UI/frontend doesn't properly validate recipient addresses.

3. **Integration Risk**: Third-party contracts or protocols integrating with wiTRY OFT might construct `SendParam` with invalid addresses due to bugs, causing user fund loss.

4. **Inconsistency**: The protocol validates `address(0)` in other critical functions like `wiTryVaultComposer._handleUnstake` [4](#0-3)  and quote functions [5](#0-4) , but this critical path is missing the check.

The fix is straightforward and should be applied before mainnet deployment to prevent permanent user fund loss.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L84-97)
```text
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

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L105-110)
```text
    function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
        if (blackList[_from]) revert BlackListed(_from);
        if (blackList[_to]) revert BlackListed(_to);
        if (blackList[msg.sender]) revert BlackListed(msg.sender);
        super._beforeTokenTransfer(_from, _to, _amount);
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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L250-252)
```text
        // Validate user
        if (user == address(0)) revert InvalidZeroAddress();
        if (_origin.srcEid == 0) revert InvalidOrigin();
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L300-303)
```text
        // Validate inputs
        if (to == address(0)) revert InvalidZeroAddress();
        if (amount == 0) revert InvalidAmount();
        if (dstEid == 0) revert InvalidDestination();
```
