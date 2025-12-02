## Title
iTRY Cross-Chain Adapter Lacks Blacklist Protection Causing Permanent Fund Loss

## Summary
The `iTryTokenOFTAdapter` on the hub chain does not override the `_credit` function to handle blacklisted recipients gracefully. When tokens are bridged back from spoke chain to hub chain for a blacklisted user, the transfer reverts at the token level, causing permanent fund loss as tokens are already burned on the spoke chain but cannot be delivered on the hub chain.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The adapter should safely handle cross-chain token transfers in both directions (L1↔L2) while respecting the blacklist enforcement invariant that blacklisted users cannot receive iTRY tokens.

**Actual Logic:** The `iTryTokenOFTAdapter` inherits from LayerZero's `OFTAdapter` base contract without overriding the `_credit` function. When a LayerZero message arrives to unlock tokens, the inherited `_credit` function attempts to transfer tokens to the recipient. If the recipient is blacklisted, the transfer fails at the token level [2](#0-1) , causing the entire LayerZero message delivery to revert. The tokens were already burned on L2, but cannot be delivered on L1, resulting in permanent fund loss.

**Exploitation Path:**
1. User bridges iTRY tokens from hub chain (L1) to spoke chain (L2) - tokens are locked in adapter on L1
2. User gets added to blacklist while their tokens are on L2 (admin action, but affects user's funds)
3. User attempts to bridge tokens back from L2 to L1 by calling `iTryTokenOFT.send()`
4. Tokens are burned on L2, LayerZero message sent to L1
5. On L1, `iTryTokenOFTAdapter.lzReceive()` is called, which internally calls inherited `_credit(recipient, amount)`
6. The adapter attempts `token.transfer(recipient, amount)` to unlock tokens
7. This triggers `iTry._beforeTokenTransfer()` which checks blacklist status and reverts
8. LayerZero message fails, but tokens already burned on L2 - permanent fund loss

**Security Property Broken:** This violates the protocol's fund safety guarantees and creates an inconsistency with the wiTRY implementation which properly handles this scenario.

## Impact Explanation
- **Affected Assets**: iTRY tokens held by users on spoke chains who later get blacklisted
- **Damage Severity**: Complete and permanent loss of user funds - tokens burned on L2 cannot be recovered on L1
- **User Impact**: Any user who bridges iTRY to L2 and subsequently gets blacklisted (before bridging back) loses their entire bridged amount. While blacklisting is an admin action, users should not lose funds as a consequence - the proper behavior is to redirect to treasury/owner as implemented in wiTryOFT.

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a protocol design flaw affecting legitimate users who get blacklisted
- **Preconditions**: 
  1. User has bridged iTRY tokens to L2
  2. User gets added to blacklist (admin action for compliance/legal reasons)
  3. User or protocol attempts to return tokens to L1
- **Execution Complexity**: Single cross-chain transaction that fails during execution
- **Frequency**: Every time a blacklisted user attempts to bridge back from L2, or could affect multiple users in a mass blacklist event

## Recommendation

Override the `_credit` function in `iTryTokenOFTAdapter` to match the protective pattern used in `wiTryOFT`: [3](#0-2) 

The fix should:
1. Check if recipient is blacklisted before attempting transfer
2. If blacklisted, redirect tokens to contract owner/treasury instead
3. Emit an event for tracking redistributed funds
4. This prevents fund loss while still enforcing blacklist compliance

Alternative mitigation: Implement a recovery mechanism that allows owner to manually redistribute stuck funds, though this is less elegant than preventing the issue.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedRecipientFundLoss.t.sol
// Run with: forge test --match-test test_BlacklistedRecipientFundLoss -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_BlacklistedRecipientFundLoss is CrossChainTestBase {
    using OptionsBuilder for bytes;
    
    uint256 constant BRIDGE_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;
    
    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }
    
    function test_BlacklistedRecipientFundLoss() public {
        // SETUP: User bridges iTRY to L2
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, BRIDGE_AMOUNT);
        
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
        
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        // Verify tokens on L2
        vm.selectFork(opSepoliaForkId);
        assertEq(opSepoliaOFT.balanceOf(userL1), BRIDGE_AMOUNT, "User should have tokens on L2");
        
        // EXPLOIT: User gets blacklisted on L1
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        address[] memory blacklistUsers = new address[](1);
        blacklistUsers[0] = userL1;
        sepoliaITryToken.addBlacklistAddress(blacklistUsers);
        
        // User attempts to bridge back to L1
        vm.selectFork(opSepoliaForkId);
        vm.startPrank(userL1);
        
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // Verify tokens burned on L2
        assertEq(opSepoliaOFT.balanceOf(userL1), 0, "Tokens burned on L2");
        assertEq(opSepoliaOFT.totalSupply(), 0, "Total supply 0 on L2");
        
        // VERIFY: Message delivery fails on L1, funds lost
        message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        vm.selectFork(sepoliaForkId);
        vm.expectRevert(); // Transfer will revert due to blacklist
        relayMessage(message);
        
        // Tokens are stuck - burned on L2, locked in adapter on L1
        assertEq(sepoliaITryToken.balanceOf(userL1), 0, "User has 0 tokens on L1");
        assertEq(sepoliaITryToken.balanceOf(address(sepoliaAdapter)), BRIDGE_AMOUNT, "Tokens locked in adapter");
        
        // User permanently lost BRIDGE_AMOUNT
    }
}
```

## Notes

This vulnerability represents a significant **inconsistency in the protocol's cross-chain architecture**. The wiTRY cross-chain implementation correctly handles this edge case by overriding `_credit` to redirect funds to the owner when the recipient is blacklisted [4](#0-3) , but the iTRY implementation lacks this protection.

The issue is particularly severe because:
1. It violates the principle that user funds should be safe even when compliance actions (blacklisting) occur
2. The tokens are irrecoverable through normal means - they remain locked in the adapter
3. The protocol's own documentation states: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" [5](#0-4)  - this is enforced, but at the cost of permanent fund loss rather than graceful redirection

The wiTRY implementation demonstrates that the protocol team is aware of this pattern and has implemented it correctly for share tokens, making the iTRY implementation's omission more critical.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-29)
```text
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

**File:** src/token/iTRY/iTry.sol (L189-195)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
```

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

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```
