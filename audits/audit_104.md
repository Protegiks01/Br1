## Title
Cross-Chain Whitelist State Mismatch Causes Permanent Loss of User Funds

## Summary
A critical vulnerability exists in the iTRY cross-chain bridging system where users can bridge tokens from a hub chain in `FULLY_ENABLED` state to a spoke chain in `WHITELIST_ENABLED` state, but non-whitelisted users will receive tokens they cannot use or bridge back, resulting in permanent fund loss. The spoke chain's `iTryTokenOFT` contract allows minting to non-whitelisted addresses but blocks all subsequent operations, trapping user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 140-177, specifically lines 160-161)

**Intended Logic:** The whitelist enforcement mechanism should prevent non-whitelisted users from receiving or holding iTRY tokens when the spoke chain is in `WHITELIST_ENABLED` state, protecting users from receiving unusable tokens.

**Actual Logic:** The `_beforeTokenTransfer` function's minting validation in `WHITELIST_ENABLED` state only checks if the recipient is not blacklisted, but fails to verify whitelist status. This allows LayerZero to mint tokens to non-whitelisted users during cross-chain transfers, but those users cannot perform any subsequent operations (transfer or burn). [1](#0-0) 

**Exploitation Path:**
1. **Hub Setup**: Hub chain (Ethereum) has iTry in `FULLY_ENABLED` state, allowing all non-blacklisted users to transfer freely
2. **Spoke Setup**: Spoke chain has iTryTokenOFT in `WHITELIST_ENABLED` state, User Alice is not whitelisted on spoke
3. **Bridge to Spoke**: Alice approves and calls `send()` on `iTryTokenOFTAdapter` to bridge 1000 iTRY from hub to spoke
4. **Tokens Locked**: iTryTokenOFTAdapter locks 1000 iTRY on hub chain
5. **Mint on Spoke**: LayerZero endpoint calls `lzReceive` → `_credit` → `_mint` on spoke. The `_beforeTokenTransfer` check at lines 160-161 passes because it only validates `!blacklisted[to]`, not `whitelisted[to]`. Alice receives 1000 iTRY on spoke.
6. **Cannot Transfer**: Alice attempts to transfer or use tokens but `_beforeTokenTransfer` at lines 168-169 requires `whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]`, which fails - transaction reverts
7. **Cannot Bridge Back**: Alice tries to bridge back by calling `send()` which burns tokens. The burn path at lines 166-167 requires `whitelisted[msg.sender] && whitelisted[from]`, which fails - transaction reverts
8. **Permanent Loss**: Alice's 1000 iTRY is locked in the adapter on hub and sitting unusable in her spoke wallet. No recovery path exists without admin intervention.

**Security Property Broken:** Violates **Whitelist Enforcement Invariant #3**: "In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY." The contract allows non-whitelisted users to receive iTRY via cross-chain minting, breaking the invariant and causing permanent fund loss.

## Impact Explanation
- **Affected Assets**: User iTRY tokens bridged from hub to spoke chain
- **Damage Severity**: 100% permanent loss of bridged amount for non-whitelisted users. Tokens are locked in adapter on hub and frozen in user wallet on spoke with no withdrawal mechanism.
- **User Impact**: Any user bridging from hub (FULLY_ENABLED) to spoke (WHITELIST_ENABLED) without being whitelisted on spoke loses their entire bridged amount. This affects regular users who may not be aware of spoke-side whitelist requirements, as the hub chain allows their transaction to proceed normally.

## Likelihood Explanation
- **Attacker Profile**: Any regular user (not an attacker per se) bridging tokens cross-chain without being whitelisted on the destination
- **Preconditions**: 
  - Hub chain in `FULLY_ENABLED` or `WHITELIST_ENABLED` (user whitelisted on hub)
  - Spoke chain in `WHITELIST_ENABLED` 
  - User not whitelisted on spoke chain
- **Execution Complexity**: Single transaction on hub chain - user simply calls standard OFT `send()` function
- **Frequency**: Every cross-chain transfer by non-whitelisted users under the state mismatch condition results in permanent fund loss

## Recommendation

**Fix the minting validation to check whitelist status:** [2](#0-1) 

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, function _beforeTokenTransfer, line 160:

// CURRENT (vulnerable):
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
    // minting
}

// FIXED:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - requires recipient to be whitelisted in WHITELIST_ENABLED state
}
```

**Alternative Mitigation:**
Override the `_credit` function (similar to wiTryOFT implementation) to redirect tokens to the contract owner if the recipient is not whitelisted:

```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // In WHITELIST_ENABLED state, redirect to owner if recipient not whitelisted
    if (transferState == TransferState.WHITELIST_ENABLED && !whitelisted[_to]) {
        emit RedirectToOwner(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}
```

**Best Practice:** Implement synchronization checks before bridging, or document clearly that users must be whitelisted on destination chain before initiating cross-chain transfers when spoke is in WHITELIST_ENABLED state.

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistCrossChainLock.t.sol
// Run with: forge test --match-test test_WhitelistCrossChainLock -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CrossChainTestBase} from "../crosschainTests/crosschain/CrossChainTestBase.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";
import {IiTryDefinitions} from "../../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_WhitelistCrossChainLock is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 1000 ether;
    uint128 constant GAS_LIMIT = 200000;
    address victim = address(0xBEEF);

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_WhitelistCrossChainLock() public {
        console.log("\n=== EXPLOIT: Cross-Chain Whitelist Lock ===");
        
        // SETUP: Hub in FULLY_ENABLED, Spoke in WHITELIST_ENABLED
        vm.selectFork(sepoliaForkId);
        
        // Mint iTRY to victim on hub (Sepolia)
        vm.prank(deployer);
        sepoliaITryToken.mint(victim, TRANSFER_AMOUNT);
        
        // Set spoke to WHITELIST_ENABLED (victim NOT whitelisted)
        vm.selectFork(opSepoliaForkId);
        vm.prank(deployer);
        opSepoliaOFT.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        console.log("Initial State:");
        console.log("  Hub: FULLY_ENABLED");
        console.log("  Spoke: WHITELIST_ENABLED");
        console.log("  Victim whitelisted on spoke:", opSepoliaOFT.whitelisted(victim));
        
        // EXPLOIT: Victim bridges from hub to spoke
        vm.selectFork(sepoliaForkId);
        vm.startPrank(victim);
        
        sepoliaITryToken.approve(address(sepoliaAdapter), TRANSFER_AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(victim))),
            amountLD: TRANSFER_AMOUNT,
            minAmountLD: TRANSFER_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(victim));
        vm.stopPrank();
        
        console.log("\nAfter Bridge to Spoke:");
        console.log("  Hub adapter locked:", sepoliaITryToken.balanceOf(address(sepoliaAdapter)));
        
        // Relay message
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        // VERIFY: Tokens minted on spoke despite victim not whitelisted
        vm.selectFork(opSepoliaForkId);
        uint256 victimBalance = opSepoliaOFT.balanceOf(victim);
        
        console.log("  Victim balance on spoke:", victimBalance);
        assertEq(victimBalance, TRANSFER_AMOUNT, "Tokens minted despite no whitelist!");
        
        // VERIFY: Victim cannot transfer on spoke
        vm.prank(victim);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        opSepoliaOFT.transfer(deployer, 100 ether);
        console.log("  [LOCKED] Cannot transfer - not whitelisted");
        
        // VERIFY: Victim cannot bridge back
        vm.startPrank(victim);
        SendParam memory returnParam = SendParam({
            dstEid: SEPOLIA_EID,
            to: bytes32(uint256(uint160(victim))),
            amountLD: TRANSFER_AMOUNT,
            minAmountLD: TRANSFER_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory returnFee = opSepoliaOFT.quoteSend(returnParam, false);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        opSepoliaOFT.send{value: returnFee.nativeFee}(returnParam, returnFee, payable(victim));
        vm.stopPrank();
        console.log("  [LOCKED] Cannot bridge back - burn requires whitelist");
        
        console.log("\n[EXPLOIT SUCCESS]");
        console.log("  Victim's 1000 iTRY permanently locked:");
        console.log("  - Locked in adapter on hub");
        console.log("  - Frozen in wallet on spoke");
        console.log("  - No recovery mechanism without admin intervention");
    }
}
```

## Notes

This vulnerability represents a critical design flaw in the cross-chain whitelist enforcement mechanism. The issue stems from inconsistent validation between minting and burning operations in `WHITELIST_ENABLED` state:

- **Minting path** (lines 160-161): Only checks `!blacklisted[to]`, allows non-whitelisted recipients
- **Burning path** (lines 166-167): Requires `whitelisted[msg.sender] && whitelisted[from]`, blocks non-whitelisted users

This asymmetry creates a one-way trap where tokens can enter but never leave a non-whitelisted user's wallet on the spoke chain. The vulnerability is particularly severe because:

1. Users on the hub chain have no indication that the spoke chain has different whitelist requirements
2. The bridge transaction succeeds normally from the user's perspective
3. Only after receiving tokens on spoke does the user discover they're locked
4. No automated recovery mechanism exists - requires owner intervention via `redistributeLockedAmount()`

The fix should ensure consistent whitelist validation across all operations or implement a safety mechanism similar to `wiTryOFT._credit()` that redirects tokens to the owner when the recipient cannot receive them.

### Citations

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
