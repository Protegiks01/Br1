## Title
iTryTokenOFT Missing `_credit` Override Causes Fund Lockup When Transferring to Blacklisted Addresses Cross-Chain

## Summary
The `iTryTokenOFT` contract does not override the `_credit` function from LayerZero's OFT base contract. When iTRY tokens are sent cross-chain to a blacklisted recipient, the `_beforeTokenTransfer` hook reverts the minting operation, causing the LayerZero message to fail and tokens to remain locked in the source chain adapter. This contrasts with `wiTryOFT` which overrides `_credit` to gracefully redirect tokens to the owner.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (entire contract, missing `_credit` override)

**Intended Logic:** Cross-chain iTRY transfers should handle blacklisted recipients gracefully, similar to how `wiTryOFT` redirects funds to the owner when the recipient is blacklisted, ensuring tokens are not locked on the source chain.

**Actual Logic:** When iTRY tokens are bridged cross-chain to a blacklisted address:
1. The LayerZero endpoint calls `lzReceive` on `iTryTokenOFT`
2. The base OFT contract's `_credit` function is invoked (not overridden in iTryTokenOFT)
3. `_credit` calls `_mint` to mint tokens to the recipient
4. `_mint` triggers `_beforeTokenTransfer` hook
5. The hook checks `msg.sender == minter && from == address(0) && !blacklisted[to]`
6. If recipient is blacklisted, the condition fails and reverts with `OperationNotAllowed()`
7. The LayerZero message delivery fails, leaving tokens locked in the adapter [1](#0-0) 

**Exploitation Path:**
1. Attacker (or innocent user) sends iTRY from L1 (hub chain) to a blacklisted address on L2 (spoke chain) via `iTryTokenOFTAdapter.send()`
2. L1 adapter locks iTRY tokens in the adapter contract
3. LayerZero message is sent to L2 iTryTokenOFT
4. L2 iTryTokenOFT receives message, attempts to mint to blacklisted recipient
5. `_beforeTokenTransfer` reverts due to blacklist check, causing message delivery to fail
6. Tokens remain locked in L1 adapter, requiring manual recovery

**Security Property Broken:** 
- **Blacklist Enforcement Invariant (#2)**: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - The protocol enforces this but at the cost of fund lockup rather than graceful handling
- **Cross-chain Message Integrity (#7)**: Message delivery fails unexpectedly, violating smooth cross-chain operation expectations

## Impact Explanation
- **Affected Assets**: iTRY tokens sent cross-chain to blacklisted addresses
- **Damage Severity**: Tokens become temporarily locked in the `iTryTokenOFTAdapter` on the source chain. Recovery requires either:
  1. Removing the recipient from the blacklist and retrying the LayerZero message
  2. Owner intervention through LayerZero's failed message recovery mechanisms
  3. Protocol governance action to unlock funds
- **User Impact**: Any user (malicious or innocent) can trigger this by sending iTRY to a known blacklisted address. All senders lose access to their tokens until manual recovery, and must pay gas fees twice (initial send + recovery attempt).

## Likelihood Explanation
- **Attacker Profile**: Any user with iTRY tokens on the hub chain can trigger this vulnerability by sending to blacklisted addresses. No special privileges required.
- **Preconditions**: 
  - At least one address must be on the blacklist
  - Cross-chain bridge must be operational
  - Victim must attempt to send iTRY cross-chain (intentionally or by mistake)
- **Execution Complexity**: Single transaction on L1 to send iTRY to a blacklisted L2 address. No complex timing or multi-step coordination required.
- **Frequency**: Can be exploited repeatedly for each cross-chain transfer attempt to blacklisted addresses. Acts as both a griefing vector and a user experience failure.

## Recommendation

**Primary Fix:** Override the `_credit` function in `iTryTokenOFT` to match the graceful handling implemented in `wiTryOFT`: [2](#0-1) 

Implement the following in `iTryTokenOFT.sol`:

```solidity
// Add after line 139 in iTryTokenOFT.sol:

/**
 * @dev Credits tokens to the recipient while checking if the recipient is blacklisted.
 * If blacklisted, redistributes the funds to the contract owner to prevent fund lockup.
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
    // If the recipient is blacklisted, redirect funds to owner to prevent lockup
    if (blacklisted[_to]) {
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative Mitigation:** If redirecting to owner is not desired, implement a refund mechanism similar to the composer's error handling: [3](#0-2) 

However, this would require wrapping the `lzReceive` flow with try-catch logic at the LayerZero endpoint level, which is more complex and gas-intensive.

**Recommended Approach:** Implement the `_credit` override as shown above to maintain consistency with `wiTryOFT`'s design pattern and prevent fund lockup scenarios.

## Proof of Concept

```solidity
// File: test/Exploit_iTryBlacklistCrosschainLockup.t.sol
// Run with: forge test --match-test test_iTryBlacklistCrosschainLockup -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_iTryBlacklistCrosschainLockup is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;
    address blacklistedUser;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
        blacklistedUser = makeAddr("blacklistedUser");
        
        console.log("\n=== Exploit: iTRY Blacklist Cross-chain Lockup ===");
    }

    function test_iTryBlacklistCrosschainLockup() public {
        // SETUP: Mint iTRY to userL1 and blacklist recipient on L2
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, TRANSFER_AMOUNT);
        
        // Blacklist the recipient on L2
        vm.selectFork(opSepoliaForkId);
        vm.prank(deployer);
        address[] memory blacklistArray = new address[](1);
        blacklistArray[0] = blacklistedUser;
        opSepoliaOFT.addBlacklistAddress(blacklistArray);
        console.log("Blacklisted user on L2:", blacklistedUser);
        
        // EXPLOIT: Send iTRY from L1 to blacklisted address on L2
        vm.selectFork(sepoliaForkId);
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaAdapter), TRANSFER_AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(blacklistedUser))),
            amountLD: TRANSFER_AMOUNT,
            minAmountLD: TRANSFER_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        
        console.log("\nSending iTRY to blacklisted address...");
        vm.recordLogs();
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // Verify tokens are locked on L1
        uint256 adapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("Tokens locked in L1 adapter:", adapterBalance);
        assertEq(adapterBalance, TRANSFER_AMOUNT, "Tokens should be locked in adapter");
        
        // VERIFY: Attempt to relay message - it will revert
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        
        console.log("\nAttempting to relay message to L2...");
        vm.selectFork(opSepoliaForkId);
        
        // This will revert due to blacklist check in _beforeTokenTransfer
        vm.expectRevert(); // OperationNotAllowed() revert
        relayMessage(message);
        
        // Verify tokens are NOT minted on L2
        uint256 blacklistedBalance = opSepoliaOFT.balanceOf(blacklistedUser);
        uint256 totalSupplyL2 = opSepoliaOFT.totalSupply();
        
        console.log("\nL2 State after failed relay:");
        console.log("  Blacklisted user balance:", blacklistedBalance);
        console.log("  L2 total supply:", totalSupplyL2);
        
        assertEq(blacklistedBalance, 0, "Blacklisted user should have 0 balance");
        assertEq(totalSupplyL2, 0, "L2 should have 0 supply (mint failed)");
        
        // Verify tokens remain locked on L1
        vm.selectFork(sepoliaForkId);
        uint256 finalAdapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("\nTokens still locked in L1 adapter:", finalAdapterBalance);
        assertEq(finalAdapterBalance, TRANSFER_AMOUNT, "Tokens remain locked - fund lockup confirmed");
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("  [FAILED] iTRY transfer to blacklisted address reverted");
        console.log("  [LOCKED] 100 iTRY stuck in L1 adapter");
        console.log("  [IMPACT] Manual recovery required");
    }
}
```

## Notes

**Comparison with wiTRY Implementation:**
The `wiTryOFT` contract properly overrides `_credit` to handle blacklisted recipients gracefully by redirecting funds to the owner. [4](#0-3) 

This approach prevents fund lockup while still enforcing blacklist restrictions. The `iTryTokenOFT` contract should implement the same pattern for consistency and user protection.

**LayerZero V2 Context:**
While LayerZero V2 provides mechanisms for retrying failed messages, this requires the root cause (blacklisted recipient) to be resolved first. The current implementation forces either:
1. Removal from blacklist (defeats the purpose of blacklisting)
2. Complex owner intervention to recover funds
3. Permanent fund lock if neither action is taken

The recommended fix prevents this scenario entirely by handling blacklisted recipients at the `_credit` level before `_beforeTokenTransfer` is invoked.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-177)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
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
            // State 1 - Transfers only enabled between whitelisted addresses
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
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
    }
```

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
