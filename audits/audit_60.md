## Title
Cross-Chain Blacklist Desynchronization Causes Permanent Fund Loss in iTRY OFT Transfers

## Summary
The `iTryTokenOFT` contract stores blacklist state per-chain with no synchronization mechanism across chains. [1](#0-0)  Unlike `wiTryOFT` which overrides `_credit` to handle blacklisted recipients, [2](#0-1)  `iTryTokenOFT` lacks this protection. When a user blacklisted on the destination chain (but not source) attempts a cross-chain transfer, tokens are permanently burned on the source chain while the destination transfer reverts, resulting in irreversible fund loss.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 36, 140-177) and `src/token/iTRY/iTry.sol` (lines 177-222)

**Intended Logic:** The blacklist mechanism should prevent blacklisted users from sending/receiving/minting/burning iTRY tokens in ANY case (Invariant #2). Cross-chain transfers via LayerZero OFT should maintain token conservation - tokens burned on source chain should always be successfully minted/unlocked on destination chain.

**Actual Logic:** Blacklist state is stored independently on each chain with no cross-chain synchronization. The source chain checks its local blacklist before burning tokens, [3](#0-2)  while the destination chain checks its local blacklist before unlocking/minting. [4](#0-3)  When these states differ, the burn succeeds but the mint/unlock fails, permanently destroying user funds.

**Exploitation Path:**
1. User has 100 iTRY on MegaETH spoke chain (obtained before being blacklisted elsewhere)
2. User is NOT blacklisted on MegaETH (`iTryTokenOFT.blacklisted[user] = false`)
3. User IS blacklisted on Ethereum Hub (`iTry` contract has `BLACKLISTED_ROLE` for user)
4. User calls `iTryTokenOFT.send()` on MegaETH to bridge 100 iTRY back to Ethereum
5. **Source chain burn phase**: `_beforeTokenTransfer` checks pass because user is NOT blacklisted on MegaETH - 100 iTRY burned successfully
6. LayerZero message sent cross-chain with recipient = user address
7. **Destination chain unlock phase**: `iTryTokenOFTAdapter` on Ethereum receives message and attempts to unlock iTRY by calling `transfer(user, 100)` on the `iTry` token contract
8. `iTry._beforeTokenTransfer` is triggered and checks `hasRole(BLACKLISTED_ROLE, to)` where `to` is the user address
9. Since user IS blacklisted on Ethereum Hub, the check at line 190-191 fails and reverts with `OperationNotAllowed`
10. `lzReceive` reverts, message stored as failed by LayerZero
11. **Result**: 100 iTRY permanently burned on MegaETH, never unlocked on Ethereum - user loses 100 iTRY forever

**Security Property Broken:** Violates Invariant #2 (Blacklist Enforcement) - the desynchronized blacklist allows partial execution of cross-chain transfers, causing permanent fund loss. Also violates basic token conservation - tokens can be destroyed without equivalent tokens being created elsewhere.

## Impact Explanation

- **Affected Assets**: iTRY tokens held by users on spoke chains (e.g., MegaETH) where they are not blacklisted, but are blacklisted on the hub chain (Ethereum) or other spoke chains
- **Damage Severity**: 100% permanent loss of tokens involved in the failed cross-chain transfer. Tokens are irreversibly burned on source chain with no recovery mechanism since retrying the LayerZero message will continue to fail while the blacklist remains active
- **User Impact**: Any user who:
  - Holds iTRY on a chain where they are not blacklisted
  - Gets blacklisted on another chain (without blacklist being synchronized)
  - Attempts to bridge their tokens to the chain where they are blacklisted
  - Loses all tokens sent in that transaction permanently

## Likelihood Explanation

- **Attacker Profile**: Not an intentional attack - this is a design flaw affecting legitimate users caught in a blacklist desynchronization scenario. Can affect any iTRY holder who becomes blacklisted on one chain but not others
- **Preconditions**: 
  - User must have iTRY tokens on a spoke chain (e.g., MegaETH)
  - User must NOT be blacklisted on that spoke chain
  - User must BE blacklisted on the destination chain (Hub or another spoke)
  - No synchronization mechanism exists to propagate blacklist changes across chains
- **Execution Complexity**: Single cross-chain transaction - user simply calls `send()` on the OFT contract with normal parameters
- **Frequency**: Occurs every time a user in this state attempts a cross-chain transfer to a chain where they are blacklisted. Given that blacklisting is likely done for regulatory/compliance reasons and may happen retroactively, this scenario has high likelihood of occurring in production

## Recommendation

Implement a `_credit` override in `iTryTokenOFT` similar to the protection already present in `wiTryOFT`:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add after line 138:

/**
 * @dev Override _credit to handle blacklisted recipients gracefully
 * @param _to The intended recipient address
 * @param _amountLD The amount to credit
 * @param _srcEid The source endpoint ID
 * @return amountReceivedLD The actual amount credited
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // If recipient is blacklisted on this chain, redirect funds to owner
    // rather than reverting and causing permanent loss on source chain
    if (blacklisted[_to]) {
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative Mitigations:**
1. **Cross-chain blacklist synchronization**: Implement a mechanism to automatically propagate blacklist changes across all chains via LayerZero messages (complex but prevents the root cause)
2. **Pre-flight blacklist check**: Add a view function on the OFT contract that checks destination blacklist status via LayerZero before initiating transfer (gas-intensive but prevents user error)
3. **Blacklist coordinator contract**: Deploy a shared blacklist registry contract accessible across all chains (requires bridge oracles or cross-chain reads)

The `_credit` override is the most practical immediate fix as it matches the existing pattern in `wiTryOFT` and prevents permanent fund loss while maintaining security (blacklisted users still cannot access their funds directly - they are redistributed to the protocol owner for proper handling).

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistFundLoss.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistPermanentLoss -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_CrossChainBlacklistFundLoss is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_CrossChainBlacklistPermanentLoss() public {
        console.log("\n=== Exploit: Cross-Chain Blacklist Desync Fund Loss ===");
        
        // SETUP: User has iTRY on L2 (MegaETH/OP Sepolia)
        // First transfer iTRY from L1 to L2
        vm.selectFork(sepoliaForkId);
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
        
        // Verify user has 100 iTRY on L2
        vm.selectFork(opSepoliaForkId);
        uint256 userBalanceL2 = opSepoliaOFT.balanceOf(userL1);
        console.log("User balance on L2:", userBalanceL2);
        assertEq(userBalanceL2, TRANSFER_AMOUNT, "User should have 100 iTRY on L2");
        
        // EXPLOIT TRIGGER: User gets blacklisted on L1 but NOT on L2
        // This represents a real scenario where blacklist is not synchronized
        vm.selectFork(sepoliaForkId);
        address[] memory usersToBlacklist = new address[](1);
        usersToBlacklist[0] = userL1;
        vm.prank(deployer); // deployer is admin
        sepoliaITryToken.addBlacklistAddress(usersToBlacklist);
        console.log("User blacklisted on L1 (Hub)");
        
        // Verify L2 blacklist is NOT synchronized (design flaw)
        vm.selectFork(opSepoliaForkId);
        bool isBlacklistedL2 = opSepoliaOFT.blacklisted(userL1);
        console.log("User blacklisted on L2:", isBlacklistedL2);
        assertEq(isBlacklistedL2, false, "User should NOT be blacklisted on L2 (desynchronized)");
        
        // EXPLOIT: User tries to send iTRY from L2 back to L1
        console.log("\nUser attempting to send 100 iTRY from L2 to L1...");
        
        uint256 totalSupplyL2Before = opSepoliaOFT.totalSupply();
        console.log("Total supply L2 before send:", totalSupplyL2Before);
        
        vm.startPrank(userL1);
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // VERIFY: Tokens burned on L2
        uint256 userBalanceL2After = opSepoliaOFT.balanceOf(userL1);
        uint256 totalSupplyL2After = opSepoliaOFT.totalSupply();
        console.log("User balance L2 after send:", userBalanceL2After);
        console.log("Total supply L2 after send:", totalSupplyL2After);
        assertEq(userBalanceL2After, 0, "Tokens burned on L2");
        assertEq(totalSupplyL2After, 0, "Total supply decreased on L2");
        
        // VERIFY: Message delivery FAILS on L1 due to blacklist
        message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        vm.selectFork(sepoliaForkId);
        console.log("\nAttempting to relay message to L1...");
        
        // The message will revert because user is blacklisted on L1
        vm.expectRevert(); // OperationNotAllowed from _beforeTokenTransfer
        relayMessage(message);
        
        console.log("Message delivery FAILED on L1 due to blacklist");
        
        // VERIFY: User has lost funds permanently
        vm.selectFork(sepoliaForkId);
        uint256 userBalanceL1 = sepoliaITryToken.balanceOf(userL1);
        uint256 adapterBalanceL1 = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("User balance L1:", userBalanceL1);
        console.log("Adapter balance L1 (should have unlocked but didn't):", adapterBalanceL1);
        console.log("User balance L2:", userBalanceL2After);
        
        // User has 0 on both chains - funds permanently lost
        assertEq(userBalanceL1, 0, "User has 0 on L1");
        assertEq(userBalanceL2After, 0, "User has 0 on L2");
        assertGt(adapterBalanceL1, 0, "Tokens still locked in adapter, never unlocked");
        
        console.log("\n[EXPLOIT SUCCESS] 100 iTRY permanently lost!");
        console.log("  [BURNED] on L2: 100 iTRY");
        console.log("  [LOCKED] on L1: Cannot unlock to blacklisted user");
        console.log("  [RESULT] Permanent fund loss due to blacklist desynchronization");
    }
}
```

## Notes

The vulnerability exists because `iTryTokenOFT` lacks the protective `_credit` override that `wiTryOFT` implements. The sister contract `wiTryOFT` correctly handles this edge case by redirecting blacklisted recipients' funds to the owner, preventing permanent loss. This same pattern should be applied to `iTryTokenOFT` to ensure cross-chain token conservation is maintained even when blacklist states are desynchronized across chains.

The root cause is architectural - the protocol relies on manual, per-chain blacklist management without cross-chain synchronization, creating inevitable desynchronization risks. The recommended fix provides damage control (no permanent loss) while the protocol can develop a longer-term blacklist synchronization solution.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L36-36)
```text
    mapping(address => bool) public blacklisted;
```

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

**File:** src/token/iTRY/iTry.sol (L177-222)
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
    }
```
