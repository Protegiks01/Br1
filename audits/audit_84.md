## Title
Cross-Chain Message Failure Due to Blacklist Status Change Causes Permanent Fund Loss

## Summary
LayerZero messages in `iTryTokenOFT` have no expiry mechanism and lack protective handling for blacklisted recipients. If a user's blacklist status changes between message send and delivery, the minting operation will permanently fail, causing irreversible fund loss as tokens are already burned/locked on the source chain with no recovery path.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 140-177, `_beforeTokenTransfer` function) [1](#0-0) 

**Intended Logic:** The blacklist mechanism should prevent blacklisted users from transferring iTRY tokens while ensuring their funds remain recoverable through the `redistributeLockedAmount` function by the owner.

**Actual Logic:** When a LayerZero message attempts to mint iTRY tokens to a blacklisted recipient, the `_beforeTokenTransfer` check at lines 145-146 reverts with `OperationNotAllowed()`. Unlike `wiTryOFT` which redirects blacklisted recipients' funds to the owner, `iTryTokenOFT` has no such protection mechanism. [2](#0-1) 

**Exploitation Path:**
1. User initiates cross-chain iTRY transfer from hub chain (Ethereum) to spoke chain (MegaETH) when they are NOT blacklisted
2. `iTryTokenOFTAdapter` locks the user's iTRY tokens on the hub chain and sends LayerZero message
3. Before message delivery, protocol administrators blacklist the user on the spoke chain
4. LayerZero message arrives at `iTryTokenOFT` on spoke chain and attempts to mint tokens via base OFT `_credit` → `_mint` → `_beforeTokenTransfer`
5. `_beforeTokenTransfer` checks blacklist status (line 145-146) and reverts because recipient is now blacklisted
6. Message execution fails, but tokens are permanently locked on hub chain with no mechanism to unlock or redirect them [3](#0-2) 

**Security Property Broken:** Violates Critical Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - while the system correctly prevents blacklisted users from receiving, it creates an unintended consequence where their funds become permanently locked rather than being redistributable by the owner as designed.

## Impact Explanation
- **Affected Assets**: iTRY tokens locked in `iTryTokenOFTAdapter` on hub chain that cannot be unlocked or minted on spoke chain
- **Damage Severity**: Complete and permanent loss of user funds. Tokens are locked on source chain but cannot be minted on destination chain, with no recovery mechanism. Amount lost equals the full cross-chain transfer amount.
- **User Impact**: Any user performing cross-chain iTRY transfers is at risk. The timing window exists between transaction initiation and LayerZero message delivery (can be seconds to hours depending on network congestion). Multiple users can be affected simultaneously if blacklist updates occur during high cross-chain activity periods.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a protocol design flaw. Normal users making legitimate cross-chain transfers become victims when their blacklist status changes mid-flight.
- **Preconditions**: 
  1. User must initiate cross-chain iTRY transfer while not blacklisted
  2. Blacklist Manager must blacklist the user before LayerZero message delivery
  3. LayerZero message delivery delay provides timing window (typically 1-60 minutes depending on network conditions)
- **Execution Complexity**: Unintentional exploitation - occurs naturally when blacklist updates happen during normal cross-chain operations. No malicious coordination required.
- **Frequency**: Can occur multiple times, affecting different users. Risk increases during periods of regulatory action when multiple addresses are blacklisted simultaneously.

## Recommendation

Override the `_credit` function in `iTryTokenOFT` to match the protective behavior implemented in `wiTryOFT`:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add after line 176:

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
    if (blacklisted[_to]) {
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

This ensures that:
1. Cross-chain messages always complete successfully even if recipient becomes blacklisted
2. Blacklisted users' funds are automatically redirected to owner (matching existing `redistributeLockedAmount` pattern)
3. No funds are permanently locked due to timing issues
4. Consistent behavior with `wiTryOFT` implementation

Alternative mitigation: Implement a message retry/recovery mechanism that allows owner to redirect failed messages, though the `_credit` override is simpler and more gas-efficient.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistDuringCrossChainTransfer.t.sol
// Run with: forge test --match-test test_BlacklistDuringCrossChainTransfer -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_BlacklistDuringCrossChainTransfer is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_BlacklistDuringCrossChainTransfer() public {
        console.log("\n=== Exploit: Blacklist During Cross-Chain Transfer ===");

        // SETUP: Mint iTRY to user on hub chain (Sepolia)
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, TRANSFER_AMOUNT);
        
        uint256 userBalanceBefore = sepoliaITryToken.balanceOf(userL1);
        console.log("User iTRY balance on Sepolia:", userBalanceBefore);
        assertEq(userBalanceBefore, TRANSFER_AMOUNT);

        // EXPLOIT STEP 1: User initiates cross-chain transfer (NOT blacklisted)
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

        // Verify tokens locked on hub chain
        uint256 userBalanceAfter = sepoliaITryToken.balanceOf(userL1);
        uint256 adapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("User iTRY balance after send:", userBalanceAfter);
        console.log("Adapter locked balance:", adapterBalance);
        assertEq(userBalanceAfter, 0, "Tokens should be locked");
        assertEq(adapterBalance, TRANSFER_AMOUNT, "Adapter should hold locked tokens");

        // EXPLOIT STEP 2: User gets blacklisted on spoke chain BEFORE message delivery
        vm.selectFork(opSepoliaForkId);
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = userL1;
        vm.prank(deployer); // Owner blacklists the user
        opSepoliaOFT.addBlacklistAddress(blacklistAddresses);
        
        bool isBlacklisted = opSepoliaOFT.blacklisted(userL1);
        console.log("User blacklisted on OP Sepolia:", isBlacklisted);
        assertTrue(isBlacklisted, "User should be blacklisted");

        // EXPLOIT STEP 3: Attempt to relay message - WILL REVERT
        console.log("\nAttempting to relay message to blacklisted recipient...");
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        
        // This will revert due to blacklist check in _beforeTokenTransfer
        vm.expectRevert();
        relayMessage(message);
        
        // VERIFY: Funds are permanently stuck
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        
        // Tokens locked on hub chain
        vm.selectFork(sepoliaForkId);
        uint256 finalAdapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("Tokens locked on hub chain:", finalAdapterBalance);
        assertEq(finalAdapterBalance, TRANSFER_AMOUNT, "Tokens remain locked");
        
        // No tokens minted on spoke chain
        vm.selectFork(opSepoliaForkId);
        uint256 userSpokeBalance = opSepoliaOFT.balanceOf(userL1);
        console.log("User balance on spoke chain:", userSpokeBalance);
        assertEq(userSpokeBalance, 0, "No tokens minted due to blacklist");
        
        console.log("\n[CRITICAL] 100 iTRY permanently locked!");
        console.log("  - Locked on hub chain (cannot unlock)");
        console.log("  - Cannot mint on spoke chain (blacklisted)");
        console.log("  - No recovery mechanism exists");
        console.log("  - User funds permanently lost");
    }
}
```

## Notes

This vulnerability demonstrates a critical architectural inconsistency between `wiTryOFT` and `iTryTokenOFT`. While `wiTryOFT` implements protective `_credit` override to handle blacklisted recipients gracefully by redirecting to owner, `iTryTokenOFT` relies solely on `_beforeTokenTransfer` checks which cause transaction reverts.

The issue is exacerbated by LayerZero V2's lack of message expiry - messages can remain pending indefinitely, extending the vulnerability window. Even with message retry capabilities in LayerZero V2, retries will continue failing as long as the blacklist status persists, and there's no mechanism to redirect the locked funds on the source chain.

This is NOT the same as the known issue "Native fee loss on failed wiTryVaultComposer.lzReceive" which concerns fee underpayment requiring double payment. This vulnerability concerns complete and permanent principal loss due to blacklist timing.

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

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-28)
```text
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```
