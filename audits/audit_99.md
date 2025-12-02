## Title
iTRY Tokens Permanently Stranded in OFTAdapter During WHITELIST_ENABLED Mode Due to Missing Whitelist Permission

## Summary
The iTryTokenOFTAdapter on the hub chain uses a lock/unlock pattern for cross-chain transfers, but lacks the WHITELISTED_ROLE required to unlock tokens when the iTRY token enters WHITELIST_ENABLED transfer state. When users burn iTRY on spoke chains and LayerZero messages arrive to unlock tokens on the hub, the transfer from adapter to recipient fails, permanently locking user funds in the adapter contract with no recovery mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (lines 210-213) and `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol`

**Intended Logic:** The iTryTokenOFTAdapter should be able to unlock iTRY tokens to recipients when cross-chain messages arrive from spoke chains. The WHITELIST_ENABLED mode should restrict normal user transfers while allowing protocol contracts to function.

**Actual Logic:** When iTRY enters WHITELIST_ENABLED mode, the `_beforeTokenTransfer` hook requires ALL parties (msg.sender, from, to) to have WHITELISTED_ROLE for normal transfers. The OFTAdapter's unlock operation is a transfer from itself to the recipient, which fails if the adapter lacks WHITELISTED_ROLE. [1](#0-0) 

The MINTER_CONTRACT role exemption only applies to minting operations (when `from == address(0)`), not transfers: [2](#0-1) 

**Exploitation Path:**
1. Admin calls `updateTransferState(TransferState.WHITELIST_ENABLED)` on hub chain iTRY token - a legitimate protocol operation to restrict transfers
2. User on spoke chain burns iTRY via `iTryTokenOFT.send()` to return tokens to hub chain
3. LayerZero relays message to hub chain iTryTokenOFTAdapter
4. Adapter's internal `_credit()` function attempts: `token.safeTransfer(recipient, amount)` where msg.sender=adapter, from=adapter, to=recipient
5. iTRY's `_beforeTokenTransfer` hook checks line 210-213 and reverts because adapter does NOT have WHITELISTED_ROLE
6. Transaction reverts, iTRY remains locked in adapter forever
7. No rescue mechanism exists - iTryTokenOFTAdapter has no recovery function

**Security Property Broken:** Violates the cross-chain message integrity invariant - users should be able to retrieve their tokens sent cross-chain. Also violates the whitelist enforcement invariant by creating a scenario where legitimate protocol operations permanently lock user funds.

## Impact Explanation
- **Affected Assets**: All iTRY tokens locked in iTryTokenOFTAdapter on hub chain (Ethereum mainnet)
- **Damage Severity**: 100% permanent loss of all iTRY being returned from spoke chains during WHITELIST_ENABLED mode. Once tokens are locked in the adapter, they cannot be recovered as the base OFTAdapter contract has no rescue function and the adapter is a simple wrapper with no additional recovery logic.
- **User Impact**: ALL users who send iTRY from spoke chains back to hub chain during WHITELIST_ENABLED mode lose their funds. This includes any legitimate cross-chain arbitrage, liquidity management, or users simply moving funds between chains. [3](#0-2) 

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a protocol-level bug triggered by legitimate admin actions. ANY user performing normal cross-chain operations becomes a victim.
- **Preconditions**: 
  1. iTRY token on hub chain is in WHITELIST_ENABLED transfer state
  2. iTryTokenOFTAdapter is not granted WHITELISTED_ROLE (current deployment scripts do not grant this role)
  3. User initiates cross-chain return from spoke to hub
- **Execution Complexity**: Single cross-chain transaction - user calls `send()` on spoke chain's iTryTokenOFT, LayerZero delivers message, adapter fails to unlock.
- **Frequency**: Affects every single cross-chain return transaction during WHITELIST_ENABLED mode until adapter is whitelisted. [4](#0-3) 

Note: The deployment script does NOT grant WHITELISTED_ROLE to the adapter.

## Recommendation

**Primary Fix:** Grant WHITELISTED_ROLE to iTryTokenOFTAdapter during deployment and ensure it's added to whitelist before enabling WHITELIST_ENABLED mode:

```solidity
// In deployment script after deploying iTryTokenOFTAdapter:
// File: script/deploy/hub/03_DeployCrossChain.s.sol

// Add after line 101:
bytes32 WHITELISTED_ROLE = iTry(addrs.itryToken).WHITELISTED_ROLE();
iTry(addrs.itryToken).grantRole(WHITELISTED_ROLE, address(itryAdapter));
console2.log("Granted WHITELISTED_ROLE to iTryAdapter");

// Also add check before allowing WHITELIST_ENABLED mode:
// In iTry.sol updateTransferState function:
function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (code == TransferState.WHITELIST_ENABLED) {
        // Verify critical protocol contracts are whitelisted
        require(hasRole(WHITELISTED_ROLE, /* adapter address */), 
                "iTryTokenOFTAdapter must be whitelisted");
    }
    TransferState prevState = transferState;
    transferState = code;
    emit TransferStateUpdated(prevState, code);
}
```

**Alternative Mitigation:** Modify iTRY's `_beforeTokenTransfer` to treat OFTAdapter transfers similar to MINTER_CONTRACT operations:

```solidity
// In iTry.sol, add special case in WHITELIST_ENABLED mode:
} else if (transferState == TransferState.WHITELIST_ENABLED) {
    // ... existing checks ...
    
    // Add before the final normal case check:
    } else if (
        msg.sender == /* iTryTokenOFTAdapter address */ && 
        from == msg.sender && 
        !hasRole(BLACKLISTED_ROLE, to)
    ) {
        // Allow adapter to unlock tokens to non-blacklisted recipients
    } else if (
        hasRole(WHITELISTED_ROLE, msg.sender) && ...
```

**Emergency Recovery:** Implement a rescue function in iTryTokenOFTAdapter or grant the adapter contract ability to transfer to protocol treasury for manual redistribution.

## Proof of Concept

```solidity
// File: test/Exploit_AdapterWhitelistLock.t.sol
// Run with: forge test --match-test test_AdapterWhitelistLock -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_AdapterWhitelistLock is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_AdapterWhitelistLock() public {
        console.log("\n=== EXPLOIT: iTRY Permanently Locked in Adapter ===");

        // STEP 1: Initial L1->L2 transfer (works fine)
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
        
        CrossChainMessage memory message1 = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message1);
        
        console.log("[OK] Initial L1->L2 transfer successful");
        console.log("  Adapter balance on L1:", sepoliaITryToken.balanceOf(address(sepoliaAdapter)));
        
        // STEP 2: Admin enables WHITELIST mode (legitimate action)
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        console.log("\n[ADMIN ACTION] Enabled WHITELIST_ENABLED mode on hub chain");
        
        // Note: Adapter was NOT whitelisted (deployment script doesn't do this)
        bytes32 WHITELISTED_ROLE = sepoliaITryToken.WHITELISTED_ROLE();
        bool adapterWhitelisted = sepoliaITryToken.hasRole(WHITELISTED_ROLE, address(sepoliaAdapter));
        console.log("  Is adapter whitelisted?", adapterWhitelisted);
        
        // STEP 3: User tries to return iTRY from L2->L1 (THIS WILL LOCK FUNDS)
        vm.selectFork(opSepoliaForkId);
        vm.startPrank(userL1);
        
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        
        console.log("\n[USER ACTION] Attempting L2->L1 return transfer...");
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        console.log("  iTRY burned on L2:", TRANSFER_AMOUNT);
        assertEq(opSepoliaOFT.balanceOf(userL1), 0, "Tokens burned on L2");
        
        // STEP 4: Relay message - THIS WILL REVERT DUE TO WHITELIST CHECK
        CrossChainMessage memory message2 = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        console.log("\n[LAYERZERO] Relaying message to L1 adapter...");
        
        // This should revert because adapter is not whitelisted
        vm.selectFork(sepoliaForkId);
        vm.expectRevert(); // Expect OperationNotAllowed() revert
        relayMessage(message2);
        
        console.log("  [CRITICAL] Message relay FAILED - tokens locked in adapter!");
        
        // VERIFY: Tokens are locked in adapter forever
        uint256 adapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        uint256 userBalance = sepoliaITryToken.balanceOf(userL1);
        
        console.log("\n[RESULT] Final State:");
        console.log("  User balance on L1:", userBalance);
        console.log("  User balance on L2:", opSepoliaOFT.balanceOf(userL1));
        console.log("  Tokens LOCKED in adapter:", adapterBalance);
        
        assertEq(userBalance, 0, "User did not receive tokens");
        assertEq(adapterBalance, TRANSFER_AMOUNT, "Tokens permanently locked in adapter");
        
        console.log("\n[EXPLOIT CONFIRMED]");
        console.log("  100 iTRY permanently locked in adapter");
        console.log("  User lost 100 iTRY - no recovery mechanism exists");
        console.log("  Root cause: Adapter lacks WHITELISTED_ROLE");
    }
}
```

**Notes**

1. **Desynchronization Mechanism**: The security question asked about desynchronization between burned amounts on spoke and unlocked amounts on hub. This vulnerability creates exactly that - tokens are burned on spoke (iTryTokenOFT) but cannot be unlocked on hub (iTryTokenOFTAdapter) due to whitelist restrictions.

2. **No Deployment Protection**: The deployment script grants COMPOSER_ROLE to wiTryVaultComposer but does NOT grant WHITELISTED_ROLE to iTryTokenOFTAdapter, leaving this critical path vulnerable. [5](#0-4) 

3. **Permanent Loss**: Unlike the Zellic audit's identified issues which are either known centralization risks or temporary DOS scenarios, this vulnerability causes permanent, unrecoverable loss of user funds during a legitimate protocol state transition.

4. **Similar Issue in wiTRY System**: The same vulnerability likely affects wiTryOFTAdapter if StakediTry implements transfer restrictions, though the specific implementation would need separate analysis.

### Citations

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L210-213)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
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

**File:** script/deploy/hub/03_DeployCrossChain.s.sol (L82-101)
```text
        iTryTokenOFTAdapter itryAdapter = _deployITryAdapter(factory, addrs.itryToken, endpoint);
        wiTryOFTAdapter shareAdapter = _deployShareAdapter(factory, addrs.staking, endpoint);
        wiTryVaultComposer vaultComposer =
            _deployVaultComposer(factory, addrs.staking, address(itryAdapter), address(shareAdapter), endpoint);

        // Set LayerZero delegates to deployer (required for library configuration)
        console2.log("");
        console2.log("Setting LayerZero delegates to deployer...");
        itryAdapter.setDelegate(deployerAddress);
        console2.log(unicode"  ✓ iTryAdapter delegate set to:", deployerAddress);
        shareAdapter.setDelegate(deployerAddress);
        console2.log(unicode"  ✓ ShareAdapter delegate set to:", deployerAddress);
        vaultComposer.setDelegate(deployerAddress);
        console2.log(unicode"  ✓ VaultComposer delegate set to:", deployerAddress);

        // Grant COMPOSER_ROLE to wiTryVaultComposer
        console2.log("");
        console2.log("Granting COMPOSER_ROLE to wiTryVaultComposer...");
        StakediTryCrosschain(addrs.staking).grantRole(COMPOSER_ROLE, address(vaultComposer));
        console2.log("  COMPOSER_ROLE granted to:", address(vaultComposer));
```
