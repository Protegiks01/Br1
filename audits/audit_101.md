## Title
Blacklisted Users' iTRY Permanently Locked in Cross-Chain Adapter During Bridge Return

## Summary
The `iTryTokenOFTAdapter` contract lacks blacklist handling in its unlock mechanism. When a user bridges iTRY from hub (Ethereum) to spoke (MegaETH) and becomes blacklisted before bridging back, the adapter's unlock operation will permanently fail because the iTRY token's transfer restrictions prevent sending to blacklisted addresses. The adapter has no recovery mechanism, resulting in permanent fund loss.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` and `src/token/iTRY/iTry.sol`

**Intended Logic:** The iTryTokenOFTAdapter should enable seamless cross-chain transfers of iTRY tokens via LayerZero's OFT standard. Users bridge iTRY to spoke chains (tokens locked in adapter), and can bridge back to receive their original iTRY tokens (tokens unlocked from adapter).

**Actual Logic:** The adapter inherits from LayerZero's `OFTAdapter` without overriding the `_credit` function. [1](#0-0)  When LayerZero delivers a return message from spoke to hub, the base `OFTAdapter._credit` implementation attempts to transfer tokens from the adapter to the recipient. However, iTRY's `_beforeTokenTransfer` hook enforces blacklist restrictions on the `to` address. [2](#0-1)  If the recipient is blacklisted (line 191: `!hasRole(BLACKLISTED_ROLE, to)`), the transfer reverts with `OperationNotAllowed()`, permanently locking funds in the adapter.

**Exploitation Path:**
1. **User initiates hub→spoke bridge**: User calls `iTryTokenOFTAdapter.send()` on Ethereum, transferring 1000 iTRY. The adapter locks these tokens using `transferFrom`. [3](#0-2) 
2. **LayerZero delivers message**: `iTryTokenOFT` on MegaETH receives the message and mints 1000 iTRY to the user on the spoke chain. [4](#0-3) 
3. **User gets blacklisted**: Before bridging back, the Blacklist Manager adds the user to the blacklist on Ethereum hub chain. [5](#0-4) 
4. **User attempts spoke→hub bridge**: User calls `iTryTokenOFT.send()` on MegaETH to bridge back. Tokens are burned on spoke chain. [6](#0-5) 
5. **Unlock fails on hub chain**: When `iTryTokenOFTAdapter.lzReceive()` executes, the internal `_credit` function attempts `iTRY.transfer(blacklistedUser, 1000)`, triggering `_beforeTokenTransfer(adapter, blacklistedUser, 1000)`. The check at line 191 fails because the user has `BLACKLISTED_ROLE`, causing the transaction to revert.
6. **Funds permanently locked**: The 1000 iTRY remains locked in the adapter with no recovery mechanism. The adapter has no `redistributeLockedAmount` or `rescueTokens` function to handle this case.

**Security Property Broken:** Violates Critical Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." While the invariant is technically enforced (blacklisted user cannot receive), the consequence is permanent fund loss rather than clean rejection, which is worse than the intended behavior.

## Impact Explanation

- **Affected Assets**: All iTRY tokens locked in the `iTryTokenOFTAdapter` belonging to users who become blacklisted between outbound and inbound bridge operations.
- **Damage Severity**: 100% permanent loss of bridged iTRY for affected users. Tokens are locked in the adapter contract with no administrative recovery function. The only remediation would require removing the user from the blacklist, which defeats the purpose of blacklisting.
- **User Impact**: Any user who bridges iTRY to a spoke chain and subsequently gets blacklisted (for regulatory, compliance, or security reasons) before bridging back will lose all bridged funds permanently. This affects legitimate users who may be blacklisted due to regulatory requirements while their tokens are in transit or on spoke chains.

## Likelihood Explanation

- **Attacker Profile**: Not an attacker scenario - this affects legitimate users subjected to compliance-driven blacklisting. No malicious intent required.
- **Preconditions**: 
  1. User must have bridged iTRY from hub to spoke chain
  2. User must be added to blacklist on hub chain before attempting to bridge back
  3. Transfer state must be `FULLY_ENABLED` or `WHITELIST_ENABLED` (normal operating modes)
- **Execution Complexity**: Occurs through normal protocol operations. Requires no sophisticated exploitation - simply bridging back after being blacklisted triggers the fund lock.
- **Frequency**: Can occur for any user who gets blacklisted while having funds on spoke chains. Given that blacklisting is an expected compliance feature, this is a realistic and recurring risk.

## Recommendation

Override the `_credit` function in `iTryTokenOFTAdapter` to redirect funds to the protocol owner when the recipient is blacklisted, similar to the pattern implemented in `wiTryOFT`: [7](#0-6) 

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol:

// ADD: Import iTry interface to check blacklist status
import {iTry} from "../iTry.sol";

// ADD: Event for fund redistribution
event FundsRedirectedFromBlacklist(address indexed originalRecipient, uint256 amount);

// ADD: Override _credit to handle blacklisted recipients
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // Check if recipient is blacklisted
    iTry token = iTry(address(innerToken));
    bytes32 BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    
    if (token.hasRole(BLACKLISTED_ROLE, _to)) {
        // Redirect funds to contract owner instead of blacklisted address
        emit FundsRedirectedFromBlacklist(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative mitigation:** Implement an emergency rescue function callable by admin to manually redistribute locked funds from blacklisted users, similar to `iTry.redistributeLockedAmount`. However, the override approach is cleaner and prevents funds from getting locked in the first place.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBridgeLock.t.sol
// Run with: forge test --match-test test_BlacklistCausesPermamentLockInAdapter -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_BlacklistBridgeLock is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant BRIDGE_AMOUNT = 1000 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_BlacklistCausesPermamentLockInAdapter() public {
        // SETUP: User bridges iTRY from Ethereum (hub) to MegaETH (spoke)
        vm.selectFork(sepoliaForkId);
        
        // Mint iTRY to user on Ethereum
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, BRIDGE_AMOUNT);
        
        console.log("=== Step 1: Bridge iTRY from Ethereum to MegaETH ===");
        uint256 userBalanceBefore = sepoliaITryToken.balanceOf(userL1);
        console.log("User iTRY balance on Ethereum:", userBalanceBefore);
        
        // User bridges to MegaETH
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
        
        uint256 adapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("iTRY locked in adapter:", adapterBalance);
        assertEq(adapterBalance, BRIDGE_AMOUNT, "Adapter should have locked iTRY");
        
        // Relay message to MegaETH
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        vm.selectFork(opSepoliaForkId);
        uint256 userBalanceOnSpoke = opSepoliaOFT.balanceOf(userL1);
        console.log("User iTRY balance on MegaETH:", userBalanceOnSpoke);
        assertEq(userBalanceOnSpoke, BRIDGE_AMOUNT, "User should have iTRY on spoke");
        
        // EXPLOIT: User gets blacklisted on Ethereum while tokens are on MegaETH
        console.log("\n=== Step 2: User gets blacklisted on Ethereum ===");
        vm.selectFork(sepoliaForkId);
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = userL1;
        vm.prank(deployer);
        sepoliaITryToken.addBlacklistAddress(blacklistAddresses);
        
        bytes32 BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
        bool isBlacklisted = sepoliaITryToken.hasRole(BLACKLISTED_ROLE, userL1);
        console.log("User blacklisted:", isBlacklisted);
        assertTrue(isBlacklisted, "User should be blacklisted");
        
        // User attempts to bridge back to Ethereum
        console.log("\n=== Step 3: User attempts to bridge back (WILL FAIL) ===");
        vm.selectFork(opSepoliaForkId);
        vm.startPrank(userL1);
        
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        console.log("iTRY burned on MegaETH:", BRIDGE_AMOUNT);
        assertEq(opSepoliaOFT.balanceOf(userL1), 0, "Tokens burned on spoke");
        
        // VERIFY: Attempting to relay message back to Ethereum REVERTS
        message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        console.log("\n=== Step 4: LayerZero message delivery FAILS ===");
        vm.expectRevert(); // Expect OperationNotAllowed from iTry._beforeTokenTransfer
        relayMessage(message);
        
        // VERIFY: Funds permanently locked in adapter
        vm.selectFork(sepoliaForkId);
        uint256 finalAdapterBalance = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        uint256 finalUserBalance = sepoliaITryToken.balanceOf(userL1);
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("iTRY still locked in adapter:", finalAdapterBalance);
        console.log("User iTRY balance on Ethereum:", finalUserBalance);
        console.log("User iTRY balance on MegaETH:", opSepoliaOFT.balanceOf(userL1));
        
        assertEq(finalAdapterBalance, BRIDGE_AMOUNT, "Funds permanently locked in adapter");
        assertEq(finalUserBalance, 0, "User cannot receive their funds");
        
        console.log("\n[CRITICAL] User's 1000 iTRY is permanently lost!");
        console.log("No recovery mechanism exists in iTryTokenOFTAdapter");
    }
}
```

## Notes

This vulnerability is distinct from the known Zellic issue about blacklisted users transferring via allowance on the same chain. [8](#0-7)  This finding involves cross-chain message delivery failure causing permanent fund loss, which is not mentioned in the known issues list. [9](#0-8) 

The `wiTryOFT` contract on spoke chains implements the correct pattern by overriding `_credit` to redirect tokens from blacklisted recipients to the owner, preventing fund loss. [7](#0-6)  However, `iTryTokenOFTAdapter` on the hub chain lacks this protection, creating an asymmetric risk where funds can be locked during the return journey.

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

**File:** src/token/iTRY/iTry.sol (L73-77)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
```

**File:** src/token/iTRY/iTry.sol (L177-196)
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
```

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L104-116)
```text
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();

        // Verify tokens locked on Sepolia
        uint256 userL1BalanceAfterSend = sepoliaITryToken.balanceOf(userL1);
        uint256 adapterBalanceAfterSend = sepoliaITryToken.balanceOf(address(sepoliaAdapter));

        console.log("\nAfter Send (Sepolia):");
        console.log("  userL1 balance:", userL1BalanceAfterSend);
        console.log("  adapter balance (locked):", adapterBalanceAfterSend);

        assertEq(userL1BalanceAfterSend, 0, "User should have 0 iTRY after send");
        assertEq(adapterBalanceAfterSend, adapterBalanceBefore + TRANSFER_AMOUNT, "Adapter should have locked iTRY");
```

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L133-141)
```text
        uint256 userL1BalanceOnL2 = opSepoliaOFT.balanceOf(userL1);
        uint256 totalSupplyL2 = opSepoliaOFT.totalSupply();

        console.log("\nAfter Relay (OP Sepolia):");
        console.log("  userL1 balance:", userL1BalanceOnL2);
        console.log("  Total supply:", totalSupplyL2);

        assertEq(userL1BalanceOnL2, TRANSFER_AMOUNT, "User should have 100 iTRY on L2");
        assertEq(totalSupplyL2, TRANSFER_AMOUNT, "Total supply on L2 should be 100 iTRY");
```

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L205-213)
```text
        uint256 userL1BalanceAfterSendL2 = opSepoliaOFT.balanceOf(userL1);
        uint256 totalSupplyAfterSendL2 = opSepoliaOFT.totalSupply();

        console.log("\nAfter Send (OP Sepolia):");
        console.log("  userL1 balance:", userL1BalanceAfterSendL2);
        console.log("  Total supply:", totalSupplyAfterSendL2);

        assertEq(userL1BalanceAfterSendL2, 0, "User should have 0 iTRY on L2 after send");
        assertEq(totalSupplyAfterSendL2, 0, "Total supply on L2 should be 0 (burned)");
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

**File:** README.md (L23-42)
```markdown
## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

### Centralization Risks

Any centralization risks are out-of-scope for the purposes of this audit contest.

### Zellic Audit Report Issues

The codebase has undergone a Zellic audit with a fix review pending. The following issues identified in the Zellic audit are considered out-of-scope, with some being fixed in the current iteration of the codebase:

-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
- Griefing attacks around the `MIN_SHARES` variable of the ERC2646 vault: The protocol will perform an initial deposit to offset this risk. 
- The `redistributeLockedAmount` does not validate that the resulted `totalSupply` is not less than the minimum threshold. As a result of executing the `redistributeLockedAmount` function, the `totalSupply` amount may fall within a prohibited range between 0 and `MIN_SHARES` amount. And subsequent legitimate
deposits or withdrawals operations, which do not increase totalSupply to the `MIN_SHARES` value will be blocked.
- iTRY backing can fall below 1:1 on NAV drop. If NAV drops below 1, iTRY becomes undercollateralized with no guaranteed, on-chain remediation. Holders bear insolvency risk until a top-up or discretionary admin intervention occurs.
- Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request.
- Non-standard ERC20 tokens may break the transfer function. If a non-standard token is recovered using a raw transfer, the function may appear to succeed, even though no tokens were transferred, or it may revert unexpectedly. This can result in tokens becoming stuck in the contract, which breaks the tokens rescue mechanism.

```
