## Title
Adapter Blacklisting Enables redistributeLockedAmount to Drain Bridge Funds, Permanently Locking Users' Cross-Chain Tokens

## Summary
The iTryTokenOFTAdapter can be blacklisted by the BLACKLIST_MANAGER_ROLE, allowing the admin to call `redistributeLockedAmount` on the adapter, burning all locked iTRY tokens held for cross-chain users. This breaks the bridge's unlock mechanism, permanently locking users' tokens on L2 with no path to recover them on L1.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` - `addBlacklistAddress` function (lines 73-78), `redistributeLockedAmount` function (lines 112-121), and `_beforeTokenTransfer` function (lines 177-196)

**Intended Logic:** 
The iTryTokenOFTAdapter locks iTRY tokens when users bridge from L1 to L2, holding them in custody until users bridge back. [1](#0-0) 

The `redistributeLockedAmount` function is designed to recover funds from blacklisted user addresses by burning their balance and minting it to a recovery address. [2](#0-1) 

**Actual Logic:** 
The `addBlacklistAddress` function has no protection preventing critical infrastructure contracts like the iTryTokenOFTAdapter from being blacklisted. The code comment explicitly states "It is deemed acceptable for admin or access manager roles to be blacklisted accidentally since it does not affect operations." [3](#0-2) 

Once the adapter is blacklisted, `redistributeLockedAmount` can be called on it, burning the adapter's entire iTRY balance (which represents all locked tokens for cross-chain users) and minting it elsewhere. [4](#0-3) 

The `_beforeTokenTransfer` function explicitly allows burn and mint operations when the admin calls `redistributeLockedAmount` on a blacklisted address. [5](#0-4) 

**Exploitation Path:**
1. User A bridges 1,000 iTRY from L1 (Ethereum) to L2 (MegaETH) via the iTryTokenOFTAdapter
2. The adapter locks 1,000 iTRY on L1 and LayerZero mints 1,000 iTRY on L2
3. BLACKLIST_MANAGER_ROLE accidentally blacklists the iTryTokenOFTAdapter address (the protocol accepts this can happen per the code comment)
4. Admin calls `redistributeLockedAmount(adapterAddress, recoveryAddress)` thinking they are recovering "locked" funds from a problematic address
5. The function burns 1,000 iTRY from the adapter and mints it to the recovery address, leaving the adapter with 0 balance
6. User A attempts to bridge 1,000 iTRY back from L2 to L1
7. LayerZero burns 1,000 iTRY on L2 and sends a message to L1
8. The adapter attempts to transfer 1,000 iTRY to User A but reverts due to insufficient balance (ERC20 transfer failure)
9. User A's tokens are permanently lost - burned on L2, unable to be unlocked on L1

**Security Property Broken:** 
Violates the cross-chain message integrity invariant: "LayerZero messages for unstaking must be delivered to correct user with proper validation." The adapter can no longer deliver tokens back to users because its balance has been drained.

## Impact Explanation
- **Affected Assets**: All iTRY tokens locked in the iTryTokenOFTAdapter for users who have bridged to L2
- **Damage Severity**: Total and permanent loss of all bridged funds. If 100,000 iTRY is locked in the adapter across all L2 users, all 100,000 iTRY becomes unrecoverable when `redistributeLockedAmount` is called on the adapter
- **User Impact**: Every user who has bridged iTRY to L2 loses their entire bridged amount with no recovery mechanism. The bridge becomes permanently broken for all historical and future transactions until the adapter is re-funded and removed from the blacklist

## Likelihood Explanation
- **Attacker Profile**: Not an attacker scenario - this is an operational risk from accidental blacklisting combined with standard admin procedures
- **Preconditions**: 
  - Users have bridged iTRY to L2 (normal protocol operation)
  - Adapter is accidentally added to blacklist (protocol explicitly accepts this can happen)
  - Admin attempts to "recover" funds from the blacklisted adapter address using `redistributeLockedAmount`
- **Execution Complexity**: Two separate trusted role actions that can occur independently without malicious intent
- **Frequency**: One-time event with catastrophic impact - once the adapter balance is drained, all historical and future bridge operations fail

## Recommendation

Add explicit protection in `addBlacklistAddress` to prevent critical infrastructure contracts from being blacklisted:

```solidity
// In src/token/iTRY/iTry.sol, function addBlacklistAddress, lines 73-78:

// CURRENT (vulnerable):
function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    for (uint8 i = 0; i < users.length; i++) {
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
    }
}

// FIXED:
// Add a mapping to track protected addresses
mapping(address => bool) public protectedAddresses;

function setProtectedAddress(address addr, bool isProtected) external onlyRole(DEFAULT_ADMIN_ROLE) {
    protectedAddresses[addr] = isProtected;
}

function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    for (uint8 i = 0; i < users.length; i++) {
        // Prevent blacklisting of protected infrastructure contracts
        require(!protectedAddresses[users[i]], "Cannot blacklist protected address");
        
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
    }
}
```

Alternative mitigation: Add a check in `redistributeLockedAmount` to prevent it from being called on addresses with significant balances that could indicate critical infrastructure:

```solidity
function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
    if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
        uint256 amountToDistribute = balanceOf(from);
        
        // Require explicit confirmation for large balances that might indicate infrastructure
        require(amountToDistribute < INFRASTRUCTURE_THRESHOLD || confirmedRedistributions[from], 
                "Large balance requires explicit confirmation");
        
        _burn(from, amountToDistribute);
        _mint(to, amountToDistribute);
        emit LockedAmountRedistributed(from, to, amountToDistribute);
    } else {
        revert OperationNotAllowed();
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_AdapterBlacklistDrain.t.sol
// Run with: forge test --match-test test_AdapterBlacklistDrain -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_AdapterBlacklistDrain is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant BRIDGE_AMOUNT = 1000 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_AdapterBlacklistDrain() public {
        console.log("\n=== PoC: Adapter Blacklist Enables Balance Drain ===");

        // SETUP: User bridges iTRY from L1 to L2
        vm.selectFork(sepoliaForkId);
        
        // Mint iTRY to user
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, BRIDGE_AMOUNT);
        
        // User bridges to L2
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
        
        uint256 adapterBalanceAfterBridge = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        console.log("Adapter balance after bridge:", adapterBalanceAfterBridge);
        assertEq(adapterBalanceAfterBridge, BRIDGE_AMOUNT, "Adapter should hold locked iTRY");
        
        // Relay message to L2
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        vm.selectFork(opSepoliaForkId);
        uint256 userBalanceL2 = opSepoliaOFT.balanceOf(userL1);
        console.log("User L2 balance:", userBalanceL2);
        assertEq(userBalanceL2, BRIDGE_AMOUNT, "User should have iTRY on L2");
        
        // EXPLOIT: Adapter accidentally gets blacklisted
        vm.selectFork(sepoliaForkId);
        console.log("\n--- Adapter accidentally blacklisted ---");
        
        // Grant BLACKLIST_MANAGER_ROLE to deployer for testing
        bytes32 BLACKLIST_MANAGER_ROLE = sepoliaITryToken.BLACKLIST_MANAGER_ROLE();
        vm.prank(deployer);
        sepoliaITryToken.grantRole(BLACKLIST_MANAGER_ROLE, deployer);
        
        // Blacklist the adapter (accidental)
        address[] memory toBlacklist = new address[](1);
        toBlacklist[0] = address(sepoliaAdapter);
        vm.prank(deployer);
        sepoliaITryToken.addBlacklistAddress(toBlacklist);
        
        console.log("Adapter blacklisted successfully");
        
        // Admin calls redistributeLockedAmount thinking they're recovering funds
        address recoveryAddress = makeAddr("recovery");
        vm.prank(deployer);
        sepoliaITryToken.redistributeLockedAmount(address(sepoliaAdapter), recoveryAddress);
        
        uint256 adapterBalanceAfterRedistribute = sepoliaITryToken.balanceOf(address(sepoliaAdapter));
        uint256 recoveryBalance = sepoliaITryToken.balanceOf(recoveryAddress);
        
        console.log("Adapter balance after redistribute:", adapterBalanceAfterRedistribute);
        console.log("Recovery address balance:", recoveryBalance);
        
        assertEq(adapterBalanceAfterRedistribute, 0, "Adapter balance drained");
        assertEq(recoveryBalance, BRIDGE_AMOUNT, "Funds moved to recovery");
        
        // VERIFY: User cannot bridge back from L2 to L1
        console.log("\n--- User attempts to bridge back ---");
        vm.selectFork(opSepoliaForkId);
        
        vm.startPrank(userL1);
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // Tokens burned on L2
        uint256 userBalanceL2After = opSepoliaOFT.balanceOf(userL1);
        assertEq(userBalanceL2After, 0, "Tokens burned on L2");
        
        // Try to relay message back to L1 - this will FAIL
        message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        vm.selectFork(sepoliaForkId);
        
        // This should revert because adapter has insufficient balance
        vm.expectRevert();
        relayMessage(message);
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("- User's tokens burned on L2");
        console.log("- Adapter cannot unlock tokens on L1 (insufficient balance)");
        console.log("- User's funds permanently lost");
    }
}
```

## Notes

This vulnerability demonstrates a critical failure mode in the cross-chain bridge architecture. While the protocol's comment states that blacklisting admin or access manager roles is "acceptable" and doesn't affect operations, this is only true for regular admin addresses. The iTryTokenOFTAdapter is critical infrastructure that holds custody of all users' bridged funds, and its blacklisting has catastrophic consequences.

The LayerZero OFT adapter pattern relies on the adapter's token balance to service unlock requests from L2. The adapter has no explicit per-user accounting - it simply holds a pool of tokens equal to the sum of all locked amounts across all spoke chains. When `redistributeLockedAmount` burns this balance, the adapter becomes insolvent and cannot fulfill its obligations to users.

This is not a theoretical concern - operational mistakes like accidentally blacklisting the wrong address can happen in production systems, especially when managing large blacklists. The lack of safeguards makes this a realistic scenario that would result in total loss of user funds with no recovery mechanism.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L1-28)
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
```

**File:** src/token/iTRY/iTry.sol (L69-78)
```text
    /**
     * @param users List of address to be blacklisted
     * @notice It is deemed acceptable for admin or access manager roles to be blacklisted accidentally since it does not affect operations.
     */
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L107-121)
```text
    /**
     * @dev Burns the blacklisted user iTry and mints to the desired owner address.
     * @param from The address to burn the entire balance, with the BLACKLISTED_ROLE
     * @param to The address to mint the entire balance of "from" parameter.
     */
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L184-188)
```text
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
```
