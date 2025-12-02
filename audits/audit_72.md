## Title
Cross-Chain Bridge Failure Causes Permanent Token Loss When Hub Recipient is Blacklisted

## Summary
When a user bridges iTRY tokens from spoke chain (MegaETH) back to hub chain (Ethereum), if the recipient becomes blacklisted on the hub before `lzReceive` execution, the hub adapter's token unlock will revert due to blacklist enforcement in `iTry._beforeTokenTransfer`. This results in tokens being burned on the spoke chain but remaining permanently locked in the adapter on the hub chain, creating unbacked locked iTRY and causing user fund loss.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/token/iTRY/iTry.sol` (lines 177-222, specifically lines 189-195)
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` (spoke chain burn via OFT.send)
- `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` (hub chain unlock via lzReceive) [1](#0-0) 

**Intended Logic:** 
The cross-chain bridge should atomically burn tokens on spoke and unlock equivalent tokens on hub, maintaining supply conservation across chains. The LayerZero OFT architecture is designed to ensure that burned tokens on one chain result in unlocked/minted tokens on another.

**Actual Logic:** 
When `iTryTokenOFTAdapter.lzReceive()` is called on the hub, it attempts to unlock tokens by transferring them from the adapter to the recipient. This transfer goes through `iTry._beforeTokenTransfer()`, which enforces blacklist restrictions. If the recipient is blacklisted, the check at lines 189-195 fails because it requires `!hasRole(BLACKLISTED_ROLE, to)`. The entire `lzReceive` transaction reverts, but the tokens have already been burned on the spoke chain. [2](#0-1) 

**Exploitation Path:**
1. User has 1000 iTRY OFT tokens on spoke chain (MegaETH)
2. User calls `iTryTokenOFT.send(hubEid, userAddress, 1000 iTRY)` to bridge back to hub
3. On spoke: `_beforeTokenTransfer` allows the burn (lines 143-144 permit minter to burn from non-blacklisted users)
4. Tokens are burned on spoke, LayerZero message is sent to hub
5. During message delivery delay, user gets blacklisted on hub via `iTry.addBlacklistAddress()`
6. LayerZero executor calls `iTryTokenOFTAdapter.lzReceive()` on hub
7. Adapter attempts `iTry.safeTransfer(user, 1000 iTRY)` to unlock tokens
8. `iTry._beforeTokenTransfer(from=adapter, to=user, amount=1000)` is triggered
9. Line 190-191 check fails: `!hasRole(BLACKLISTED_ROLE, user)` is false
10. Transaction reverts with `OperationNotAllowed()`
11. Result: 1000 iTRY burned on spoke, but 1000 iTRY locked in adapter on hub

**Security Property Broken:** 
- **Invariant #2 (Blacklist Enforcement)**: The blacklist mechanism creates a DOS condition that results in permanent fund loss during cross-chain operations
- **Invariant #7 (Cross-chain Message Integrity)**: Messages fail to deliver funds to the correct user, and no recovery mechanism exists
- **Cross-chain Supply Conservation**: Total supply is no longer conserved (burned on spoke, locked on hub)

## Impact Explanation
- **Affected Assets**: iTRY tokens locked in `iTryTokenOFTAdapter` on hub chain (Ethereum), with corresponding burned supply on spoke chain (MegaETH)
- **Damage Severity**: Complete loss of bridged tokens for affected users. The locked tokens in the adapter become "dead capital" - not circulating on spoke, not accessible on hub. This creates protocol insolvency as locked tokens have no corresponding live supply.
- **User Impact**: Any user bridging from spoke to hub can lose 100% of their bridged amount if blacklisted during the message delivery window (typically seconds to minutes). Once blacklisted, retrying the LayerZero message will continue to fail, making the loss permanent unless admin removes the blacklist.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a protocol design flaw. Any legitimate user can trigger this by being blacklisted between initiating a bridge transaction and message execution on hub.
- **Preconditions**: 
  - User must have iTRY OFT tokens on spoke chain
  - User must initiate a bridge back to hub
  - User must be added to blacklist on hub before `lzReceive` executes
- **Execution Complexity**: No special actions required. The vulnerability triggers naturally when blacklist state changes during the cross-chain message delay window.
- **Frequency**: Can occur for every affected user attempting to bridge during or after being blacklisted. In LayerZero V2, failed messages can be retried, but they will keep failing as long as the user remains blacklisted.

## Recommendation

The protocol should implement graceful handling of blacklisted recipients during cross-chain token unlocking, similar to the protection already implemented in `wiTryOFT._credit()`: [3](#0-2) 

**Option 1: Override `_credit` in a custom adapter contract:**

```solidity
// Create iTryTokenOFTAdapterWithBlacklistHandling.sol

function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // Check if recipient is blacklisted on hub
    if (iTry(token).hasRole(iTry(token).BLACKLISTED_ROLE(), _to)) {
        // Redirect to protocol treasury/owner instead of reverting
        emit BlacklistedRecipientRedirected(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}
```

**Option 2: Modify iTry._beforeTokenTransfer to allow adapter transfers:**

```solidity
// In iTry.sol, _beforeTokenTransfer function
// Add special case for OFT adapter unlocking to blacklisted users
else if (
    hasRole(OFT_ADAPTER_ROLE, msg.sender) && 
    hasRole(BLACKLISTED_ROLE, to) && 
    from == msg.sender
) {
    // Allow adapter to unlock to blacklisted users (funds are stuck anyway)
    // Consider emitting event for monitoring
}
```

**Option 3: Implement a recovery mechanism:**

Add a function in `iTryTokenOFTAdapter` that allows admin to redirect stuck tokens from failed `lzReceive` calls to a designated treasury address, with proper event emission for transparency.

The first option is recommended as it's non-invasive, prevents the issue proactively, and maintains blacklist enforcement by redirecting funds to a safe address rather than locking them permanently.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistLock.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistLock -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_CrossChainBlacklistLock is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant BRIDGE_AMOUNT = 1000 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_CrossChainBlacklistLock() public {
        console.log("\n=== Exploit: Cross-Chain Blacklist Lock ===");

        // SETUP: User has iTRY on spoke (L2)
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
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();

        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);

        // Verify user has tokens on L2
        vm.selectFork(opSepoliaForkId);
        assertEq(opSepoliaOFT.balanceOf(userL1), BRIDGE_AMOUNT, "User should have iTRY on L2");

        // EXPLOIT: Bridge back to L1, then blacklist user before lzReceive
        vm.startPrank(userL1);
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();

        // Verify tokens burned on L2
        assertEq(opSepoliaOFT.balanceOf(userL1), 0, "Tokens burned on L2");
        assertEq(opSepoliaOFT.totalSupply(), 0, "L2 supply is 0");

        // Admin blacklists user on L1 before message delivery
        vm.selectFork(sepoliaForkId);
        address[] memory blacklistees = new address[](1);
        blacklistees[0] = userL1;
        vm.prank(deployer);
        sepoliaITryToken.addBlacklistAddress(blacklistees);

        // Try to relay message - should revert due to blacklist
        message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        vm.expectRevert(); // Will revert with OperationNotAllowed from _beforeTokenTransfer
        relayMessage(message);

        // VERIFY: Tokens are lost
        console.log("User balance on L1:", sepoliaITryToken.balanceOf(userL1));
        console.log("Adapter locked balance:", sepoliaITryToken.balanceOf(address(sepoliaAdapter)));
        console.log("L2 total supply:", opSepoliaOFT.totalSupply());

        assertEq(sepoliaITryToken.balanceOf(userL1), 0, "User has 0 on L1 (blacklisted)");
        assertEq(sepoliaITryToken.balanceOf(address(sepoliaAdapter)), BRIDGE_AMOUNT, "Tokens locked in adapter");
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("- Tokens burned on spoke: ", BRIDGE_AMOUNT);
        console.log("- Tokens locked on hub:   ", BRIDGE_AMOUNT);
        console.log("- User loss:              ", BRIDGE_AMOUNT);
        console.log("- Unbacked locked iTRY:   ", BRIDGE_AMOUNT);
    }
}
```

## Notes

This vulnerability specifically affects `iTryTokenOFT` and `iTryTokenOFTAdapter`. The `wiTryOFT` contract already implements protection against this issue by overriding `_credit()` to redirect tokens to the owner if the recipient is blacklisted, as shown in the code. The iTRY cross-chain contracts lack this same protection, creating an asymmetry in blacklist handling between the two token systems.

The issue becomes critical when considering that LayerZero V2's message retry mechanism cannot resolve this - retrying the message will continue to fail as long as the user remains blacklisted. The only recovery path requires admin intervention to either: (1) remove the user from the blacklist (defeating the purpose of blacklisting), or (2) implement a custom recovery mechanism to extract the locked tokens.

This violates the documented invariant that "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - in this scenario, the blacklist enforcement causes permanent fund loss rather than simply preventing token movement.

### Citations

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
