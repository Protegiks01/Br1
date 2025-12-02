## Title
Cross-Chain Blacklist Desynchronization Allows Blacklisted Users to Transfer Tokens on Spoke Chains

## Summary
The iTRY token system implements separate, independently-managed blacklist systems on hub chain (Ethereum) and spoke chains (MegaETH) with no automatic synchronization mechanism. A user blacklisted on the hub chain can continue to transfer tokens freely on spoke chains until the owner manually calls `addBlacklistAddress()` on each spoke chain, creating an exploitation window that violates the protocol's critical blacklist enforcement invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 35-84, 140-177) and `src/token/iTRY/iTry.sol` (lines 31, 73-87, 177-222)

**Intended Logic:** The protocol intends to enforce that blacklisted users cannot send/receive/mint/burn iTRY tokens in ANY case, as stated in the critical invariants. [1](#0-0) 

**Actual Logic:** The hub chain uses AccessControl-based blacklisting with the `BLACKLISTED_ROLE`, [2](#0-1)  while the spoke chain uses a simple mapping-based blacklist system. [3](#0-2)  These are completely separate systems requiring manual synchronization by the owner on each chain. [4](#0-3) 

The spoke chain's `_beforeTokenTransfer` hook only checks the spoke chain's local blacklist mapping, not the hub chain's blacklist status: [5](#0-4)  Specifically, line 151 only verifies `!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]` using the local spoke mapping.

**Exploitation Path:**
1. **Initial State**: User has iTRY tokens bridged to spoke chain (MegaETH) through normal LayerZero OFT bridging
2. **Trigger Event**: User gets blacklisted on hub chain via `iTry.addBlacklistAddress()` by the BLACKLIST_MANAGER_ROLE [6](#0-5) 
3. **Exploitation Window**: Before owner calls `iTryTokenOFT.addBlacklistAddress()` on spoke chain, the user can:
   - Transfer tokens to other addresses on spoke chain (passes the `_beforeTokenTransfer` check on line 151 since spoke's `blacklisted[user]` is still false)
   - Sell tokens on any DEX on spoke chain for other assets
   - Bridge tokens back to hub to a DIFFERENT non-blacklisted address (spoke allows burn, hub adapter unlocks to specified recipient)
   - Use tokens in any DeFi protocol on spoke chain
4. **Unauthorized Outcome**: Blacklisted user successfully moves/extracts value from tokens that should be frozen, defeating the blacklist mechanism

**Security Property Broken:** This directly violates Critical Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." [1](#0-0)  The protocol explicitly identifies blacklist/whitelist bugs as a top concern for "rescue operations in case of hacks or similar black swan events." [7](#0-6) 

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by blacklisted users on spoke chains during the synchronization window
- **Damage Severity**: Blacklisted users can fully circumvent the blacklist enforcement mechanism, transferring, selling, or bridging their tokens before the blacklist propagates to spoke chains. This defeats the entire purpose of blacklisting, which is critical for responding to hacks and security incidents.
- **User Impact**: This affects protocol security during emergency response situations. When a user must be blacklisted due to a security incident (compromised keys, malicious activity, etc.), they retain full control over their tokens on spoke chains until manual synchronization occurs, potentially allowing them to extract funds before remediation.

## Likelihood Explanation
- **Attacker Profile**: Any user who gets blacklisted on the hub chain while holding iTRY tokens on spoke chains
- **Preconditions**: 
  - User must have iTRY tokens on a spoke chain
  - User must be blacklisted on hub chain
  - Owner has not yet manually blacklisted the user on the spoke chain
- **Execution Complexity**: Single transaction on spoke chain - user simply transfers or bridges tokens using standard ERC20 or LayerZero OFT functions
- **Frequency**: Exploitable continuously during the entire window between hub blacklisting and spoke blacklisting (potentially hours or days depending on operational response time)

## Recommendation

Implement one of the following mitigations:

**Option 1 - Automated Cross-Chain Blacklist Synchronization:**
```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add new function:

/// @notice Receives cross-chain blacklist updates from hub chain
/// @param users Array of addresses to blacklist
/// @param operation true for add, false for remove
function syncBlacklistFromHub(address[] calldata users, bool operation) 
    external 
    onlyOwner // Or dedicated cross-chain message handler
{
    for (uint8 i = 0; i < users.length; i++) {
        if (operation) {
            // Add to blacklist
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        } else {
            // Remove from blacklist
            blacklisted[users[i]] = false;
        }
    }
    emit BlacklistSynchronized(users, operation);
}

// In src/token/iTRY/iTry.sol, modify addBlacklistAddress to trigger sync:

function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    for (uint8 i = 0; i < users.length; i++) {
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
    }
    // Send LayerZero message to all spoke chains to sync blacklist
    _syncBlacklistToSpokes(users, true);
}
```

**Option 2 - Hub Chain Verification in Spoke OFT (More Gas Intensive):**
Implement a mechanism where spoke chain can query hub chain blacklist status through LayerZero messages or oracle before allowing transfers, though this adds significant complexity and gas costs.

**Option 3 - Emergency Pause on Spoke Chains:**
Add ability to immediately pause all transfers on spoke chains when a critical blacklist event occurs on hub, giving time for manual synchronization:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol:

bool public emergencyPaused;

function setEmergencyPause(bool paused) external onlyOwner {
    emergencyPaused = paused;
    emit EmergencyPauseUpdated(paused);
}

function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
    require(!emergencyPaused, "Emergency pause active");
    // ... rest of existing logic
}
```

**Recommended Approach:** Implement Option 1 (automated synchronization) for the most robust solution, with Option 3 (emergency pause) as a backup safety mechanism.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistBypass.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistBypass -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_CrossChainBlacklistBypass is CrossChainTestBase {
    using OptionsBuilder for bytes;
    
    uint256 constant INITIAL_AMOUNT = 100 ether;
    address maliciousUser;
    address accomplice;
    
    function setUp() public override {
        super.setUp();
        deployAllContracts();
        
        maliciousUser = makeAddr("maliciousUser");
        accomplice = makeAddr("accomplice");
        
        // Fund malicious user
        vm.selectFork(sepoliaForkId);
        vm.deal(maliciousUser, 100 ether);
        vm.selectFork(opSepoliaForkId);
        vm.deal(maliciousUser, 100 ether);
        
        console.log("\n=== Cross-Chain Blacklist Bypass Exploit ===");
    }
    
    function test_CrossChainBlacklistBypass() public {
        // STEP 1: Setup - Mint iTRY to malicious user on hub and bridge to spoke
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(maliciousUser, INITIAL_AMOUNT);
        
        console.log("\n[SETUP] Initial balances:");
        console.log("  Hub (Sepolia) - maliciousUser:", sepoliaITryToken.balanceOf(maliciousUser));
        
        // Bridge tokens to spoke chain
        vm.startPrank(maliciousUser);
        sepoliaITryToken.approve(address(sepoliaAdapter), INITIAL_AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(maliciousUser))),
            amountLD: INITIAL_AMOUNT,
            minAmountLD: INITIAL_AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(maliciousUser));
        vm.stopPrank();
        
        // Relay message
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        vm.selectFork(opSepoliaForkId);
        console.log("  Spoke (OP Sepolia) - maliciousUser:", opSepoliaOFT.balanceOf(maliciousUser));
        
        // STEP 2: BLACKLIST USER ON HUB CHAIN ONLY
        vm.selectFork(sepoliaForkId);
        address[] memory usersToBlacklist = new address[](1);
        usersToBlacklist[0] = maliciousUser;
        
        vm.prank(deployer);
        sepoliaITryToken.grantRole(sepoliaITryToken.BLACKLIST_MANAGER_ROLE(), deployer);
        
        vm.prank(deployer);
        sepoliaITryToken.addBlacklistAddress(usersToBlacklist);
        
        console.log("\n[ATTACK] User blacklisted on HUB chain");
        console.log("  Hub blacklist status:", sepoliaITryToken.hasRole(sepoliaITryToken.BLACKLISTED_ROLE(), maliciousUser));
        
        vm.selectFork(opSepoliaForkId);
        console.log("  Spoke blacklist status:", opSepoliaOFT.blacklisted(maliciousUser));
        console.log("  --> DESYNC: Blacklisted on hub but NOT on spoke!");
        
        // STEP 3: EXPLOIT - Transfer tokens on spoke chain (should be blocked but isn't)
        vm.selectFork(opSepoliaForkId);
        
        // Scenario A: Transfer to accomplice
        vm.prank(maliciousUser);
        opSepoliaOFT.transfer(accomplice, INITIAL_AMOUNT / 2);
        
        console.log("\n[EXPLOIT SUCCESS] Blacklisted user transferred tokens on spoke chain!");
        console.log("  Accomplice balance:", opSepoliaOFT.balanceOf(accomplice));
        console.log("  Malicious user remaining:", opSepoliaOFT.balanceOf(maliciousUser));
        
        // STEP 4: VERIFY - Attempt same transfer on hub (should fail)
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(maliciousUser, 1 ether); // Try to mint (should fail)
        
        // This would revert - blacklist works on hub
        vm.selectFork(sepoliaForkId);
        vm.prank(maliciousUser);
        vm.expectRevert();
        sepoliaITryToken.transfer(accomplice, 1 ether);
        
        console.log("\n[VERIFICATION] Hub chain correctly blocks blacklisted user");
        console.log("  But spoke chain allows full token movement!");
        console.log("\n[CRITICAL] Invariant violated: 'Blacklisted users cannot send/receive/mint/burn iTry tokens in ANY case'");
    }
}
```

## Notes

This vulnerability is particularly critical because:

1. **Time-Sensitive Blacklisting**: Blacklisting is typically used in emergency situations (compromised keys, detected malicious activity, regulatory compliance). The time window between hub and spoke blacklisting could be hours or days depending on operational procedures.

2. **Multiple Spoke Chains**: With multiple spoke chains, the synchronization burden increases, making consistent enforcement even more difficult.

3. **Irrecoverable Value Loss**: Once a blacklisted user transfers tokens on a spoke chain or sells them on a DEX, the value is effectively extracted and cannot be recovered through the `redistributeLockedAmount` function which only works on the same chain.

4. **Protocol Design Priority**: The protocol explicitly states blacklist enforcement is one of their top concerns for handling black swan events, making this a high-priority vulnerability. [7](#0-6) 

5. **Not a Known Issue**: While the Zellic audit identified an allowance-based blacklist bypass, it did not identify this cross-chain synchronization issue which is architecturally different and affects cross-chain operations specifically.

### Citations

**File:** README.md (L112-112)
```markdown
The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events. More generally, the areas we want to verify are:
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** src/token/iTRY/iTry.sol (L31-31)
```text
    bytes32 public constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
```

**File:** src/token/iTRY/iTry.sol (L73-78)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L35-36)
```text
    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L70-84)
```text
    function addBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        }
    }

    /**
     * @param users List of address to be removed from blacklist
     */
    function removeBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            blacklisted[users[i]] = false;
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
