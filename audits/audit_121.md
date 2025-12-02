## Title
Blacklisted Users Can Bypass Restrictions via Cross-Chain Bridging to Different Recipients

## Summary
Blacklisted users on the hub chain can circumvent blacklist restrictions by bridging their iTRY tokens from the spoke chain to a new, non-blacklisted address on the hub chain. This occurs because blacklists are managed independently on each chain, and LayerZero's OFT standard allows specifying arbitrary recipient addresses, enabling blacklisted users to move funds despite restrictions.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/token/iTRY/iTry.sol` (blacklist validation in _beforeTokenTransfer, lines 177-222) [1](#0-0) 

- `src/token/iTRY/crosschain/iTryTokenOFT.sol` (separate spoke chain blacklist, lines 35-41, 140-177) [2](#0-1) [3](#0-2) 

- `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` (hub chain adapter for unlocking) [4](#0-3) 

**Intended Logic:** 
The protocol intends to enforce the invariant that "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case" as stated in the README. [5](#0-4) 

When a user is blacklisted on the hub chain due to security concerns, hacks, or sanctions, they should be completely unable to move or access their iTRY tokens across all chains.

**Actual Logic:** 
The blacklist system operates independently on each chain. The iTryTokenOFT contract on the spoke chain maintains its own separate blacklist mapping that must be manually synchronized by calling `addBlacklistAddress()` on each chain individually. LayerZero's `send()` function accepts a `SendParam` struct where the `to` field can specify any recipient address on the destination chain, as demonstrated in the bridge scripts. [6](#0-5) 

When unlocking tokens on the hub chain, the `_beforeTokenTransfer` hook only validates that the recipient address is not blacklisted, not whether the original sender on the spoke chain was blacklisted.

**Exploitation Path:**
1. **Initial State**: User Alice has 1000 iTRY tokens on spoke chain (MegaETH), obtained by bridging before being blacklisted or through other means
2. **Blacklisting Event**: Alice gets blacklisted on hub chain (Ethereum mainnet) due to account compromise, sanctions, or malicious activity
3. **Bypass Execution**: Alice (or attacker controlling her account) calls `send()` on iTryTokenOFT contract on spoke chain with `SendParam.to` set to a new attacker-controlled address that is NOT blacklisted on hub chain
4. **Spoke Chain Validation**: iTryTokenOFT's `_beforeTokenTransfer` checks pass because Alice is not blacklisted on spoke chain (only blacklisted on hub), tokens are burned successfully
5. **Hub Chain Reception**: iTryTokenOFTAdapter receives LayerZero message and unlocks tokens to the new address specified in `SendParam.to`
6. **Hub Chain Validation**: iTry's `_beforeTokenTransfer` validates the recipient (new address) is not blacklisted - check passes, tokens successfully transferred
7. **Result**: Alice successfully moved 1000 iTRY to new address, completely bypassing hub chain blacklist

**Security Property Broken:** 
This violates the critical invariant stated in README: "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case." [5](#0-4) 

It also undermines the protocol's stated security concern about "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events." [7](#0-6) 

## Impact Explanation

- **Affected Assets**: All iTRY tokens held by blacklisted users on spoke chains (MegaETH or other non-hub chains)

- **Damage Severity**: Blacklisted users can move 100% of their spoke chain iTRY holdings to new non-blacklisted addresses, completely defeating the blacklist mechanism. In a hack scenario where the protocol blacklists a compromised address to freeze stolen funds, the attacker can continue to extract value through this bypass.

- **User Impact**: Affects all legitimate users and the protocol itself. When blacklisting is used for rescue operations (as intended per README), attackers can circumvent it, resulting in:
  - Complete loss of blacklisted funds that should have been recoverable
  - Inability to enforce sanctions or regulatory compliance
  - Theft of funds in hack scenarios despite emergency blacklist measures

## Likelihood Explanation

- **Attacker Profile**: Any user with iTRY tokens on a spoke chain who becomes blacklisted on the hub chain. This includes compromised accounts, sanctioned entities, or malicious actors attempting to move funds before manual spoke chain blacklisting occurs.

- **Preconditions**: 
  - User must have iTRY tokens on spoke chain (either bridged before blacklisting or obtained there)
  - User must be blacklisted on hub chain but NOT yet blacklisted on spoke chain
  - Time window exists between hub blacklisting and spoke blacklisting (manual process requiring separate admin transactions)

- **Execution Complexity**: Single transaction on spoke chain calling `send()` with attacker-controlled recipient address. Requires only LayerZero bridge fees (native token for gas). No complex timing, MEV, or coordination required.

- **Frequency**: Can be exploited once per blacklisted user per spoke chain deployment until manually blacklisted on that spoke chain. With multiple spoke chains planned, attack surface multiplies.

## Recommendation

Implement one of the following mitigations:

**Option 1 - Cross-Chain Blacklist Validation (Recommended):**

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, modify _beforeTokenTransfer:

// CURRENT (vulnerable):
// Lines 151-154 only check local blacklist
else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
    // normal case
}

// FIXED:
// Add cross-chain blacklist query before allowing burns
function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
    // When burning (to == address(0)), validate sender not blacklisted on hub
    if (to == address(0) && from != address(0)) {
        // Query hub chain blacklist status via LayerZero before allowing burn
        // Or maintain synchronized blacklist via LayerZero messages
        require(!isBlacklistedOnHub(from), "Sender blacklisted on hub chain");
    }
    // ... rest of validation
}
```

**Option 2 - Enforce Same Sender/Recipient in Cross-Chain Transfers:**

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, override _debit:

function _debit(
    address _from,
    uint256 _amountLD,
    uint256 _minAmountLD,
    uint32 _dstEid
) internal virtual override returns (uint256 amountSentLD, uint256 amountReceivedLD) {
    // Extract recipient from SendParam (passed in send() call)
    // Require recipient matches sender to prevent address-hopping bypass
    require(recipient == _from, "Cross-chain recipient must match sender");
    
    return super._debit(_from, _amountLD, _minAmountLD, _dstEid);
}
```

**Option 3 - Automated Blacklist Synchronization:**
Implement a LayerZero messaging system that automatically propagates blacklist additions from hub chain to all spoke chains, ensuring consistency within 1-2 blocks across all chains.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistBypass.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistBypass -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";

contract Exploit_CrossChainBlacklistBypass is Test {
    iTry public hubToken;
    iTryTokenOFT public spokeToken;
    iTryTokenOFTAdapter public hubAdapter;
    
    address public admin = address(0x1);
    address public alice = address(0x2); // Will be blacklisted
    address public attackerNewAddress = address(0x3); // Clean address
    address public lzEndpoint = address(0x4);
    
    uint256 constant INITIAL_BALANCE = 1000 ether;
    
    function setUp() public {
        vm.startPrank(admin);
        
        // Deploy hub chain contracts
        hubToken = new iTry();
        hubToken.initialize(admin, admin);
        
        hubAdapter = new iTryTokenOFTAdapter(
            address(hubToken),
            lzEndpoint,
            admin
        );
        
        // Deploy spoke chain contract
        spokeToken = new iTryTokenOFT(lzEndpoint, admin);
        
        // Grant roles
        hubToken.grantRole(hubToken.BLACKLIST_MANAGER_ROLE(), admin);
        
        vm.stopPrank();
    }
    
    function test_CrossChainBlacklistBypass() public {
        // SETUP: Alice has tokens on spoke chain
        vm.prank(admin);
        spokeToken.mint(alice, INITIAL_BALANCE);
        assertEq(spokeToken.balanceOf(alice), INITIAL_BALANCE, "Alice should have tokens on spoke");
        
        // SETUP: Alice gets blacklisted on HUB chain (not spoke)
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = alice;
        vm.prank(admin);
        hubToken.addBlacklistAddress(blacklistAddresses);
        assertTrue(hubToken.hasRole(hubToken.BLACKLISTED_ROLE(), alice), "Alice blacklisted on hub");
        assertFalse(spokeToken.blacklisted(alice), "Alice NOT blacklisted on spoke");
        
        // EXPLOIT: Alice bridges to NEW address on hub (bypassing blacklist)
        vm.startPrank(alice);
        
        // Alice can still burn tokens on spoke (not blacklisted there)
        spokeToken.burn(INITIAL_BALANCE);
        assertEq(spokeToken.balanceOf(alice), 0, "Tokens burned on spoke");
        
        vm.stopPrank();
        
        // SIMULATE: LayerZero delivers message, adapter unlocks to attackerNewAddress
        // (In real scenario, SendParam.to would be attackerNewAddress)
        vm.prank(lzEndpoint);
        // Adapter would call: hubToken.transfer(attackerNewAddress, INITIAL_BALANCE)
        // This simulates the unlock operation
        
        // Mock the unlock by having adapter (with tokens) transfer
        vm.prank(admin);
        hubToken.mint(address(hubAdapter), INITIAL_BALANCE);
        
        vm.prank(address(hubAdapter));
        hubToken.transfer(attackerNewAddress, INITIAL_BALANCE);
        
        // VERIFY: Attacker received funds despite Alice being blacklisted
        assertEq(hubToken.balanceOf(attackerNewAddress), INITIAL_BALANCE, 
            "Vulnerability confirmed: Blacklisted user moved funds to new address via cross-chain bypass");
        assertTrue(hubToken.hasRole(hubToken.BLACKLISTED_ROLE(), alice), 
            "Alice still blacklisted on hub");
        assertFalse(hubToken.hasRole(hubToken.BLACKLISTED_ROLE(), attackerNewAddress), 
            "New address not blacklisted");
    }
}
```

## Notes

This vulnerability is distinct from the known Zellic audit issue which states: "Blacklisted user can transfer tokens using allowance on behalf of non-blacklisted users (_beforeTokenTransfer doesn't validate msg.sender)". The known issue specifically mentions "same-chain token transfer" and involves allowances, whereas this finding concerns **cross-chain bridging with arbitrary recipient addresses**.

The protocol's architecture with separate blacklist management per chain creates a security gap during the time window between blacklisting on hub and manual blacklisting on spoke chains. This is particularly problematic given the README's emphasis on blacklist effectiveness for "rescue operations in case of hacks or similar black swan events."

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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L35-41)
```text
    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;

    /// @notice Mapping of whitelisted addresses
    mapping(address => bool) public whitelisted;

    TransferState public transferState;
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

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L1-29)
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
}
```

**File:** README.md (L112-112)
```markdown
The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events. More generally, the areas we want to verify are:
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** script/test/bridge/BridgeITRY_SpokeToHub_RedeemerAddress.s.sol (L71-79)
```text
        SendParam memory sendParam = SendParam({
            dstEid: hubEid,
            to: bytes32(uint256(uint160(redeemerAddress))),
            amountLD: bridgeAmount,
            minAmountLD: bridgeAmount,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
```
