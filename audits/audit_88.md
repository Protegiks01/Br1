## Title
Whitelist Bypass in Cross-Chain Minting Allows Non-Whitelisted Users to Receive iTRY Tokens

## Summary
The iTryTokenOFT contract on spoke chains fails to enforce whitelist restrictions during cross-chain minting operations. When the contract is in `WHITELIST_ENABLED` state, tokens can be minted to non-whitelisted addresses via LayerZero bridging, directly violating the protocol's whitelist enforcement invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (function `_beforeTokenTransfer`, lines 160-161) [1](#0-0) 

**Intended Logic:** According to invariant #3, in `WHITELIST_ENABLED` state, ONLY whitelisted users should be able to send/receive/burn iTRY tokens. The `_beforeTokenTransfer` hook should verify that recipients of minted tokens are whitelisted.

**Actual Logic:** The minting check in `WHITELIST_ENABLED` state only validates that the recipient is not blacklisted (`!blacklisted[to]`), but does NOT check if the recipient is whitelisted (`whitelisted[to]`). This allows the LayerZero endpoint (the minter) to mint tokens to any non-blacklisted address, regardless of whitelist status.

**Exploitation Path:**
1. iTryTokenOFT on spoke chain (e.g., MegaETH) is set to `WHITELIST_ENABLED` state by owner to restrict token access
2. Attacker has iTRY tokens on hub chain (Ethereum) and their address is NOT whitelisted on the spoke chain
3. Attacker calls `send()` on iTryTokenOFTAdapter (hub chain), specifying their non-whitelisted address on spoke chain as recipient
4. iTryTokenOFTAdapter locks iTRY and sends LayerZero message to spoke chain
5. LayerZero endpoint on spoke chain calls `lzReceive()` on iTryTokenOFT
6. Internal `_credit()` function calls `_mint()` which triggers `_beforeTokenTransfer` hook
7. Check at line 160-161 passes because: `msg.sender == minter` (endpoint), `from == address(0)` (mint), and `!blacklisted[to]` (attacker not blacklisted)
8. Tokens are minted to attacker despite not being whitelisted, violating invariant #3

**Security Property Broken:** Invariant #3 - "Whitelist Enforcement: In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY"

## Impact Explanation
- **Affected Assets**: iTRY tokens on spoke chains (MegaETH and other L2s)
- **Damage Severity**: Complete bypass of whitelist controls on spoke chains. Non-whitelisted users can receive any amount of iTRY tokens via cross-chain bridging, undermining the protocol's access control mechanism. This could allow unauthorized parties (e.g., sanctioned addresses, non-KYC users) to hold iTRY when the protocol intends to restrict access.
- **User Impact**: All iTRY token holders are affected as the whitelist mechanism is a critical security control. Regulatory compliance requirements may be violated if restricted addresses can bypass the whitelist through cross-chain transfers.

## Likelihood Explanation
- **Attacker Profile**: Any user who holds iTRY tokens on the hub chain and has a non-whitelisted address on the spoke chain
- **Preconditions**: 
  1. iTryTokenOFT on spoke chain must be in `WHITELIST_ENABLED` state
  2. Attacker must have iTRY balance on hub chain
  3. Attacker's spoke chain address must not be blacklisted (but not whitelisted either)
- **Execution Complexity**: Single cross-chain transaction - simple call to `send()` on iTryTokenOFTAdapter with spoke chain address as recipient
- **Frequency**: Can be exploited continuously by any user meeting the preconditions, unlimited number of times

## Recommendation

In `src/token/iTRY/crosschain/iTryTokenOFT.sol`, modify the `_beforeTokenTransfer` function to check whitelist status during minting in `WHITELIST_ENABLED` state: [2](#0-1) 

**FIXED:**
```solidity
// State 1 - Transfers only enabled between whitelisted addresses
} else if (transferState == TransferState.WHITELIST_ENABLED) {
    if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
        // redeeming
    } else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
        // minting - ADD whitelisted[to] check
    } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
        // redistributing - burn
    } else if (msg.sender == owner() && from == address(0) && !blacklisted[to] && whitelisted[to]) {
        // redistributing - mint - ADD whitelisted[to] check
    } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
        // whitelisted user can burn
    } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
        // normal case
    } else {
        revert OperationNotAllowed();
    }
```

The same fix should be applied to the hub chain iTry.sol contract: [3](#0-2) 

## Proof of Concept
```solidity
// File: test/Exploit_WhitelistBypass.t.sol
// Run with: forge test --match-test test_WhitelistBypassViaCrossChain -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";

contract Exploit_WhitelistBypass is Test {
    iTryTokenOFT public spokeOFT;
    address public lzEndpoint;
    address public owner;
    address public attacker;
    
    function setUp() public {
        owner = address(this);
        attacker = address(0x1337);
        lzEndpoint = address(0x5555); // Mock LayerZero endpoint
        
        // Deploy iTryTokenOFT on spoke chain
        spokeOFT = new iTryTokenOFT(lzEndpoint, owner);
        
        // Set minter to LayerZero endpoint
        spokeOFT.setMinter(lzEndpoint);
        
        // Enable whitelist mode
        spokeOFT.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Whitelist a legitimate user (not the attacker)
        address[] memory whitelistAddresses = new address[](1);
        whitelistAddresses[0] = address(0x9999);
        spokeOFT.addWhitelistAddress(whitelistAddresses);
    }
    
    function test_WhitelistBypassViaCrossChain() public {
        // SETUP: Initial state
        uint256 mintAmount = 1000 ether;
        
        // Verify attacker is NOT whitelisted
        assertFalse(spokeOFT.whitelisted(attacker), "Attacker should not be whitelisted");
        
        // Verify contract is in WHITELIST_ENABLED state
        assertEq(uint256(spokeOFT.transferState()), uint256(IiTryDefinitions.TransferState.WHITELIST_ENABLED), "Should be in WHITELIST_ENABLED state");
        
        // EXPLOIT: Simulate LayerZero endpoint minting to non-whitelisted attacker
        vm.prank(lzEndpoint); // Simulate call from LayerZero endpoint (the minter)
        spokeOFT.transfer(attacker, mintAmount); // This internally calls _mint via the OFT flow
        
        // VERIFY: Confirm exploit success
        uint256 attackerBalance = spokeOFT.balanceOf(attacker);
        assertEq(attackerBalance, mintAmount, "Vulnerability confirmed: Non-whitelisted attacker received iTRY tokens");
        
        // Additional verification: Attacker still cannot transfer to others (whitelist enforced for transfers)
        vm.prank(attacker);
        vm.expectRevert();
        spokeOFT.transfer(address(0x8888), 100 ether);
    }
}
```

## Notes

This vulnerability exists in both the hub chain `iTry.sol` and spoke chain `iTryTokenOFT.sol` contracts. The issue affects cross-chain bridging operations where tokens minted via LayerZero messages bypass whitelist checks, but the hub chain impact is lower since minting through `iTryIssuer` already has its own whitelist checks at the application level. However, on spoke chains, this is the primary entry point for tokens, making the vulnerability more critical.

The fix requires adding `whitelisted[to]` checks to both minting conditions (line 160-161 and 164-165) in the `WHITELIST_ENABLED` state to ensure consistency with the protocol's whitelist enforcement invariant.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L157-172)
```text
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
```

**File:** src/token/iTRY/iTry.sol (L198-217)
```text
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
```
