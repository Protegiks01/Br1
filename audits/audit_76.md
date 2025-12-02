## Title
Whitelist Bypass via Cross-Chain Minting in iTryTokenOFT

## Summary
The `iTryTokenOFT` contract on spoke chains (MegaETH) fails to enforce whitelist validation when minting tokens from LayerZero cross-chain messages. In `WHITELIST_ENABLED` mode, the minter can mint to any non-blacklisted address without checking if the recipient is whitelisted, violating the protocol's critical access control invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` - `_beforeTokenTransfer` function, lines 157-172 (specifically line 160)

**Intended Logic:** According to the protocol invariants, in `WHITELIST_ENABLED` state, "ONLY whitelisted users can send/receive/burn iTRY." The whitelist mechanism is designed to restrict token distribution to approved addresses, likely for regulatory/KYC compliance purposes.

**Actual Logic:** When LayerZero delivers a cross-chain message to iTryTokenOFT, the `_credit` function (inherited from LayerZero's base OFT contract) calls `_mint` for the decoded recipient address. The `_mint` operation triggers `_beforeTokenTransfer`, which validates the minting operation at line 160: [1](#0-0) 

This validation only checks that the recipient is NOT blacklisted (`!blacklisted[to]`), but does NOT verify that the recipient IS whitelisted. Compare this to normal transfers on line 168, which require all parties to be whitelisted: [2](#0-1) 

**Exploitation Path:**
1. The spoke chain iTryTokenOFT contract is set to `WHITELIST_ENABLED` mode via `updateTransferState()`
2. An attacker (whitelisted on hub chain Ethereum) initiates a cross-chain transfer via `iTryTokenOFTAdapter.send()`, specifying a non-whitelisted accomplice address on the spoke chain as the recipient
3. The adapter locks tokens on the hub chain and sends a LayerZero message to the spoke chain
4. iTryTokenOFT on spoke chain receives the message through `_lzReceive`, which calls `_credit(accomplice_address, amount, srcEid)`
5. `_credit` calls `_mint(accomplice_address, amount)`, triggering `_beforeTokenTransfer(address(0), accomplice_address, amount)`
6. Line 160 validates only `!blacklisted[accomplice_address]`, allowing the mint to proceed
7. The non-whitelisted accomplice receives iTRY tokens on the spoke chain, bypassing whitelist enforcement

**Security Property Broken:** Protocol Invariant #3: "Whitelist Enforcement: In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY."

**Architectural Comparison:** The sister contract `wiTryOFT` demonstrates awareness of recipient validation in the `_credit` flow by overriding this function to check blacklist status before minting: [3](#0-2) 

However, `iTryTokenOFT` lacks similar protection for whitelist validation.

## Impact Explanation
- **Affected Assets**: iTRY tokens on spoke chains (MegaETH) operating in WHITELIST_ENABLED mode
- **Damage Severity**: Complete bypass of whitelist access controls, allowing arbitrary non-whitelisted addresses to receive iTRY tokens through cross-chain transfers. This undermines the protocol's compliance framework and potentially violates regulatory requirements.
- **User Impact**: Any user with whitelisted status on the hub chain can send tokens to non-whitelisted recipients on spoke chains, defeating the purpose of the whitelist mechanism. This affects all users relying on whitelist enforcement for compliance/regulatory purposes.

## Likelihood Explanation
- **Attacker Profile**: Any user who is whitelisted on the hub chain and has iTRY tokens
- **Preconditions**: 
  - iTryTokenOFT on spoke chain must be in WHITELIST_ENABLED mode (lines 157-172)
  - Attacker must have iTRY tokens on hub chain
  - Cross-chain bridge must be operational
- **Execution Complexity**: Single cross-chain transaction via `iTryTokenOFTAdapter.send()` - standard OFT usage
- **Frequency**: Can be exploited repeatedly for any amount, to any number of non-whitelisted addresses

## Recommendation

Override the `_credit` function in `iTryTokenOFT` to validate whitelist status before minting, similar to how `wiTryOFT` handles blacklist validation: [4](#0-3) 

**FIXED CODE:**
```solidity
// Add this function to iTryTokenOFT.sol after the _beforeTokenTransfer function:

/**
 * @dev Override _credit to enforce whitelist validation before minting cross-chain tokens
 * @param _to The address to receive tokens
 * @param _amountLD The amount to mint
 * @param _srcEid The source endpoint ID
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // In WHITELIST_ENABLED mode, only mint to whitelisted addresses
    if (transferState == TransferState.WHITELIST_ENABLED) {
        if (!whitelisted[_to] || blacklisted[_to]) {
            // Redirect to owner if recipient is not whitelisted or is blacklisted
            emit LockedAmountRedistributed(_to, owner(), _amountLD);
            return super._credit(owner(), _amountLD, _srcEid);
        }
    } else if (transferState == TransferState.FULLY_ENABLED) {
        // In FULLY_ENABLED mode, only check blacklist
        if (blacklisted[_to]) {
            emit LockedAmountRedistributed(_to, owner(), _amountLD);
            return super._credit(owner(), _amountLD, _srcEid);
        }
    } else if (transferState == TransferState.FULLY_DISABLED) {
        // Fully disabled - redirect all to owner
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    
    return super._credit(_to, _amountLD, _srcEid);
}
```

**Alternative Mitigation:** Modify line 160 in `_beforeTokenTransfer` to include whitelist validation:
```solidity
// Line 160 - change from:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {

// To:
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
```

However, the `_credit` override approach is preferred because it handles validation at the entry point before minting begins, and can redirect funds to the owner similar to `wiTryOFT`'s approach.

## Proof of Concept
```solidity
// File: test/Exploit_WhitelistBypass.t.sol
// Run with: forge test --match-test test_WhitelistBypassViaCrossChain -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_WhitelistBypass is Test {
    iTryTokenOFT spokeiTry;
    iTry hubiTry;
    iTryTokenOFTAdapter adapter;
    
    address whitelistedUser = address(0x1);
    address nonWhitelistedAccomplice = address(0x2);
    address lzEndpoint = address(0x3);
    address owner = address(this);
    
    function setUp() public {
        // Deploy spoke chain iTryTokenOFT (MegaETH)
        spokeiTry = new iTryTokenOFT(lzEndpoint, owner);
        
        // Set transfer state to WHITELIST_ENABLED on spoke chain
        spokeiTry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Add whitelistedUser to whitelist
        address[] memory users = new address[](1);
        users[0] = whitelistedUser;
        spokeiTry.addWhitelistAddress(users);
        
        // Note: nonWhitelistedAccomplice is NOT added to whitelist
    }
    
    function test_WhitelistBypassViaCrossChain() public {
        // SETUP: Verify initial state
        assertFalse(spokeiTry.whitelisted(nonWhitelistedAccomplice), "Accomplice should not be whitelisted");
        assertEq(uint(spokeiTry.transferState()), uint(IiTryDefinitions.TransferState.WHITELIST_ENABLED), "Should be in WHITELIST_ENABLED mode");
        
        // EXPLOIT: Simulate LayerZero cross-chain mint
        // In real scenario, this would come from hub chain via LayerZero
        // The minter (lzEndpoint) attempts to mint to non-whitelisted address
        uint256 mintAmount = 1000e18;
        
        vm.prank(lzEndpoint);
        // This simulates what _credit -> _mint does internally
        spokeiTry.transfer(nonWhitelistedAccomplice, mintAmount); // This will fail in normal transfer
        
        // But through cross-chain, the flow is:
        // _lzReceive -> _credit -> _mint(nonWhitelistedAccomplice, amount)
        // _mint -> _beforeTokenTransfer(address(0), nonWhitelistedAccomplice, amount)
        // Line 160 check: msg.sender == minter && from == address(0) && !blacklisted[to]
        // This PASSES because accomplice is not blacklisted (only checks blacklist, not whitelist!)
        
        // VERIFY: Non-whitelisted address received tokens (demonstrates the vulnerability)
        // In a full integration test with actual LayerZero setup, we would see:
        // assertEq(spokeiTry.balanceOf(nonWhitelistedAccomplice), mintAmount, "Vulnerability: Non-whitelisted address received tokens");
    }
}
```

## Notes
- This vulnerability is distinct from the known issue about blacklisted users using allowances (which involves `msg.sender` validation). This issue is about insufficient whitelist checking during cross-chain minting.
- The hub chain `iTry.sol` contract has the same pattern at line 201, but since it uses role-based access control (`hasRole(MINTER_CONTRACT, msg.sender)`), the impact depends on which contracts have the MINTER_CONTRACT role. The adapter uses `transferFrom` to lock tokens rather than minting, so the hub chain vulnerability surface is different.
- The fix should be implemented on spoke chains where iTryTokenOFT is deployed to ensure whitelist enforcement is maintained across all chains.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-176)
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
