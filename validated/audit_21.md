# Validation Result: VALID HIGH SEVERITY VULNERABILITY

After exhaustive validation against the Brix Money protocol validation framework, this claim represents a **genuine HIGH severity vulnerability**. All validation checkpoints pass.

## Title
Cross-Chain Bridge Failure Causes Permanent Token Loss When Hub Recipient is Blacklisted

## Summary
When iTRY tokens are bridged from spoke chain back to hub chain, if the recipient is blacklisted on the hub before LayerZero message execution, the adapter's token unlock reverts due to blacklist enforcement, causing permanent fund loss. Tokens are burned on spoke but remain locked in the adapter on hub with no recovery mechanism.

## Impact
**Severity**: High

Users suffer 100% permanent loss of bridged tokens when blacklisted during the LayerZero message delivery window (seconds to minutes). The locked tokens become "dead capital" in the adapter, breaking cross-chain supply conservation and creating protocol insolvency risk. Recovery requires admin intervention (removing blacklist, which defeats compliance purpose) with no automated mechanism. [1](#0-0) 

## Finding Description

**Location:** 
- `src/token/iTRY/iTry.sol` (blacklist enforcement in _beforeTokenTransfer)
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` (spoke chain burn mechanism)
- `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` (hub chain unlock without protection)

**Intended Logic:**
Cross-chain bridges should maintain supply conservation: tokens burned on spoke equal tokens unlocked on hub. The LayerZero OFT architecture ensures atomic cross-chain token movements.

**Actual Logic:**
When `iTryTokenOFTAdapter.lzReceive()` executes on hub, it attempts to unlock tokens by transferring from adapter to recipient. This transfer triggers `iTry._beforeTokenTransfer()` which enforces blacklist restrictions. The normal case requires all parties (msg.sender, from, to) to NOT have BLACKLISTED_ROLE. If the recipient is blacklisted, the condition fails and the transaction reverts with `OperationNotAllowed()`. However, tokens have already been burned on the spoke chain, creating permanent fund loss. [2](#0-1) 

**Exploitation Path:**
1. User has iTRY OFT tokens on spoke chain (MegaETH)
2. User calls `iTryTokenOFT.send()` to bridge back to hub
3. **Spoke chain:** Tokens burned via minter role (line 143-144 of iTryTokenOFT allows minter to burn from non-blacklisted users)
4. LayerZero message sent to hub chain
5. **During message delivery delay:** User gets blacklisted on hub via `iTry.addBlacklistAddress()` (legitimate compliance action)
6. **Hub chain:** LayerZero executor calls `iTryTokenOFTAdapter.lzReceive()`
7. Adapter attempts `_credit()` which transfers tokens from adapter to user
8. `iTry._beforeTokenTransfer(from=adapter, to=user, amount)` triggered
9. Lines 189-195 check fails: `!hasRole(BLACKLISTED_ROLE, to)` evaluates to false
10. Transaction reverts with `OperationNotAllowed()`
11. **Result:** Tokens burned on spoke, permanently locked in adapter on hub [3](#0-2) 

**Security Property Broken:**
- **Cross-chain Supply Conservation:** Total supply no longer conserved (burned on spoke, locked on hub)
- **README Invariant (line 124):** "Blacklisted users cannot send/receive/mint/burn iTRY tokens in any case" - enforcement causes permanent fund loss rather than preventing transfer
- **Cross-chain Message Integrity:** Messages fail to deliver funds with no recovery mechanism

## Impact Explanation

**Affected Assets:** iTRY tokens locked in `iTryTokenOFTAdapter` on hub chain (Ethereum), with corresponding burned supply on spoke chain (MegaETH)

**Damage Severity:**
- Complete loss of bridged tokens for affected users (100% of bridge amount)
- Locked tokens become "dead capital" - not circulating on spoke, not accessible on hub
- Protocol insolvency risk: locked tokens have no corresponding live supply
- No recovery without admin removing blacklist (defeats compliance purpose) or custom recovery mechanism (doesn't exist)

**User Impact:** Any user bridging from spoke to hub loses entire bridged amount if blacklisted during message delivery window. LayerZero V2's message retry mechanism cannot resolve this - retries continue failing while user remains blacklisted.

## Likelihood Explanation

**Attacker Profile:** No attacker needed - this is a protocol design flaw affecting legitimate users

**Preconditions:**
1. User has iTRY OFT tokens on spoke chain
2. User initiates bridge back to hub (normal operation)
3. User added to blacklist on hub before `lzReceive` executes (legitimate compliance action)

**Execution Complexity:** No special actions required - vulnerability triggers naturally when blacklist state changes during cross-chain message delay (typically seconds to minutes)

**Frequency:** Can occur for every user attempting to bridge during or after being blacklisted

**Overall Likelihood:** Medium to High - depends on blacklist operation timing, but when it occurs, impact is always severe (100% loss)

## Recommendation

Implement graceful handling of blacklisted recipients during cross-chain token unlocking, following the pattern already established in `wiTryOFT._credit()`: [4](#0-3) 

**Recommended Solution:** Override `_credit` in iTryTokenOFTAdapter to check blacklist status before crediting and redirect to protocol owner if recipient is blacklisted:

```solidity
// Enhanced iTryTokenOFTAdapter with blacklist handling
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // Check if recipient is blacklisted on hub
    if (iTry(token).hasRole(iTry(token).BLACKLISTED_ROLE(), _to)) {
        // Redirect to protocol owner instead of reverting
        emit BlacklistedRecipientRedirected(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}
```

This approach:
- Prevents permanent fund loss
- Maintains blacklist enforcement (blacklisted user doesn't receive tokens)
- Allows admin to later redistribute tokens appropriately
- Mirrors existing protection in wiTryOFT, creating consistency across protocol [5](#0-4) 

## Notes

**Critical Asymmetry:** The `wiTryOFT` contract already implements this exact protection, demonstrating that:
1. Protocol developers are aware of this issue
2. A working solution exists in the codebase  
3. Lack of similar protection in iTryTokenOFTAdapter represents an oversight, not intentional design

The vulnerability violates the spirit of the documented invariant (README line 124) - while technically enforcing "blacklisted users cannot receive iTRY," the enforcement mechanism itself causes permanent fund loss rather than simply preventing unauthorized token movement.

**Recovery Limitations:** LayerZero V2's message retry mechanism cannot resolve this. Retries will continue failing as long as user remains blacklisted. The only recovery paths require either:
1. Admin removes user from blacklist (defeats compliance purpose)
2. Implement custom recovery mechanism (doesn't currently exist)

This is a **valid High severity vulnerability** requiring immediate remediation before production deployment.

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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-155)
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
