# Validation Result: VALID HIGH SEVERITY VULNERABILITY

## Title
Cross-Chain Bridge Failure Causes Permanent Token Loss When Hub Recipient is Blacklisted

## Summary
When iTRY tokens are bridged from spoke chain back to hub chain, if the recipient is blacklisted on the hub before `lzReceive` execution, the adapter's token unlock reverts due to blacklist enforcement in `iTry._beforeTokenTransfer`. This creates permanent fund loss: tokens are burned on spoke but remain locked in the adapter on hub, with no recovery mechanism.

## Impact
**Severity**: High

This represents a critical permanent fund loss vulnerability. Users lose 100% of their bridged tokens with no recovery path except admin intervention to remove the blacklist (which defeats its compliance purpose). The locked tokens in the adapter become "dead capital" - creating protocol insolvency as the supply accounting breaks (burned on spoke, locked on hub).

## Finding Description

**Location:** 
- `src/token/iTRY/iTry.sol` (lines 177-222, specifically lines 189-195) [1](#0-0) 
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` (spoke chain burn mechanism) [2](#0-1) 
- `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` (hub chain unlock mechanism) [3](#0-2) 

**Intended Logic:**
The cross-chain bridge should atomically burn tokens on spoke and unlock equivalent tokens on hub, maintaining supply conservation. The LayerZero OFT architecture ensures burned tokens on one chain result in unlocked tokens on another.

**Actual Logic:**
When `iTryTokenOFTAdapter.lzReceive()` is called on the hub, it attempts to unlock tokens by transferring from the adapter to the recipient. This transfer goes through `iTry._beforeTokenTransfer()`, which enforces blacklist restrictions. The normal case check at lines 189-195 requires `!hasRole(BLACKLISTED_ROLE, to)`. If the recipient is blacklisted, this condition fails and the entire transaction reverts with `OperationNotAllowed()`, but tokens have already been burned on spoke.

**Exploitation Path:**
1. User has iTRY OFT tokens on spoke chain (MegaETH)
2. User calls `iTryTokenOFT.send(hubEid, userAddress, amount)` to bridge back to hub
3. On spoke: Tokens are burned (lines 143-144 of iTryTokenOFT allow minter to burn from non-blacklisted users)
4. LayerZero message sent to hub chain
5. During message delivery delay, user gets blacklisted on hub via `iTry.addBlacklistAddress()`
6. LayerZero executor calls `iTryTokenOFTAdapter.lzReceive()` on hub
7. Adapter attempts to transfer tokens from adapter to user
8. `iTry._beforeTokenTransfer(from=adapter, to=user, amount)` is triggered
9. Line 190-191 check fails: `!hasRole(BLACKLISTED_ROLE, to)` evaluates to false
10. Transaction reverts with `OperationNotAllowed()`
11. Result: Tokens burned on spoke, permanently locked in adapter on hub

**Security Property Broken:**
- **Cross-chain Supply Conservation**: Total supply is no longer conserved (burned on spoke, locked on hub)
- **Invariant #2 (Blacklist Enforcement)**: The blacklist mechanism creates a condition that results in permanent fund loss rather than preventing unauthorized transfers
- **Cross-chain Message Integrity**: Messages fail to deliver funds, with no recovery mechanism

## Impact Explanation

**Affected Assets**: iTRY tokens locked in `iTryTokenOFTAdapter` on hub chain (Ethereum), with corresponding burned supply on spoke chain (MegaETH)

**Damage Severity**:
- Complete loss of bridged tokens for affected users (100% of bridge amount)
- Locked tokens in adapter become "dead capital" - not circulating on spoke, not accessible on hub
- Protocol insolvency: locked tokens have no corresponding live supply, breaking the supply accounting invariant
- Cannot be recovered without admin removing blacklist (defeating compliance purpose) or implementing custom recovery mechanism (doesn't exist)

**User Impact**: Any user bridging from spoke to hub loses their entire bridged amount if blacklisted during the message delivery window (typically seconds to minutes). LayerZero V2's message retry mechanism cannot resolve this - retries will continue failing as long as user remains blacklisted.

## Likelihood Explanation

**Attacker Profile**: No attacker needed - this is a protocol design flaw affecting legitimate users

**Preconditions**:
1. User has iTRY OFT tokens on spoke chain
2. User initiates bridge back to hub
3. User is added to blacklist on hub before `lzReceive` executes

**Execution Complexity**: No special actions required - vulnerability triggers naturally when blacklist state changes during cross-chain message delay

**Frequency**: Can occur for every user attempting to bridge during or after being blacklisted

**Overall Likelihood**: Medium to High - depends on blacklist operations timing, but when it occurs, impact is always severe (100% loss)

## Recommendation

Implement graceful handling of blacklisted recipients during cross-chain token unlocking, following the pattern already established in `wiTryOFT._credit()` [4](#0-3) 

**Recommended Solution: Override `_credit` in iTryTokenOFTAdapter**

Create an enhanced adapter contract that checks blacklist status before crediting and redirects to protocol treasury/owner if recipient is blacklisted:

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
- Mirrors the existing protection in wiTryOFT, creating consistency across the protocol

## Proof of Concept

The provided PoC is realistic and demonstrates:
1. User successfully bridges iTRY from hub to spoke
2. User attempts to bridge back from spoke to hub
3. Admin blacklists user on hub before message delivery
4. Message relay reverts due to blacklist check
5. Tokens confirmed burned on spoke (supply = 0)
6. Tokens confirmed locked in adapter on hub

The PoC is executable using the provided test framework with `forge test --match-test test_CrossChainBlacklistLock -vvv`.

## Notes

**Critical Asymmetry**: The `wiTryOFT` contract already implements this exact protection [4](#0-3) , demonstrating that:
1. The protocol developers are aware of this issue
2. A working solution exists in the codebase
3. The lack of similar protection in iTryTokenOFTAdapter represents an oversight, not intentional design

The vulnerability violates the documented invariant that "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - in this scenario, the blacklist enforcement mechanism itself causes permanent fund loss rather than simply preventing unauthorized token movement.

**Recovery Limitations**: LayerZero V2's message retry mechanism cannot resolve this issue. Retrying the message will continue to fail as long as the user remains blacklisted. The only recovery paths require either:
1. Admin removes user from blacklist (defeats compliance purpose)
2. Implement custom recovery mechanism (doesn't currently exist)

This is a **valid High severity vulnerability** that requires immediate remediation before production deployment.

### Citations

**File:** src/token/iTRY/iTry.sol (L189-195)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
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
