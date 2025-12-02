## Title
Blacklisted Users Lose Funds Permanently When Bridging wiTRY from Spoke to Hub Chain Due to Missing _credit Override

## Summary
The `wiTryOFTAdapter` on the hub chain lacks blacklist handling in its token unlock mechanism, creating an asymmetry with the spoke chain's `wiTryOFT` implementation. When a user blacklisted on the hub chain (but not on the spoke chain) attempts to bridge wiTRY tokens back, tokens are burned on the spoke chain but fail to unlock on the hub chain due to `StakediTry`'s `_beforeTokenTransfer` restriction, resulting in permanent fund loss for sanctioned addresses. [1](#0-0) 

## Impact
**Severity**: Medium (High for permanently blacklisted addresses)

**Affected Assets**: wiTRY share tokens of users who are blacklisted on the hub chain but not on the spoke chain.

**Damage Severity**: 
- Tokens are burned on the spoke chain but remain locked in the hub chain adapter
- Recoverable only if the user can be removed from the blacklist and the LayerZero message retried
- Permanent loss for sanctioned addresses (OFAC compliance) or users with permanent blacklist status
- No direct protocol insolvency, but violates the protocol's stated concern about "blacklist/whitelist bugs that would impair rescue operations" (README line 112)

**User Impact**: Any user who (1) holds wiTRY OFT on spoke chains, (2) becomes blacklisted on hub chain (granted `FULL_RESTRICTED_STAKER_ROLE`), and (3) attempts to bridge back to hub. This includes legitimate users temporarily blacklisted during investigations and sanctioned addresses.

## Finding Description

**Location:** `src/token/wiTRY/crosschain/wiTryOFTAdapter.sol` (entire contract), `src/token/wiTRY/StakediTry.sol` (lines 292-299), `src/token/wiTRY/crosschain/wiTryOFT.sol` (lines 84-97)

**Intended Logic:** 
The wiTRY cross-chain bridging system should maintain consistent blacklist enforcement across all chains. The hub chain uses a lock/unlock pattern where `wiTryOFTAdapter` locks shares when sending to spoke chains and unlocks them when receiving from spoke chains. Blacklisted users should be prevented from receiving tokens on any chain.

**Actual Logic:** 
`wiTryOFTAdapter` inherits the base LayerZero `OFTAdapter` implementation without overriding the `_credit()` function to handle blacklisted recipients. Meanwhile, `wiTryOFT` on spoke chains correctly implements `_credit()` override that redirects tokens to the owner if the recipient is blacklisted [2](#0-1) . This creates an asymmetry.

The critical issue is that blacklists are not synchronized between chains:
- **Hub chain**: Uses role-based blacklisting (`FULL_RESTRICTED_STAKER_ROLE` in `StakediTry`)
- **Spoke chain**: Uses mapping-based blacklisting (`blackList` mapping in `wiTryOFT`)

These are separate, independently managed blacklist systems.

**Exploitation Path:**
1. User holds wiTRY OFT tokens on spoke chain
2. User is NOT blacklisted on spoke chain (`wiTryOFT.blackList[user] = false`)
3. User IS blacklisted on hub chain (`StakediTry` grants `FULL_RESTRICTED_STAKER_ROLE`)
4. User calls `send()` on `wiTryOFT` to bridge tokens back to hub
5. **Spoke chain**: `wiTryOFT` burns user's tokens successfully (no blacklist restriction)
6. LayerZero message sent to hub chain
7. **Hub chain**: `wiTryOFTAdapter` receives message, calls inherited `_credit()` from base `OFTAdapter`
8. Base `_credit()` attempts to transfer wiTRY shares from adapter to user
9. `StakediTry._beforeTokenTransfer()` reverts because recipient has `FULL_RESTRICTED_STAKER_ROLE` [3](#0-2) 
10. LayerZero message fails, tokens remain locked in adapter
11. **Result**: Tokens burned on spoke, stuck in adapter on hub

**Security Property Broken:** 
This violates the protocol's stated concern about "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events" and creates a cross-chain blacklist synchronization vulnerability.

## Likelihood Explanation

**Attacker Profile**: Any user with wiTRY OFT tokens on spoke chains who becomes blacklisted on the hub chain (not necessarily malicious—could be legitimate users under temporary investigation or sanctioned addresses)

**Preconditions**:
1. User must bridge tokens to spoke chain before being blacklisted on hub
2. Hub and spoke blacklists must become desynchronized (user blacklisted on hub but not spoke)
3. User attempts to bridge back while in this state

**Execution Complexity**: Simple—single cross-chain bridge transaction via `wiTryOFT.send()`

**Economic Cost**: Standard bridge transaction gas fees (~$5-50 depending on L2)

**Frequency**: Can occur for every user who gets blacklisted on hub after bridging to spoke and attempts to bridge back

**Overall Likelihood**: Medium—requires specific cross-chain blacklist desynchronization state, but this is a realistic scenario for compliance operations

## Recommendation

**Primary Fix**: Override the `_credit()` function in `wiTryOFTAdapter` to implement blacklist-aware token unlocking, mirroring the protection already present in `wiTryOFT`:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFTAdapter.sol:

import {IStakediTry} from "../interfaces/IStakediTry.sol";

event SharesRedirected(address indexed originalRecipient, address indexed actualRecipient, uint256 amount);

function _credit(
    address _to,
    uint256 _amountLD,
    uint32 _srcEid
) internal virtual override returns (uint256 amountReceivedLD) {
    // Check if recipient is blacklisted (has FULL_RESTRICTED_STAKER_ROLE)
    IStakediTry stakedToken = IStakediTry(address(innerToken));
    bytes32 FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
    
    if (stakedToken.hasRole(FULL_RESTRICTED_STAKER_ROLE, _to)) {
        // Redirect to owner instead of reverting
        emit SharesRedirected(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative Mitigation**: Implement a rescue function in `wiTryOFTAdapter` that allows the contract owner to manually redirect stuck tokens to the protocol owner for manual resolution of blacklist cases.

## Notes

This vulnerability represents a design asymmetry between hub and spoke chain implementations:

1. **Spoke chain protection exists**: `wiTryOFT` correctly implements `_credit()` override to redirect blacklisted recipients to the owner [2](#0-1) 

2. **Hub chain protection missing**: `wiTryOFTAdapter` is only 33 lines with no `_credit()` override [1](#0-0) 

3. **Transfer enforcement blocks recovery**: `StakediTry._beforeTokenTransfer()` prevents ANY transfer to blacklisted addresses [3](#0-2) 

4. **Cross-chain blacklist desynchronization**: The hub chain uses role-based blacklisting while spoke chains use mapping-based blacklisting, creating opportunities for state inconsistency

5. **Protocol concern alignment**: This directly relates to the protocol's stated concern about "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events"

This is NOT the same as the known Zellic issue about allowance-based transfers (README line 35), which relates to same-chain transfers. This is a cross-chain bridge vulnerability affecting the OFT adapter's unlock mechanism.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L26-33)
```text
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
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

**File:** src/token/wiTRY/StakediTry.sol (L292-299)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
    }
```
