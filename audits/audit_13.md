Based on my thorough analysis of the Brix Money codebase, I have validated this security claim against all framework requirements. Here is my assessment:

## Title
Cross-Chain Share/Token Transfer to Blacklisted Recipient Causes Permanent Fund Lock in OFTAdapter

## Summary
The `wiTryOFTAdapter` and `iTryTokenOFTAdapter` contracts on L1 (hub chain) lack blacklist validation when unlocking shares/tokens for cross-chain recipients. When users bridge wiTRY shares or iTRY tokens from L2 back to L1 with a blacklisted recipient, the underlying token's `_beforeTokenTransfer` hook reverts the transfer, causing the LayerZero message to fail and permanently locking the funds in the adapter contract. This architectural inconsistency creates a one-way blacklist enforcement gap, as the spoke chain OFT contracts implement protective `_credit` overrides that the hub chain adapters lack.

## Impact
**Severity**: Medium

This represents a **Medium severity** vulnerability under the Code4rena framework due to:
- **High impact**: Complete and permanent loss of bridged funds with no recovery mechanism
- **Medium likelihood**: Requires recipient to be blacklisted on L1, but realistic given cross-chain blacklist state desynchronization and the protocol's active use of blacklisting for compliance

The combination of permanent loss with moderate preconditions yields an overall Medium severity rating.

## Finding Description

**Location:** 
- [1](#0-0) 
- [2](#0-1) 

**Intended Logic:** 
When shares/tokens are sent from L2 back to L1, the OFTAdapter should unlock them from the adapter contract and transfer them to the specified recipient address. The protocol should enforce blacklist restrictions consistently across all transfer paths to prevent blacklisted users from receiving funds.

**Actual Logic:** 
Both adapter contracts inherit from LayerZero's base `OFTAdapter` without overriding the `_credit` function. When the base implementation attempts to transfer unlocked shares/tokens to a blacklisted recipient, the underlying token's `_beforeTokenTransfer` hook reverts:

- For wiTRY: [3](#0-2)  reverts when recipient has `FULL_RESTRICTED_STAKER_ROLE`
- For iTRY: [4](#0-3)  reverts when recipient has `BLACKLISTED_ROLE`

The revert causes the entire LayerZero message to fail. Critically, the spoke chain contracts implement protective `_credit` overrides [5](#0-4)  that redirect funds to the owner when recipients are blacklisted, but the hub chain adapters lack this protection and also lack any rescue function to recover locked tokens.

**Exploitation Path:**
1. User holds wiTRY shares or iTRY tokens on L2 (OP Sepolia/MegaETH)
2. User initiates cross-chain transfer back to L1, specifying a recipient address
3. Recipient is blacklisted on L1 (could be already blacklisted, or blacklisted between transaction initiation and L1 arrival due to compliance actions)
4. LayerZero message arrives at L1 adapter, base `OFTAdapter._credit` attempts to transfer shares/tokens to recipient
5. Token's `_beforeTokenTransfer` hook checks blacklist status and reverts
6. LayerZero message execution fails, but tokens are already burned on L2
7. Shares/tokens remain permanently locked in adapter on L1 with no recovery mechanism

**Architectural Gap:**
The vulnerability stems from an architectural inconsistency:
- **Spoke chains (L2)**: Implement `_credit` overrides with blacklist protection
- **Hub chains (L1)**: No `_credit` overrides, rely on base OFTAdapter behavior
- **Result**: One-way protection gap that locks funds when bridging L2→L1

## Impact Explanation

**Affected Assets**: 
- wiTRY shares locked in `wiTryOFTAdapter` on L1 (Ethereum mainnet)
- iTRY tokens locked in `iTryTokenOFTAdapter` on L1 (Ethereum mainnet)

**Damage Severity**:
- Complete and permanent loss of 100% of shares/tokens sent in the failed cross-chain transfer
- Users cannot recover their funds as the adapters lack rescue functions (unlike other protocol contracts that implement `rescueTokens` functionality)
- Funds are effectively burned on L2 and imprisoned on L1

**User Impact**: 
Any user performing L2→L1 transfers with a blacklisted recipient loses their entire transferred amount. This affects:
- Users unknowingly sending to blacklisted addresses
- Race conditions where recipients are blacklisted between L2 transaction submission and L1 execution
- Cross-chain blacklist state desynchronization scenarios

**Recovery Options**:
1. LayerZero V2 allows message retry, but retrying will fail repeatedly if recipient remains blacklisted
2. Admin could temporarily remove blacklist to complete transfer, but this defeats the compliance purpose of blacklisting
3. No rescue function exists in adapter contracts to recover locked tokens

## Likelihood Explanation

**Attacker Profile**: 
Any user performing cross-chain transfers, no special privileges required. Can also occur through user error or legitimate compliance actions.

**Preconditions**: 
1. Recipient address must have blacklist role (`FULL_RESTRICTED_STAKER_ROLE` for wiTRY or `BLACKLISTED_ROLE` for iTRY) on L1
2. User must initiate L2→L1 cross-chain transfer via LayerZero
3. LayerZero message successfully relayed (standard operation)

**Execution Complexity**: 
Single transaction on L2 initiating the send. The vulnerability manifests automatically when the message is processed on L1.

**Realistic Scenarios**:
1. **Cross-chain blacklist desynchronization**: User address not blacklisted on L2 but blacklisted on L1 due to different compliance requirements or timing of blacklist updates
2. **Timing race condition**: Recipient blacklisted by protocol admins for legitimate compliance reasons between L2 transaction submission and L1 message arrival
3. **User error**: User unknowingly sends funds to an address that was previously blacklisted on L1

**Frequency**: 
Can occur on every L2→L1 transfer to a blacklisted recipient. Given that blacklisting is an active protocol feature for regulatory compliance and security, this scenario is realistic and expected to occur in production environments.

## Recommendation

Override the `_credit` function in both adapter contracts to match the protection pattern already implemented in the spoke chain OFT contracts. This provides consistent blacklist enforcement across all chains:

**For `wiTryOFTAdapter.sol`:**
```solidity
import {StakediTry} from "../../StakediTry.sol";

bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");

function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    StakediTry token = StakediTry(address(innerToken));
    
    // If recipient is blacklisted, redirect to owner instead
    if (token.hasRole(FULL_RESTRICTED_STAKER_ROLE, _to)) {
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**For `iTryTokenOFTAdapter.sol`:**
```solidity
import {iTry} from "../iTry.sol";

bytes32 private constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");

function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    iTry token = iTry(address(innerToken));
    
    // If recipient is blacklisted, redirect to owner instead
    if (token.hasRole(BLACKLISTED_ROLE, _to)) {
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative Mitigation**: 
Add a `rescueTokens` function to both adapters following the pattern used in other protocol contracts, allowing the owner to recover tokens locked due to failed transfers. However, the `_credit` override is preferred as it prevents the issue proactively rather than requiring manual recovery intervention.

## Notes

This vulnerability represents an architectural inconsistency in the protocol's cross-chain blacklist enforcement. The spoke chain contracts [5](#0-4)  correctly implement `_credit` overrides that redirect funds to the owner when recipients are blacklisted, demonstrating that the protocol team was aware of this risk and implemented protection on one side of the bridge. However, the hub chain adapters lack this same protection, creating a one-way enforcement gap.

The issue is particularly significant because:
1. Blacklisting is an active compliance feature, making this scenario highly likely
2. The protocol already implemented the correct pattern on spoke chains, proving this is not intentional design
3. Other protocol contracts implement `rescueTokens` functions, showing rescue mechanisms are standard practice
4. The adapters lack any rescue functionality, making fund loss truly permanent
5. The only recovery requires undermining the compliance purpose of blacklisting

This represents a clear gap in the defense-in-depth approach that should be addressed by implementing consistent blacklist handling across both hub and spoke chains.

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

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-28)
```text
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/wiTRY/StakediTry.sol (L292-298)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
```

**File:** src/token/iTRY/iTry.sol (L177-196)
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
