# VALIDATION RESULT: VALID HIGH SEVERITY VULNERABILITY

After rigorous validation against the Brix Money Protocol framework, this security claim is **CONFIRMED VALID**.

## Title
Cross-Chain Message Failure Due to Blacklist Status Change Causes Permanent Fund Loss

## Summary
The `iTryTokenOFT` contract on spoke chains lacks protective `_credit` function override to handle blacklisted recipients during cross-chain transfers. When a user's blacklist status changes between message send and delivery, the minting operation permanently fails, causing irreversible fund loss as tokens are already locked on the source chain with no recovery mechanism.

## Impact
**Severity**: High

**Justification**: Permanent and complete loss of user funds. Tokens locked on hub chain cannot be unlocked or minted on destination chain, with no owner-controlled rescue mechanism. This violates the critical invariant that blacklisted users' funds should remain recoverable through `redistributeLockedAmount`. [1](#0-0) 

## Finding Description

**Location**: `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 140-177, `_beforeTokenTransfer` function)

**Intended Logic**: The blacklist mechanism should prevent blacklisted users from receiving iTRY tokens while ensuring their funds remain recoverable through owner-controlled redistribution.

**Actual Logic**: When a LayerZero message attempts to mint iTRY tokens to a blacklisted recipient on the spoke chain, the `_beforeTokenTransfer` check at line 145-146 requires `!blacklisted[to]` for minting operations. If the recipient is blacklisted, this condition fails and execution falls through to line 154, which reverts with `OperationNotAllowed()`.

Unlike `wiTryOFT` which implements a protective `_credit` override to redirect blacklisted recipients' funds to the contract owner, `iTryTokenOFT` has no such protection mechanism. [2](#0-1) 

**Exploitation Path**:
1. User initiates cross-chain iTRY transfer from hub chain (Ethereum) to spoke chain (MegaETH) when they are NOT blacklisted
2. `iTryTokenOFTAdapter` locks the user's iTRY tokens on the hub chain and sends LayerZero message
3. Before message delivery, protocol administrators blacklist the user on the spoke chain
4. LayerZero message arrives at `iTryTokenOFT` on spoke chain and attempts to mint tokens via base OFT `_credit()` → `_mint()` → `_beforeTokenTransfer()`
5. `_beforeTokenTransfer()` checks blacklist status and reverts because recipient is now blacklisted
6. Message execution fails, but tokens are permanently locked on hub chain with no mechanism to unlock or redirect them [3](#0-2) 

**Security Property Broken**: The system correctly prevents blacklisted users from receiving tokens but creates an unintended consequence where their funds become permanently locked rather than being redistributable by the owner as designed.

## Impact Explanation

**Affected Assets**: iTRY tokens locked in `iTryTokenOFTAdapter` on hub chain that cannot be unlocked or minted on spoke chain.

**Damage Severity**: Complete and permanent loss of user funds. Tokens are locked on source chain but cannot be minted on destination chain, with no recovery mechanism. Amount lost equals the full cross-chain transfer amount.

**User Impact**: Any user performing cross-chain iTRY transfers is at risk. The timing window exists between transaction initiation and LayerZero message delivery (typically seconds to hours depending on network conditions). Multiple users can be affected simultaneously if blacklist updates occur during high cross-chain activity periods.

**Recovery Options**: NONE. The `iTryTokenOFTAdapter` is a bare-bones contract with no rescue functions. Standard LayerZero V2 retry mechanisms cannot help because retrying a message that always reverts due to blacklist status provides no solution.

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is a protocol design flaw. Normal users making legitimate cross-chain transfers become victims when their blacklist status changes mid-flight.

**Preconditions**:
1. User must initiate cross-chain iTRY transfer while not blacklisted
2. Blacklist Manager must blacklist the user before LayerZero message delivery
3. LayerZero message delivery delay provides timing window

**Execution Complexity**: Unintentional exploitation - occurs naturally when blacklist updates happen during normal cross-chain operations. No malicious coordination required.

**Frequency**: Can occur multiple times, affecting different users. Risk increases during periods of regulatory action when multiple addresses are blacklisted simultaneously.

**Overall Likelihood**: MEDIUM to HIGH - While requires specific timing, blacklist updates during active cross-chain periods make this a realistic scenario.

## Recommendation

Override the `_credit` function in `iTryTokenOFT` to match the protective behavior implemented in `wiTryOFT`:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add after line 177:

/**
 * @dev Credits tokens to the recipient while checking if the recipient is blacklisted.
 * If blacklisted, redistributes the funds to the contract owner.
 * @param _to The address of the recipient.
 * @param _amountLD The amount of tokens to credit.
 * @param _srcEid The source endpoint identifier.
 * @return amountReceivedLD The actual amount of tokens received.
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
    if (blacklisted[_to]) {
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

This ensures that:
1. Cross-chain messages always complete successfully even if recipient becomes blacklisted
2. Blacklisted users' funds are automatically redirected to owner (matching existing `redistributeLockedAmount` pattern)
3. No funds are permanently locked due to timing issues
4. Consistent behavior with `wiTryOFT` implementation

## Notes

This vulnerability demonstrates a critical architectural inconsistency between `wiTryOFT` and `iTryTokenOFT`. While `wiTryOFT` implements protective `_credit` override to handle blacklisted recipients gracefully by redirecting to owner, `iTryTokenOFT` relies solely on `_beforeTokenTransfer` checks which cause transaction reverts.

The issue is distinct from the known issue "Native fee loss on failed wiTryVaultComposer.lzReceive execution" which concerns fee underpayment requiring double payment in **composer operations**. This vulnerability concerns complete and permanent **principal loss** in **standard OFT transfers** due to blacklist timing.

The `iTryTokenOFTAdapter` is a bare-bones contract inheriting only from `OFTAdapter` with no additional rescue functions, confirming there is no recovery path for locked tokens. [3](#0-2)

### Citations

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
