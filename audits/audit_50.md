# Validation Result: VALID HIGH SEVERITY VULNERABILITY

## Title
iTRY Tokens Permanently Stranded in OFTAdapter During WHITELIST_ENABLED Mode Due to Missing Whitelist Permission

## Summary
The `iTryTokenOFTAdapter` on the hub chain lacks the `WHITELISTED_ROLE` required to unlock tokens when iTRY enters `WHITELIST_ENABLED` transfer state. When users burn iTRY on spoke chains and LayerZero messages arrive to unlock tokens on the hub, the transfer from adapter to recipient fails, permanently locking user funds in the adapter contract with no recovery mechanism.

## Impact
**Severity**: High

**Rationale**: This vulnerability causes permanent, unrecoverable loss of user funds during a legitimate protocol state transition. It affects ALL users performing cross-chain operations during `WHITELIST_ENABLED` mode and violates a core protocol invariant.

**Affected Assets**: All iTRY tokens being returned from spoke chains to hub chain during `WHITELIST_ENABLED` mode

**Damage Severity**: 100% permanent loss. Once tokens are burned on spoke chains and locked in the adapter on hub chain, they cannot be recovered. The base `OFTAdapter` contract has no rescue function, and `iTryTokenOFTAdapter` is a simple wrapper with no additional recovery logic.

**User Impact**: Every user who sends iTRY from spoke chains back to hub chain during `WHITELIST_ENABLED` mode loses their funds. This includes legitimate cross-chain transfers, liquidity management, and users moving funds between chains.

## Finding Description

**Location**: `src/token/iTRY/iTry.sol` (lines 198-217) and `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol`

**Intended Logic**: The `iTryTokenOFTAdapter` should be able to unlock iTRY tokens to recipients when cross-chain messages arrive from spoke chains. The `WHITELIST_ENABLED` mode should restrict normal user transfers while allowing protocol contracts to function.

**Actual Logic**: When iTRY enters `WHITELIST_ENABLED` mode, the `_beforeTokenTransfer` hook requires ALL parties (`msg.sender`, `from`, `to`) to have `WHITELISTED_ROLE` for normal transfers: [1](#0-0) 

The OFTAdapter's unlock operation is a transfer from itself to the recipient, which fails if the adapter lacks `WHITELISTED_ROLE`. The `MINTER_CONTRACT` role exemption only applies to minting operations (`from == address(0)`), not transfers: [2](#0-1) 

**Exploitation Path**:
1. Admin calls `updateTransferState(TransferState.WHITELIST_ENABLED)` on hub chain iTRY token - a legitimate protocol operation to restrict transfers
2. User on spoke chain burns iTRY via `iTryTokenOFT.send()` to return tokens to hub chain
3. LayerZero relays message to hub chain `iTryTokenOFTAdapter`
4. Adapter's internal `_credit()` function attempts: `token.safeTransfer(recipient, amount)` where `msg.sender=adapter`, `from=adapter`, `to=recipient`
5. iTRY's `_beforeTokenTransfer` hook checks lines 210-213 and reverts because adapter does NOT have `WHITELISTED_ROLE`
6. Transaction reverts with `OperationNotAllowed()`, iTRY remains locked in adapter
7. No rescue mechanism exists - `iTryTokenOFTAdapter` has no recovery function

**Security Property Broken**: Violates the protocol invariant stated in README: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." The adapter is a protocol contract that needs to transfer tokens but is not whitelisted, creating a scenario where legitimate cross-chain operations permanently lock user funds.

**Code Evidence**: The adapter is a simple wrapper with no special logic or recovery mechanisms: [3](#0-2) 

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is a protocol-level bug triggered by legitimate admin actions. ANY user performing normal cross-chain operations becomes a victim.

**Preconditions**:
1. iTRY token on hub chain is in `WHITELIST_ENABLED` transfer state
2. `iTryTokenOFTAdapter` is not granted `WHITELISTED_ROLE` (current deployment does not grant this role)
3. User initiates cross-chain return from spoke to hub

**Execution Complexity**: Single cross-chain transaction - user calls `send()` on spoke chain's `iTryTokenOFT`, LayerZero delivers message, adapter fails to unlock.

**Frequency**: Affects every single cross-chain return transaction during `WHITELIST_ENABLED` mode until adapter is whitelisted.

**Overall Likelihood**: HIGH if `WHITELIST_ENABLED` mode is ever used. The protocol documentation explicitly mentions whitelist functionality as a feature, making this a realistic scenario.

## Recommendation

**Primary Fix**: Grant `WHITELISTED_ROLE` to `iTryTokenOFTAdapter` during deployment and add validation to `updateTransferState()`:

```solidity
// In iTry.sol updateTransferState function:
function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (code == TransferState.WHITELIST_ENABLED) {
        // Verify critical protocol contracts are whitelisted
        require(
            hasRole(WHITELISTED_ROLE, oftAdapterAddress),
            "iTryTokenOFTAdapter must be whitelisted before enabling WHITELIST_ENABLED mode"
        );
    }
    TransferState prevState = transferState;
    transferState = code;
    emit TransferStateUpdated(prevState, code);
}
```

**Alternative Mitigation**: Modify iTRY's `_beforeTokenTransfer` to add special handling for the OFTAdapter, similar to how the spoke chain's `iTryTokenOFT` handles the minter:

```solidity
} else if (transferState == TransferState.WHITELIST_ENABLED) {
    // ... existing MINTER_CONTRACT checks ...
    } else if (
        msg.sender == oftAdapterAddress && 
        from == msg.sender && 
        !hasRole(BLACKLISTED_ROLE, to)
    ) {
        // Allow adapter to unlock tokens to non-blacklisted recipients
    } else if (
        hasRole(WHITELISTED_ROLE, msg.sender) && ...
```

**Emergency Recovery**: Implement an admin rescue function in `iTryTokenOFTAdapter` to recover stranded tokens, or ensure `WHITELISTED_ROLE` is granted before any `WHITELIST_ENABLED` mode activation.

## Notes

1. **Asymmetry with Spoke Chain**: The spoke chain's `iTryTokenOFT` (lines 158-161) allows the minter (LayerZero endpoint) to mint/burn without whitelist status. However, on the hub chain, the adapter is NOT a `MINTER_CONTRACT`, so it doesn't receive this exemption, creating the vulnerability. [4](#0-3) 

2. **Area of Concern Match**: README explicitly mentions concern about "theft or loss of funds when staking/unstaking (particularly crosschain)" and "blacklist/whitelist bugs". This vulnerability directly addresses both concerns.

3. **Deployment Gap**: While deployment scripts are out of scope for vulnerabilities, the evidence shows the deployment script grants `COMPOSER_ROLE` to other contracts but does NOT grant `WHITELISTED_ROLE` to the adapter, confirming the vulnerability exists in the intended deployment configuration.

4. **Similar Risk in wiTRY**: The same vulnerability pattern may affect `wiTryOFTAdapter` if `StakediTry` implements transfer restrictions, warranting separate analysis.

5. **No Existing Tests**: The cross-chain test suite (`Step5_BasicOFTTransfer.t.sol`) does not test the `WHITELIST_ENABLED` scenario, allowing this vulnerability to remain undetected.

### Citations

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L210-213)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L158-161)
```text
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```
