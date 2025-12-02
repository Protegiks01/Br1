# Validation Result: VALID HIGH SEVERITY VULNERABILITY

## Title
iTRY Tokens Permanently Stranded in OFTAdapter During WHITELIST_ENABLED Mode Due to Missing Whitelist Permission

## Summary
The `iTryTokenOFTAdapter` on the hub chain lacks the `WHITELISTED_ROLE` required to unlock tokens when iTRY enters `WHITELIST_ENABLED` transfer state. When users burn iTRY on spoke chains and LayerZero messages arrive to unlock tokens on the hub, the transfer from adapter to recipient fails, permanently locking user funds in the adapter contract with no recovery mechanism.

## Impact
**Severity**: High

This vulnerability causes permanent, unrecoverable loss of user funds during a legitimate protocol state transition. It affects ALL users performing cross-chain operations during `WHITELIST_ENABLED` mode and directly violates a core protocol invariant stated in the README: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state."

**Affected Assets**: All iTRY tokens being returned from spoke chains to hub chain during `WHITELIST_ENABLED` mode experience 100% permanent loss. Once tokens are burned on spoke chains and the adapter receives the LayerZero message on the hub chain, the tokens remain locked in the adapter with no recovery mechanism.

**User Impact**: Every user who sends iTRY from spoke chains back to hub chain during `WHITELIST_ENABLED` mode loses their funds completely. This affects legitimate cross-chain transfers, liquidity management operations, and users moving funds between chains.

## Finding Description

**Location**: `src/token/iTRY/iTry.sol` (lines 198-217) and `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol`

**Intended Logic**: The `iTryTokenOFTAdapter` should be able to unlock iTRY tokens to recipients when cross-chain messages arrive from spoke chains. The `WHITELIST_ENABLED` mode is designed to restrict normal user transfers while allowing protocol contracts to function properly.

**Actual Logic**: When iTRY enters `WHITELIST_ENABLED` mode, the `_beforeTokenTransfer` hook enforces that ALL parties (`msg.sender`, `from`, `to`) must have `WHITELISTED_ROLE` for normal transfers: [1](#0-0) 

The OFTAdapter's unlock operation is a transfer from itself to the recipient. When the adapter receives a cross-chain message and attempts to execute `token.safeTransfer(recipient, amount)`, this internally triggers a transfer where `msg.sender = adapter`, `from = adapter`, and `to = recipient`. 

The `MINTER_CONTRACT` role exemption only applies to minting operations where `from == address(0)`: [2](#0-1) 

Since the adapter is transferring existing tokens (not minting), this exemption does not apply. The adapter therefore requires `WHITELISTED_ROLE` to successfully transfer tokens, but this role is not granted during deployment.

**Exploitation Path**:
1. Admin calls `updateTransferState(TransferState.WHITELIST_ENABLED)` on hub chain iTRY token - a legitimate protocol operation to restrict transfers
2. User on spoke chain burns iTRY via `iTryTokenOFT.send()` to return tokens to hub chain
3. LayerZero relays message to hub chain `iTryTokenOFTAdapter`
4. Adapter's internal `_credit()` function attempts: `token.safeTransfer(recipient, amount)` where `msg.sender=adapter`, `from=adapter`, `to=recipient`
5. iTRY's `_beforeTokenTransfer` hook checks lines 210-213 and reverts because adapter does NOT have `WHITELISTED_ROLE`
6. Transaction reverts with `OperationNotAllowed()`, iTRY remains locked in adapter
7. No rescue mechanism exists - `iTryTokenOFTAdapter` is a simple wrapper with no recovery function [3](#0-2) 

**Security Property Broken**: This violates the protocol invariant that the whitelist system should allow protocol contracts to function while restricting user transfers. The adapter is a critical protocol contract that must be able to transfer tokens as part of the cross-chain unlock mechanism.

## Likelihood Explanation

**Attacker Profile**: No attacker required - this is a protocol-level bug triggered by legitimate admin actions combined with normal user operations. ANY user performing normal cross-chain operations becomes a victim.

**Preconditions**:
1. iTRY token on hub chain is in `WHITELIST_ENABLED` transfer state (documented feature in README)
2. `iTryTokenOFTAdapter` is not granted `WHITELISTED_ROLE` (confirmed in deployment script - only `COMPOSER_ROLE` is granted to other contracts)
3. User initiates legitimate cross-chain return from spoke to hub

**Execution Complexity**: Single cross-chain transaction - user calls `send()` on spoke chain's `iTryTokenOFT`, LayerZero delivers message to hub, adapter fails to unlock tokens.

**Frequency**: Affects every single cross-chain return transaction during `WHITELIST_ENABLED` mode until adapter is whitelisted.

**Overall Likelihood**: HIGH if `WHITELIST_ENABLED` mode is ever used. The protocol documentation explicitly mentions whitelist functionality as a feature (README line 125), making this a realistic operational scenario.

## Asymmetry Analysis

The spoke chain's `iTryTokenOFT` allows the minter (LayerZero endpoint) to mint/burn without whitelist status: [4](#0-3) 

However, on the hub chain, the adapter is NOT a `MINTER_CONTRACT` (deployment scripts confirm only `iTryIssuer` receives this role), so it doesn't receive the minting exemption. Since the adapter is transferring existing tokens rather than minting, it requires `WHITELISTED_ROLE` which it lacks.

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

**Alternative Mitigation**: Modify iTRY's `_beforeTokenTransfer` to add special handling for the OFTAdapter, similar to the `MINTER_CONTRACT` exemption, allowing it to transfer tokens to non-blacklisted recipients during `WHITELIST_ENABLED` mode.

**Emergency Recovery**: Implement an admin rescue function in `iTryTokenOFTAdapter` to recover stranded tokens, or ensure `WHITELISTED_ROLE` is granted before any `WHITELIST_ENABLED` mode activation.

## Notes

1. **Deployment Confirmation**: The deployment script grants `COMPOSER_ROLE` to other protocol contracts but does NOT grant `WHITELISTED_ROLE` to the adapter, confirming this vulnerability exists in the intended deployment configuration.

2. **No Existing Tests**: The cross-chain test suite does not test the `WHITELIST_ENABLED` scenario, allowing this vulnerability to remain undetected. Tests only cover `FULLY_ENABLED` mode operations.

3. **Similar Risk**: The same vulnerability pattern may affect `wiTryOFTAdapter` if `StakediTry` implements similar transfer restrictions, warranting separate analysis.

4. **Area of Concern Match**: The README explicitly lists "theft or loss of funds when staking/unstaking (particularly crosschain)" and "blacklist/whitelist bugs" as areas of concern. This vulnerability directly addresses both concerns.

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
