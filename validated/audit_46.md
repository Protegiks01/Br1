## Title
OFT Cross-Chain Minting Bypasses Whitelist Enforcement in WHITELIST_ENABLED Mode

## Summary
The `_beforeTokenTransfer` hook in `iTryTokenOFT.sol` and `iTry.sol` fails to enforce whitelist restrictions during cross-chain minting operations when contracts operate in `WHITELIST_ENABLED` state. This allows non-whitelisted addresses to receive iTRY tokens via LayerZero cross-chain transfers, completely bypassing the protocol's regulatory compliance controls designed to restrict token access to KYC/AML-approved addresses only.

## Impact
**Severity**: High

The vulnerability enables complete bypass of the whitelist access control mechanism, which is the protocol's primary tool for regulatory compliance. When operating in `WHITELIST_ENABLED` mode—specifically designed to restrict iTRY operations to approved addresses—any non-whitelisted address can receive iTRY tokens through cross-chain transfers from either hub (Ethereum) or spoke (MegaETH) chains. This undermines the protocol's ability to enforce KYC/AML requirements and exposes it to potential regulatory violations and legal liability. All iTRY tokens across both chains are affected when the protocol operates in this compliance-restricted state. [1](#0-0) 

## Finding Description

**Location:** 
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` lines 157-172, function `_beforeTokenTransfer()`
- `src/token/iTRY/iTry.sol` lines 198-217, function `_beforeTokenTransfer()`

**Intended Logic:**
According to the protocol's critical invariants, in `WHITELIST_ENABLED` state, ONLY whitelisted users can send/receive/burn iTRY tokens. [1](#0-0)  The `_beforeTokenTransfer` hook should enforce this restriction uniformly across all token operations, including cross-chain minting when tokens arrive via LayerZero messages.

**Actual Logic:**
In `WHITELIST_ENABLED` mode, when the minter (LayerZero endpoint on spoke chain) initiates a mint operation during cross-chain token receipt, the validation only verifies the recipient is NOT blacklisted, without checking whitelist status: [2](#0-1) [3](#0-2) 

In contrast, normal transfers in `WHITELIST_ENABLED` mode correctly require ALL parties (msg.sender, from, to) to be whitelisted: [4](#0-3) [5](#0-4) 

**Exploitation Path:**
1. Protocol administrators set `transferState` to `WHITELIST_ENABLED` on both hub and spoke chains to restrict operations to compliance-approved addresses [6](#0-5) 
2. Non-whitelisted attacker coordinates with any whitelisted user possessing iTRY tokens on the opposite chain
3. Whitelisted user calls OFT `send()` function to bridge iTRY to the attacker's non-whitelisted address on destination chain
4. LayerZero delivers the message, triggering the destination chain's `_credit()` → `_mint(attackerAddress, amount)` → `_beforeTokenTransfer(address(0), attackerAddress, amount)` with `msg.sender` = minter (LayerZero endpoint)
5. The `_beforeTokenTransfer` hook's WHITELIST_ENABLED validation matches the minting condition at lines 160-161 (iTryTokenOFT.sol) or 201-202 (iTry.sol), checking only `!blacklisted[to]` without verifying `whitelisted[to]`
6. Attacker receives iTRY tokens despite not being whitelisted, violating the protocol's documented access control invariant

**Security Property Broken:**
Violates the critical invariant: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" [1](#0-0) 

## Impact Explanation

**Affected Assets**: All iTRY tokens on both hub (Ethereum) and spoke (MegaETH) chains when operating in `WHITELIST_ENABLED` mode

**Damage Severity**: Complete circumvention of regulatory compliance controls. Any non-whitelisted address can acquire iTRY tokens through cross-chain transfers, fundamentally undermining the protocol's ability to enforce KYC/AML requirements or restrict token distribution to jurisdictionally-approved entities. This creates direct regulatory exposure, potential sanctions violations if blacklisted-but-not-protocol-blacklisted entities acquire tokens, and legal liability for the protocol operators.

**User Impact**: Affects the entire protocol's compliance posture and all legitimate users who rely on the whitelist mechanism for regulatory assurance. The whitelist feature exists specifically for regulatory compliance [7](#0-6) , and its bypass enables unrestricted token distribution to non-approved addresses during periods when compliance restrictions should be enforced.

## Likelihood Explanation

**Attacker Profile**: Any non-whitelisted individual or entity capable of coordinating with someone holding iTRY on another chain—an extremely low barrier requiring no special technical skills, privileges, or capital beyond basic cross-chain transaction fees.

**Preconditions**:
- Protocol operating in `WHITELIST_ENABLED` mode (the specific state designed for compliance enforcement)
- Attacker is not blacklisted (but critically, also not whitelisted)
- Any user with iTRY balance on the opposite chain willing to send tokens (could be the attacker using a compliant intermediary, a social engineering victim, or a paid service)

**Execution Complexity**: Single cross-chain transaction using the standard LayerZero OFT `send()` function—no special privileges, complex contract interactions, or advanced technical knowledge required. The attack leverages normal protocol functionality.

**Frequency**: Continuously exploitable by unlimited users whenever the protocol operates in `WHITELIST_ENABLED` mode. Each cross-chain transfer to a non-whitelisted recipient constitutes a successful bypass.

**Overall Likelihood**: HIGH - The attack is trivial to execute during the specific protocol state (WHITELIST_ENABLED) when compliance enforcement is most critical.

## Recommendation

Modify the `_beforeTokenTransfer` validation logic in `WHITELIST_ENABLED` mode to enforce whitelist checks for minter-initiated mints. The minting case should verify the recipient is whitelisted, not merely non-blacklisted.

**For `src/token/iTRY/crosschain/iTryTokenOFT.sol` line 160:**

Change the condition from:
```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
```

To:
```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
```

**For `src/token/iTRY/iTry.sol` line 201:**

Change the condition from:
```solidity
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
```

To:
```solidity
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
```

**Alternative Mitigation**: Add a dedicated check at the beginning of the `WHITELIST_ENABLED` branch that validates the recipient's whitelist status for ALL mint operations (`from == address(0)`), ensuring consistent enforcement regardless of the caller's role. This would provide defense-in-depth and prevent similar issues if additional minting patterns are introduced.

**Additional Recommendations**:
- Add integration tests specifically covering cross-chain transfers to non-whitelisted addresses in `WHITELIST_ENABLED` mode to verify the fix
- Consider adding invariant tests that verify no non-whitelisted address can receive iTRY tokens when `transferState == WHITELIST_ENABLED`
- Review all other state transition branches to ensure consistent whitelist enforcement across all operation types

## Notes

This vulnerability represents a critical gap between the protocol's documented security invariants and its actual implementation. While the whitelist mechanism functions correctly for direct on-chain transfers, the cross-chain minting path—a core feature of the multi-chain architecture—fails to apply the same restrictions.

The issue is particularly severe because:
1. It affects the `WHITELIST_ENABLED` state specifically designed for regulatory compliance scenarios
2. The bypass is not obvious to protocol administrators who may believe enabling whitelist mode provides comprehensive access control
3. Cross-chain operations are a primary use case for the protocol, making this attack vector highly accessible

The vulnerability exists in both `iTryTokenOFT.sol` (spoke chain) and `iTry.sol` (hub chain), though the most direct exploitation path is through the spoke chain where true minting occurs during cross-chain receives. On the hub chain, the OFTAdapter unlocks tokens rather than minting, but any contract with `MINTER_CONTRACT` role would exhibit the same vulnerability pattern when calling the `mint()` function directly.

### Citations

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L134-138)
```text
    function updateTransferState(TransferState code) external onlyOwner {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L160-161)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L168-169)
```text
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
```

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

**File:** src/token/iTRY/IiTryDefinitions.sol (L5-9)
```text
    enum TransferState {
        FULLY_DISABLED,
        WHITELIST_ENABLED,
        FULLY_ENABLED
    }
```
