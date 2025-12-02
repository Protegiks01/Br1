# VALIDATION RESULT: VALID HIGH SEVERITY VULNERABILITY

## Title
OFT Cross-Chain Minting Bypasses Whitelist Enforcement in WHITELIST_ENABLED Mode

## Summary
The `_beforeTokenTransfer` hook in both iTryTokenOFT and iTry contracts contains a critical access control flaw: during cross-chain minting operations in WHITELIST_ENABLED mode, the validation only checks that recipients are not blacklisted, completely bypassing the whitelist requirement. This directly violates the protocol's documented invariant that "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state."

## Impact
**Severity**: High

This vulnerability completely undermines the protocol's regulatory compliance framework. When the protocol operates in WHITELIST_ENABLED mode—specifically designed to restrict token transfers to KYC/AML-approved addresses—any non-whitelisted address can receive iTRY tokens through LayerZero cross-chain transfers. This exposes the protocol to:

- **Regulatory Violations**: Unrestricted distribution to non-approved entities defeats the purpose of the whitelist feature
- **Compliance Failure**: The protocol cannot enforce its stated access controls for compliance-approved addresses only
- **Legal Liability**: Potential exposure to regulatory sanctions for failing to enforce stated compliance measures
- **Protocol-Wide Impact**: Affects all iTRY holders across both hub (Ethereum) and spoke (MegaETH) chains

## Finding Description

**Location:** 
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` in the `_beforeTokenTransfer` function [1](#0-0) 
- `src/token/iTRY/iTry.sol` in the `_beforeTokenTransfer` function [2](#0-1) 

**Intended Logic:** 
According to the protocol's documented invariants, in WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY tokens [3](#0-2) . The `_beforeTokenTransfer` hook must enforce this restriction for ALL token operations, including cross-chain receives.

**Actual Logic:** 
In WHITELIST_ENABLED mode, when the minter (LayerZero endpoint on spoke chain) initiates a mint operation during cross-chain receipt, the validation only verifies the recipient is NOT blacklisted, without checking whitelist status:

- **iTryTokenOFT.sol spoke chain**: The minting condition checks only `!blacklisted[to]` [4](#0-3) 

- **iTry.sol hub chain**: The minting condition checks only `!hasRole(BLACKLISTED_ROLE, to)` [5](#0-4) 

In stark contrast, normal transfers in WHITELIST_ENABLED mode correctly require ALL parties to be whitelisted:

- **iTryTokenOFT.sol normal transfers**: Requires `whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]` [6](#0-5) 

- **iTry.sol normal transfers**: Requires all parties to have `WHITELISTED_ROLE` [7](#0-6) 

**Exploitation Path:**
1. Protocol administrators set `transferState` to `WHITELIST_ENABLED` on both chains to enforce compliance-only operations [8](#0-7) 
2. Attacker (non-whitelisted but not blacklisted) coordinates with any whitelisted user holding iTRY on the opposite chain
3. The whitelisted user calls the OFT `send()` function to bridge iTRY to the attacker's address on the destination chain
4. LayerZero delivers the message, triggering `_credit()` → `_mint()` → `_beforeTokenTransfer()` with `msg.sender` as the minter/endpoint
5. The `_beforeTokenTransfer` hook's WHITELIST_ENABLED validation matches the minter condition, checking only `!blacklisted[to]` and completely bypassing the whitelist requirement
6. Attacker receives iTRY tokens despite not being whitelisted, directly violating the protocol's access control invariant

**Security Property Broken:** 
This vulnerability violates the critical documented invariant: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" [3](#0-2) 

## Impact Explanation

**Affected Assets**: All iTRY tokens on both hub (Ethereum) and spoke (MegaETH) chains when operating in WHITELIST_ENABLED mode

**Damage Severity**:
- Complete bypass of regulatory compliance controls designed for KYC/AML enforcement
- Any non-whitelisted address can receive iTRY through cross-chain transfers, rendering the whitelist feature ineffective
- Undermines the protocol's ability to restrict token access to approved entities only
- Potential exposure to regulatory violations and legal liability for failing to enforce stated compliance measures

**User Impact**: Affects all users and the protocol's compliance posture. The WHITELIST_ENABLED state is specifically intended for regulatory compliance scenarios [9](#0-8) , and its bypass allows unrestricted distribution to non-approved addresses.

## Likelihood Explanation

**Attacker Profile**: Any non-whitelisted user who can coordinate with someone holding iTRY on another chain—an extremely low barrier to exploitation

**Preconditions**:
- Protocol operating in WHITELIST_ENABLED mode (the specific state designed for compliance enforcement)
- Attacker is not blacklisted (but also not whitelisted)
- Any whitelisted user with iTRY on the opposite chain willing to send tokens

**Execution Complexity**: Single cross-chain transaction using the standard OFT `send()` function—no special privileges, complex setup, or technical sophistication required

**Economic Cost**: Only standard LayerZero cross-chain messaging fees (typically a few dollars)

**Frequency**: Can be exploited continuously by any number of users whenever the protocol operates in WHITELIST_ENABLED mode

**Overall Likelihood**: HIGH - Trivial execution, minimal preconditions, repeatable at will

## Recommendation

**Primary Fix:**

Modify the `_beforeTokenTransfer` validation logic in WHITELIST_ENABLED mode to enforce whitelist checks for minter-initiated mints:

In `src/token/iTRY/crosschain/iTryTokenOFT.sol`, line 160, add whitelist validation:
```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - now enforces whitelist in WHITELIST_ENABLED mode
```

In `src/token/iTRY/iTry.sol`, line 201, add whitelist role validation:
```solidity
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - now enforces whitelist in WHITELIST_ENABLED mode
```

**Alternative Mitigation**: Add a dedicated check at the start of the WHITELIST_ENABLED branch that validates whitelist status for the recipient in all mint operations, ensuring consistent enforcement regardless of the caller.

**Additional Recommendations**:
- Add comprehensive test coverage for cross-chain transfers in WHITELIST_ENABLED mode with non-whitelisted recipients
- Consider adding invariant tests that verify whitelist enforcement across all transfer paths
- Document the intended behavior explicitly in code comments to prevent future regressions

## Notes

**Validation Rationale:**
This vulnerability passes all critical validation checkpoints:
- ✅ Both affected files are explicitly in scope (scope.txt lines 4 and 6)
- ✅ NOT a known issue from the Zellic audit report
- ✅ Does NOT require any trusted role to act maliciously
- ✅ Violates a clearly documented protocol invariant
- ✅ Has concrete, measurable security impact (compliance bypass)
- ✅ Is trivially exploitable by any user
- ✅ Confirmed through direct code analysis with exact line citations

**Architectural Context:**
The vulnerability exists in the cross-chain token bridging flow where LayerZero's OFT (Omnichain Fungible Token) standard is used. When tokens are bridged from one chain to another, the destination chain's OFT contract mints new tokens to the recipient. The `_beforeTokenTransfer` hook is correctly invoked during this minting operation, but the validation logic incorrectly treats minter-initiated mints differently from normal transfers, creating an inconsistency that bypasses the whitelist requirement.

**Severity Justification:**
This is classified as HIGH severity because it:
1. Directly violates a documented security invariant
2. Completely undermines a critical compliance feature
3. Has broad protocol-wide impact
4. Is trivially exploitable with no special privileges required
5. Cannot be mitigated without code changes

The whitelist feature exists specifically for regulatory compliance scenarios, and its bypass exposes the protocol to potential regulatory violations—a critical risk for any real-world asset (RWA) protocol handling Turkish Money Market Fund investments.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L134-138)
```text
    function updateTransferState(TransferState code) external onlyOwner {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

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

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/token/iTRY/IiTryDefinitions.sol (L5-9)
```text
    enum TransferState {
        FULLY_DISABLED,
        WHITELIST_ENABLED,
        FULLY_ENABLED
    }
```
