# VALIDATION RESULT: VALID HIGH SEVERITY VULNERABILITY

After performing rigorous validation against the Brix Money Protocol Validation Framework, this security claim is **CONFIRMED VALID**.

---

## Title
Whitelist Bypass via Cross-Chain Minting Allows Non-Whitelisted Addresses to Receive iTRY on Spoke Chain

## Summary
The `iTryTokenOFT` and `iTry` contracts fail to enforce whitelist requirements during minting operations in `WHITELIST_ENABLED` mode. The `_beforeTokenTransfer` function only validates that the recipient is not blacklisted, but does not verify whitelist membership, allowing LayerZero to mint tokens to any non-blacklisted address. This completely bypasses the protocol's documented invariant requiring whitelist enforcement.

## Impact
**Severity**: High

This vulnerability enables complete bypass of the whitelist access control system during restricted operational periods. When the protocol operates in `WHITELIST_ENABLED` mode (intended for KYC/AML compliance, security incidents, or controlled rollouts), unauthorized users can still receive iTRY tokens via cross-chain bridging. [1](#0-0)  This defeats the entire purpose of the whitelist system and could enable regulatory compliance violations, distribution to unverified actors, circumvention of KYC requirements, and inability to enforce restricted token distribution during critical operational states.

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol:160-161` and `src/token/iTRY/iTry.sol:201-202`, function `_beforeTokenTransfer()`

**Intended Logic:**
According to the protocol's documented invariant, "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" [1](#0-0) . This means that receiving tokens (including via minting) should require the recipient to be whitelisted when the contract is in `WHITELIST_ENABLED` mode.

**Actual Logic:**
The minting check in `WHITELIST_ENABLED` mode only validates `!blacklisted[to]` but completely omits the `whitelisted[to]` check [2](#0-1) . In contrast, normal transfers in the same mode require ALL parties to be whitelisted [3](#0-2) .

**Exploitation Path:**
1. **Setup**: Protocol owner sets `transferState = WHITELIST_ENABLED` on spoke chain to restrict operations to approved addresses
2. **Attacker Position**: Attacker is NOT whitelisted on spoke chain but NOT blacklisted either; has iTRY tokens on hub chain
3. **Trigger**: Attacker initiates cross-chain bridge transfer from hub chain via `iTryTokenOFTAdapter`
4. **Message Delivery**: LayerZero delivers message to spoke chain `iTryTokenOFT` with attacker's address as recipient
5. **Minting Flow**: LayerZero endpoint (set as `minter` in constructor [4](#0-3) ) calls `_credit` → `_mint` → `_beforeTokenTransfer`
6. **Bypass**: Check at line 160-161 passes because attacker is not blacklisted, despite not being whitelisted [5](#0-4) 
7. **Result**: Tokens successfully minted to non-whitelisted attacker, violating the documented invariant

**Dual Vulnerability:**
The identical issue exists in the hub chain `iTry.sol` contract at line 201, where minting in `WHITELIST_ENABLED` mode also omits the whitelist check [6](#0-5) .

## Impact Explanation

**Affected Assets**: iTRY tokens on all chains (hub and spoke chains), protocol's whitelist access control system

**Damage Severity**:
- Complete bypass of whitelist enforcement during `WHITELIST_ENABLED` operational mode
- Any user with hub chain iTRY access can receive tokens on spoke chains regardless of whitelist status
- Protocol loses ability to enforce restricted token distribution during critical phases
- Potential regulatory violations if whitelist is used for KYC/AML compliance
- Security incident response failure if whitelist is activated to contain threats

**User Impact**: All non-whitelisted users gain unauthorized access to receive iTRY tokens during restricted periods, completely undermining the protocol's access control guarantees

## Likelihood Explanation

**Attacker Profile**: Any user with iTRY tokens on hub chain or access to them; no special privileges required

**Preconditions**:
1. Spoke chain `iTryTokenOFT` has `transferState = WHITELIST_ENABLED` (intended restricted mode)
2. Attacker is not blacklisted (but doesn't need to be whitelisted)
3. Attacker has iTRY tokens on hub chain
4. Cross-chain bridge operational (normal operational state)

**Execution Complexity**: Single cross-chain transaction via standard LayerZero OFT bridging flow; no complex coordination or special timing required

**Economic Cost**: Standard gas fees plus LayerZero cross-chain messaging fees

**Frequency**: Exploitable repeatedly by any non-whitelisted user whenever whitelist mode is active; no cooldown or rate limiting

**Overall Likelihood**: HIGH - Easy to execute, minimal preconditions, affects core security functionality

## Recommendation

**Primary Fix for iTryTokenOFT.sol:**

In `src/token/iTRY/crosschain/iTryTokenOFT.sol`, function `_beforeTokenTransfer`, modify line 160 to include whitelist check: [2](#0-1) 

Change to:
```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - enforce whitelist requirement
```

**Consistency Fix for Owner Redistribution:**

Also update line 164 for owner redistribution minting: [7](#0-6) 

Change to:
```solidity
} else if (msg.sender == owner() && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // redistributing - mint - enforce whitelist requirement
```

**Fix for Hub Chain:**

Apply the same fix to `src/token/iTRY/iTry.sol` at line 201: [6](#0-5) 

Change to:
```solidity
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - enforce whitelist requirement
```

And line 205-207: [8](#0-7) 

Change to:
```solidity
} else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // redistributing - mint - enforce whitelist requirement
```

**Additional Mitigations:**
- Add invariant tests that verify whitelist enforcement during minting operations
- Consider comprehensive audit of all `_beforeTokenTransfer` paths to ensure consistent access control enforcement
- Add events when whitelist mode blocks minting attempts for monitoring

## Notes

**Validation Confirmed:**

1. ✅ **In-Scope Files**: Both `iTryTokenOFT.sol` and `iTry.sol` are in the audit scope
2. ✅ **Code Evidence**: Missing `whitelisted[to]` check confirmed at exact line numbers with direct code inspection
3. ✅ **Invariant Violation**: Documented protocol invariant explicitly requires whitelist enforcement for receiving tokens
4. ✅ **No Trusted Role Misbehavior**: Exploit requires only unprivileged user action (cross-chain bridging)
5. ✅ **Not a Known Issue**: Not listed in Zellic audit known issues or README
6. ✅ **Realistic Exploitation**: Standard cross-chain bridging flow, no complex attack coordination
7. ✅ **High Severity Impact**: Complete bypass of critical access control mechanism

**Key Insight:**

The vulnerability stems from inconsistent validation logic within the same `_beforeTokenTransfer` function. Normal transfers require all parties to be whitelisted [3](#0-2) , but minting only checks blacklist status [2](#0-1) . This inconsistency creates a bypass path specifically for cross-chain minting operations.

**Protocol Impact:**

This affects the protocol's ability to operate in restricted modes, which may be required for initial controlled rollout phases, regulatory compliance during audits or investigations, emergency response to security incidents, geographic or jurisdictional restrictions, and KYC/AML enforcement periods. The fix is straightforward (adding `&& whitelisted[to]` to minting conditions), but the current vulnerability completely undermines a core security feature of the protocol.

### Citations

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L53-53)
```text
        minter = _lzEndpoint;
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

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L205-207)
```text
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
```
