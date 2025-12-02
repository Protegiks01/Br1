## VALIDATION RESULT: VALID HIGH SEVERITY VULNERABILITY

After performing strict validation against the Brix Money Protocol Validation Framework, this security claim is **CONFIRMED VALID**.

---

## Title
Whitelist Bypass via Cross-Chain Minting Allows Non-Whitelisted Addresses to Receive iTRY on Spoke Chain

## Summary
The `iTryTokenOFT` and `iTry` contracts fail to enforce whitelist requirements during minting operations in `WHITELIST_ENABLED` mode. The `_beforeTokenTransfer` function only validates that the recipient is not blacklisted, but does not verify whitelist membership, allowing LayerZero to mint tokens to any non-blacklisted address. This completely bypasses the protocol's documented invariant requiring whitelist enforcement.

## Impact
**Severity**: High

This vulnerability enables complete bypass of the whitelist access control system during restricted operational periods. When the protocol operates in `WHITELIST_ENABLED` mode (intended for KYC/AML compliance, security incidents, or controlled rollouts), unauthorized users can still receive iTRY tokens via cross-chain bridging. This defeats the entire purpose of the whitelist system and could enable:
- Regulatory compliance violations
- Distribution to unverified or malicious actors
- Circumvention of KYC requirements during restricted phases
- Protocol's inability to enforce who can hold tokens during critical operational states

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol`, function `_beforeTokenTransfer()`

**Intended Logic:**
According to the protocol's documented invariant, "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" [1](#0-0) . This means that receiving tokens (including via minting) should require the recipient to be whitelisted when the contract is in `WHITELIST_ENABLED` mode.

**Actual Logic:**
The minting check in `WHITELIST_ENABLED` mode only validates `!blacklisted[to]` but completely omits the `whitelisted[to]` check [2](#0-1) .

In contrast, normal transfers in the same mode require ALL parties to be whitelisted [3](#0-2) .

**Exploitation Path:**
1. **Setup**: Protocol owner sets `transferState = WHITELIST_ENABLED` on spoke chain to restrict operations to approved addresses
2. **Attacker Position**: Attacker is NOT whitelisted on spoke chain but NOT blacklisted either; has iTRY tokens on hub chain
3. **Trigger**: Attacker initiates cross-chain bridge transfer from hub chain via `iTryTokenOFTAdapter`
4. **Message Delivery**: LayerZero delivers message to spoke chain `iTryTokenOFT` with attacker's address as recipient
5. **Minting Flow**: LayerZero endpoint (set as `minter` in constructor [4](#0-3) ) calls `_credit` → `_mint` → `_beforeTokenTransfer`
6. **Bypass**: Check at line 160-161 passes because attacker is not blacklisted, despite not being whitelisted
7. **Result**: Tokens successfully minted to non-whitelisted attacker, violating the documented invariant

**Security Property Broken:**
Protocol invariant from README: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" [1](#0-0) 

**Dual Vulnerability:**
The identical issue exists in the hub chain `iTry.sol` contract, where minting in `WHITELIST_ENABLED` mode also omits the whitelist check [5](#0-4) .

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

**Economic Cost**: Standard gas fees plus LayerZero cross-chain messaging fees (~$10-50 depending on chains)

**Frequency**: Exploitable repeatedly by any non-whitelisted user whenever whitelist mode is active; no cooldown or rate limiting

**Overall Likelihood**: HIGH - Easy to execute, minimal preconditions, affects core security functionality

## Recommendation

**Primary Fix for iTryTokenOFT.sol:**

In `src/token/iTRY/crosschain/iTryTokenOFT.sol`, function `_beforeTokenTransfer`, modify the minting validation to include whitelist check (line 160):

```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // minting - enforce whitelist requirement
```

**Consistency Fix for Owner Redistribution:**

Also update the owner redistribution minting logic for consistency (line 164):

```solidity
} else if (msg.sender == owner() && from == address(0) && !blacklisted[to] && whitelisted[to]) {
    // redistributing - mint - enforce whitelist requirement
```

**Fix for Hub Chain:**

Apply the same fix to `src/token/iTRY/iTry.sol` at line 201 to maintain consistency across the protocol:

```solidity
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - enforce whitelist requirement
```

And at line 205-207 for consistency:

```solidity
} else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // redistributing - mint - enforce whitelist requirement
```

**Additional Mitigations:**
- Add invariant tests that verify whitelist enforcement during minting operations in `WHITELIST_ENABLED` mode
- Consider comprehensive audit of all `_beforeTokenTransfer` paths to ensure consistent access control enforcement across all transfer states
- Add events when whitelist mode blocks minting attempts for monitoring and security incident response

## Notes

**Validation Confirmed:**

1. ✅ **In-Scope Files**: Both `iTryTokenOFT.sol` and `iTry.sol` are in the audit scope
2. ✅ **Code Evidence**: Missing `whitelisted[to]` check confirmed at exact line numbers with direct code inspection [6](#0-5) 
3. ✅ **Invariant Violation**: Documented protocol invariant explicitly requires whitelist enforcement for receiving tokens [1](#0-0) 
4. ✅ **No Trusted Role Misbehavior**: Exploit requires only unprivileged user action (cross-chain bridging)
5. ✅ **Not a Known Issue**: Not listed in Zellic audit known issues [7](#0-6) 
6. ✅ **Realistic Exploitation**: Standard cross-chain bridging flow, no complex attack coordination
7. ✅ **High Severity Impact**: Complete bypass of critical access control mechanism

**Key Insight:**

The vulnerability stems from inconsistent validation logic within the same `_beforeTokenTransfer` function. Normal transfers require all parties to be whitelisted [3](#0-2) , but minting only checks blacklist status [2](#0-1) . This inconsistency creates a bypass path specifically for cross-chain minting operations.

**Protocol Impact:**

This affects the protocol's ability to operate in restricted modes, which may be required for:
- Initial controlled rollout phases
- Regulatory compliance during audits or investigations
- Emergency response to security incidents
- Geographic or jurisdictional restrictions
- KYC/AML enforcement periods

The fix is straightforward (adding `&& whitelisted[to]` to minting conditions), but the current vulnerability completely undermines a core security feature of the protocol.

### Citations

**File:** README.md (L33-41)
```markdown
The codebase has undergone a Zellic audit with a fix review pending. The following issues identified in the Zellic audit are considered out-of-scope, with some being fixed in the current iteration of the codebase:

-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
- Griefing attacks around the `MIN_SHARES` variable of the ERC2646 vault: The protocol will perform an initial deposit to offset this risk. 
- The `redistributeLockedAmount` does not validate that the resulted `totalSupply` is not less than the minimum threshold. As a result of executing the `redistributeLockedAmount` function, the `totalSupply` amount may fall within a prohibited range between 0 and `MIN_SHARES` amount. And subsequent legitimate
deposits or withdrawals operations, which do not increase totalSupply to the `MIN_SHARES` value will be blocked.
- iTRY backing can fall below 1:1 on NAV drop. If NAV drops below 1, iTRY becomes undercollateralized with no guaranteed, on-chain remediation. Holders bear insolvency risk until a top-up or discretionary admin intervention occurs.
- Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request.
- Non-standard ERC20 tokens may break the transfer function. If a non-standard token is recovered using a raw transfer, the function may appear to succeed, even though no tokens were transferred, or it may revert unexpectedly. This can result in tokens becoming stuck in the contract, which breaks the tokens rescue mechanism.
```

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
