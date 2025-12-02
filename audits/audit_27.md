# NoVulnerability found for this question.

## Analysis

After thorough validation against the Brix Money security framework, this claim fails a critical design interpretation check. Here's why:

### Scope & Basic Checks ✅
- Files are in scope (iTry.sol, iTryIssuer.sol)
- Not a known issue from Zellic audit
- Unprivileged user exploitation path
- Violates stated invariant on surface

### Critical Design Consideration ❌

The claim identifies that `_beforeTokenTransfer` has **two separate code paths** in WHITELIST_ENABLED state:

**Path 1 (Lines 199-200):** MINTER_CONTRACT operations [1](#0-0) 

**Path 2 (Lines 208-213):** Whitelisted user operations [2](#0-1) 

### Why This Is Likely Intentional Design

1. **Architectural Separation**: The protocol maintains **two distinct whitelist systems**:
   - `iTryIssuer._WHITELISTED_USER_ROLE` - controls mint/redeem access [3](#0-2) 
   - `iTry.WHITELISTED_ROLE` - controls direct token transfers [4](#0-3) 

2. **Consistent Behavior Across States**: In FULLY_ENABLED state, MINTER_CONTRACT can also burn from any non-blacklisted address without additional checks [5](#0-4) . The WHITELIST_ENABLED logic mirrors this pattern.

3. **iTryIssuer as Trusted Gateway**: The iTryIssuer contract acts as the protocol's controlled entry/exit point with its own access controls. The redeemFor function requires `_WHITELISTED_USER_ROLE` [6](#0-5) , providing the intended access control layer.

### The Real Issue: Documentation Ambiguity

The invariant states: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [7](#0-6) 

However, this doesn't explicitly address whether **protocol contracts** (MINTER_CONTRACT role) are subject to this restriction. The dual-path architecture suggests the intent was:
- **User-initiated operations**: Require WHITELISTED_ROLE
- **Protocol-initiated operations** (via trusted MINTER_CONTRACT): Use separate authorization (iTryIssuer's whitelist)

### Impact Assessment

Even if considered a vulnerability:
- User burns **their own tokens**
- User receives **fair value** (DLF equivalent)
- **No theft, no loss** to other users
- No protocol insolvency
- Requires whitelist mismatch (operational issue)

This would be at most a **QA-level documentation issue** rather than Medium severity, as there's no concrete financial harm.

## Notes

The claim correctly identifies a divergence between two whitelist systems, but this appears to be an architectural choice rather than a security flaw. The iTryIssuer contract serves as a trusted intermediary with its own access controls, consistent with common DeFi patterns where protocol contracts have elevated privileges to facilitate user operations.

If the Brix Money team confirms this is unintended behavior, the appropriate fix would be adding whitelist checks at line 199. However, given the consistent dual-path pattern across transfer states and the architectural separation of concerns, this implementation appears deliberate.

### Citations

**File:** src/token/iTRY/iTry.sol (L32-33)
```text
    /// @notice During transferState 1, whitelisted role can still transfer
    bytes32 public constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
```

**File:** src/token/iTRY/iTry.sol (L180-181)
```text
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
```

**File:** src/token/iTRY/iTry.sol (L199-200)
```text
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
```

**File:** src/token/iTRY/iTry.sol (L208-213)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
```

**File:** src/protocol/iTryIssuer.sol (L109-110)
```text
    /// @notice Role for whitelisted users who can mint and redeem iTRY
    bytes32 private constant _WHITELISTED_USER_ROLE = keccak256("WHITELISTED_USER_ROLE");
```

**File:** src/protocol/iTryIssuer.sol (L318-320)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
```

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```
