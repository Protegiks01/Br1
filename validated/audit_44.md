## Title
Whitelist Bypass in Cross-Chain Minting Allows Non-Whitelisted Users to Receive iTRY Tokens on Spoke Chains

## Summary
The `iTryTokenOFT` contract on spoke chains fails to enforce whitelist restrictions during cross-chain minting operations. In `WHITELIST_ENABLED` state, tokens can be minted to non-whitelisted addresses via LayerZero bridging, directly violating the protocol's documented whitelist enforcement invariant.

## Impact
**Severity**: High

This vulnerability completely bypasses the whitelist access control mechanism on spoke chains, allowing any non-whitelisted user to receive iTRY tokens through cross-chain transfers. This undermines the protocol's regulatory compliance framework and could allow sanctioned addresses or non-KYC users to hold iTRY when the protocol explicitly intends to restrict access. The whitelist mechanism is a critical security control for the protocol, and its bypass represents a complete failure of this access control layer on spoke chains.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** 
According to the protocol's documented invariants, specifically stated in the README: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [2](#0-1) 

The `_beforeTokenTransfer` hook should verify that recipients of minted tokens are whitelisted when the contract is in `WHITELIST_ENABLED` state.

**Actual Logic:** 
The minting validation in `WHITELIST_ENABLED` state only checks that the recipient is not blacklisted but does NOT verify whitelist status. [3](#0-2) 

This is inconsistent with the normal transfer case, which correctly requires all parties to be whitelisted. [4](#0-3) 

**Exploitation Path:**
1. **Setup**: iTryTokenOFT on spoke chain (e.g., MegaETH) is set to `WHITELIST_ENABLED` state by owner to restrict token access
2. **Precondition**: Attacker has iTRY tokens on hub chain (Ethereum) but their address is NOT whitelisted on the spoke chain
3. **Trigger**: Attacker calls `send()` on iTryTokenOFTAdapter (hub chain), specifying their non-whitelisted spoke chain address as recipient
4. **Lock & Message**: iTryTokenOFTAdapter locks iTRY on hub chain and sends LayerZero message to spoke chain
5. **Receive**: LayerZero endpoint on spoke chain receives message and calls into iTryTokenOFT
6. **Mint**: Internal OFT `_credit()` function calls `_mint()` which triggers `_beforeTokenTransfer` hook with `msg.sender == minter` (LayerZero endpoint), `from == address(0)`, and `to == attacker`
7. **Bypass**: The check at lines 160-161 passes because the conditions are met: minter is calling, it's a mint operation, and recipient is not blacklisted
8. **Result**: Tokens are successfully minted to the attacker's non-whitelisted address on spoke chain, violating the whitelist enforcement invariant

**Security Property Broken:**
This directly violates the documented invariant: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." [2](#0-1) 

**Code Evidence - Hub Chain Protection:**
On the hub chain, the `iTryIssuer` contract enforces whitelist at the application level through the `onlyRole(_WHITELISTED_USER_ROLE)` modifier on minting functions. [5](#0-4) 

This provides defense-in-depth on the hub chain, even though the underlying `iTry` token contract has the same vulnerability. [6](#0-5) 

**Spoke Chain Vulnerability:**
However, on spoke chains, there is NO equivalent issuer contract. The LayerZero OFT minting is the ONLY entry point for iTRY tokens, and it completely bypasses the whitelist check.

## Impact Explanation

**Affected Assets**: iTRY tokens on all spoke chains (MegaETH and any other L2 deployments)

**Damage Severity**:
- Complete bypass of whitelist controls on spoke chains
- Non-whitelisted users can receive unlimited amounts of iTRY tokens via cross-chain bridging
- Regulatory compliance requirements may be violated if restricted addresses (e.g., sanctioned entities, non-KYC users) can bypass the whitelist
- The whitelist mechanism becomes effectively meaningless on spoke chains, as users can trivially receive tokens by bridging from the hub chain

**User Impact**: 
All iTRY token holders are affected as the whitelist mechanism is a critical security control and regulatory compliance tool. The protocol's ability to restrict token access to approved participants is completely undermined on spoke chains.

**Trigger Conditions**: 
Any user can trigger this with a single cross-chain transaction from the hub chain to a spoke chain, as long as their address is not explicitly blacklisted (being non-whitelisted is sufficient to exploit).

## Likelihood Explanation

**Attacker Profile**: Any user who holds iTRY tokens on the hub chain and has a non-whitelisted address on the spoke chain

**Preconditions**:
1. iTryTokenOFT on spoke chain must be in `WHITELIST_ENABLED` state (protocol will use this mode for regulatory compliance)
2. Attacker must have iTRY balance on hub chain (easily obtainable through normal minting)
3. Attacker's spoke chain address must not be blacklisted (but not whitelisted either - the common case)

**Execution Complexity**: 
Single cross-chain transaction - straightforward call to `send()` on iTryTokenOFTAdapter with spoke chain address as recipient. No special timing, ordering, or advanced techniques required.

**Economic Cost**: 
Only LayerZero bridging fees and gas costs (minimal), no capital lockup or other barriers

**Frequency**: 
Can be exploited continuously by any user meeting the preconditions, unlimited number of times

**Overall Likelihood**: HIGH - If the spoke chain operates in `WHITELIST_ENABLED` mode, this bypass is trivially executable by any non-whitelisted user with hub chain iTRY.

## Recommendation

**Primary Fix:**
Modify the `_beforeTokenTransfer` function in `iTryTokenOFT.sol` to enforce whitelist status during minting operations in `WHITELIST_ENABLED` state: [3](#0-2) 

Add `&& whitelisted[to]` check to line 160 (minting condition) and line 164 (owner redistribution minting).

**Secondary Fix:**
Apply the same fix to the hub chain `iTry.sol` contract for defense-in-depth, even though it's currently mitigated by `iTryIssuer`: [7](#0-6) 

Add `&& hasRole(WHITELISTED_ROLE, to)` check to lines 201-202 (minting condition) and lines 205-206 (admin redistribution minting).

**Additional Mitigations**:
- Add invariant tests verifying that minting in `WHITELIST_ENABLED` state always requires the recipient to be whitelisted
- Consider implementing address whitelist synchronization between hub and spoke chains via LayerZero messaging
- Document that whitelist management must be performed on ALL chains before enabling `WHITELIST_ENABLED` mode

## Proof of Concept

The provided PoC demonstrates the vulnerability by:
1. Deploying `iTryTokenOFT` on a spoke chain and setting it to `WHITELIST_ENABLED` state
2. Setting the LayerZero endpoint as the minter
3. Whitelisting only a legitimate user (not the attacker)
4. Simulating the LayerZero endpoint (minter) minting tokens to the non-whitelisted attacker address
5. Verifying the mint succeeds despite the attacker not being whitelisted
6. Confirming that the attacker still cannot perform normal transfers (whitelist is enforced for those operations)

This PoC accurately simulates the cross-chain flow where the LayerZero endpoint calls `_mint()` on behalf of a cross-chain message, demonstrating that the whitelist check is bypassed for minting operations.

## Notes

**Critical Distinction - Hub vs Spoke Chains:**
While the same code pattern exists in both `iTry.sol` (hub chain) and `iTryTokenOFT.sol` (spoke chains), the impact differs significantly:

- **Hub Chain**: The vulnerability is mitigated by the `iTryIssuer` contract, which enforces `onlyRole(_WHITELISTED_USER_ROLE)` at the application level [8](#0-7) 
  
- **Spoke Chains**: NO such issuer contract exists. LayerZero OFT minting is the ONLY way to receive iTRY tokens, making this the primary entry point and the vulnerability critical.

**Why This Is Not a Known Issue:**
This is distinct from the Zellic audit's known issue about "Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance" [9](#0-8) . That issue concerns the `msg.sender` not being validated in transfers. This issue concerns the recipient of minting operations not being validated against the whitelist, which is a separate access control bypass affecting a different operation (minting vs transfer) and different parties (recipient vs sender).

**Consistency Issue:**
The code correctly enforces whitelist for normal transfers (requiring all parties to be whitelisted) [4](#0-3)  but fails to apply the same logic to minting operations, creating an inconsistent security policy that undermines the entire whitelist mechanism on spoke chains.

### Citations

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

**File:** README.md (L35-35)
```markdown
-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
```

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/protocol/iTryIssuer.sol (L270-275)
```text
    function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (uint256 iTRYAmount)
    {
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
