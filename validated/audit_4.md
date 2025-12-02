Based on my comprehensive validation of this security claim against the Brix Money codebase, I can confirm this is a **VALID Medium severity vulnerability**.

## Validation Summary

After rigorous analysis against all framework requirements, this claim passes all validation checks:

### ✅ Scope & Threat Model Validation

**In-Scope Files Confirmed:**
- [1](#0-0) 
- [2](#0-1) 

Both adapter contracts are explicitly listed in scope.txt. No trusted role misbehavior required - this affects regular users performing standard cross-chain transfers.

### ✅ Code Evidence Verification

**Critical Finding: Adapters Lack Blacklist Protection**

The hub chain (L1) adapters inherit from LayerZero's base `OFTAdapter` without overriding the `_credit` function, which means they will attempt to transfer tokens directly to recipients without checking blacklist status.

**Blacklist Enforcement on L1 Tokens:**

For wiTRY shares: [3](#0-2) 

For iTRY tokens: [4](#0-3) 

Both `_beforeTokenTransfer` hooks will **revert** when attempting to transfer to blacklisted recipients, causing the entire LayerZero message to fail.

**Architectural Inconsistency - The Smoking Gun:**

The spoke chain (L2) wiTRY OFT contract demonstrates that the protocol team was **aware** of this exact risk and implemented protection: [5](#0-4) 

This `_credit` override redirects funds to the owner when recipients are blacklisted, preventing the revert. The hub chain adapters lack this same protection, creating a one-way enforcement gap.

### ✅ No Known Issue Conflict

The README line 40 mentions: *"Native fee loss on failed wiTryVaultComposer.lzReceive execution (requires double payment)"*

That known issue is about **fee loss due to underpayment**, not permanent fund lock due to blacklist reverts in the OFTAdapter. These are distinct issues affecting different contracts (`wiTryVaultComposer` vs `OFTAdapter`) with different root causes.

### ✅ Missing Rescue Mechanism Confirmed

Through grep search across all in-scope files, I confirmed that multiple protocol contracts implement `rescueTokens` functions (FastAccessVault, YieldForwarder, iTry, StakediTry, iTryTokenOFT, UnstakeMessenger, wiTryVaultComposer) - but **neither adapter contract has one**. This demonstrates the oversight is inconsistent with the protocol's standard defensive patterns.

### ✅ Severity Assessment Validated

**Impact: HIGH** (Permanent and complete loss of bridged funds - no recovery mechanism exists)

**Likelihood: MEDIUM** (Requires recipient to be blacklisted on L1, which is realistic given):
- Cross-chain blacklist systems operate independently (L2 uses mapping-based, L1 uses role-based)
- Compliance actions can occur between L2 transaction submission and L1 execution
- Users may unknowingly send to previously blacklisted addresses

**Combined Severity: MEDIUM** per Code4rena framework ✅

### ✅ Exploitation Path Verified

1. User holds wiTRY/iTRY on L2 (MegaETH/OP Sepolia)
2. User calls `OFT.send()` with recipient address → tokens burned on L2
3. LayerZero message arrives at L1 adapter
4. Base `OFTAdapter._credit()` attempts `innerToken.transfer(recipient, amount)`
5. Token's `_beforeTokenTransfer` checks blacklist role → **REVERTS**
6. Message execution fails, tokens remain locked in adapter on L1
7. No rescue function exists to recover funds

## Conclusion

This represents a **genuine architectural security flaw** where the protocol implemented the correct defensive pattern (`_credit` override) on spoke chains but failed to apply it consistently to hub chain adapters. The vulnerability enables permanent fund lock in realistic cross-chain scenarios involving blacklist desynchronization.

**The claim is VALID as a Medium severity finding.**

### Notes

The recommendation to override `_credit` in both adapters following the `wiTryOFT` pattern is sound and would provide consistent blacklist enforcement across all chains. The alternative suggestion to add `rescueTokens` functions is also valid, though the proactive `_credit` override is the superior solution as it prevents the issue entirely rather than requiring manual intervention.

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
