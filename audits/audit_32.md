# Validation Analysis: Cross-Chain Blacklist Minting Failure

After performing a rigorous technical validation of this security claim against the Brix Money codebase, I have confirmed this is a **VALID HIGH SEVERITY VULNERABILITY**.

## Technical Verification

### 1. Scope and Known Issues Validation ✅

The vulnerability affects `src/token/iTRY/crosschain/iTryTokenOFT.sol` which is explicitly in scope. [1](#0-0) 

Cross-referencing with known issues from the Zellic audit (README lines 35-41), this specific cross-chain minting failure is **NOT** listed as a known issue. The known issue about blacklists only covers "Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance" which is a same-chain allowance bypass, not cross-chain minting failure. [2](#0-1) 

### 2. Execution Path Confirmation ✅

The claim's execution path is technically accurate:

**When LayerZero delivers a message to mint iTRY on spoke chain:**
- The inherited OFT `_credit` function calls `_mint(recipient, amount)`
- `_mint` triggers `_beforeTokenTransfer(address(0), recipient, amount)`
- Line 145 checks: `msg.sender == minter && from == address(0) && !blacklisted[to]`
- If recipient is blacklisted, `!blacklisted[to]` evaluates to FALSE
- None of the allowed conditions match (lines 143-152)
- Transaction reverts at line 154 with `OperationNotAllowed()` [3](#0-2) 

### 3. Critical Inconsistency Identified ✅

**wiTryOFT implements protective pattern:**
The protocol's `wiTryOFT` contract overrides `_credit` to gracefully handle blacklisted recipients by redirecting funds to the owner instead of reverting. [4](#0-3) 

**iTryTokenOFT lacks this protection:**
Grep search confirms that only `wiTryOFT` has a `_credit` override. `iTryTokenOFT` does not implement this protective pattern, relying solely on `_beforeTokenTransfer` which causes reverts and permanent fund loss.

This inconsistency proves that:
- The team was aware of this cross-chain blacklist issue
- They chose graceful handling (redirect to owner) as the correct solution for wiTRY
- iTryTokenOFT inexplicably lacks the same protection

### 4. No Recovery Mechanism ✅

LayerZero V2 OFT does not have automatic refund mechanisms for failed `lzReceive` operations. The `_refund` mechanism found in the codebase only applies to `lzCompose` operations in `VaultComposerSync`, not to standard OFT minting failures. When `_credit` (which calls `_mint`) reverts, tokens remain permanently locked on the source chain with no recovery path.

The adapter is a simple wrapper with no special recovery functions. [5](#0-4) 

### 5. Impact Severity: HIGH ✅

**Permanent Fund Loss:**
- User bridges iTRY from hub to spoke chain
- If recipient is blacklisted on spoke, mint reverts
- Tokens locked on hub chain (in adapter)
- Zero tokens minted on spoke chain
- **Result: 100% permanent loss of bridged amount**

**User Impact:**
- Affects any user (even non-blacklisted senders) who bridges to blacklisted addresses
- Can occur via race condition (address blacklisted during message flight)
- No recovery mechanism exists
- Violates user expectations - innocent senders lose funds

This satisfies Code4rena HIGH severity criteria: direct loss of user funds, permanent and irrecoverable, affects multiple users.

### 6. Likelihood: HIGH ✅

**Execution Complexity:** Single cross-chain transaction, trivial to trigger
**Preconditions:** Only requires recipient to be blacklisted (normal operational state)
**Frequency:** Repeatable - every bridge to blacklisted address causes permanent loss
**Attacker Profile:** Any user (even accidentally), or malicious griefing attacks

### 7. Violates Protocol Invariants ✅

While the README states "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case" [6](#0-5) , the current implementation over-enforces this by causing **collateral damage** to non-blacklisted senders who permanently lose funds.

The wiTryOFT implementation demonstrates the protocol's intended approach: enforce blacklist rules WITHOUT causing permanent fund loss by redirecting to owner.

## Validation Decision

**This vulnerability claim PASSES all validation checks:**
- ✅ In scope file
- ✅ Not a known issue  
- ✅ No admin misbehavior required
- ✅ Technical execution path confirmed with exact code citations
- ✅ HIGH severity impact (permanent fund loss)
- ✅ HIGH likelihood (simple to trigger)
- ✅ wiTryOFT proves the correct solution exists
- ✅ Violates user expectations and protocol consistency

## Recommendation

The fix is straightforward - implement the same protective pattern used in wiTryOFT:

```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    if (blacklisted[_to]) {
        emit LockedAmountRedistributed(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}
```

## Notes

This vulnerability is particularly concerning because:

1. **The solution already exists in the codebase** - wiTryOFT demonstrates the correct approach, making this an implementation inconsistency rather than a design flaw

2. **Silent fund loss** - Users receive no error when initiating the bridge transaction on hub chain; funds are lost only when delivery fails on spoke chain

3. **Race condition exposure** - Legitimate users can lose funds if an admin blacklists an address between hub-side transaction submission and spoke-side message delivery

4. **Transfer state vulnerability** - The same permanent loss occurs if `transferState` is set to `FULLY_DISABLED` on spoke chain [7](#0-6) 

The existence of the protective pattern in wiTryOFT, combined with the absence of recovery mechanisms and the severe impact of permanent fund loss, confirms this is a valid HIGH severity vulnerability requiring immediate remediation.

### Citations

**File:** README.md (L35-35)
```markdown
-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
```

**File:** README.md (L67-67)
```markdown
|[src/token/iTRY/crosschain/iTryTokenOFT.sol](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/token/iTRY/crosschain/iTryTokenOFT.sol)| 87 |
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-155)
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
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L174-176)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
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
