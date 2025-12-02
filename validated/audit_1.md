# VALIDATION RESULT: VALID HIGH SEVERITY VULNERABILITY

After rigorous validation against the Brix Money Protocol security framework, this claim is **CONFIRMED VALID**.

## Vulnerability Summary

The `iTryTokenOFTAdapter` lacks blacklist handling in its unlock mechanism, causing permanent fund loss when users are blacklisted during cross-chain operations. This represents a critical design gap with no recovery path.

## Evidence-Based Validation

### 1. Scope Verification ✅

The vulnerability affects in-scope contracts:
- [1](#0-0) 
- [2](#0-1) 

### 2. Execution Path Analysis ✅

**Critical Flow - Spoke to Hub Return:**

When a blacklisted user attempts to bridge iTRY back from spoke to hub:

1. **Spoke Chain**: User calls `iTryTokenOFT.send()` → tokens burned on spoke
2. **Hub Chain Reception**: `iTryTokenOFTAdapter.lzReceive()` is invoked
3. **Unlock Attempt**: Base `OFTAdapter._credit()` calls `iTry.transfer(blacklistedUser, amount)`
4. **Revert**: iTry's `_beforeTokenTransfer` hook blocks the transfer

The adapter contract has **no override** of the `_credit()` function: [1](#0-0) 

This forces reliance on the base LayerZero implementation, which attempts a direct transfer to the recipient.

### 3. Blacklist Enforcement ✅

The iTry token enforces strict blacklist restrictions: [3](#0-2) 

At line 190-191, the code requires that the recipient (`to`) does NOT have `BLACKLISTED_ROLE`. If violated, the transaction reverts at line 195 with `OperationNotAllowed()`.

### 4. Asymmetric Protection - Key Evidence ✅

The protocol **already implements the correct pattern** in `wiTryOFT`: [4](#0-3) 

The `wiTryOFT` contract overrides `_credit()` to redirect tokens to the owner when the recipient is blacklisted (lines 91-93). This proves:
1. The protocol understands this risk
2. The solution pattern exists in the codebase
3. The absence in `iTryTokenOFTAdapter` is an **oversight, not intentional design**

### 5. No Recovery Mechanism ✅

The `redistributeLockedAmount` function cannot rescue these funds: [5](#0-4) 

This function requires the `from` address (line 113) to have `BLACKLISTED_ROLE`. However:
- The **adapter** holds the locked tokens
- The **user** is blacklisted, not the adapter
- Therefore, `redistributeLockedAmount` cannot access funds locked in the adapter

### 6. Distinct from Known Issues ✅

The Zellic known issue states: [6](#0-5) 

That issue concerns **same-chain** transfers using `transferFrom` where `msg.sender` isn't validated. This finding involves **cross-chain** message delivery failure causing permanent adapter fund lock - a completely distinct attack vector.

## Impact Assessment

**Severity: HIGH**

- **Direct permanent loss**: 100% of bridged iTRY for affected users
- **No recovery path**: Tokens locked in adapter with no rescue function
- **Affected users**: Any legitimate user blacklisted while having funds on spoke chains
- **Compliance dilemma**: Recovery requires un-blacklisting users, defeating the purpose of sanctions compliance

## Likelihood Assessment

**Likelihood: MEDIUM**

- **Preconditions**: User bridges iTRY → gets blacklisted → attempts bridge return
- **Realistic scenario**: Blacklisting is an expected compliance feature per the protocol design
- **Execution**: Occurs through normal protocol operations, no exploit required
- **Frequency**: Can affect any user blacklisted while having cross-chain positions

## Technical Recommendation

Implement the same pattern used in `wiTryOFT` by overriding `_credit()` in `iTryTokenOFTAdapter`:

```solidity
function _credit(address _to, uint256 _amountLD, uint32 _srcEid) 
    internal virtual override returns (uint256) 
{
    // Check if recipient is blacklisted
    if (ITry(innerToken).hasRole(BLACKLISTED_ROLE, _to)) {
        emit FundsRedirected(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}
```

This prevents funds from becoming permanently locked while maintaining compliance requirements.

## Notes

**Asymmetric Risk**: The protocol has protection on the **spoke chain** (`wiTryOFT._credit` override) but lacks it on the **hub chain** (`iTryTokenOFTAdapter`). This creates a one-way vulnerability where funds can be locked during the return journey from spoke to hub.

**Design Inconsistency**: The existence of the correct implementation in `wiTryOFT` proves this is not an accepted risk but rather an incomplete implementation pattern across the cross-chain architecture.

### Citations

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

**File:** src/token/iTRY/iTry.sol (L112-121)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
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

**File:** README.md (L35-35)
```markdown
-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
```
