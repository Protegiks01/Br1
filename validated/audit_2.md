# VALIDATION RESULT: VALID VULNERABILITY ✅

After rigorous validation against the Brix Money Protocol security framework, this claim is **CONFIRMED VALID** as a **Medium severity** vulnerability.

## Validation Summary

### Phase 1: Scope & Threat Model ✅
All three affected files are in scope:
- [1](#0-0) 
- [2](#0-1) 
- [3](#0-2) 

No trusted role misbehavior required. Happens naturally through blacklist desynchronization.

### Phase 2: Code Evidence Verification ✅

**Critical Asymmetry Confirmed:**

1. **Hub Chain (wiTryOFTAdapter)**: The contract contains ONLY a constructor with no `_credit()` override, meaning it uses the base LayerZero OFTAdapter implementation which directly transfers tokens without blacklist awareness. [1](#0-0) 

2. **Spoke Chain (wiTryOFT)**: Implements blacklist-aware `_credit()` function that gracefully redirects tokens to the owner when the recipient is blacklisted, preventing reversions. [2](#0-1) 

3. **Hub Chain Enforcement**: StakediTry's `_beforeTokenTransfer` hook blocks ALL transfers to addresses with `FULL_RESTRICTED_STAKER_ROLE`, causing the OFTAdapter's unlock attempt to revert. [3](#0-2) 

### Phase 3: Execution Path Traced ✅

**Spoke to Hub Bridging Flow:**
1. User (blacklisted on hub, NOT on spoke) calls `wiTryOFT.send()` on spoke chain
2. Tokens burn successfully on spoke (no blacklist restriction there)
3. LayerZero message sent to hub chain
4. `wiTryOFTAdapter` receives message, calls inherited `_credit()`
5. Base `_credit()` attempts `safeTransfer()` to unlock shares from adapter to user
6. Transfer triggers StakediTry's `_beforeTokenTransfer()` [4](#0-3) 
7. **REVERTS** because recipient has `FULL_RESTRICTED_STAKER_ROLE`
8. Message fails, tokens remain locked in adapter

**Result**: Tokens burned on spoke, locked on hub - permanent loss for OFAC-sanctioned addresses who cannot be removed from blacklist.

### Phase 4: Protocol Alignment Verified ✅

This vulnerability directly addresses the protocol's **explicit stated concerns** in the README:

*"The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and **blacklist/whitelist bugs that would impair rescue operations** in case of hacks or similar black swan events."* [5](#0-4) 

### Phase 5: Differentiation from Known Issues ✅

**NOT the Zellic known issue**: The README line 35 describes same-chain allowance bypass. This is a **different vulnerability** affecting cross-chain bridging via OFT adapter's unlock mechanism. [6](#0-5) 

## Impact Assessment

**Severity: Medium** (justified per Code4rena framework)

**Affected Assets**: wiTRY shares of users blacklisted on hub but not spoke chain

**Damage Quantification**:
- Tokens irreversibly burned on spoke chain
- Tokens locked in hub chain adapter  
- **Recoverable** IF user removed from blacklist AND LayerZero message retried
- **Permanent loss** for OFAC-sanctioned addresses (cannot be removed)
- Violates protocol's blacklist rescue operation guarantees

**Likelihood: Medium** - Requires blacklist desynchronization (realistic compliance scenario), simple execution (single bridge transaction), affects any user in this state.

## Technical Root Cause

The vulnerability stems from an **architectural inconsistency**:
- Spoke chain implements defensive `_credit()` override with graceful blacklist handling
- Hub chain lacks equivalent protection, relying on ungraceful revert mechanism
- Independent blacklist systems (role-based vs mapping-based) enable desynchronization

## Notes

1. **Design Asymmetry**: The spoke chain's graceful handling (redirect to owner) contrasts sharply with the hub chain's ungraceful handling (revert and lock). [7](#0-6) 

2. **Separate Blacklist Systems**: Hub uses role-based (`FULL_RESTRICTED_STAKER_ROLE`), spoke uses mapping (`blackList`), creating synchronization gaps.

3. **Protocol-Critical**: Directly impacts stated protocol concern about blacklist bugs impairing rescue operations. [5](#0-4) 

4. **Recommended Fix**: The proposed `_credit()` override in `wiTryOFTAdapter` mirrors the spoke chain's protection pattern, creating symmetric blacklist handling across chains. This is architecturally sound.

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

**File:** src/token/wiTRY/StakediTry.sol (L292-299)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
    }
```

**File:** README.md (L35-35)
```markdown
-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
```

**File:** README.md (L112-112)
```markdown
The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events. More generally, the areas we want to verify are:
```
