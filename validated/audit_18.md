After rigorous validation against the Brix Money Protocol security framework, I have completed my analysis.

# VALIDATION RESULT: **VALID HIGH SEVERITY VULNERABILITY**

## Title
Cross-Chain Blacklist Bypass: Blacklisted Users Can Receive iTRY Tokens on Spoke Chain

## Summary
The `iTryTokenOFT` contract lacks a `_credit()` override to validate blacklist status during cross-chain token receipt, allowing users blacklisted on the Hub chain to receive iTRY tokens on Spoke chains. This directly violates the protocol's critical invariant that blacklisted users cannot receive iTRY tokens in any circumstance.

## Impact
**Severity**: High

This vulnerability enables complete bypass of blacklist enforcement for cross-chain token receipts. Blacklisted addresses (sanctioned entities, compromised accounts, or flagged malicious actors) can receive and control iTRY tokens on spoke chains, circumventing the protocol's compliance and risk management controls. This undermines the entire blacklist security mechanism and exposes the protocol to regulatory, reputational, and security risks. [1](#0-0) 

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol`, missing `_credit()` override

**Intended Logic:**
The protocol enforces that "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case" across all chains, including cross-chain transfers. [1](#0-0) 

**Actual Logic:**
When LayerZero delivers cross-chain messages to `iTryTokenOFT`, the inherited OFT contract calls `_credit()` which triggers `_mint()`. The `_mint()` function invokes `_beforeTokenTransfer()` which only validates the recipient's blacklist status against the **local** spoke chain blacklist mapping, not the Hub chain status. [2](#0-1) [3](#0-2) 

**Critical Architectural Inconsistency:**
The `wiTryOFT` contract correctly implements a `_credit()` override that checks blacklist status and redirects tokens to the owner if the recipient is blacklisted. The `iTryTokenOFT` contract **completely lacks this protection**, despite having identical cross-chain architecture and blacklist requirements. [4](#0-3) 

**Exploitation Path:**
1. Alice is blacklisted on Hub chain (Ethereum) via `iTry.addBlacklistAddress()`
2. Bob (non-blacklisted) initiates cross-chain transfer via `iTryTokenOFTAdapter.send()` with Alice as recipient
3. Hub chain: Adapter locks Bob's iTRY tokens (Bob's non-blacklisted status passes validation)
4. Spoke chain: `iTryTokenOFT.lzReceive()` processes message and calls inherited `_credit()` → `_mint(Alice)`
5. `_beforeTokenTransfer()` validates Alice against **Spoke chain** blacklist only (lines 145-146)
6. Since blacklist mappings are independent with no synchronization mechanism, Alice receives tokens despite Hub chain blacklisting [5](#0-4) [6](#0-5) 

**Security Property Broken:**
Violates critical invariant: "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case" [1](#0-0) 

## Impact Explanation

**Affected Assets**: iTRY tokens on all spoke chains (MegaETH and future deployments)

**Damage Severity**:
- Complete bypass of blacklist enforcement for cross-chain receipts
- Blacklisted entities can re-enter protocol ecosystem via different chain
- Enables sanctions evasion, money laundering, and continued operation by flagged malicious actors
- Undermines protocol's compliance framework and regulatory standing
- Creates operational burden requiring manual blacklist synchronization

**User Impact**: All protocol users and stakeholders are affected as blacklist mechanism is a fundamental security and compliance control protecting the entire ecosystem.

## Likelihood Explanation

**Attacker Profile**: Any non-blacklisted user can serve as intermediary (witting or unwitting). Blacklisted user only needs to convince someone to send tokens cross-chain or use a complicit party.

**Preconditions**:
1. Target blacklisted on Hub but not on Spoke (always true due to independent mappings)
2. Intermediary has iTRY on Hub and is non-blacklisted (trivial to obtain)
3. Cross-chain infrastructure operational (expected normal state)

**Execution Complexity**: Single cross-chain transaction. No special timing, front-running, or complex coordination required.

**Frequency**: Exploitable continuously until blacklists are manually synchronized.

**Overall Likelihood**: HIGH - Trivial execution with no special preconditions or privileges required.

## Recommendation

Implement a `_credit()` override in `iTryTokenOFT.sol` following the proven pattern from `wiTryOFT.sol`: [4](#0-3) 

Add after line 177 in `src/token/iTRY/crosschain/iTryTokenOFT.sol` a `_credit()` function that checks if the recipient is blacklisted and redirects to owner if true, similar to the wiTryOFT implementation.

**Additional Mitigations**:
1. Establish operational procedures for manual blacklist synchronization across chains
2. Consider implementing automated cross-chain blacklist synchronization via LayerZero messages (more complex but provides stronger guarantees)
3. Add monitoring for cross-chain transfers to blacklisted addresses

## Notes

This vulnerability represents a **critical architectural inconsistency**. The protocol developers correctly implemented `_credit()` override protection in `wiTryOFT` but omitted it from `iTryTokenOFT`, despite identical cross-chain architecture and blacklist requirements. This proves the protection is not only necessary but was intentionally designed for the wiTRY system—making its absence from iTRY a clear oversight rather than a design decision. [4](#0-3) [2](#0-1) 

The vulnerability is particularly severe because:
- Requires zero privileged access
- Uses normal protocol operations (no exploit of broken logic)
- Completely bypasses stated security invariant
- Has proven mitigation pattern already implemented elsewhere in codebase
- Creates ongoing compliance and operational risks until fixed

The blacklist systems are independent: Hub chain uses AccessControl roles while Spoke chain uses simple mappings, with no synchronization mechanism between them. [5](#0-4) [2](#0-1)

### Citations

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L35-36)
```text
    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-177)
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
            // State 1 - Transfers only enabled between whitelisted addresses
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
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
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

**File:** src/token/iTRY/iTry.sol (L31-31)
```text
    bytes32 public constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
```

**File:** src/token/iTRY/iTry.sol (L73-78)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
```
