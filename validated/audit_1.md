## Title
Blacklisted Users' iTRY Permanently Locked in Cross-Chain Adapter During Bridge Return

## Summary
The `iTryTokenOFTAdapter` contract lacks blacklist handling in its unlock mechanism, causing permanent fund loss when users are blacklisted between outbound and inbound cross-chain bridge operations. The adapter has no override for `_credit()` and no recovery mechanism, resulting in irreversible token lock.

## Impact
**Severity**: High

Direct permanent loss of user funds. When a blacklisted user attempts to bridge iTRY back from spoke chain to hub chain, the unlock operation permanently fails because iTRY's transfer restrictions prevent sending to blacklisted addresses, locking tokens in the adapter with no administrative recovery path.

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` and `src/token/iTRY/iTry.sol`

**Intended Logic:** 
The iTryTokenOFTAdapter should enable seamless cross-chain transfers of iTRY tokens. Users bridge iTRY to spoke chains (tokens locked in adapter) and can bridge back to receive their original tokens (tokens unlocked from adapter).

**Actual Logic:** 
The adapter inherits from LayerZero's `OFTAdapter` without overriding the `_credit` function, creating a critical gap in blacklist handling. [1](#0-0) 

When LayerZero delivers a return message from spoke to hub, the base `OFTAdapter._credit` implementation attempts to transfer tokens from the adapter to the recipient. However, iTRY's `_beforeTokenTransfer` hook enforces strict blacklist restrictions: [2](#0-1) 

The critical check at line 191 requires that the recipient (`to`) does NOT have `BLACKLISTED_ROLE`. If the recipient is blacklisted, the entire transaction reverts with `OperationNotAllowed()`, permanently locking funds in the adapter.

**Exploitation Path:**

1. **User initiates hub→spoke bridge**: User calls `iTryTokenOFTAdapter.send()` on Ethereum, transferring 1000 iTRY. The adapter locks these tokens via `transferFrom`. [3](#0-2) 

2. **LayerZero delivers message**: `iTryTokenOFT` on spoke chain receives the message and mints 1000 iTRY to the user. [4](#0-3) 

3. **User gets blacklisted**: Before bridging back, the Blacklist Manager adds the user to the blacklist on Ethereum hub chain. [5](#0-4) 

4. **User attempts spoke→hub bridge**: User calls `iTryTokenOFT.send()` on spoke chain to bridge back. Tokens are burned on spoke chain. [6](#0-5) 

5. **Unlock fails on hub chain**: When `iTryTokenOFTAdapter.lzReceive()` executes, the internal `_credit` function attempts `iTRY.transfer(blacklistedUser, 1000)`, triggering `_beforeTokenTransfer(adapter, blacklistedUser, 1000)`. The check at line 191 fails because the user has `BLACKLISTED_ROLE`, causing the transaction to revert.

6. **Funds permanently locked**: The 1000 iTRY remains locked in the adapter with no recovery mechanism. The adapter has no `redistributeLockedAmount` or `rescueTokens` function to handle this case.

## Impact Explanation

**Affected Assets**: All iTRY tokens locked in the `iTryTokenOFTAdapter` belonging to users who become blacklisted between outbound and inbound bridge operations.

**Damage Severity**: 
- 100% permanent loss of bridged iTRY for affected users
- Tokens are locked in the adapter contract with no administrative recovery function
- The only remediation would require removing the user from the blacklist, which defeats the purpose of compliance-driven blacklisting

**User Impact**: Any user who bridges iTRY to a spoke chain and subsequently gets blacklisted (for regulatory, compliance, or security reasons) before bridging back will lose all bridged funds permanently. This affects legitimate users who may be blacklisted due to regulatory requirements while their tokens are in transit or on spoke chains.

## Likelihood Explanation

**Attacker Profile**: Not an attacker scenario - this affects legitimate users subjected to compliance-driven blacklisting. No malicious intent required.

**Preconditions**: 
1. User must have bridged iTRY from hub to spoke chain
2. User must be added to blacklist on hub chain before attempting to bridge back
3. Transfer state must be `FULLY_ENABLED` or `WHITELIST_ENABLED` (normal operating modes)

**Execution Complexity**: Occurs through normal protocol operations. Requires no sophisticated exploitation - simply bridging back after being blacklisted triggers the fund lock.

**Frequency**: Can occur for any user who gets blacklisted while having funds on spoke chains. Given that blacklisting is an expected compliance feature, this is a realistic and recurring risk.

**Overall Likelihood**: MEDIUM-HIGH - Realistic preconditions with normal protocol usage patterns.

## Recommendation

Override the `_credit` function in `iTryTokenOFTAdapter` to redirect funds to the protocol owner when the recipient is blacklisted, similar to the pattern implemented in `wiTryOFT`: [7](#0-6) 

**Implementation for iTryTokenOFTAdapter:**

Add import for iTry interface to check blacklist status, implement event for fund redistribution, and override `_credit()` to handle blacklisted recipients by redirecting to owner instead of reverting.

**Alternative mitigation:** Implement an emergency rescue function callable by admin to manually redistribute locked funds, similar to `iTry.redistributeLockedAmount`. However, the override approach is cleaner and prevents funds from getting locked in the first place.

## Notes

This vulnerability is **distinct** from the known Zellic issue about blacklisted users transferring via allowance on the same chain. The Zellic issue concerns same-chain allowance-based transfers, while this finding involves cross-chain message delivery failure causing permanent fund loss. [8](#0-7) 

The known issues list does not mention cross-chain blacklist handling failures or adapter fund lock scenarios, confirming this is a new finding.

**Asymmetric Protection**: The `wiTryOFT` contract on spoke chains implements the correct pattern by overriding `_credit` to redirect tokens from blacklisted recipients to the owner. However, `iTryTokenOFTAdapter` on the hub chain lacks this protection, creating an asymmetric risk where funds can be locked during the return journey from spoke to hub.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-29)
```text
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
}
```

**File:** src/token/iTRY/iTry.sol (L73-77)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
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

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L104-116)
```text
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();

        // Verify tokens locked on Sepolia
        uint256 userL1BalanceAfterSend = sepoliaITryToken.balanceOf(userL1);
        uint256 adapterBalanceAfterSend = sepoliaITryToken.balanceOf(address(sepoliaAdapter));

        console.log("\nAfter Send (Sepolia):");
        console.log("  userL1 balance:", userL1BalanceAfterSend);
        console.log("  adapter balance (locked):", adapterBalanceAfterSend);

        assertEq(userL1BalanceAfterSend, 0, "User should have 0 iTRY after send");
        assertEq(adapterBalanceAfterSend, adapterBalanceBefore + TRANSFER_AMOUNT, "Adapter should have locked iTRY");
```

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L133-141)
```text
        uint256 userL1BalanceOnL2 = opSepoliaOFT.balanceOf(userL1);
        uint256 totalSupplyL2 = opSepoliaOFT.totalSupply();

        console.log("\nAfter Relay (OP Sepolia):");
        console.log("  userL1 balance:", userL1BalanceOnL2);
        console.log("  Total supply:", totalSupplyL2);

        assertEq(userL1BalanceOnL2, TRANSFER_AMOUNT, "User should have 100 iTRY on L2");
        assertEq(totalSupplyL2, TRANSFER_AMOUNT, "Total supply on L2 should be 100 iTRY");
```

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L205-213)
```text
        uint256 userL1BalanceAfterSendL2 = opSepoliaOFT.balanceOf(userL1);
        uint256 totalSupplyAfterSendL2 = opSepoliaOFT.totalSupply();

        console.log("\nAfter Send (OP Sepolia):");
        console.log("  userL1 balance:", userL1BalanceAfterSendL2);
        console.log("  Total supply:", totalSupplyAfterSendL2);

        assertEq(userL1BalanceAfterSendL2, 0, "User should have 0 iTRY on L2 after send");
        assertEq(totalSupplyAfterSendL2, 0, "Total supply on L2 should be 0 (burned)");
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

**File:** README.md (L23-42)
```markdown
## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

### Centralization Risks

Any centralization risks are out-of-scope for the purposes of this audit contest.

### Zellic Audit Report Issues

The codebase has undergone a Zellic audit with a fix review pending. The following issues identified in the Zellic audit are considered out-of-scope, with some being fixed in the current iteration of the codebase:

-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
- Griefing attacks around the `MIN_SHARES` variable of the ERC2646 vault: The protocol will perform an initial deposit to offset this risk. 
- The `redistributeLockedAmount` does not validate that the resulted `totalSupply` is not less than the minimum threshold. As a result of executing the `redistributeLockedAmount` function, the `totalSupply` amount may fall within a prohibited range between 0 and `MIN_SHARES` amount. And subsequent legitimate
deposits or withdrawals operations, which do not increase totalSupply to the `MIN_SHARES` value will be blocked.
- iTRY backing can fall below 1:1 on NAV drop. If NAV drops below 1, iTRY becomes undercollateralized with no guaranteed, on-chain remediation. Holders bear insolvency risk until a top-up or discretionary admin intervention occurs.
- Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request.
- Non-standard ERC20 tokens may break the transfer function. If a non-standard token is recovered using a raw transfer, the function may appear to succeed, even though no tokens were transferred, or it may revert unexpectedly. This can result in tokens becoming stuck in the contract, which breaks the tokens rescue mechanism.

```
