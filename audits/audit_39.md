# VALID VULNERABILITY CONFIRMED

After rigorous validation against the Brix Money Protocol framework, this security claim is **VALID** and represents a **HIGH severity vulnerability**.

## Summary

The `iTryTokenOFT` contract on spoke chains lacks the protective `_credit()` override that `wiTryOFT` implements. When tokens are burned during spoke-to-hub transfers and the recipient is blacklisted before `lzReceive` completes, tokens are permanently lost—burned on spoke (irreversible) and locked in the adapter on hub (no rescue mechanism). [1](#0-0) 

## Impact

**Severity**: High

**Permanent Token Loss**: Users performing cross-chain iTRY transfers who become blacklisted (e.g., regulatory sanctions) during message processing will lose their tokens permanently. The tokens are burned on the spoke chain and cannot be recovered, while remaining locked in the adapter on the hub chain with no rescue function available.

**Affected Assets**: All iTRY tokens in cross-chain transfers between MegaETH (spoke) and Ethereum (hub).

## Finding Description

**Location**: `src/token/iTRY/crosschain/iTryTokenOFT.sol` and `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol`

**Intended Logic**: Cross-chain transfers should be atomic and fault-tolerant. Even if a recipient becomes blacklisted during transfer, the system should handle it gracefully (as `wiTryOFT` does by redirecting to the owner). [2](#0-1) 

**Actual Logic**: The `iTryTokenOFT` contract has no `_credit()` override. When LayerZero's `lzReceive` attempts to mint tokens to a blacklisted recipient, the `_beforeTokenTransfer` hook rejects the operation because the minting condition explicitly requires the recipient NOT be blacklisted. [3](#0-2) 

**Exploitation Path (Spoke → Hub)**:
1. User initiates cross-chain transfer via `send()` on spoke iTryTokenOFT
2. Tokens immediately burned on spoke via inherited OFT `_debit()` (confirmed in test suite showing supply drops to 0) [4](#0-3) 
3. User added to blacklist before `lzReceive` executes on hub
4. Hub adapter attempts to transfer underlying iTry tokens to blacklisted recipient
5. Transfer fails due to iTry's `_beforeTokenTransfer` checking BLACKLISTED_ROLE [5](#0-4) 
6. LayerZero stores message for retry, but all retries fail while user remains blacklisted
7. **Result**: Tokens permanently burned on spoke (cannot undo), locked in minimal adapter with no rescue function [6](#0-5) 

**Security Property Broken**: Violates cross-chain atomicity—tokens should always reach destination or be returned to sender, not destroyed without delivery.

## Impact Explanation

**Affected Assets**: iTRY tokens in cross-chain transfers

**Damage Severity**: 
- 100% permanent loss of transferred amount for affected users
- Tokens burned on spoke chain are cryptographically destroyed (irreversible)
- Tokens locked in adapter on hub chain with no rescue mechanism in the minimal wrapper contract
- No administrative override to redirect funds (unlike wiTryOFT's owner redirect pattern)

**User Impact**: Any user performing spoke-to-hub iTRY transfers who is subject to regulatory blacklisting during the cross-chain message processing window.

## Likelihood Explanation

**Attacker Profile**: Not an attack—legitimate users affected by compliance blacklisting

**Preconditions**: User must be blacklisted between when tokens are burned on spoke and when `lzReceive` successfully completes on hub

**Execution Complexity**: Single cross-chain transfer transaction; blacklist update occurs during message processing (realistic for regulatory compliance)

**Frequency**: Affects every cross-chain transfer where recipient is blacklisted before message completion

## Recommendation

Implement the same protective `_credit()` override that `wiTryOFT` uses:

```solidity
/// @notice Event emitted when funds are redistributed from blacklisted user
event RedistributeFunds(address indexed user, uint256 amount);

function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    if (blacklisted[_to]) {
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

This ensures `lzReceive` succeeds by redirecting tokens to the contract owner when the recipient is blacklisted, preventing permanent loss and maintaining cross-chain atomicity.

## Notes

**Critical Design Inconsistency**: The fact that `wiTryOFT` explicitly implements this protection [2](#0-1)  while `iTryTokenOFT` does not is smoking-gun evidence this is an oversight, not intentional design. The developers knew about this risk and protected wiTRY but forgot to protect iTRY.

**Not a Known Issue**: This differs from Zellic known issues:
- Known issue #35 (allowance bypass) is about same-chain transfers
- Known issue #40 (native fee loss) is about losing the messaging fee, not the token principal
- This issue is about permanent loss of the actual iTRY token amount being transferred

**Both Directions Affected**:
- **Spoke→Hub** (worse): Tokens BURNED on spoke (irreversible) + locked in adapter on hub
- **Hub→Spoke**: Tokens locked in adapter on hub + mint fails on spoke

The vulnerability violates the atomic cross-chain transfer guarantee and affects legitimate users with no recovery path.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L29-54)
```text
contract iTryTokenOFT is OFT, IiTryDefinitions, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Address allowed to mint iTry (typically the LayerZero endpoint)
    address public minter;

    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;

    /// @notice Mapping of whitelisted addresses
    mapping(address => bool) public whitelisted;

    TransferState public transferState;

    /// @notice Emitted when minter address is updated
    event MinterUpdated(address indexed oldMinter, address indexed newMinter);

    /**
     * @notice Constructor for iTryTokenOFT
     * @param _lzEndpoint LayerZero endpoint address for MegaETH
     * @param _owner Address that will own this OFT (typically deployer)
     */
    constructor(address _lzEndpoint, address _owner) OFT("iTry Token", "iTRY", _lzEndpoint, _owner) {
        transferState = TransferState.FULLY_ENABLED;
        minter = _lzEndpoint;
    }
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

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L204-213)
```text
        // Verify tokens burned on L2
        uint256 userL1BalanceAfterSendL2 = opSepoliaOFT.balanceOf(userL1);
        uint256 totalSupplyAfterSendL2 = opSepoliaOFT.totalSupply();

        console.log("\nAfter Send (OP Sepolia):");
        console.log("  userL1 balance:", userL1BalanceAfterSendL2);
        console.log("  Total supply:", totalSupplyAfterSendL2);

        assertEq(userL1BalanceAfterSendL2, 0, "User should have 0 iTRY on L2 after send");
        assertEq(totalSupplyAfterSendL2, 0, "Total supply on L2 should be 0 (burned)");
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

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L1-29)
```text
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {OFTAdapter} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFTAdapter.sol";

/**
 * @title iTryTokenAdapter
 * @notice OFT Adapter for existing iTRY token on hub chain (Ethereum Mainnet)
 * @dev Wraps the existing iTryToken to enable cross-chain transfers via LayerZero
 *
 * Architecture:
 * - Hub Chain (Ethereum): iTryToken (native) + iTryTokenAdapter (locks tokens)
 * - Spoke Chain (MegaETH): iTryTokenOFT (mints/burns based on messages)
 *
 * Flow:
 * 1. User approves iTryTokenAdapter to spend their iTRY
 * 2. User calls send() on iTryTokenAdapter
 * 3. Adapter locks iTRY and sends LayerZero message to spoke chain
 * 4. iTryTokenOFT mints equivalent amount on spoke chain
 */
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
