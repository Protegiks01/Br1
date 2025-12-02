# NoVulnerability found for this question.

## Analysis

The security question asks whether locking shares in the wiTryOFTAdapter during bridging could reduce L1 totalSupply below MIN_SHARES and break vault operations. After thorough investigation, this scenario is **not possible** due to the fundamental mechanics of LayerZero's OFTAdapter pattern.

### Key Finding: Adapter Uses Lock/Unlock, Not Burn/Mint

The wiTryOFTAdapter inherits from LayerZero's OFTAdapter base contract, which uses a **lock/unlock pattern** for the hub chain, not a burn/mint pattern. [1](#0-0) 

When shares are bridged cross-chain:
1. Shares are **transferred** from the user to the adapter contract (locked)
2. The adapter's share balance increases
3. **The vault's totalSupply remains unchanged** because transfers don't affect totalSupply

This is confirmed by the test suite which shows that after bridging 50 shares from a total of 100, the L1 vault totalSupply remains at 100 (the 50 locked shares are still part of totalSupply). [2](#0-1) 

### MIN_SHARES Protection Mechanism

The vault enforces MIN_SHARES through `_checkMinShares()` which ensures totalSupply never falls between 0 and MIN_SHARES (exclusive). [3](#0-2) 

This check is called after deposit and withdraw operations. [4](#0-3) [5](#0-4) 

### Why No Vulnerability Exists

**Locking shares in the adapter cannot reduce totalSupply** because:
- Only **burning** shares reduces totalSupply (via withdraw/redeem operations)
- **Transferring** shares (what the adapter does) merely redistributes ownership without changing totalSupply
- The adapter holding 99% of shares vs users holding 99% of shares makes no difference to totalSupply
- MIN_SHARES violations can only occur through actual burn operations, independent of prior lock operations

The test suite explicitly verifies this behavior, showing that locked shares remain part of the vault's totalSupply. [6](#0-5) 

### Conclusion

The premise of the question—that adapter locking could reduce totalSupply—is fundamentally incorrect based on the OFTAdapter's lock/unlock implementation pattern. There is no exploitable vulnerability related to MIN_SHARES enforcement when shares are bridged cross-chain.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L22-24)
```text
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
```

**File:** test/crosschainTests/crosschain/Step8_ShareBridging.t.sol (L426-434)
```text
        // Total should be: vault total supply (100) + L2 minted (50) = 150
        // Wait, this is incorrect. Let me think...
        // In ShareOFTAdapter, shares are LOCKED in the adapter (transferred to adapter)
        // But they remain part of vault's totalSupply
        // Then on L2, new shares are MINTED
        // So total = L1 vault totalSupply (100, includes locked) + L2 totalSupply (50 minted) = 150
        assertEq(
            totalAfterL1toL2, INITIAL_DEPOSIT + SHARES_TO_BRIDGE, "Total should be L1 vault supply + L2 minted supply"
        );
```

**File:** test/crosschainTests/crosschain/Step8_ShareBridging.t.sol (L449-449)
```text
        assertEq(vaultTotalSupplyL1, INITIAL_DEPOSIT, "L1 vault should have 100 shares total");
```

**File:** src/token/wiTRY/StakediTry.sol (L228-231)
```text
    function _checkMinShares() internal view {
        uint256 _totalSupply = totalSupply();
        if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L251-251)
```text
        _checkMinShares();
```

**File:** src/token/wiTRY/StakediTry.sol (L277-277)
```text
        _checkMinShares();
```
