# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the iTRY cross-chain bridging mechanism and transfer state enforcement, I can confirm that **users CANNOT bypass the FULLY_DISABLED transfer state** through the OFT adapter's `send()` function.

## Key Findings

### 1. Transfer State Enforcement is Absolute

The `iTry` token's `_beforeTokenTransfer()` hook enforces the FULLY_DISABLED state unconditionally: [1](#0-0) 

When `transferState` is set to `FULLY_DISABLED`, the function reverts with `OperationNotAllowed()` with **no exceptions** for any role, including MINTER_CONTRACT, DEFAULT_ADMIN_ROLE, or any other privileged address.

### 2. OFT Adapter Uses Standard Transfer Flow

The `iTryTokenOFTAdapter` is a simple wrapper around LayerZero's `OFTAdapter`: [2](#0-1) 

The adapter uses the standard **lock/unlock pattern**, which requires calling `transferFrom()` to lock tokens from the user into the adapter contract before sending cross-chain messages. This was confirmed in the test files: [3](#0-2) 

### 3. No Special Privileges Granted

The deployment script confirms that the adapter is deployed without any special roles on the iTry token: [4](#0-3) 

No `grantRole()` calls are made to give the adapter any privileged access.

### 4. Transfer Hook is Always Triggered

Since the OFT adapter must call `transferFrom()` to lock tokens, this will always trigger the `_beforeTokenTransfer()` hook, which enforces all transfer restrictions including the FULLY_DISABLED state.

## Conclusion

The invariant **"FULLY_DISABLED: NO addresses can transfer"** is properly enforced across all transfer mechanisms, including cross-chain bridging. The OFT adapter cannot bypass this restriction because it relies on the standard ERC20 `transferFrom()` function, which triggers the transfer hook that enforces the FULLY_DISABLED state.

### Citations

**File:** src/token/iTRY/iTry.sol (L219-221)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```

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

**File:** script/deploy/hub/03_DeployCrossChain.s.sol (L82-85)
```text
        iTryTokenOFTAdapter itryAdapter = _deployITryAdapter(factory, addrs.itryToken, endpoint);
        wiTryOFTAdapter shareAdapter = _deployShareAdapter(factory, addrs.staking, endpoint);
        wiTryVaultComposer vaultComposer =
            _deployVaultComposer(factory, addrs.staking, address(itryAdapter), address(shareAdapter), endpoint);
```
