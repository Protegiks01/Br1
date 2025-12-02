# NoVulnerability found for this question.

## Analysis Summary

After thoroughly investigating the security question about MIN_SHARES protection differences between hub chain's `StakediTry` and spoke chain's `wiTryOFT`, I conclude that **the lack of MIN_SHARES protection in wiTryOFT is not a vulnerability**.

## Key Architectural Differences

**Hub Chain - StakediTry (ERC4626 Vault):** [1](#0-0) 

StakediTry enforces MIN_SHARES = 1 ether protection through `_checkMinShares()`: [2](#0-1) 

This check is called after deposit/withdrawal operations and in `redistributeLockedAmount()`: [3](#0-2) 

**Spoke Chain - wiTryOFT (Simple OFT Token):** [4](#0-3) 

The `redistributeBlackListedFunds()` function has no MIN_SHARES validation: [5](#0-4) 

## Why This Is Not A Vulnerability

**1. Fundamental Design Difference:**

wiTryOFT extends LayerZero's OFT standard and is a **token representation** of shares, not a vault. It has no ERC4626 mechanics, no `convertToAssets()`, `convertToShares()`, or `totalAssets()` functions.

**2. Share Price Determination:**

The critical insight is documented in the VaultComposerSync constructor: [6](#0-5) 

This explains why the hub chain's `wiTryOFTAdapter` must use **lock/unlock** pattern (not mint/burn) - to preserve the vault's totalSupply and maintain correct asset:share ratios. On the spoke chain, wiTryOFT can freely mint/burn because:
- Its totalSupply is independent of the hub chain's vault accounting
- Share value is determined entirely by the hub chain's `StakediTry` vault

**3. No Inflation Attack Vector:**

MIN_SHARES protection exists to prevent first depositor attacks in ERC4626 vaults where an attacker can manipulate share prices by:
1. Depositing 1 wei to get initial shares
2. Donating assets directly to vault to inflate share price
3. Stealing from subsequent depositors

This attack is impossible on wiTryOFT because:
- It has no share-to-asset conversion logic
- Share value comes from the hub chain's vault (which has MIN_SHARES protection)
- Donating tokens to wiTryOFT doesn't affect share value

**4. TotalSupply = 0 Scenario Analysis:**

Even if `redistributeBlackListedFunds()` causes wiTryOFT's totalSupply to drop to 0:
- No share accounting breaks (wiTryOFT has no accounting logic)
- No price manipulation possible (price determined by hub chain)
- Next bridge from hub mints shares at correct value from hub chain's vault calculations

## Conclusion

The lack of MIN_SHARES protection in wiTryOFT is **by design**, not a vulnerability. MIN_SHARES protection is only necessary for ERC4626 vaults with share price calculations, not for simple token representations of shares whose value is determined externally.

## Notes

This is explicitly a known design consideration per the Zellic audit findings mentioned in the README, where MIN_SHARES griefing attacks are acknowledged for the vault (StakediTry), but the spoke chain token (wiTryOFT) operates under different mechanics that don't require such protection.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L32-32)
```text
    uint256 private constant MIN_SHARES = 1 ether;
```

**File:** src/token/wiTRY/StakediTry.sol (L168-173)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && !hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            uint256 iTryToVest = previewRedeem(amountToDistribute);
            _burn(from, amountToDistribute);
            _checkMinShares();
```

**File:** src/token/wiTRY/StakediTry.sol (L228-231)
```text
    function _checkMinShares() internal view {
        uint256 _totalSupply = totalSupply();
        if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L6-27)
```text
/**
 * @title wiTryOFT
 * @notice OFT representation of wiTRY shares on spoke chains (MegaETH)
 * @dev This contract mints/burns share tokens based on LayerZero messages from the hub chain
 *
 * Architecture (Phase 1 - Instant Redeems):
 * - Hub Chain (Ethereum): StakediTry (vault) + wiTryOFTAdapter (locks shares)
 * - Spoke Chain (MegaETH): wiTryOFT (mints/burns based on messages)
 *
 * Flow from Hub to Spoke:
 * 1. Hub adapter locks native wiTRY shares
 * 2. LayerZero message sent to this contract
 * 3. This contract mints equivalent OFT share tokens
 *
 * Flow from Spoke to Hub:
 * 1. This contract burns OFT share tokens
 * 2. LayerZero message sent to hub adapter
 * 3. Hub adapter unlocks native wiTRY shares
 *
 * NOTE: These shares represent staked iTRY in the vault. The share value
 * increases as yield is distributed to the vault on the hub chain.
 */
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L117-127)
```text
    function redistributeBlackListedFunds(address _from, uint256 _amount) external onlyOwner {
        // @dev Only allow redistribution if the address is blacklisted
        if (!blackList[_from]) revert NotBlackListed();

        // @dev Temporarily remove from the blacklist, transfer funds, and restore to the blacklist
        blackList[_from] = false;
        _transfer(_from, owner(), _amount);
        blackList[_from] = true;

        emit RedistributeFunds(_from, _amount);
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L90-92)
```text
        /// @dev ShareOFT must be an OFT adapter. We can infer this by checking 'approvalRequired()'.
        /// @dev burn() on tokens when a user sends changes totalSupply() which the asset:share ratio depends on.
        if (!IOFT(SHARE_OFT).approvalRequired()) revert ShareOFTNotAdapter(SHARE_OFT);
```
