# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the `unstakeThroughComposer` function in `StakediTryCrosschain.sol` (lines 77-101), I can confirm that the if-else structure safely handles cooldown storage mutations and the else branch revert cannot be bypassed to leave data in a partially updated state. [1](#0-0) 

**Key findings:**

1. **No partial storage updates possible**: Line 87 performs only a READ operation (copying `userCooldown.underlyingAmount` to the memory variable `assets`). No storage mutations occur before the if-else structure. [2](#0-1) 

2. **IF branch (cooldown ended)**: Storage is cleared at lines 90-91, then an external call is made at line 93. If the external call fails, Solidity's transaction atomicity guarantees that all storage updates (lines 90-91) are rolled back. [3](#0-2) 

3. **ELSE branch (cooldown not ended)**: The revert at line 95 occurs BEFORE any storage modifications. The transaction is reverted with no state changes persisted.

4. **No bypass mechanism exists**: A `revert` statement is unconditional and cannot be "bypassed" within the same transaction context. While external callers (like `wiTryVaultComposer._handleUnstake`) could use try-catch to handle the revert, this does not affect storage in `StakediTryCrosschain` - the cooldown data remains unchanged. [4](#0-3) 

5. **Reentrancy protection**: The function has the `nonReentrant` modifier, preventing any reentrant calls that could interfere with the cooldown state during the external call at line 93. [5](#0-4) 

**Conclusion**: Both branches of the if-else structure handle cooldown storage consistently. The IF branch clears the cooldown after successful validation and asset withdrawal, while the ELSE branch reverts without any storage modifications. Solidity's transaction atomicity ensures that storage is either fully updated (success) or completely unchanged (revert), with no possibility of partial updates.

## Notes

While analyzing the code, I did identify one design difference from the base `unstake()` function: `unstakeThroughComposer` does not include the `|| cooldownDuration == 0` check that would allow claiming when cooldowns are globally disabled. However, this is not a vulnerability for the specific question asked, as users can still recover their assets by calling the regular `unstake()` function directly when cooldowns are disabled. [6](#0-5)

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L77-80)
```text
    function unstakeThroughComposer(address receiver)
        external
        onlyRole(COMPOSER_ROLE)
        nonReentrant
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L86-87)
```text
        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L89-96)
```text
        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
        } else {
            revert InvalidCooldown();
        }
```

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L254-255)
```text
        // Call vault to unstake
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L84-84)
```text
        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
```
