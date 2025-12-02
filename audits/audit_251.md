# NoVulnerability found for this question.

After thorough investigation of the `unstakeThroughComposer` function in `StakediTryCrosschain.sol` lines 86-87, I found **no TOCTOU vulnerability**.

## Analysis Summary

The security question asks whether reading `userCooldown.underlyingAmount` before checking `cooldownEnd` creates a Time-of-Check Time-of-Use vulnerability where `cooldownEnd` could be modified between the read and check, causing `underlyingAmount` to be stale.

**Why no TOCTOU exists:**

1. **Reentrancy Protection**: The function has the `nonReentrant` modifier [1](#0-0) , preventing any re-entrant calls that could modify state.

2. **No External Calls Before Check**: Between line 87 (reading `underlyingAmount`) and line 89 (checking `cooldownEnd`), there are no external calls. The `silo.withdraw()` call occurs AFTER the check at line 93 [2](#0-1) .

3. **Protected Withdrawal Flow**: The underlying `_withdraw` function also has `nonReentrant` protection [3](#0-2) , preventing any state modification through that path.

4. **Simple Silo Transfer**: The silo's `withdraw` function is a simple token transfer with no callbacks [4](#0-3) .

5. **Access Control**: Only the COMPOSER role can modify cooldowns for cross-chain users via `_startComposerCooldown` [5](#0-4) , and this role is trusted per the protocol's design.

**Cooldown Accumulation is Intentional**: While multiple cooldowns do accumulate (with `underlyingAmount` using `+=` and `cooldownEnd` using `=`), this is verified as intentional behavior in the test suite [6](#0-5) .

The storage pointer remains consistent throughout execution, and there is no window—either within the transaction or across transactions—where `cooldownEnd` modification would create a TOCTOU vulnerability affecting the read `underlyingAmount` value.

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L77-81)
```text
    function unstakeThroughComposer(address receiver)
        external
        onlyRole(COMPOSER_ROLE)
        nonReentrant
        returns (uint256 assets)
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L86-96)
```text
        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
        } else {
            revert InvalidCooldown();
        }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L170-178)
```text
    function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

        // Interaction: External call to base contract (protected by nonReentrant modifier)
        _withdraw(composer, address(silo), composer, assets, shares);

        // Effects: State changes after external call (following CEI pattern)
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);
```

**File:** src/token/wiTRY/StakediTry.sol (L262-265)
```text
    function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
        internal
        override
        nonReentrant
```

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** test/crosschainTests/StakediTryCrosschain.t.sol (L213-236)
```text
    function test_cooldownSharesByComposer_multipleCooldownsAccumulate() public {
        // Setup
        vm.prank(owner);
        vault.grantRole(COMPOSER_ROLE, vaultComposer);
        _mintAndDeposit(vaultComposer, 200e18);

        // First cooldown
        vm.prank(vaultComposer);
        uint256 assets1 = vault.cooldownSharesByComposer(50e18, alice);

        (uint104 cooldownEnd1, uint256 amount1) = vault.cooldowns(alice);
        assertEq(amount1, assets1);

        // Fast forward time (but not past cooldown)
        vm.warp(block.timestamp + 30 days);

        // Second cooldown (should overwrite timestamp but accumulate assets)
        vm.prank(vaultComposer);
        uint256 assets2 = vault.cooldownSharesByComposer(50e18, alice);

        (uint104 cooldownEnd2, uint256 amount2) = vault.cooldowns(alice);
        assertEq(amount2, assets1 + assets2); // Assets accumulate
        assertGt(cooldownEnd2, cooldownEnd1); // Timestamp updates (overwrites)
    }
```
