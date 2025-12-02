# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the `cooldownAssets` function and the cooldown accumulation mechanism, I found that the behavior is **working as intended** and there is **no exploitable vulnerability**.

### Key Findings:

**1. The `maxWithdraw(msg.sender)` check DOES account for shares in cooldown**

The check at line 97 validates against the user's **current** share balance. [1](#0-0) 

Shares that have already been cooldown'd are **burned** via the `_withdraw` call at line 104, removing them from the user's balance. [2](#0-1) 

The `_withdraw` function has a `nonReentrant` modifier and properly burns shares through the ERC4626 implementation. [3](#0-2) 

**2. The accumulation behavior (+=) is intentional and tested**

The protocol includes a test case `test_cooldownSharesByComposer_multipleCooldownsAccumulate` that explicitly validates that multiple cooldowns should accumulate assets while resetting the timestamp. [4](#0-3) 

The test comment states "should overwrite timestamp but accumulate assets" and asserts that `amount2 == assets1 + assets2`, confirming this is expected behavior.

**3. Each cooldown properly burns shares proportional to locked assets**

When `cooldownAssets(assets)` is called:
- Line 97: Validates user has sufficient current shares for the requested asset amount
- Line 99: Calculates the exact number of shares to burn using `previewWithdraw(assets)`
- Line 102: Adds to the accumulated `underlyingAmount`
- Line 104: Burns the calculated shares via `_withdraw` [5](#0-4) 

**4. Attack scenario does not create unfair advantage**

Testing the proposed scenario:
- User cooldowns 1000 shares → burns 1000 shares, locks 1000 iTRY
- User receives 1000 new shares → total burned: 1000 shares
- User cooldowns again → burns 1000 more shares, locks 1000 more iTRY
- Total: 2000 shares burned, 2000 iTRY locked
- User unstakes: receives 2000 iTRY

**Result: Fair exchange - no value extraction**

### Notes

The security question's concern about "shares already in cooldown" is addressed by the protocol design: those shares are **no longer in the user's balance** because they've been burned. The `maxWithdraw` check on subsequent calls only validates against remaining (unburned) shares, which is the correct behavior. The accumulation mechanism allows users to cooldown in multiple batches, with each batch properly burning shares before adding to the cooldown amount.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L96-105)
```text
    function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
        if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();

        shares = previewWithdraw(assets);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L262-277)
```text
    function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
        internal
        override
        nonReentrant
        notZero(assets)
        notZero(shares)
    {
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
        }

        super._withdraw(caller, receiver, _owner, assets, shares);
        _checkMinShares();
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
