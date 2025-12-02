# NoVulnerability found for this question.

After thorough investigation of the cooldown mechanism and cross-chain unstaking flow, the attack described in the security question is **not possible**.

## Analysis Summary

The question asks if an attacker can front-run `unstakeThroughComposer` by initiating their own cooldown for the same receiver address. I examined all potential attack vectors:

### 1. Regular Cooldown Functions Cannot Target Other Users
The `cooldownShares` and `cooldownAssets` functions only modify the caller's own cooldown state: [1](#0-0) 

These functions set `cooldowns[msg.sender]`, making it impossible for an attacker to affect another user's cooldown data.

### 2. Composer Cooldown Functions Have Protected Redeemer Assignment
The composer-based cooldown functions require `COMPOSER_ROLE` and the redeemer address is determined by the LayerZero message sender: [2](#0-1) 

The redeemer parameter comes from `_composeFrom` in the vault composer: [3](#0-2) 

### 3. ComposeFrom Cannot Be Spoofed
The `_composeFrom` value is extracted from the LayerZero message header using `OFTComposeMsgCodec.composeFrom()`: [4](#0-3) 

This address represents the actual sender of the OFT message on the source chain and is encoded by the OFT contract itself—it cannot be manipulated by users.

### 4. Unstake Message Sender Is Validated
When initiating an unstake via `UnstakeMessenger`, the user address is always set to `msg.sender`: [5](#0-4) 

This prevents authorization spoofing.

## Notes

While the `_startComposerCooldown` function does OVERWRITE `cooldownEnd` (not accumulate it), this only becomes relevant if the same user initiates multiple cooldowns: [6](#0-5) 

However, this is user error (sending multiple conflicting operations), not an external attack vector. An attacker cannot exploit this to grief or steal from other users because they cannot initiate a cooldown for an arbitrary victim address—all cooldown mechanisms are tied to either `msg.sender` or the authenticated OFT message sender.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L96-118)
```text
    function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
        if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();

        shares = previewWithdraw(assets);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }

    /// @notice redeem shares into assets and starts a cooldown to claim the converted underlying asset
    /// @param shares shares to redeem
    function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
        if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();

        assets = previewRedeem(shares);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L36-48)
```text
    function cooldownSharesByComposer(uint256 shares, address redeemer)
        external
        onlyRole(COMPOSER_ROLE)
        ensureCooldownOn
        returns (uint256 assets)
    {
        address composer = msg.sender;
        if (redeemer == address(0)) revert InvalidZeroAddress();
        if (shares > maxRedeem(composer)) revert ExcessiveRedeemAmount();

        assets = previewRedeem(shares);
        _startComposerCooldown(composer, redeemer, shares, assets);
    }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L170-181)
```text
    function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

        // Interaction: External call to base contract (protected by nonReentrant modifier)
        _withdraw(composer, address(silo), composer, assets, shares);

        // Effects: State changes after external call (following CEI pattern)
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);

        emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L91-96)
```text
    function _initiateCooldown(bytes32 _redeemer, uint256 _shareAmount) internal virtual {
        address redeemer = _redeemer.bytes32ToAddress();
        if (redeemer == address(0)) revert InvalidZeroAddress();
        uint256 assetAmount = IStakediTryCrosschain(address(VAULT)).cooldownSharesByComposer(_shareAmount, redeemer);
        emit CooldownInitiated(_redeemer, redeemer, _shareAmount, assetAmount);
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L129-131)
```text
        bytes32 composeFrom = _message.composeFrom();
        uint256 amount = _message.amountLD();
        bytes memory composeMsg = _message.composeMsg();
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L119-121)
```text
        // Encode UnstakeMessage with msg.sender as user (prevents spoofing)
        UnstakeMessage memory message = UnstakeMessage({user: msg.sender, extraOptions: extraOptions});
        bytes memory payload = abi.encode(MSG_TYPE_UNSTAKE, message);
```
