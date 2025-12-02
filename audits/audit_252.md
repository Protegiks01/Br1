## Title
Blacklisted Composer Permanently Locks L2 Users' wiTRY Shares in Cross-Chain Unstaking Flow

## Summary
When the `wiTryVaultComposer` (composer) is assigned `FULL_RESTRICTED_STAKER_ROLE`, all cross-chain cooldown initiations fail because `_startComposerCooldown` calls `_withdraw` which explicitly reverts for restricted stakers. This permanently locks L2 users' wiTRY shares that were bridged to the composer, as no alternative recovery mechanism exists for cross-chain entitlements.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` (function `_startComposerCooldown`, line 174)

**Intended Logic:** The `_startComposerCooldown` function should burn the composer's wiTRY shares, transfer the underlying iTRY to the silo for cooldown, and credit the cooldown entitlement to the L2 user (redeemer). This enables L2 users to bridge their shares cross-chain, initiate cooldown, and later unstake their assets. [1](#0-0) 

**Actual Logic:** When the composer has `FULL_RESTRICTED_STAKER_ROLE`, the `_withdraw` call at line 174 reverts because the base `StakediTry._withdraw` function explicitly blocks withdrawals where the caller, receiver, or owner has this role. [2](#0-1) 

**Exploitation Path:**
1. **L2 users bridge wiTRY shares**: L2 users send wiTRY shares to `wiTryVaultComposer` on L1 via LayerZero OFT with "INITIATE_COOLDOWN" command in the compose message. [3](#0-2) 

2. **Composer is blacklisted**: The `wiTryVaultComposer` address is assigned `FULL_RESTRICTED_STAKER_ROLE` by the blacklist manager (e.g., for regulatory compliance reasons). [4](#0-3) 

3. **Cooldown initiation fails**: When `cooldownSharesByComposer` is called, it invokes `_startComposerCooldown`, which calls `_withdraw(composer, address(silo), composer, assets, shares)` at line 174. Since the composer has `FULL_RESTRICTED_STAKER_ROLE`, the check at lines 269-273 evaluates to true and reverts with `OperationNotAllowed()`. [5](#0-4) 

4. **Permanent fund lock**: L2 users' shares remain stuck in the composer contract. They cannot:
   - Complete cooldown initiation (reverts at `_withdraw`)
   - Fast redeem (also calls `_withdraw` through `_redeemWithFee`)
   - Transfer shares out (blocked by `_beforeTokenTransfer`)
   - Unstake later (no cooldown entry was created) [6](#0-5) 

**Security Property Broken:** Violates the "Cross-chain Message Integrity" invariant - LayerZero messages for unstaking must be delivered to the correct user with proper validation, but the blacklisting of infrastructure breaks this guarantee permanently.

## Impact Explanation
- **Affected Assets**: All wiTRY shares held by the `wiTryVaultComposer` on behalf of L2 users who bridged their shares for cross-chain unstaking.
- **Damage Severity**: Complete and permanent loss of access to staked assets. L2 users lose 100% of their bridged wiTRY shares with no recovery mechanism, as the shares are owned by the composer contract, not by individual users.
- **User Impact**: All L2 users who bridged wiTRY shares to the composer while it had or subsequently received `FULL_RESTRICTED_STAKER_ROLE` are affected. This could impact hundreds or thousands of users depending on the protocol's L2 adoption.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is triggered by legitimate protocol operations. The blacklist manager assigns `FULL_RESTRICTED_STAKER_ROLE` to the composer for valid reasons (regulatory compliance, security incident, etc.).
- **Preconditions**: 
  - Composer has received `COMPOSER_ROLE` and is operational
  - L2 users have bridged wiTRY shares to the composer
  - Blacklist manager assigns `FULL_RESTRICTED_STAKER_ROLE` to the composer address
- **Execution Complexity**: Single administrative action (blacklisting) immediately breaks all pending and future cross-chain unstaking operations.
- **Frequency**: Permanent effect once composer is blacklisted. All subsequent cross-chain cooldown initiations will fail until the composer is un-blacklisted, but already-bridged shares remain locked.

## Recommendation

The core issue is that `_withdraw` treats the composer as a restricted staker when it should be treated as a trusted intermediary. The fix should exempt the composer role from the `FULL_RESTRICTED_STAKER_ROLE` check when it's acting on behalf of L2 users.

```solidity
// In src/token/wiTRY/StakediTry.sol, function _withdraw, lines 262-278:

// CURRENT (vulnerable):
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
}

// FIXED:
function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
{
    // Skip restriction check if caller is a composer acting on behalf of users
    // Composers are trusted protocol infrastructure that handle cross-chain operations
    bool isComposerOperation = hasRole(COMPOSER_ROLE, caller) && hasRole(COMPOSER_ROLE, _owner);
    
    if (!isComposerOperation) {
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
        }
    }

    super._withdraw(caller, receiver, _owner, assets, shares);
    _checkMinShares();
}
```

**Alternative Mitigation:** Create a separate internal function `_composerWithdraw` that bypasses the restriction check and is only callable from `StakediTryCrosschain` functions. This maintains separation of concerns while allowing composer operations to function independently of the composer's own restriction status.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedComposerLocksL2Funds.t.sol
// Run with: forge test --match-test test_BlacklistedComposerLocksL2Funds -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/iTRY/iTry.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_BlacklistedComposerLocksL2Funds is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    iTry itry;
    address admin;
    address blacklistManager;
    address l2User;
    uint256 shareAmount;
    
    function setUp() public {
        admin = address(0x1);
        blacklistManager = address(0x2);
        l2User = address(0x3);
        
        // Deploy iTRY and vault (simplified for PoC)
        vm.startPrank(admin);
        itry = new iTry(admin, admin, admin, admin);
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            address(0x4), // rewarder
            admin,
            address(0x5)  // fast redeem treasury
        );
        
        // Grant roles
        vault.grantRole(vault.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        vault.grantRole(vault.COMPOSER_ROLE(), address(composer));
        vm.stopPrank();
        
        // Simulate L2 user bridging shares to composer
        shareAmount = 100 ether;
        deal(address(vault), address(composer), shareAmount);
    }
    
    function test_BlacklistedComposerLocksL2Funds() public {
        // SETUP: Composer has shares on behalf of L2 user
        uint256 composerBalanceBefore = vault.balanceOf(address(composer));
        assertEq(composerBalanceBefore, shareAmount, "Composer should have L2 user's shares");
        
        // EXPLOIT: Blacklist manager assigns FULL_RESTRICTED_STAKER_ROLE to composer
        vm.prank(blacklistManager);
        vault.addToBlacklist(address(composer), true); // true = full blacklisting
        
        // VERIFY: Cooldown initiation fails, permanently locking L2 user's shares
        vm.prank(address(composer));
        vm.expectRevert(IStakediTry.OperationNotAllowed.selector);
        vault.cooldownSharesByComposer(shareAmount, l2User);
        
        // L2 user's shares are stuck - no recovery mechanism
        assertEq(vault.balanceOf(address(composer)), shareAmount, 
            "Shares remain locked in composer with no recovery path");
        
        // Fast redeem also fails (same _withdraw path)
        vm.prank(address(composer));
        vm.expectRevert(IStakediTry.OperationNotAllowed.selector);
        vault.fastRedeemThroughComposer(shareAmount, l2User, address(composer));
    }
}
```

## Notes

This vulnerability represents a critical flaw in the cross-chain unstaking architecture. The `FULL_RESTRICTED_STAKER_ROLE` was designed to prevent individual users from unstaking their shares, but applying it to the composer (a protocol infrastructure component) breaks the entire L2→L1 unstaking flow.

The `redistributeLockedAmount` function can move the composer's shares to another address, but this doesn't solve the problem because:
1. It doesn't track which shares belong to which L2 user
2. L2 users have no on-chain record of their entitlement to specific shares
3. The cooldown entries (`cooldowns[redeemer]`) were never created, so L2 users cannot claim assets even if shares are redistributed

This is distinct from the known issue about blacklisted users transferring via allowance - this vulnerability affects protocol infrastructure (the composer) not individual user accounts, and results in permanent fund loss for multiple L2 users rather than a single-user bypass.

### Citations

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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L162-181)
```text
     * @dev Internal function to initiate cooldown for a redeemer using composer's shares
     * @param composer Address that owns the shares being burned
     * @param redeemer Address that will be able to claim the cooled-down assets
     * @param shares Amount of shares to burn
     * @param assets Amount of assets to place in cooldown
     * @notice Follows Checks-Effects-Interactions pattern: external call to _withdraw occurs first,
     *         then state changes. _withdraw has nonReentrant modifier from base StakediTryV2 for safety.
     */
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

**File:** src/token/wiTRY/StakediTry.sol (L126-133)
```text
    function addToBlacklist(address target, bool isFullBlacklisting)
        external
        onlyRole(BLACKLIST_MANAGER_ROLE)
        notOwner(target)
    {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _grantRole(role, target);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L262-278)
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
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L292-299)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L87-96)
```text
     * @notice Initiates async redemption via cooldown mechanism
     * @param _redeemer The bytes32 address of the redeemer
     * @param _shareAmount The number of shares to redeem
     */
    function _initiateCooldown(bytes32 _redeemer, uint256 _shareAmount) internal virtual {
        address redeemer = _redeemer.bytes32ToAddress();
        if (redeemer == address(0)) revert InvalidZeroAddress();
        uint256 assetAmount = IStakediTryCrosschain(address(VAULT)).cooldownSharesByComposer(_shareAmount, redeemer);
        emit CooldownInitiated(_redeemer, redeemer, _shareAmount, assetAmount);
    }
```
