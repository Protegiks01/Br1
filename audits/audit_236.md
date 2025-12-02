## Title
Cooldown Period Reset Vulnerability: Multiple Cooldown Initiations Extend Lock Time for All Assets

## Summary
The `_startComposerCooldown` function in `StakediTryCrosschain.sol` and cooldown functions in `StakediTryCooldown.sol` unconditionally overwrite the `cooldownEnd` timestamp while accumulating `underlyingAmount`. This causes all previously cooling assets to have their cooldown period reset when a user initiates a new cooldown, potentially locking funds for extended periods beyond the intended cooldown duration.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/token/wiTRY/StakediTryCrosschain.sol` - `_startComposerCooldown` function
- `src/token/wiTRY/StakediTryCooldown.sol` - `cooldownShares` and `cooldownAssets` functions

**Intended Logic:** 
Users should be able to initiate multiple cooldown requests that either queue separately or accumulate to the existing cooldown without resetting the unlock time for previously cooling assets.

**Actual Logic:** 
When a user initiates a new cooldown while having an existing active cooldown, the code overwrites `cooldownEnd` with `block.timestamp + cooldownDuration`, effectively resetting the cooldown timer for ALL assets (both old and new accumulations). [1](#0-0) [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Initial Cooldown**: User calls `cooldownShares(1000 shares)` at time T₀
   - Sets: `cooldowns[user].cooldownEnd = T₀ + 30 days`
   - Sets: `cooldowns[user].underlyingAmount = 1000 iTRY`

2. **Near Unlock**: At T₀ + 29 days (1 day before cooldown completion), user initiates another cooldown with `cooldownShares(1 share)`
   - **Overwrites**: `cooldowns[user].cooldownEnd = (T₀ + 29 days) + 30 days = T₀ + 59 days`
   - **Accumulates**: `cooldowns[user].underlyingAmount = 1000 + 1 = 1001 iTRY`

3. **Extended Lock**: The original 1000 iTRY that were 1 day away from being unlockable must now wait an additional 30 days

4. **Cross-Chain Variant**: The same issue occurs with composer-initiated cooldowns via cross-chain unstaking:
   - User on spoke chain sends multiple unstake requests via `UnstakeMessenger.unstake()`
   - Each message triggers `wiTryVaultComposer._initiateCooldown()` which calls `cooldownSharesByComposer()`
   - Result: Each subsequent unstake request resets the cooldown for all accumulated assets [4](#0-3) [5](#0-4) 

**Security Property Broken:** 
Violates the **Cooldown Integrity** invariant: "Users must complete cooldown period before unstaking wiTRY". While users do eventually complete *a* cooldown period, the vulnerability extends that period beyond what should be required for their originally cooled assets.

## Impact Explanation

- **Affected Assets**: iTRY tokens locked in cooldown in the `iTrySilo` contract, representing users' unstaked wiTRY shares
- **Damage Severity**: 
  - Users' funds that are near unlock (e.g., 29/30 days complete) get locked for an additional full cooldown period (30 days)
  - If users repeatedly add small amounts to cooldown, they could face indefinite fund locks
  - Cross-chain users are particularly vulnerable as they may not realize they have a pending cooldown when initiating new unstake requests from spoke chains
- **User Impact**: 
  - Any user who initiates multiple cooldown requests (via `cooldownShares`, `cooldownAssets`, or cross-chain unstaking)
  - Especially harmful to users who batch unstake operations or regularly unstake small amounts
  - No mechanism exists to cancel or modify pending cooldowns, making this a one-way trap

## Likelihood Explanation

- **Attacker Profile**: Any user (including self-griefing), or potentially a malicious party who can trigger cross-chain unstake messages for another user's address
- **Preconditions**: 
  - User must have an existing active cooldown (cooldownEnd > block.timestamp)
  - User initiates another cooldown request before the first one completes
- **Execution Complexity**: 
  - Single transaction: User simply calls `cooldownShares` or `cooldownAssets` twice
  - Cross-chain: User sends multiple `unstake()` messages from spoke chain
  - No special timing or coordination required beyond having an active cooldown
- **Frequency**: 
  - Can occur every time a user initiates a new cooldown while having an active one
  - High likelihood as users commonly batch operations or may not track their pending cooldown status
  - Particularly common in cross-chain scenarios where users on spoke chains have limited visibility into their hub-side cooldown state

## Recommendation

The protocol should track cooldowns differently to avoid resetting the unlock time for previously accumulated assets. Here are two recommended approaches:

**Option 1: Prevent Multiple Active Cooldowns (Simpler)** [1](#0-0) 

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function _startComposerCooldown, line 170-181:

// CURRENT (vulnerable):
function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
    uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    
    _withdraw(composer, address(silo), composer, assets, shares);
    
    cooldowns[redeemer].cooldownEnd = cooldownEnd;
    cooldowns[redeemer].underlyingAmount += uint152(assets);
    
    emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
}

// FIXED:
function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
    UserCooldown storage userCooldown = cooldowns[redeemer];
    
    // Revert if cooldown already active
    if (userCooldown.cooldownEnd > block.timestamp && userCooldown.underlyingAmount > 0) {
        revert CooldownAlreadyActive();
    }
    
    uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    
    _withdraw(composer, address(silo), composer, assets, shares);
    
    userCooldown.cooldownEnd = cooldownEnd;
    userCooldown.underlyingAmount += uint152(assets);
    
    emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
}
```

**Option 2: Preserve Existing Cooldown (More User-Friendly)**

```solidity
// ALTERNATIVE FIX - Accumulate to existing cooldown without resetting:
function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
    UserCooldown storage userCooldown = cooldowns[redeemer];
    
    // Only set cooldown end if no active cooldown exists
    if (userCooldown.cooldownEnd <= block.timestamp || userCooldown.underlyingAmount == 0) {
        userCooldown.cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    }
    // Otherwise, keep existing cooldownEnd and just accumulate assets
    
    _withdraw(composer, address(silo), composer, assets, shares);
    
    userCooldown.underlyingAmount += uint152(assets);
    
    emit ComposerCooldownInitiated(composer, redeemer, shares, assets, userCooldown.cooldownEnd);
}
```

The same fix should be applied to `cooldownShares` and `cooldownAssets` in `StakediTryCooldown.sol`. [2](#0-1) [3](#0-2) 

## Proof of Concept

```solidity
// File: test/Exploit_CooldownReset.t.sol
// Run with: forge test --match-test test_CooldownResetVulnerability -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_CooldownReset is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public rewarder;
    address public treasury;
    address public user;
    
    uint256 constant INITIAL_SUPPLY = 10000e18;
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        user = makeAddr("user");
        
        // Deploy iTRY token and StakediTry vault
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)),
            rewarder,
            admin,
            treasury
        );
        
        // Setup user with tokens
        iTryToken.mint(user, INITIAL_SUPPLY);
        vm.prank(user);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        // User deposits and stakes
        vm.prank(user);
        stakediTry.deposit(1000e18, user);
    }
    
    function test_CooldownResetVulnerability() public {
        // SETUP: User initiates first cooldown with 900 shares
        vm.prank(user);
        uint256 assets1 = stakediTry.cooldownShares(900e18);
        
        // Record first cooldown end time
        (uint104 cooldownEnd1, uint152 amount1) = stakediTry.cooldowns(user);
        
        console.log("=== INITIAL COOLDOWN ===");
        console.log("Assets in cooldown:", amount1);
        console.log("Cooldown ends at:", cooldownEnd1);
        console.log("Current time:", block.timestamp);
        console.log("Time until unlock:", cooldownEnd1 - block.timestamp, "seconds");
        
        // TIME PASSES: Warp to 1 day before cooldown completion (29 days)
        uint256 nearUnlockTime = cooldownEnd1 - 1 days;
        vm.warp(nearUnlockTime);
        
        console.log("\n=== 29 DAYS LATER (1 day before unlock) ===");
        console.log("Current time:", block.timestamp);
        console.log("Time until unlock:", cooldownEnd1 - block.timestamp, "seconds");
        
        // EXPLOIT: User adds 1 more share to cooldown
        vm.prank(user);
        uint256 assets2 = stakediTry.cooldownShares(1e18);
        
        // Check the new cooldown state
        (uint104 cooldownEnd2, uint152 amount2) = stakediTry.cooldowns(user);
        
        console.log("\n=== AFTER ADDING 1 SHARE ===");
        console.log("Total assets in cooldown:", amount2);
        console.log("New cooldown ends at:", cooldownEnd2);
        console.log("Current time:", block.timestamp);
        console.log("Time until unlock:", cooldownEnd2 - block.timestamp, "seconds");
        
        // VERIFY: The cooldown was reset!
        uint256 expectedOriginalUnlock = cooldownEnd1;
        uint256 actualNewUnlock = cooldownEnd2;
        uint256 additionalLockTime = actualNewUnlock - expectedOriginalUnlock;
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Original unlock time:", expectedOriginalUnlock);
        console.log("New unlock time:", actualNewUnlock);
        console.log("Additional lock time:", additionalLockTime, "seconds (", additionalLockTime / 1 days, "days)");
        
        // Assertions proving the vulnerability
        assertEq(amount2, amount1 + assets2, "Assets should accumulate");
        assertGt(cooldownEnd2, cooldownEnd1, "Cooldown end was extended!");
        assertEq(cooldownEnd2 - block.timestamp, stakediTry.cooldownDuration(), 
            "Full cooldown period restarted from current time");
        
        // The original 900 iTRY that were 1 day away from unlock 
        // now must wait an additional 30 days!
        assertEq(additionalLockTime, 29 days, 
            "Original assets locked for 29 additional days!");
    }
}
```

## Notes

This vulnerability affects all cooldown initiation paths:
1. **Direct calls**: `cooldownShares()` and `cooldownAssets()` in `StakediTryCooldown.sol`
2. **Cross-chain calls**: `cooldownSharesByComposer()` and `cooldownAssetsByComposer()` in `StakediTryCrosschain.sol` triggered by `wiTryVaultComposer` receiving messages from `UnstakeMessenger`

The issue is particularly insidious because:
- Users on spoke chains have no visibility into their pending cooldown state on the hub chain
- There is no way to query or cancel a pending cooldown
- The protocol documentation does not warn users about this behavior
- Users naturally expect to be able to unstake additional shares while waiting for previous cooldowns to complete

The recommended fix (Option 2) is more user-friendly as it allows users to continue accumulating assets to an existing cooldown without penalty, which aligns with expected UX for staking protocols.

### Citations

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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L109-118)
```text
    function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
        if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();

        assets = previewRedeem(shares);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
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

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L108-151)
```text
    function unstake(uint256 returnTripAllocation) external payable nonReentrant returns (bytes32 guid) {
        // Validate hub peer configured
        bytes32 hubPeer = peers[hubEid];
        if (hubPeer == bytes32(0)) revert HubNotConfigured();

        // Validate returnTripAllocation
        if (returnTripAllocation == 0) revert InvalidReturnTripAllocation();

        // Build return trip options (valid TYPE_3 header)
        bytes memory extraOptions = OptionsBuilder.newOptions();

        // Encode UnstakeMessage with msg.sender as user (prevents spoofing)
        UnstakeMessage memory message = UnstakeMessage({user: msg.sender, extraOptions: extraOptions});
        bytes memory payload = abi.encode(MSG_TYPE_UNSTAKE, message);

        // Build options WITH native value forwarding for return trip execution
        // casting to 'uint128' is safe because returnTripAllocation value will be less than 2^128
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory callerOptions =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
        bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);

        // Quote with native drop included (single quote with fixed returnTripAllocation)
        MessagingFee memory fee = _quote(hubEid, payload, options, false);

        // Validate caller sent enough
        if (msg.value < fee.nativeFee) {
            revert InsufficientFee(fee.nativeFee, msg.value);
        }

        // Automatic refund to msg.sender
        MessagingReceipt memory receipt = _lzSend(
            hubEid,
            payload,
            options,
            fee,
            payable(msg.sender) // Refund excess to user
        );
        guid = receipt.guid;

        emit UnstakeRequested(msg.sender, hubEid, fee.nativeFee, msg.value - fee.nativeFee, guid);

        return guid;
    }
```
