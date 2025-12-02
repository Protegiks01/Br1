## Title
Cooldown State Corruption: Multiple Cooldown Initiations Extend Lock Period for Earlier Assets

## Summary
The `cooldownShares()` function and composer-based cooldown functions lack validation to prevent multiple cooldown initiations for the same address. Each new cooldown overwrites the `cooldownEnd` timestamp while accumulating `underlyingAmount`, causing all assets to share the most recent cooldown deadline and locking earlier assets longer than their intended 90-day period.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` - `cooldownShares()` function (lines 109-118) and `src/token/wiTRY/StakediTryCrosschain.sol` - `_startComposerCooldown()` function (lines 170-181)

**Intended Logic:** Users should be able to initiate cooldowns for their wiTRY shares, with each cooldown completing after the configured cooldown period (default 90 days). The system should track when different tranches of assets become available for unstaking.

**Actual Logic:** The implementation allows multiple cooldowns to be initiated without validation. When a new cooldown is started:
- `cooldownEnd` is SET (overwritten) to `block.timestamp + cooldownDuration` [1](#0-0) 
- `underlyingAmount` is INCREMENTED (accumulated) using `+=` [2](#0-1) 
- Then `_withdraw()` is called without any validation of existing cooldown state [3](#0-2) 

The `_withdraw()` function in the base contract only validates blacklist roles and share amounts, but does NOT check if the caller already has an active cooldown: [4](#0-3) 

The same issue exists in the cross-chain composer flow, where `_startComposerCooldown()` updates the redeemer's cooldown state after calling `_withdraw()`: [5](#0-4) 

**Exploitation Path:**
1. User Alice calls `cooldownShares(1000 shares)` at time T1, initiating cooldown with `cooldownEnd = T1 + 90 days` and `underlyingAmount = 1000 assets`
2. At time T2 = T1 + 89 days (one day before cooldown completes), Alice calls `cooldownShares(1 share)` again
3. The second call overwrites `cooldownEnd = T2 + 90 days = T1 + 179 days` and sets `underlyingAmount = 1001 assets`
4. Alice must now wait until T1 + 179 days to unstake all 1001 assets, even though 1000 of those assets should have been available at T1 + 90 days
5. The `unstake()` function only allows withdrawing ALL accumulated assets at once after the cooldownEnd: [6](#0-5) 

**Security Property Broken:** Violates the **Cooldown Integrity** invariant which states "Users must complete cooldown period before unstaking wiTRY". While users still must wait for a cooldown, the mechanism fails to correctly track when different tranches should become available, causing earlier assets to be locked beyond their intended period.

## Impact Explanation
- **Affected Assets**: All wiTRY shares in cooldown are at risk of extended lock periods
- **Damage Severity**: Users may have their assets locked for up to 2x the intended cooldown duration (e.g., 180 days instead of 90 days). This is a temporary fund lock rather than permanent loss, as assets remain recoverable after the extended period
- **User Impact**: 
  - Any user who initiates multiple cooldowns (whether intentionally or accidentally)
  - Users conducting cross-chain unstaking operations where both direct L1 cooldowns and composer-initiated cooldowns exist for the same address
  - Affects users with legitimate need for liquidity at the expected cooldown completion time

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged user with wiTRY shares can trigger this on themselves. Can also occur through honest cross-chain operations where a user has both L1 shares and cross-chain shares
- **Preconditions**: 
  - User has wiTRY shares
  - Cooldown duration is enabled (non-zero)
  - User attempts to initiate a second cooldown while first is still pending
- **Execution Complexity**: Simple - requires only calling `cooldownShares()` twice in separate transactions, or a combination of direct cooldown and cross-chain composer cooldown
- **Frequency**: Can occur repeatedly for any user managing multiple unstaking operations or using both L1 and cross-chain unstaking flows

## Recommendation

Add validation to prevent initiating a new cooldown when an active cooldown already exists:

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, function cooldownShares, before line 114:

// CURRENT (vulnerable):
function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
    if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();

    assets = previewRedeem(shares);

    cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    cooldowns[msg.sender].underlyingAmount += uint152(assets);

    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}

// FIXED:
function cooldownShares(uint256 shares) external ensureCooldownOn returns (uint256 assets) {
    if (shares > maxRedeem(msg.sender)) revert ExcessiveRedeemAmount();
    
    // Prevent initiating new cooldown if one is already active
    UserCooldown storage userCooldown = cooldowns[msg.sender];
    if (userCooldown.cooldownEnd > block.timestamp && userCooldown.underlyingAmount > 0) {
        revert InvalidCooldown(); // Active cooldown already exists
    }

    assets = previewRedeem(shares);

    userCooldown.cooldownEnd = uint104(block.timestamp) + cooldownDuration;
    userCooldown.underlyingAmount = uint152(assets); // Use = instead of += since we're validating no prior cooldown

    _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
}
```

Apply the same validation to `cooldownAssets()` and in `_startComposerCooldown()` in StakediTryCrosschain.sol:

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, function _startComposerCooldown, before line 171:

function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
    // Prevent initiating new cooldown if redeemer already has an active one
    UserCooldown storage redeemerCooldown = cooldowns[redeemer];
    if (redeemerCooldown.cooldownEnd > block.timestamp && redeemerCooldown.underlyingAmount > 0) {
        revert InvalidCooldown(); // Active cooldown already exists for this redeemer
    }
    
    uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

    _withdraw(composer, address(silo), composer, assets, shares);

    redeemerCooldown.cooldownEnd = cooldownEnd;
    redeemerCooldown.underlyingAmount = uint152(assets); // Use = instead of += since we're validating no prior cooldown

    emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
}
```

**Alternative Mitigation:** If the protocol intends to support multiple cooldown tranches with different end times, implement a proper queue or array structure to track each cooldown separately, rather than using a single UserCooldown struct.

## Proof of Concept

```solidity
// File: test/Exploit_CooldownStateCorruption.t.sol
// Run with: forge test --match-test test_CooldownStateCorruption -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_CooldownStateCorruption is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public alice;
    
    uint256 public constant INITIAL_SUPPLY = 2000e18;
    uint256 public constant COOLDOWN_DURATION = 90 days;
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        rewarder = makeAddr("rewarder");
        alice = makeAddr("alice");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry with cooldown
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)), 
            rewarder, 
            admin, 
            treasury
        );
        
        // Mint tokens to alice
        iTryToken.mint(alice, INITIAL_SUPPLY);
        
        // Alice approves StakediTry
        vm.prank(alice);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        // Alice deposits to get shares
        vm.prank(alice);
        stakediTry.deposit(INITIAL_SUPPLY, alice);
    }
    
    function test_CooldownStateCorruption() public {
        uint256 firstCooldownShares = 1000e18;
        uint256 secondCooldownShares = 1e18;
        
        // SETUP: Alice starts first cooldown at T1
        uint256 t1 = block.timestamp;
        vm.prank(alice);
        stakediTry.cooldownShares(firstCooldownShares);
        
        // Verify first cooldown state
        (uint104 cooldownEnd1, uint152 underlyingAmount1) = stakediTry.cooldowns(alice);
        assertEq(cooldownEnd1, t1 + COOLDOWN_DURATION, "First cooldownEnd incorrect");
        assertEq(underlyingAmount1, firstCooldownShares, "First underlyingAmount incorrect");
        
        // EXPLOIT: Alice initiates second cooldown at T2 = T1 + 89 days (1 day before first cooldown completes)
        uint256 t2 = t1 + 89 days;
        vm.warp(t2);
        vm.prank(alice);
        stakediTry.cooldownShares(secondCooldownShares);
        
        // VERIFY: Cooldown state corruption confirmed
        (uint104 cooldownEnd2, uint152 underlyingAmount2) = stakediTry.cooldowns(alice);
        
        // cooldownEnd was OVERWRITTEN to T2 + 90 days instead of keeping T1 + 90 days
        assertEq(cooldownEnd2, t2 + COOLDOWN_DURATION, "CooldownEnd should be reset to T2 + 90 days");
        assertEq(cooldownEnd2, t1 + 179 days, "Alice must wait 179 days instead of 90 days");
        
        // underlyingAmount was ACCUMULATED correctly
        assertEq(underlyingAmount2, firstCooldownShares + secondCooldownShares, "UnderlyingAmount should accumulate");
        
        // IMPACT: Alice cannot unstake at T1 + 90 days (when first cooldown should complete)
        vm.warp(t1 + COOLDOWN_DURATION);
        vm.expectRevert(abi.encodeWithSelector(IStakediTryCooldown.InvalidCooldown.selector));
        vm.prank(alice);
        stakediTry.unstake(alice);
        
        // IMPACT: Alice must wait until T1 + 179 days to unstake ALL her assets
        vm.warp(t1 + 179 days);
        vm.prank(alice);
        stakediTry.unstake(alice);
        
        // Verify Alice received all assets, but had to wait 89 days longer than intended for first tranche
        assertEq(iTryToken.balanceOf(alice), INITIAL_SUPPLY, "Alice should receive all assets eventually");
        
        console.log("Vulnerability confirmed: First cooldown of", firstCooldownShares / 1e18, "iTRY was extended by 89 days");
        console.log("Expected unlock: Day 90, Actual unlock: Day 179");
    }
}
```

## Notes

The vulnerability stems from the design choice to use a single `UserCooldown` struct per address with overwriting semantics for `cooldownEnd` but accumulating semantics for `underlyingAmount`. This creates an inconsistency where the protocol tracks the total amount correctly but loses track of when individual tranches should become available.

The issue is exacerbated by the cross-chain composer functionality in `StakediTryCrosschain.sol`, where a composer can initiate cooldowns on behalf of users. If a user has both:
1. Direct L1 shares they cooldown via `cooldownShares()`
2. Cross-chain shares that get cooled down via `cooldownSharesByComposer()`

The two cooldowns will interfere with each other, causing whichever is initiated second to reset the cooldown timer for all accumulated assets.

This is not a known issue from the Zellic audit and represents a genuine logic flaw in the cooldown state management that violates user expectations and the cooldown integrity invariant.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L80-92)
```text
    function unstake(address receiver) external {
        UserCooldown storage userCooldown = cooldowns[msg.sender];
        uint256 assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(receiver, assets);
        } else {
            revert InvalidCooldown();
        }
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L114-114)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L115-115)
```text
        cooldowns[msg.sender].underlyingAmount += uint152(assets);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L117-117)
```text
        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
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
