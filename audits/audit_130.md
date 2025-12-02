## Title
Soft-Blacklisted Users Can Bypass Deposit Restrictions Via Direct Transfer of wiTRY Shares

## Summary
The `_deposit()` function in StakediTry correctly blocks soft-blacklisted users from both calling deposit/mint operations AND receiving shares as the receiver parameter. However, the `_beforeTokenTransfer()` hook only checks `FULL_RESTRICTED_STAKER_ROLE`, allowing soft-blacklisted users to receive wiTRY shares via direct `transfer()` or `transferFrom()`, bypassing the intended staking restriction.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTry.sol` (StakediTry contract, `_beforeTokenTransfer` function, lines 292-299)

**Intended Logic:** Based on the role documentation at line 28, `SOFT_RESTRICTED_STAKER_ROLE` is designed to "prevent an address to stake". The `_deposit()` function enforces this by checking both the caller AND receiver against `SOFT_RESTRICTED_STAKER_ROLE` [1](#0-0) , preventing soft-blacklisted addresses from acquiring shares through deposit/mint operations.

**Actual Logic:** The `_beforeTokenTransfer()` hook, which governs all ERC20 token transfers (including direct transfers), only validates `FULL_RESTRICTED_STAKER_ROLE` [2](#0-1) . It does not check if the recipient has `SOFT_RESTRICTED_STAKER_ROLE`, creating an inconsistency with the deposit entry point protection.

**Exploitation Path:**
1. Alice (normal user) stakes iTRY via `deposit()` and receives 1000 wiTRY shares
2. Bob is soft-blacklisted by the `BLACKLIST_MANAGER_ROLE` with `isFullBlacklisting = false` [3](#0-2) 
3. Bob cannot call `deposit()` or `mint()` due to the check in `_deposit()` - transaction would revert with `OperationNotAllowed`
4. Alice calls `transfer(bob, 500)` to send 500 wiTRY shares directly to Bob
5. The `_beforeTokenTransfer()` hook executes but only checks `FULL_RESTRICTED_STAKER_ROLE`, not `SOFT_RESTRICTED_STAKER_ROLE`
6. Transfer succeeds - Bob now holds 500 wiTRY shares and earns yield proportional to his holdings
7. Bob can later withdraw these shares via `withdraw()` or `redeem()` since these functions only check `FULL_RESTRICTED_STAKER_ROLE` [4](#0-3) 

**Security Property Broken:** The soft-blacklist mechanism fails to prevent restricted addresses from holding staked positions and earning yield. The protection at the deposit layer is circumvented through the transfer layer.

## Impact Explanation
- **Affected Assets**: wiTRY shares (staked iTRY positions) and the yield distribution mechanism
- **Damage Severity**: Soft-blacklisted users can maintain staking positions and earn protocol yield indefinitely by receiving shares via transfer, defeating the purpose of soft-blacklisting them from staking operations
- **User Impact**: All soft-blacklisted addresses can bypass restrictions. The protocol loses the ability to restrict specific addresses from participating in staking rewards while still allowing them to exit positions (the intended soft-blacklist behavior)

## Likelihood Explanation
- **Attacker Profile**: Any user with `SOFT_RESTRICTED_STAKER_ROLE` (soft-blacklisted) who has a willing counterparty or uses social engineering
- **Preconditions**: 
  1. Attacker must be soft-blacklisted (has `SOFT_RESTRICTED_STAKER_ROLE`)
  2. Another user must hold wiTRY shares and be willing to transfer them
  3. StakediTry vault must be operational with positive yield
- **Execution Complexity**: Single transaction - just a standard ERC20 `transfer()` call
- **Frequency**: Can be executed continuously; attacker can accumulate unlimited wiTRY shares through repeated transfers

## Recommendation

The `_beforeTokenTransfer()` hook should check `SOFT_RESTRICTED_STAKER_ROLE` for the recipient to maintain consistency with the deposit entry point protection:

```solidity
// In src/token/wiTRY/StakediTry.sol, function _beforeTokenTransfer, lines 292-299:

// CURRENT (vulnerable):
function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
        revert OperationNotAllowed();
    }
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
        revert OperationNotAllowed();
    }
}

// FIXED:
function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
        revert OperationNotAllowed();
    }
    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
        revert OperationNotAllowed();
    }
    // Add soft-blacklist check for recipient to prevent bypassing deposit restrictions
    if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, to) && to != address(0)) {
        revert OperationNotAllowed();
    }
}
```

**Alternative mitigation**: If the protocol intentionally allows soft-blacklisted users to receive shares via transfer (for example, to allow them to receive shares back after lending them), then the check in `_deposit()` at line 247 should be modified to only check the caller, not the receiver. However, this would weaken the blacklist enforcement.

## Proof of Concept

```solidity
// File: test/Exploit_SoftBlacklistBypass.t.sol
// Run with: forge test --match-test test_SoftBlacklistBypass -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_SoftBlacklistBypass is Test {
    StakediTry public vault;
    iTry public itry;
    address public alice;
    address public bob;
    address public admin;
    address public blacklistManager;
    
    function setUp() public {
        admin = makeAddr("admin");
        blacklistManager = makeAddr("blacklistManager");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy iTRY token
        vm.prank(admin);
        itry = new iTry(admin);
        
        // Deploy StakediTry vault
        vm.prank(admin);
        vault = new StakediTry(IERC20(address(itry)), admin, admin);
        
        // Grant blacklist manager role
        vm.prank(admin);
        vault.grantRole(vault.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        
        // Mint iTRY to Alice and Bob
        vm.prank(admin);
        itry.grantRole(itry.MINTER_ROLE(), admin);
        vm.startPrank(admin);
        itry.mint(alice, 2000 ether);
        itry.mint(bob, 1000 ether);
        vm.stopPrank();
    }
    
    function test_SoftBlacklistBypass() public {
        // SETUP: Alice stakes normally
        vm.startPrank(alice);
        itry.approve(address(vault), 1000 ether);
        uint256 aliceShares = vault.deposit(1000 ether, alice);
        vm.stopPrank();
        
        console.log("Alice staked and received shares:", aliceShares);
        
        // Bob is soft-blacklisted
        vm.prank(blacklistManager);
        vault.addToBlacklist(bob, false); // false = soft blacklist
        
        // VERIFY: Bob cannot deposit directly
        vm.startPrank(bob);
        itry.approve(address(vault), 1000 ether);
        vm.expectRevert(abi.encodeWithSignature("OperationNotAllowed()"));
        vault.deposit(1000 ether, bob);
        vm.stopPrank();
        
        console.log("Bob correctly blocked from deposit()");
        
        // VERIFY: Bob cannot mint directly
        vm.startPrank(bob);
        vm.expectRevert(abi.encodeWithSignature("OperationNotAllowed()"));
        vault.mint(500 ether, bob);
        vm.stopPrank();
        
        console.log("Bob correctly blocked from mint()");
        
        // EXPLOIT: Alice transfers shares to Bob (bypasses soft-blacklist)
        vm.prank(alice);
        vault.transfer(bob, 500 ether);
        
        uint256 bobShares = vault.balanceOf(bob);
        console.log("Bob bypassed soft-blacklist via transfer. Shares:", bobShares);
        
        // VERIFY: Bob now holds shares and can earn yield
        assertEq(bobShares, 500 ether, "Bob should have received shares via transfer");
        
        // VERIFY: Bob can withdraw these shares (only FULL_RESTRICTED blocks withdrawals)
        vm.prank(bob);
        uint256 bobAssets = vault.redeem(bobShares, bob, bob);
        
        console.log("Bob successfully withdrew assets:", bobAssets);
        assertGt(bobAssets, 0, "Bob should be able to redeem shares");
        
        // Vulnerability confirmed: Soft-blacklisted user acquired and redeemed shares
        assertEq(vault.balanceOf(bob), 0, "Bob redeemed all shares");
        assertEq(itry.balanceOf(bob), 1000 ether + bobAssets, "Bob has original + redeemed iTRY");
    }
}
```

## Notes

To directly answer the original security question:

1. **Can soft-blacklisted users call mint() instead of deposit()?** No - both `deposit()` and `mint()` call the same internal `_deposit()` function [5](#0-4) , which checks `SOFT_RESTRICTED_STAKER_ROLE` for both caller and receiver. There is no bypass between these two functions.

2. **Are all ERC4626 entry points properly protected?** No - while `deposit()` and `mint()` are protected, the vulnerability exists in the ERC20 transfer layer. The `_beforeTokenTransfer()` hook does not enforce `SOFT_RESTRICTED_STAKER_ROLE` checks on recipients [2](#0-1) , allowing soft-blacklisted users to receive shares via `transfer()` or `transferFrom()`.

3. **Withdraw/Redeem protection**: These functions only check `FULL_RESTRICTED_STAKER_ROLE` [6](#0-5) , which is intentional per the role design - soft-blacklisted users should be able to exit their positions.

The core issue is the inconsistency between deposit-layer protection (which blocks soft-blacklisted receivers) and transfer-layer protection (which does not), creating a bypass vector for the soft-blacklist mechanism.

### Citations

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

**File:** src/token/wiTRY/StakediTry.sol (L240-252)
```text
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
        internal
        override
        nonReentrant
        notZero(assets)
        notZero(shares)
    {
        if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
            revert OperationNotAllowed();
        }
        super._deposit(caller, receiver, assets, shares);
        _checkMinShares();
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

**File:** src/token/wiTRY/StakediTry.sol (L292-298)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
```
