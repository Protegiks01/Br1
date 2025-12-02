## Title
`maxRedeem()` and `maxWithdraw()` Do Not Account for MIN_SHARES Requirement, Causing ERC4626 Spec Violation and Withdrawal DOS

## Summary
The `cooldownShares` and `cooldownAssets` functions rely on `maxRedeem()` and `maxWithdraw()` to validate withdrawal limits, but these functions do not consider the MIN_SHARES (1 ether) requirement enforced by `_checkMinShares()`. This causes transactions to revert even when users attempt to withdraw amounts that `maxRedeem()`/`maxWithdraw()` indicate are permissible, violating the ERC4626 specification and causing temporary denial of service on withdrawals. [1](#0-0) 

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTryCooldown.sol` (StakediTryV2 contract, `cooldownShares` function line 109-110, `cooldownAssets` function line 96-97)

**Intended Logic:** According to the ERC4626 specification, `maxRedeem(owner)` must return "the maximum amount of shares that could be transferred from owner through redeem and not cause a revert." Similarly, `maxWithdraw(owner)` should return the maximum assets withdrawable without reverting. The `cooldownShares` and `cooldownAssets` functions use these values to validate user inputs before proceeding with withdrawals. [2](#0-1) 

**Actual Logic:** The contract inherits `maxRedeem()` and `maxWithdraw()` from OpenZeppelin's ERC4626 implementation without overriding them. These functions simply return `balanceOf(owner)` and `convertToAssets(balanceOf(owner))` respectively, without considering that withdrawals are constrained by the MIN_SHARES requirement. After the withdrawal validation passes, the internal `_withdraw()` function calls `_checkMinShares()`, which reverts if `0 < totalSupply < MIN_SHARES`. [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. **Setup**: Vault has total supply of 1.8 ether. User A has 1.5 ether shares, User B has 0.3 ether shares.
2. **User Query**: User A calls `maxRedeem(userA)` which returns 1.5 ether (their full balance).
3. **Withdrawal Attempt**: User A calls `cooldownShares(1.5 ether)`, expecting it to succeed since it's within the `maxRedeem` limit.
4. **Transaction Revert**: The `_withdraw()` function burns 1.5 ether shares, leaving total supply at 0.3 ether. The `_checkMinShares()` check detects `0.3 ether > 0 && 0.3 ether < 1 ether` and reverts with `MinSharesViolation`.
5. **DOS Effect**: User A cannot withdraw despite `maxRedeem` indicating they should be able to. They must either wait for more deposits to increase total supply, or withdraw only 0.8 ether to keep total supply exactly at MIN_SHARES. [5](#0-4) 

**Security Property Broken:** The ERC4626 specification compliance is violated. The contract claims to follow ERC4626 standard but `maxRedeem`/`maxWithdraw` return values that cause reverts, breaking the fundamental promise that these functions return safe withdrawal limits.

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY tokens in the StakediTry vault
- **Damage Severity**: Users experience temporary denial of service on withdrawals. While no funds are permanently lost, users cannot access their staked assets when `maxRedeem` indicates they should be able to. This breaks integrations with external protocols (DEX aggregators, portfolio managers, etc.) that rely on `maxRedeem` to determine safe withdrawal amounts. The same issue affects `cooldownAssets`, `fastRedeem`, and `fastWithdraw` functions. [6](#0-5) [7](#0-6) 

- **User Impact**: Any user attempting to withdraw shares when `totalSupply - userShares < MIN_SHARES` (and total supply would remain above 0) will experience transaction reverts despite `maxRedeem` validation passing. External protocols integrating this vault will have broken withdrawal logic, potentially locking user funds in those protocols.

## Likelihood Explanation
- **Attacker Profile**: Not an attack, but a protocol design flaw affecting all users. Any staker with a balance near the total supply can trigger this issue.
- **Preconditions**: Vault must have low total supply (close to MIN_SHARES) with users holding significant portions. This is common in early vault stages or after significant withdrawals.
- **Execution Complexity**: No special execution required. Normal withdrawal attempts trigger the issue.
- **Frequency**: Occurs whenever a user attempts to withdraw an amount that would leave `0 < totalSupply < MIN_SHARES`. Likelihood increases as vault matures and users withdraw.

## Recommendation

Override `maxRedeem()` and `maxWithdraw()` to account for the MIN_SHARES requirement:

```solidity
// In src/token/wiTRY/StakediTry.sol, add these functions:

/**
 * @dev Returns the maximum amount of shares that can be redeemed from the owner balance
 * through a redeem call, accounting for MIN_SHARES requirement.
 * @param owner The address to check
 * @return Maximum shares redeemable without violating MIN_SHARES
 */
function maxRedeem(address owner) public view virtual override returns (uint256) {
    uint256 userShares = balanceOf(owner);
    uint256 _totalSupply = totalSupply();
    
    // If user owns all shares, they can redeem everything (totalSupply becomes 0, which is allowed)
    if (userShares >= _totalSupply) {
        return userShares;
    }
    
    // Calculate remaining supply after user's full redemption
    uint256 remainingSupply = _totalSupply - userShares;
    
    // If remaining would violate MIN_SHARES, user can only redeem up to (totalSupply - MIN_SHARES)
    if (remainingSupply > 0 && remainingSupply < MIN_SHARES) {
        // User can redeem at most (totalSupply - MIN_SHARES)
        // If totalSupply < MIN_SHARES, no redemption possible (but this should never happen due to _checkMinShares)
        if (_totalSupply <= MIN_SHARES) {
            return 0;
        }
        return _totalSupply - MIN_SHARES;
    }
    
    // Otherwise, user can redeem their full balance
    return userShares;
}

/**
 * @dev Returns the maximum amount of assets that can be withdrawn from the owner balance
 * through a withdraw call, accounting for MIN_SHARES requirement.
 * @param owner The address to check
 * @return Maximum assets withdrawable without violating MIN_SHARES
 */
function maxWithdraw(address owner) public view virtual override returns (uint256) {
    return convertToAssets(maxRedeem(owner));
}
```

**Alternative Mitigation:** Document this behavior clearly and update integrations to handle potential reverts, but this doesn't fix the ERC4626 spec violation.

## Proof of Concept

```solidity
// File: test/Exploit_MaxRedeemMinSharesViolation.t.sol
// Run with: forge test --match-test test_maxRedeemMinSharesViolation -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../src/token/iTry.sol";

contract Exploit_MaxRedeemMinSharesViolation is Test {
    StakediTryFastRedeem vault;
    iTry itry;
    address owner = address(1);
    address userA = address(2);
    address userB = address(3);
    
    function setUp() public {
        // Deploy iTry token
        vm.prank(owner);
        itry = new iTry("iTry", owner);
        
        // Deploy vault
        vm.prank(owner);
        vault = new StakediTryFastRedeem(
            IERC20(address(itry)),
            owner,
            owner,
            owner
        );
        
        // Mint iTry to users
        vm.startPrank(owner);
        itry.grantRole(itry.MINTER_ROLE(), owner);
        itry.mint(userA, 2 ether);
        itry.mint(userB, 1 ether);
        vm.stopPrank();
        
        // Users approve vault
        vm.prank(userA);
        itry.approve(address(vault), type(uint256).max);
        vm.prank(userB);
        itry.approve(address(vault), type(uint256).max);
    }
    
    function test_maxRedeemMinSharesViolation() public {
        // SETUP: Users deposit to create the vulnerable state
        vm.prank(userA);
        vault.deposit(1.5 ether, userA);
        
        vm.prank(userB);
        vault.deposit(0.3 ether, userB);
        
        // Total supply is now 1.8 ether
        // UserA has 1.5 ether shares
        // UserB has 0.3 ether shares
        
        assertEq(vault.totalSupply(), 1.8 ether, "Total supply should be 1.8 ether");
        assertEq(vault.balanceOf(userA), 1.5 ether, "UserA should have 1.5 ether shares");
        
        // EXPLOIT: maxRedeem says userA can redeem 1.5 ether
        uint256 maxRedeemAmount = vault.maxRedeem(userA);
        assertEq(maxRedeemAmount, 1.5 ether, "maxRedeem should return userA's full balance");
        
        // But attempting to cooldown that amount REVERTS
        // because it would leave 0.3 ether < MIN_SHARES (1 ether)
        vm.prank(userA);
        vm.expectRevert(abi.encodeWithSelector(IStakediTry.MinSharesViolation.selector));
        vault.cooldownShares(maxRedeemAmount);
        
        // VERIFY: The ERC4626 spec is violated
        // maxRedeem returned a value that causes cooldownShares to revert
        // This proves the vulnerability
        
        // UserA can only actually cooldown 0.8 ether to keep total supply at MIN_SHARES
        vm.prank(userA);
        vault.cooldownShares(0.8 ether); // This succeeds
        
        assertEq(vault.totalSupply(), 1.0 ether, "Total supply should now be exactly MIN_SHARES");
    }
}
```

## Notes

This vulnerability is confirmed by the existing test case in `test/StakediTryV2.fastRedeem.t.sol` at lines 351-376, which explicitly tests that `fastRedeem` reverts when it would violate MIN_SHARES. The test demonstrates that even though `maxRedeem` would indicate a redemption is possible, the actual redemption fails due to the MIN_SHARES check. [8](#0-7) 

The issue affects multiple functions:
- `cooldownShares()` (uses `maxRedeem`)
- `cooldownAssets()` (uses `maxWithdraw`)  
- `fastRedeem()` (uses `maxRedeem`)
- `fastWithdraw()` (uses `maxWithdraw`)

While the known issues section mentions "Griefing attacks around MIN_SHARES" and issues with `redistributeLockedAmount`, this specific ERC4626 specification violation in the user-facing withdrawal functions is distinct and not explicitly covered in the known issues list.

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

**File:** src/token/wiTRY/StakediTry.sol (L32-32)
```text
    uint256 private constant MIN_SHARES = 1 ether;
```

**File:** src/token/wiTRY/StakediTry.sol (L228-231)
```text
    function _checkMinShares() internal view {
        uint256 _totalSupply = totalSupply();
        if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
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

**File:** test/StakediTryV2.fastRedeem.t.sol (L351-376)
```text
    /// @notice Tests that fast redeem reverts when it would violate MIN_SHARES
    function test_fastRedeem_whenWouldViolateMinShares_reverts() public {
        // Setup
        vm.startPrank(admin);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(DEFAULT_FEE);
        vm.stopPrank();

        // User1 deposits to get exactly 1.5e18 shares (just above MIN_SHARES)
        vm.prank(user1);
        uint256 shares = stakediTry.deposit(1.5e18, user1);

        // Try to fast redeem all shares - this would leave 0 in vault temporarily during split withdraw
        // Actually, since we're redeeming ALL shares, totalSupply becomes 0 which is allowed
        // So we need a scenario where we DON'T redeem all, but what remains is < MIN_SHARES

        // Let's have user2 also deposit
        vm.prank(user2);
        stakediTry.deposit(0.3e18, user2);

        // Now total supply = 1.8e18
        // If user1 redeems their 1.5e18, remaining = 0.3e18 < MIN_SHARES (1e18)
        vm.expectRevert(abi.encodeWithSelector(IStakediTry.MinSharesViolation.selector));
        vm.prank(user1);
        stakediTry.fastRedeem(shares, user1, user1);
    }
```
