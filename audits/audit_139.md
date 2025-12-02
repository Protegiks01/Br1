## Title
Silo Balance Underflow via iTRY Token Blacklist Enabling Permanent Fund Lock

## Summary
The iTrySilo contract holds iTRY tokens to back user cooldown claims during the unstaking process. If the silo address is blacklisted in the iTRY token contract, an admin can call `redistributeLockedAmount()` to drain all iTRY from the silo while cooldown accounting remains unchanged. This causes all subsequent `unstake()` calls to revert permanently, locking user funds.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/token/iTRY/iTry.sol` (lines 73-77, 112-120)
- `src/token/wiTRY/iTrySilo.sol` (lines 28-30)
- `src/token/wiTRY/StakediTryCooldown.sol` (lines 80-92)

**Intended Logic:** 

The silo is designed to hold iTRY tokens that back user cooldown claims. When users initiate cooldowns, their iTRY is transferred to the silo and their `cooldowns[user].underlyingAmount` is incremented. After the cooldown period, users call `unstake()` which withdraws iTRY from the silo back to them. [1](#0-0) 

**Actual Logic:** 

The iTRY token contract has a `redistributeLockedAmount()` function that allows admin to burn all tokens from a blacklisted address and mint them elsewhere. The silo address can be blacklisted like any other address, and if this happens, all its iTRY can be drained without updating the cooldown accounting in the staking vault. [2](#0-1) [3](#0-2) 

**Exploitation Path:**

1. **Users initiate cooldowns**: Multiple users call `cooldownAssets()` or `cooldownShares()`, transferring iTRY to the silo. Total cooldown claims = 1000 iTRY, silo balance = 1000 iTRY.

2. **Silo gets blacklisted**: Admin or blacklist manager calls `addBlacklistAddress([siloAddress])` on the iTRY token contract, granting the `BLACKLISTED_ROLE` to the silo.

3. **Admin redistributes silo funds**: Admin calls `redistributeLockedAmount(siloAddress, recipient)` on the iTRY token, which burns all 1000 iTRY from the silo and mints to recipient. Silo balance = 0 iTRY, but cooldown accounting still shows users owed 1000 iTRY.

4. **Users cannot unstake**: When any user calls `unstake()`, the function calls `silo.withdraw(receiver, assets)` which internally calls `iTry.transfer(to, amount)`. This reverts with "ERC20: transfer amount exceeds balance" because the silo has 0 iTRY but tries to transfer their cooldown amount. [4](#0-3) 

**Security Property Broken:** 

This violates the **Cooldown Integrity** invariant: "Users must complete cooldown period before unstaking wiTRY." While users complete the cooldown period, they cannot unstake because the silo balance is insufficient, effectively locking their funds permanently.

## Impact Explanation

- **Affected Assets**: All iTRY tokens held in the silo backing active cooldown claims become permanently inaccessible to users who initiated cooldowns.

- **Damage Severity**: 100% loss of all pending cooldown claims. If 1000 iTRY worth of cooldowns are pending and the silo is drained, all 1000 iTRY becomes permanently locked. Users cannot unstake, cannot cancel cooldowns, and have no recovery mechanism.

- **User Impact**: All users with active cooldowns (any user who called `cooldownAssets()`, `cooldownShares()`, `cooldownSharesByComposer()`, or `cooldownAssetsByComposer()` before the silo was blacklisted) are affected. The issue persists indefinitely unless the silo is refunded, which would require admin intervention outside normal protocol operations.

## Likelihood Explanation

- **Attacker Profile**: Requires blacklist manager role to blacklist the silo and admin role to call `redistributeLockedAmount()`. However, per the trust model, this is NOT malicious admin action - it's a legitimate admin function (designed to recover funds from blacklisted users) that has an unintended devastating side effect when applied to the silo.

- **Preconditions**: 
  1. Active cooldowns exist (users have called cooldown functions)
  2. Silo holds iTRY tokens backing these cooldowns
  3. Silo address gets blacklisted (could be accidental or during legitimate blacklist operations)
  4. Admin calls `redistributeLockedAmount()` believing they're recovering misplaced funds

- **Execution Complexity**: Two transactions - one to blacklist the silo, one to redistribute. Both are legitimate admin functions being used as designed.

- **Frequency**: Can occur once, but affects all current and future cooldowns until resolved. The impact is permanent unless admin manually refunds the silo.

## Recommendation

Implement protections to prevent the silo from being blacklisted in the iTRY token contract:

```solidity
// In src/token/iTRY/iTry.sol, in the addBlacklistAddress function (line 73):

// CURRENT (vulnerable):
function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    for (uint8 i = 0; i < users.length; i++) {
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
    }
}

// FIXED:
// Add silo address as immutable state variable or query from minter contract
address public immutable STAKED_ITRY_SILO;

function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
    for (uint8 i = 0; i < users.length; i++) {
        // Prevent blacklisting the silo to maintain cooldown accounting integrity
        if (users[i] == STAKED_ITRY_SILO) revert OperationNotAllowed();
        
        if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
        _grantRole(BLACKLISTED_ROLE, users[i]);
    }
}
```

**Alternative mitigation**: Add a balance check in `iTrySilo.withdraw()` to revert with a clear error message if insufficient balance:

```solidity
// In src/token/wiTRY/iTrySilo.sol, function withdraw (line 28):

// CURRENT (vulnerable):
function withdraw(address to, uint256 amount) external onlyStakingVault {
    iTry.transfer(to, amount);
}

// FIXED:
function withdraw(address to, uint256 amount) external onlyStakingVault {
    uint256 balance = iTry.balanceOf(address(this));
    if (balance < amount) revert InsufficientSiloBalance(amount, balance);
    iTry.transfer(to, amount);
}
```

However, the first mitigation (preventing silo blacklisting) is preferred as it prevents the root cause rather than just making failures more graceful.

## Proof of Concept

```solidity
// File: test/Exploit_SiloBalanceUnderflow.t.sol
// Run with: forge test --match-test test_siloBalanceUnderflowViaBlacklist -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/iTrySilo.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract Exploit_SiloBalanceUnderflow is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    StakediTryCrosschain public vault;
    iTrySilo public silo;
    
    address public owner;
    address public rewarder;
    address public treasury;
    address public alice;
    address public bob;
    address public recipient;
    
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    
    function setUp() public {
        owner = makeAddr("owner");
        rewarder = makeAddr("rewarder");
        treasury = makeAddr("treasury");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        recipient = makeAddr("recipient");
        
        // Deploy iTry with proxy
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner,
            owner
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(IERC20(address(itryToken)), rewarder, owner, treasury);
        
        silo = vault.silo();
        
        // Grant blacklist manager role to owner
        vm.prank(owner);
        itryToken.grantRole(BLACKLIST_MANAGER_ROLE, owner);
        
        // Mint iTRY to users
        vm.prank(owner);
        itryToken.mint(alice, 1000 ether);
        vm.prank(owner);
        itryToken.mint(bob, 1000 ether);
    }
    
    function test_siloBalanceUnderflowViaBlacklist() public {
        // SETUP: Alice and Bob stake and initiate cooldowns
        vm.startPrank(alice);
        itryToken.approve(address(vault), type(uint256).max);
        vault.deposit(500 ether, alice);
        vault.cooldownAssets(500 ether);
        vm.stopPrank();
        
        vm.startPrank(bob);
        itryToken.approve(address(vault), type(uint256).max);
        vault.deposit(300 ether, bob);
        vault.cooldownAssets(300 ether);
        vm.stopPrank();
        
        // Verify silo holds the cooldown iTRY
        uint256 siloBalanceBefore = itryToken.balanceOf(address(silo));
        assertEq(siloBalanceBefore, 800 ether, "Silo should hold 800 iTRY");
        
        // Verify cooldown accounting
        (,uint256 aliceCooldown) = vault.cooldowns(alice);
        (,uint256 bobCooldown) = vault.cooldowns(bob);
        assertEq(aliceCooldown, 500 ether, "Alice cooldown should be 500 iTRY");
        assertEq(bobCooldown, 300 ether, "Bob cooldown should be 300 iTRY");
        
        // EXPLOIT: Admin blacklists the silo address
        address[] memory addresses = new address[](1);
        addresses[0] = address(silo);
        
        vm.prank(owner);
        itryToken.addBlacklistAddress(addresses);
        
        // Admin redistributes locked amount from silo
        vm.prank(owner);
        itryToken.redistributeLockedAmount(address(silo), recipient);
        
        // VERIFY: Silo balance is now 0, but cooldown accounting unchanged
        uint256 siloBalanceAfter = itryToken.balanceOf(address(silo));
        assertEq(siloBalanceAfter, 0, "Vulnerability confirmed: Silo drained to 0");
        assertEq(itryToken.balanceOf(recipient), 800 ether, "Recipient received all silo funds");
        
        // Cooldown accounting still shows users are owed iTRY
        (,uint256 aliceCooldownAfter) = vault.cooldowns(alice);
        (,uint256 bobCooldownAfter) = vault.cooldowns(bob);
        assertEq(aliceCooldownAfter, 500 ether, "Alice cooldown unchanged - accounting inconsistent");
        assertEq(bobCooldownAfter, 300 ether, "Bob cooldown unchanged - accounting inconsistent");
        
        // Fast forward past cooldown period
        vm.warp(block.timestamp + vault.cooldownDuration() + 1);
        
        // Users cannot unstake - reverts due to insufficient silo balance
        vm.prank(alice);
        vm.expectRevert(); // ERC20: transfer amount exceeds balance
        vault.unstake(alice);
        
        vm.prank(bob);
        vm.expectRevert(); // ERC20: transfer amount exceeds balance
        vault.unstake(bob);
        
        // Funds are permanently locked - users have completed cooldown but cannot withdraw
        console.log("Vulnerability confirmed: Sum of cooldown claims (800 iTRY) exceeds silo balance (0 iTRY)");
        console.log("All users with pending cooldowns permanently locked out of their funds");
    }
}
```

## Notes

This vulnerability directly answers the security question about silo balance inconsistency. The key issue is that the iTRY token's `redistributeLockedAmount()` function is a legitimate admin function designed for recovering funds from blacklisted users, but when applied to the silo contract, it creates a critical accounting mismatch. The cooldown claims in the vault remain unchanged while the actual silo balance drops to zero, causing permanent fund locks for all users with pending cooldowns.

The issue is NOT about malicious admin behavior - it's about an architectural oversight where a legitimate token-level function (blacklist + redistribution) can be applied to a system-critical contract (the silo) with devastating consequences for protocol integrity.

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

**File:** src/token/iTRY/iTry.sol (L73-77)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
```

**File:** src/token/iTRY/iTry.sol (L112-120)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
```

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```
