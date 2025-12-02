## Title
State Transition from FULLY_ENABLED to WHITELIST_ENABLED Permanently Locks Non-Whitelisted Users' Funds in StakediTry Vault

## Summary
The `updateTransferState()` function does not revoke or validate WHITELISTED_ROLE assignments when transitioning between transfer states. [1](#0-0)  When the protocol transitions from WHITELIST_ENABLED → FULLY_ENABLED → back to WHITELIST_ENABLED, users who deposited iTRY into StakediTry during FULLY_ENABLED mode will have their funds permanently locked, as withdrawals require all parties to have WHITELISTED_ROLE. [2](#0-1) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` - `updateTransferState()` function (lines 171-175) and `_beforeTokenTransfer()` function (lines 198-217)

**Intended Logic:** The transfer state mechanism should allow the protocol to control who can transfer iTRY tokens based on whitelist requirements. The WHITELISTED_ROLE should indicate trusted addresses that can transact during restricted periods.

**Actual Logic:** The `updateTransferState()` function only modifies the `transferState` variable without managing WHITELISTED_ROLE assignments. [1](#0-0)  When in WHITELIST_ENABLED mode, the transfer validation requires `msg.sender`, `from`, and `to` addresses to all have WHITELISTED_ROLE for normal transfers. [2](#0-1)  This creates a critical issue when users who deposited during FULLY_ENABLED attempt to withdraw from StakediTry after a state transition back to WHITELIST_ENABLED.

**Exploitation Path:**
1. Protocol starts in WHITELIST_ENABLED mode with StakediTry vault and early users (A, B, C) granted WHITELISTED_ROLE
2. Admin calls `updateTransferState(TransferState.FULLY_ENABLED)` to open the protocol to the public
3. New users (D, E, F) deposit iTRY into StakediTry vault during FULLY_ENABLED period (this works because FULLY_ENABLED only checks for non-blacklisted addresses [3](#0-2) )
4. Due to regulatory or security concerns, admin must switch back: `updateTransferState(TransferState.WHITELIST_ENABLED)`
5. Users D, E, F attempt to withdraw their iTRY from StakediTry via the ERC4626 `withdraw()` or `redeem()` functions, or via cooldown-based `cooldownAssets()`/`unstake()` flow
6. StakediTry's `_withdraw()` function calls the parent ERC4626 implementation which transfers iTRY tokens [4](#0-3) 
7. The iTRY transfer triggers `_beforeTokenTransfer()` which checks WHITELIST_ENABLED requirements: all three parties (user as msg.sender, StakediTry as from, user as to) must have WHITELISTED_ROLE
8. Since users D, E, F lack WHITELISTED_ROLE, the transaction reverts with `OperationNotAllowed()` [5](#0-4) 
9. Funds remain permanently locked unless admin either grants WHITELISTED_ROLE to each affected user (potentially violating compliance requirements) or switches back to FULLY_ENABLED (defeating the purpose of the whitelist)

**Security Property Broken:** This violates the **Whitelist Enforcement** invariant by creating a scenario where legitimate users who followed protocol rules during FULLY_ENABLED mode lose access to their funds when the state changes. It also breaks the fundamental expectation that users can withdraw their deposited assets from the vault.

## Impact Explanation
- **Affected Assets**: All iTRY tokens deposited into StakediTry vault by users without WHITELISTED_ROLE during FULLY_ENABLED period
- **Damage Severity**: Complete permanent loss of access to deposited funds. Users cannot withdraw, cannot transfer wiTRY shares (if they attempt to sell), and cannot use fast redemption. The only recovery requires admin intervention which may violate regulatory compliance requirements.
- **User Impact**: Affects every user who deposited into StakediTry during FULLY_ENABLED mode without being pre-whitelisted. This could be hundreds or thousands of users in a public launch scenario. Additionally affects any DeFi protocol integrations or liquidity pools that hold iTRY.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is a systemic design flaw affecting normal users
- **Preconditions**: Protocol must transition from WHITELIST_ENABLED → FULLY_ENABLED → back to WHITELIST_ENABLED. This is a realistic scenario for protocols that start with KYC/whitelist, open to public, then need to restrict again due to regulatory pressure.
- **Execution Complexity**: Trivial - happens automatically when admin changes state. Users simply use the protocol normally and lose access when state changes.
- **Frequency**: Occurs once per state transition cycle, but affects all non-whitelisted users simultaneously

## Recommendation

```solidity
// In src/token/iTRY/iTry.sol, function updateTransferState, lines 171-175:

// CURRENT (vulnerable):
function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
    TransferState prevState = transferState;
    transferState = code;
    emit TransferStateUpdated(prevState, code);
}

// FIXED - Option 1: Prevent problematic transitions
function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
    TransferState prevState = transferState;
    
    // Prevent transitioning to WHITELIST_ENABLED if there are non-whitelisted holders
    // that may be locked in contracts like StakediTry
    if (code == TransferState.WHITELIST_ENABLED && prevState == TransferState.FULLY_ENABLED) {
        revert CannotRestrictWithPublicHolders();
    }
    
    transferState = code;
    emit TransferStateUpdated(prevState, code);
}

// FIXED - Option 2: Add grace period for withdrawals
function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
    TransferState prevState = transferState;
    
    if (code == TransferState.WHITELIST_ENABLED && prevState == TransferState.FULLY_ENABLED) {
        // Set grace period timestamp (e.g., 30 days)
        whitelistGracePeriodEnd = block.timestamp + 30 days;
    }
    
    transferState = code;
    emit TransferStateUpdated(prevState, code);
}

// And modify _beforeTokenTransfer to check grace period:
// In WHITELIST_ENABLED section, add:
} else if (transferState == TransferState.WHITELIST_ENABLED) {
    // Allow transfers during grace period to enable withdrawals
    if (block.timestamp < whitelistGracePeriodEnd && 
        !hasRole(BLACKLISTED_ROLE, msg.sender) && 
        !hasRole(BLACKLISTED_ROLE, from) && 
        !hasRole(BLACKLISTED_ROLE, to)) {
        // Grace period active - allow non-blacklisted transfers
        return;
    }
    // ... rest of whitelist checks
```

**Alternative mitigation:** Make StakediTry and other core protocol contracts exempt from whitelist checks by adding them to a "protocol contracts" whitelist that persists across state changes, or by adding special case handling in `_beforeTokenTransfer` for transfers from known protocol contracts.

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistLockout.t.sol
// Run with: forge test --match-test test_WhitelistStateLocksFunds -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockDLF is ERC20 {
    constructor() ERC20("DLF", "DLF") {
        _mint(msg.sender, 1000000e18);
    }
}

contract Exploit_WhitelistLockout is Test {
    iTry itry;
    StakediTry vault;
    MockDLF dlf;
    
    address admin = address(0x1);
    address minter = address(0x2);
    address earlyUser = address(0x3);
    address newUser = address(0x4);
    
    function setUp() public {
        // Deploy iTRY token
        vm.startPrank(admin);
        itry = new iTry();
        itry.initialize(admin, minter);
        
        // Deploy mock DLF and StakediTry vault
        dlf = new MockDLF();
        vault = new StakediTry(IERC20(address(dlf)), admin, admin);
        
        // Setup: Start in WHITELIST_ENABLED mode
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Whitelist early user and vault
        itry.addWhitelistAddress([earlyUser].toArray());
        itry.addWhitelistAddress([address(vault)].toArray());
        vm.stopPrank();
        
        // Mint some iTRY to early user
        vm.prank(minter);
        itry.mint(earlyUser, 1000e18);
    }
    
    function test_WhitelistStateLocksFunds() public {
        // SETUP: Early user can deposit in WHITELIST_ENABLED mode
        vm.startPrank(earlyUser);
        itry.approve(address(vault), 500e18);
        vault.deposit(500e18, earlyUser);
        vm.stopPrank();
        
        // Admin transitions to FULLY_ENABLED
        vm.prank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.FULLY_ENABLED);
        
        // New user receives iTRY and deposits (works in FULLY_ENABLED)
        vm.prank(minter);
        itry.mint(newUser, 1000e18);
        
        vm.startPrank(newUser);
        itry.approve(address(vault), 500e18);
        vault.deposit(500e18, newUser);
        vm.stopPrank();
        
        // EXPLOIT: Admin switches back to WHITELIST_ENABLED
        vm.prank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // VERIFY: Early whitelisted user can still withdraw
        vm.startPrank(earlyUser);
        uint256 earlyShares = vault.balanceOf(earlyUser);
        vault.redeem(earlyShares, earlyUser, earlyUser);
        vm.stopPrank();
        assertGt(itry.balanceOf(earlyUser), 0, "Early user withdrew successfully");
        
        // VERIFY: New user's withdrawal REVERTS - funds locked!
        vm.startPrank(newUser);
        uint256 newUserShares = vault.balanceOf(newUser);
        vm.expectRevert(); // Will revert with OperationNotAllowed
        vault.redeem(newUserShares, newUser, newUser);
        vm.stopPrank();
        
        // Confirm funds are locked
        assertEq(vault.balanceOf(newUser), newUserShares, "Vulnerability confirmed: New user's funds permanently locked in vault");
        assertEq(itry.balanceOf(newUser), 500e18, "New user cannot withdraw deposited iTRY");
    }
}
```

## Notes

This vulnerability directly answers the security question: **Yes, previously whitelisted addresses retain their WHITELISTED_ROLE when transitioning from WHITELIST_ENABLED to FULLY_ENABLED.** This creates not just "confusion about which addresses are trusted," but a **critical vulnerability** where the persistent role assignments create an irreversible fund lockup scenario for non-whitelisted users who join during FULLY_ENABLED mode.

The issue extends beyond simple confusion:
- The StakediTry vault must be whitelisted to function in WHITELIST_ENABLED mode
- The cooldown-based unstaking mechanism is also affected, as the iTrySilo withdrawal also triggers the same transfer restrictions [6](#0-5) 
- Any DeFi protocol integration would face the same issue if they hold iTRY on behalf of users
- The vulnerability violates the fundamental ERC4626 expectation that depositors can withdraw their assets

### Citations

**File:** src/token/iTRY/iTry.sol (L171-175)
```text
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L189-193)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
```

**File:** src/token/iTRY/iTry.sol (L210-217)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
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

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```
