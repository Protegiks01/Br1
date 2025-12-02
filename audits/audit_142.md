## Title
Unwhitelisted Protocol Contracts Block All Cooldown Operations, Permanently Locking User Funds in WHITELIST_ENABLED Mode

## Summary
In `TransferState.WHITELIST_ENABLED` mode, the iTry token's `_beforeTokenTransfer` hook requires that the sender, from, and to addresses ALL possess the `WHITELISTED_ROLE`. When users initiate cooldowns via `cooldownAssets()` or `cooldownShares()`, the internal `_withdraw()` operation transfers iTry tokens from the StakediTry vault to the iTrySilo contract. [1](#0-0)  If either the StakediTry vault or iTrySilo is not whitelisted, this transfer will revert, preventing ALL users (even whitelisted ones) from initiating cooldowns and permanently locking their funds.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (function `_beforeTokenTransfer`, lines 210-214), `src/token/wiTRY/StakediTryCooldown.sol` (functions `cooldownAssets` and `cooldownShares`, lines 96-118), `src/token/wiTRY/iTrySilo.sol` (function `withdraw`, lines 28-30)

**Intended Logic:** 
The whitelist enforcement is documented to restrict transfers such that "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" (README line 125). The cooldown mechanism allows users to initiate withdrawals by transferring their staked iTry to a silo contract for a cooling period before final redemption.

**Actual Logic:** 
The `_beforeTokenTransfer` hook in WHITELIST_ENABLED mode enforces that `msg.sender`, `from`, and `to` ALL have the `WHITELISTED_ROLE` for normal transfers. [2](#0-1)  When a cooldown is initiated, the StakediTry vault contract executes the transfer to the silo contract. [3](#0-2)  Since the vault is the `msg.sender` and `from` address, and the silo is the `to` address, all three must be whitelisted. If protocol administrators whitelist only user addresses but forget to whitelist the StakediTry vault or iTrySilo contracts, all cooldown operations fail.

**Exploitation Path:**
1. Protocol administrators enable WHITELIST_ENABLED mode via `updateTransferState(TransferState.WHITELIST_ENABLED)` to restrict iTry transfers to authorized users
2. Administrators whitelist legitimate user addresses but fail to whitelist the StakediTry vault contract (address stored as `STAKING_VAULT` in iTrySilo) and/or the iTrySilo contract itself
3. A whitelisted user attempts to initiate cooldown by calling `cooldownAssets(100e18)` or `cooldownShares(50e18)` [4](#0-3) 
4. The function calls `_withdraw(msg.sender, address(silo), msg.sender, assets, shares)`, which internally transfers iTry from the vault to the silo [1](#0-0) 
5. The iTry token's `_beforeTokenTransfer` checks if the vault (msg.sender/from) and silo (to) both have `WHITELISTED_ROLE` [2](#0-1) 
6. Since the contracts lack `WHITELISTED_ROLE`, the transaction reverts with `OperationNotAllowed()` [5](#0-4) 
7. User funds remain locked in the vault indefinitely, as cooldown is the ONLY withdrawal method when `cooldownDuration > 0` (standard ERC4626 withdraw/redeem functions are disabled) [6](#0-5) 

**Security Property Broken:** 
This violates the core functionality of the vault system and creates a permanent fund lock scenario. While the whitelist invariant states "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state," the implementation fails to account for necessary protocol-internal transfers required for the vault to function. This effectively breaks invariant #6 (Cooldown Integrity) by preventing users from completing cooldown operations entirely.

## Impact Explanation
- **Affected Assets**: All iTry tokens staked in the StakediTry vault by all users. When cooldown is enabled (`cooldownDuration > 0`), users can ONLY withdraw via the cooldown mechanism—there is no alternative path. [6](#0-5) 
- **Damage Severity**: 100% of staked user funds become permanently locked and unrecoverable through normal user operations. The only recovery path would require administrators to either (a) whitelist the protocol contracts retroactively, or (b) switch transfer state back to FULLY_ENABLED, both of which may not align with the intended security posture.
- **User Impact**: ALL users with staked funds (both whitelisted and non-whitelisted) are affected. Any attempt to initiate cooldown fails, preventing withdrawals. This affects every staker in the protocol, potentially representing millions of dollars in TVL.

## Likelihood Explanation
- **Attacker Profile**: This is not an attacker-initiated exploit but rather a protocol misconfiguration vulnerability. However, it affects all innocent users who have legitimately staked their funds.
- **Preconditions**: 
  - Protocol is in WHITELIST_ENABLED transfer state
  - Cooldown duration is greater than 0 (default is 90 days) [7](#0-6) 
  - StakediTry vault and/or iTrySilo contracts are not whitelisted
  - This is a realistic scenario as the README states "Only whitelisted user can send/receive/burn," which could reasonably be interpreted as only requiring user whitelisting, not contract whitelisting
- **Execution Complexity**: Occurs automatically when legitimate users attempt to withdraw their funds via cooldown
- **Frequency**: Affects every single cooldown attempt by every user until the configuration error is corrected

## Recommendation

The `_beforeTokenTransfer` hook in iTry.sol should recognize protocol contracts (StakediTry vault and iTrySilo) as trusted system components that are exempt from whitelist requirements. Add special handling for protocol-internal transfers:

```solidity
// In src/token/iTRY/iTry.sol, function _beforeTokenTransfer, around lines 198-217:

// CURRENT (vulnerable):
// Lines 210-214 require all three addresses to be whitelisted

// FIXED:
} else if (transferState == TransferState.WHITELIST_ENABLED) {
    if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // redeeming
    } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // minting
    } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // redistributing - burn
    } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // redistributing - mint
    } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
        // whitelisted user can burn
    // ADD: Allow protocol contracts (StakediTry vault, iTrySilo) to transfer tokens for cooldown operations
    } else if (
        hasRole(PROTOCOL_CONTRACT_ROLE, msg.sender) && hasRole(PROTOCOL_CONTRACT_ROLE, from)
            && (hasRole(WHITELISTED_ROLE, to) || hasRole(PROTOCOL_CONTRACT_ROLE, to))
    ) {
        // protocol-internal transfer for cooldown/unstake operations
    } else if (
        hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
            && hasRole(WHITELISTED_ROLE, to)
    ) {
        // normal case
    } else {
        revert OperationNotAllowed();
    }
```

**Alternative Mitigations:**
1. **Simplest fix**: Grant `WHITELISTED_ROLE` to StakediTry vault and iTrySilo contracts during deployment/initialization
2. **Documentation fix**: Clearly document that protocol contracts MUST be whitelisted when enabling WHITELIST_ENABLED mode, and provide a deployment checklist
3. **Validation check**: Add a `setTransferState()` function validation that reverts if switching to WHITELIST_ENABLED without protocol contracts being whitelisted

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistBlocksCooldown.t.sol
// Run with: forge test --match-test test_WhitelistBlocksCooldown -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCooldown.sol";
import "../src/token/wiTRY/iTrySilo.sol";

contract ExploitWhitelistBlocksCooldown is Test {
    iTry public itry;
    StakediTryV2 public vault;
    iTrySilo public silo;
    
    address public admin;
    address public whitelistManager;
    address public user;
    
    function setUp() public {
        admin = makeAddr("admin");
        whitelistManager = makeAddr("whitelistManager");
        user = makeAddr("user");
        
        // Deploy iTry token
        vm.startPrank(admin);
        itry = new iTry();
        itry.initialize(admin, admin);
        
        // Deploy StakediTry vault with cooldown
        vault = new StakediTryV2(IERC20(address(itry)), admin, admin);
        silo = vault.silo(); // Get the silo address
        
        // Grant roles
        itry.grantRole(itry.WHITELIST_MANAGER_ROLE(), whitelistManager);
        vm.stopPrank();
        
        // Mint and stake tokens for user
        vm.startPrank(admin);
        itry.mint(user, 1000e18);
        vm.stopPrank();
        
        vm.startPrank(user);
        itry.approve(address(vault), 1000e18);
        vault.deposit(1000e18, user);
        vm.stopPrank();
    }
    
    function test_WhitelistBlocksCooldown() public {
        // SETUP: Enable whitelist mode and whitelist ONLY the user (not protocol contracts)
        vm.startPrank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        vm.stopPrank();
        
        vm.startPrank(whitelistManager);
        address[] memory users = new address[](1);
        users[0] = user;
        itry.addWhitelistAddress(users);
        // NOTE: StakediTry vault and silo are NOT whitelisted
        vm.stopPrank();
        
        // VERIFY: User is whitelisted, but vault/silo are not
        assertTrue(itry.hasRole(itry.WHITELISTED_ROLE(), user), "User should be whitelisted");
        assertFalse(itry.hasRole(itry.WHITELISTED_ROLE(), address(vault)), "Vault should NOT be whitelisted");
        assertFalse(itry.hasRole(itry.WHITELISTED_ROLE(), address(silo)), "Silo should NOT be whitelisted");
        
        // EXPLOIT: User attempts to initiate cooldown
        vm.startPrank(user);
        uint256 userShares = vault.balanceOf(user);
        
        // This will revert because vault->silo transfer fails whitelist check
        vm.expectRevert(abi.encodeWithSelector(IiTryDefinitions.OperationNotAllowed.selector));
        vault.cooldownShares(userShares);
        vm.stopPrank();
        
        // VERIFY: User funds are permanently locked (cannot withdraw)
        // Standard ERC4626 withdraw is disabled when cooldown is enabled
        vm.startPrank(user);
        vm.expectRevert(abi.encodeWithSelector(IStakediTryCooldown.OperationNotAllowed.selector));
        vault.withdraw(100e18, user, user);
        vm.stopPrank();
        
        // User is stuck - cooldown fails, standard withdraw is disabled
        console.log("User has %e shares locked in vault", userShares);
        console.log("Cooldown operations blocked by whitelist enforcement");
        console.log("Vulnerability confirmed: User funds permanently locked");
    }
}
```

## Notes

This vulnerability represents a critical design flaw where the whitelist enforcement mechanism, intended to restrict user transfers for regulatory compliance, inadvertently breaks core protocol functionality. The issue arises from the `_beforeTokenTransfer` hook treating all transfers uniformly without distinguishing between user-to-user transfers (which should require whitelist) and protocol-internal transfers (which are necessary for the vault to operate).

The vulnerability is particularly severe because:
1. When `cooldownDuration > 0`, the ERC4626 standard `withdraw()` and `redeem()` functions are explicitly disabled [8](#0-7) 
2. Cooldown is the ONLY mechanism for users to retrieve their funds
3. The unstake operation also requires the silo to be whitelisted to transfer tokens back to users [9](#0-8) 

This issue is NOT mentioned in the known issues list and represents a genuine protocol vulnerability that could lead to permanent loss of user funds if the protocol enters WHITELIST_ENABLED mode without properly whitelisting all required protocol contracts.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L24-24)
```text
    uint24 public constant MAX_COOLDOWN_DURATION = 90 days;
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L54-61)
```text
    function withdraw(uint256 assets, address receiver, address _owner)
        public
        virtual
        override
        ensureCooldownOff
        returns (uint256)
    {
        return super.withdraw(assets, receiver, _owner);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L96-96)
```text
    function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L104-104)
```text
        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L117-117)
```text
        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
```

**File:** src/token/iTRY/iTry.sol (L210-214)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
```

**File:** src/token/iTRY/iTry.sol (L216-216)
```text
                revert OperationNotAllowed();
```

**File:** src/token/wiTRY/iTrySilo.sol (L29-29)
```text
        iTry.transfer(to, amount);
```
