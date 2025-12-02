## Title
Blacklisted wiTryVaultComposer Permanently Locks All Cross-Chain User Funds in iTrySilo

## Summary
The `iTrySilo.withdraw()` function transfers iTRY tokens to an arbitrary address without validating blacklist status. When called by `unstakeThroughComposer()` with a blacklisted composer as the recipient, the iTRY token's `_beforeTokenTransfer` hook reverts, permanently locking all cross-chain users' unstaked funds in the silo with no recovery mechanism.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The silo acts as a temporary custody contract during the cooldown period. After cooldown completion, `unstakeThroughComposer()` should transfer iTRY tokens from the silo to the composer for cross-chain bridging back to users.

**Actual Logic:** The `silo.withdraw()` function performs an unchecked `iTry.transfer(to, amount)` call. This triggers the iTRY token's blacklist validation in `_beforeTokenTransfer`, which reverts if the recipient has `BLACKLISTED_ROLE`. [2](#0-1) 

In the cross-chain unstaking flow, the recipient is hardcoded as the composer: [3](#0-2) 

**Exploitation Path:**

1. **Cross-chain users initiate unstaking**: Multiple L2 users send LayerZero messages via UnstakeMessenger to initiate cooldown on L1 hub chain. The wiTryVaultComposer calls `cooldownSharesByComposer()` or `cooldownAssetsByComposer()`, transferring iTRY to the silo and tracking cooldowns under each user's address.

2. **wiTryVaultComposer gets blacklisted**: The protocol admin blacklists the wiTryVaultComposer contract address (due to bug discovery, security incident, or administrative error).

3. **Cooldown periods complete**: Users' cooldowns mature and they attempt to claim their iTRY by sending LayerZero unstake messages.

4. **All unstake operations fail**: The wiTryVaultComposer receives LayerZero messages and calls `vault.unstakeThroughComposer(user)`: [4](#0-3) 

This executes `silo.withdraw(msg.sender, assets)` where `msg.sender` is the blacklisted composer. The iTRY transfer reverts because the recipient has `BLACKLISTED_ROLE`.

5. **Funds permanently locked**: 
   - Users cannot call `unstakeThroughComposer()` themselves (requires `COMPOSER_ROLE`)
   - Users cannot bypass the composer in the cross-chain flow
   - The silo continues holding all users' iTRY indefinitely
   - No built-in rescue mechanism exists for this scenario

**Security Property Broken:** Violates **Critical Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case"** - but in this case, the blacklist enforcement creates a protocol-level DOS that permanently locks non-blacklisted users' funds.

## Impact Explanation

- **Affected Assets**: All iTRY tokens held in the iTrySilo for cross-chain users awaiting unstaking completion. This could represent substantial value if many L2 users have initiated cooldowns.

- **Damage Severity**: Complete loss of access to funds for all cross-chain users with active cooldowns. If the composer is blacklisted with 100 ETH worth of iTRY in cooldown across 50 users, all 50 users lose access permanently.

- **User Impact**: Every cross-chain user who initiated a cooldown before the composer blacklisting is affected. The only recovery requires admin intervention to either (1) un-blacklist the composer (defeating the purpose of the blacklist) or (2) implement an emergency rescue function (which doesn't currently exist).

## Likelihood Explanation

- **Attacker Profile**: This requires no attacker action - it's a protocol design flaw triggered by legitimate blacklist operations.

- **Preconditions**: 
  - Cross-chain deployment is active with wiTryVaultComposer holding `COMPOSER_ROLE`
  - Users have initiated cooldowns (iTRY sitting in silo)
  - Admin blacklists the composer contract (legitimate security response to a bug/exploit in the composer)

- **Execution Complexity**: Automatic failure - every unstake attempt reverts once the composer is blacklisted.

- **Frequency**: Single blacklist event affects all pending cooldowns and all future cross-chain unstaking operations until the blacklist is removed.

## Recommendation

**Primary Fix:** Add blacklist validation in iTrySilo with emergency unstake path:

```solidity
// In src/token/wiTRY/iTrySilo.sol, lines 28-30:

// CURRENT (vulnerable):
function withdraw(address to, uint256 amount) external onlyStakingVault {
    iTry.transfer(to, amount);
}

// FIXED:
function withdraw(address to, uint256 amount) external onlyStakingVault {
    // Check if recipient is blacklisted before transfer
    // If blacklisted, revert with specific error to allow alternative recovery
    if (iTry.hasRole(iTry.BLACKLISTED_ROLE(), to)) {
        revert RecipientBlacklisted(to);
    }
    iTry.transfer(to, amount);
}

// Add emergency unstake function that bypasses composer when blacklisted:
function emergencyWithdrawForUser(address user) external onlyStakingVault {
    // Allows vault to send directly to user if composer is blacklisted
    // User must not be blacklisted themselves
    UserCooldown storage cooldown = cooldowns[user];
    require(cooldown.underlyingAmount > 0, "No funds to withdraw");
    require(!iTry.hasRole(iTry.BLACKLISTED_ROLE(), user), "User blacklisted");
    
    uint256 assets = cooldown.underlyingAmount;
    cooldown.underlyingAmount = 0;
    cooldown.cooldownEnd = 0;
    
    iTry.transfer(user, assets);
}
```

**Alternative Mitigation:** Implement a rescue mechanism in StakediTryCrosschain that allows admin to reassign cooldowns to a new composer contract if the current composer is blacklisted.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedComposerLocksUnstake.t.sol
// Run with: forge test --match-test test_BlacklistedComposerLocksUnstake -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/iTrySilo.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_BlacklistedComposerLocksUnstake is Test {
    iTry public itryToken;
    StakediTryCrosschain public vault;
    iTrySilo public silo;
    
    address public owner;
    address public composer;
    address public user;
    address public blacklistManager;
    
    function setUp() public {
        owner = makeAddr("owner");
        composer = makeAddr("composer");
        user = makeAddr("user");
        blacklistManager = makeAddr("blacklistManager");
        
        // Deploy iTRY token
        iTry itryImpl = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner,
            owner
        );
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImpl), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy vault
        vm.prank(owner);
        vault = new StakediTryCrosschain(
            IERC20(address(itryToken)),
            makeAddr("rewarder"),
            owner,
            makeAddr("treasury")
        );
        
        silo = vault.silo();
        
        // Grant roles
        vm.startPrank(owner);
        vault.grantRole(vault.COMPOSER_ROLE(), composer);
        itryToken.grantRole(itryToken.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        vm.stopPrank();
        
        // Mint iTRY to user and deposit to vault
        vm.prank(owner);
        itryToken.mint(user, 100 ether);
        
        vm.startPrank(user);
        itryToken.approve(address(vault), 100 ether);
        vault.deposit(100 ether, user);
        vm.stopPrank();
    }
    
    function test_BlacklistedComposerLocksUnstake() public {
        // SETUP: User initiates cross-chain cooldown
        uint256 userShares = vault.balanceOf(user);
        
        vm.prank(composer);
        uint256 assets = vault.cooldownSharesByComposer(userShares, user);
        
        // Verify iTRY is in silo
        assertEq(itryToken.balanceOf(address(silo)), assets, "iTRY should be in silo");
        
        // Fast forward past cooldown
        vm.warp(block.timestamp + vault.cooldownDuration() + 1);
        
        // EXPLOIT: Admin blacklists composer (legitimate security action)
        address[] memory toBlacklist = new address[](1);
        toBlacklist[0] = composer;
        
        vm.prank(blacklistManager);
        itryToken.addBlacklistAddress(toBlacklist);
        
        // VERIFY: Composer cannot unstake - funds locked
        vm.prank(composer);
        vm.expectRevert(); // Will revert with OperationNotAllowed from iTRY._beforeTokenTransfer
        vault.unstakeThroughComposer(user);
        
        // Verify funds still locked in silo
        assertEq(itryToken.balanceOf(address(silo)), assets, "Funds permanently locked in silo");
        assertEq(itryToken.balanceOf(user), 0, "User cannot receive their iTRY");
        
        // User has no way to recover - only composer can call unstakeThroughComposer
        vm.prank(user);
        vm.expectRevert(); // User doesn't have COMPOSER_ROLE
        vault.unstakeThroughComposer(user);
    }
}
```

## Notes

**Critical Distinction from Regular Unstaking:** 

In the regular `unstake()` function, users can specify any receiver address: [5](#0-4) 

This allows a blacklisted user to unstake to a different non-blacklisted address, providing a workaround. However, `unstakeThroughComposer()` hardcodes the recipient as `msg.sender` (the composer), creating a systemic risk.

**Cross-Chain Architecture Context:**

The vulnerability is specific to the cross-chain flow: [6](#0-5) 

When the composer receives LayerZero unstake messages and processes them, it must receive the iTRY from the silo to bridge back to L2. A blacklisted composer breaks this entire flow for all cross-chain users.

**Not Covered by Known Issues:** The Zellic audit identified that "Blacklisted user can transfer tokens using allowance" but did not identify this specific scenario where blacklisting a critical protocol contract (the composer) creates a permanent DOS for all users.

### Citations

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/iTRY/iTry.sol (L177-196)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L93-93)
```text
            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L244-278)
```text
    function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
        internal
        virtual
    {
        address user = unstakeMsg.user;

        // Validate user
        if (user == address(0)) revert InvalidZeroAddress();
        if (_origin.srcEid == 0) revert InvalidOrigin();

        // Call vault to unstake
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);

        if (assets == 0) {
            revert NoAssetsToUnstake();
        }

        // Build send parameters and send assets back to spoke chain
        bytes memory options = OptionsBuilder.newOptions();

        SendParam memory _sendParam = SendParam({
            dstEid: _origin.srcEid,
            to: bytes32(uint256(uint160(user))),
            amountLD: assets,
            minAmountLD: assets,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });

        _send(ASSET_OFT, _sendParam, address(this));

        // Emit success event
        emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
    }
```

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
