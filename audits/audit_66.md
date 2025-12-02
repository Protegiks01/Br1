## Title
FULLY_DISABLED Transfer State Prevents Unstaking Operations on Spoke Chains, Locking User Funds

## Summary
When `transferState` is set to `FULLY_DISABLED` in `iTryTokenOFT.sol` on spoke chains, users with pending cooldowns or completed cooldowns cannot unstake their wiTRY to receive iTRY tokens back. The `_beforeTokenTransfer` hook unconditionally reverts all transfers in this state, including the critical transfer from the silo contract to users during unstaking operations, causing a denial of service that locks user funds.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 174-176, `_beforeTokenTransfer` function)

**Intended Logic:** The `FULLY_DISABLED` transfer state is designed as an emergency brake to halt all token transfers during critical situations. [1](#0-0) 

**Actual Logic:** When `FULLY_DISABLED` is active, the `_beforeTokenTransfer` hook unconditionally reverts with `OperationNotAllowed()` for ALL operations, including legitimate internal operations necessary for unstaking. Unlike the `FULLY_ENABLED` and `WHITELIST_ENABLED` states which have exceptions for minting/burning and special operations, `FULLY_DISABLED` has zero exceptions. [2](#0-1) 

**Exploitation Path:**

1. **User stakes iTRY on spoke chain**: User deposits iTRY tokens into the StakediTry vault (wiTRY) and receives share tokens representing their stake.

2. **User initiates cooldown**: User calls `cooldownAssets()` or `cooldownShares()` to begin the unstaking process. This transfers iTRY from the vault to the silo contract for safekeeping during the cooldown period. [3](#0-2) 

3. **Admin sets FULLY_DISABLED**: The contract owner calls `updateTransferState(TransferState.FULLY_DISABLED)` for legitimate emergency purposes (e.g., security incident, regulatory requirement, system upgrade). [4](#0-3) 

4. **Cooldown expires, user attempts unstaking**: After the cooldown period completes, user calls `unstake(receiver)` to claim their iTRY tokens. The function calls `silo.withdraw(receiver, assets)` which attempts to execute `iTry.transfer(to, amount)` to return the tokens. [5](#0-4) 

5. **Transfer fails**: The silo's `withdraw()` function calls `iTry.transfer()`, triggering the `_beforeTokenTransfer` hook which immediately reverts because `transferState == FULLY_DISABLED`. [6](#0-5) 

6. **Funds locked**: User's iTRY tokens remain locked in the silo contract, inaccessible until the admin changes the transfer state back to `FULLY_ENABLED` or `WHITELIST_ENABLED`.

**Security Property Broken:** This violates the **Cooldown Integrity** invariant which states "Users must complete cooldown period before unstaking wiTRY." While users complete the cooldown period, they cannot actually unstake due to the transfer restriction, breaking the expected user flow and locking their funds.

## Impact Explanation

- **Affected Assets**: All iTRY tokens held in the silo contract for users with pending or completed cooldowns. This includes regular users who initiated cooldowns and cross-chain users whose unstaking is managed by the composer role.

- **Damage Severity**: Temporary denial of service causing complete fund lock. Users cannot access their iTRY tokens until the admin changes the transfer state. In the worst case, if the transfer state remains `FULLY_DISABLED` for an extended period, users experience prolonged inability to access their capital. All unstaking paths are affected:
  - Regular `unstake()` function [5](#0-4) 
  - Composer-based `unstakeThroughComposer()` for cross-chain operations [7](#0-6) 
  - Fast redeem operations via `_redeemWithFee()` [8](#0-7) 

- **User Impact**: Every user with iTRY in cooldown at the time `FULLY_DISABLED` is activated becomes unable to complete their unstaking. New cooldowns can still be initiated (iTRY transfers to silo), but no exits are possible. This creates a one-way trap where users can enter cooldown but cannot exit.

## Likelihood Explanation

- **Attacker Profile**: No attacker required - this is a design flaw triggered by legitimate admin actions. Any user with a pending cooldown is affected when the admin activates `FULLY_DISABLED` for valid emergency reasons.

- **Preconditions**: 
  - StakediTry vault deployed on spoke chain using iTryTokenOFT as the underlying asset
  - Users have initiated cooldowns (iTRY held in silo contract)
  - Admin sets `transferState = FULLY_DISABLED` for emergency purposes

- **Execution Complexity**: Single transaction failure - user calls `unstake()` and the transaction reverts. No complex coordination required.

- **Frequency**: Affects all users with pending cooldowns whenever `FULLY_DISABLED` state is active. Given that `FULLY_DISABLED` is an emergency measure that could be activated during security incidents, regulatory actions, or system upgrades, this is a realistic scenario.

## Recommendation

Modify the `_beforeTokenTransfer` hook in `iTryTokenOFT.sol` to add an exception for the silo contract, allowing it to transfer tokens even when transfers are fully disabled:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, function _beforeTokenTransfer, lines 174-176:

// CURRENT (vulnerable):
else if (transferState == TransferState.FULLY_DISABLED) {
    revert OperationNotAllowed();
}

// FIXED:
else if (transferState == TransferState.FULLY_DISABLED) {
    // Allow silo to transfer during unstaking operations
    // This enables users to withdraw after cooldown even in emergency shutdown
    if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
        // Allow minter to burn (needed for cross-chain bridging back to hub)
    } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
        // Allow minter to mint (needed for cross-chain bridging from hub)
    } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
        // Allow owner to burn blacklisted user funds
    } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
        // Allow owner to mint during redistribution
    } else {
        // Block all other transfers including user-to-user transfers
        revert OperationNotAllowed();
    }
}
```

**Alternative mitigation**: Store the silo contract address during vault deployment and add a specific exception:

```solidity
address public immutable SILO_CONTRACT;

// In constructor, after vault deployment:
SILO_CONTRACT = address(stakediTryVault.silo());

// In _beforeTokenTransfer for FULLY_DISABLED state:
else if (transferState == TransferState.FULLY_DISABLED) {
    // Allow silo to complete unstaking operations
    if (from == SILO_CONTRACT && !blacklisted[to]) {
        // Silo returning iTRY to users after cooldown
    } else if (hasRole(MINTER_CONTRACT, msg.sender) && ...) {
        // Other essential operations
    } else {
        revert OperationNotAllowed();
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_UnstakingBlockedByFullyDisabled.t.sol
// Run with: forge test --match-test test_UnstakingBlockedByFullyDisabled -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFT.sol";

contract Exploit_UnstakingBlockedByFullyDisabled is Test {
    iTryTokenOFT public itryOFT;
    StakediTryCrosschain public vault;
    
    address public owner;
    address public user;
    address public lzEndpoint;
    
    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        lzEndpoint = makeAddr("lzEndpoint");
        
        // Deploy iTryTokenOFT on spoke chain
        vm.prank(owner);
        itryOFT = new iTryTokenOFT(lzEndpoint, owner);
        
        // Deploy StakediTry vault using iTryTokenOFT as asset
        vm.prank(owner);
        vault = new StakediTryCrosschain(
            IERC20(address(itryOFT)),
            owner, // rewarder
            owner, // admin
            owner  // treasury
        );
        
        // Mint some iTRY to user for testing
        vm.prank(lzEndpoint);
        itryOFT.transfer(user, 1000 ether);
        
        // Set cooldown duration
        vm.prank(owner);
        vault.setCooldownDuration(1 days);
    }
    
    function test_UnstakingBlockedByFullyDisabled() public {
        // SETUP: User stakes iTRY
        vm.startPrank(user);
        itryOFT.approve(address(vault), 1000 ether);
        vault.deposit(1000 ether, user);
        vm.stopPrank();
        
        // User initiates cooldown
        vm.startPrank(user);
        vault.cooldownAssets(1000 ether);
        vm.stopPrank();
        
        // Fast forward past cooldown period
        vm.warp(block.timestamp + 1 days + 1);
        
        // EXPLOIT: Owner sets FULLY_DISABLED (for legitimate emergency)
        vm.prank(owner);
        itryOFT.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        
        // VERIFY: User cannot unstake - transaction reverts
        vm.startPrank(user);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        vault.unstake(user);
        vm.stopPrank();
        
        // Verify user's iTRY is locked in silo
        assertEq(itryOFT.balanceOf(address(vault.silo())), 1000 ether, 
            "Vulnerability confirmed: User's iTRY locked in silo, cannot unstake");
        assertEq(itryOFT.balanceOf(user), 0, 
            "User has no iTRY - funds are stuck");
    }
}
```

## Notes

- This issue affects **both hub chain** (iTry.sol) and **spoke chains** (iTryTokenOFT.sol) as they share identical `_beforeTokenTransfer` logic with unconditional revert for `FULLY_DISABLED`. [9](#0-8) 

- The vulnerability is **not present** in the `WHITELIST_ENABLED` state, which still allows whitelisted users to burn their tokens. [10](#0-9) 

- The silo contract has no emergency withdrawal function and relies entirely on the normal transfer mechanism, making it completely dependent on the transfer state. [6](#0-5) 

- This is **not a centralization risk** but a design oversight - the admin action is legitimate (emergency shutdown), but the implementation inadvertently breaks critical system functionality (unstaking).

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L134-138)
```text
    function updateTransferState(TransferState code) external onlyOwner {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-177)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
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

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
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

**File:** src/token/iTRY/iTry.sol (L219-221)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
```
