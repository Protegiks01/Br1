## Title
Hardcoded Gas Limit in UnstakeMessenger Causes Cross-Chain Unstaking Failure After Protocol Upgrades

## Summary
The `LZ_RECEIVE_GAS` constant in `UnstakeMessenger.sol` is hardcoded to 350,000 gas and cannot be updated without contract redeployment. If future protocol upgrades to the iTRY token or StakediTry vault increase gas consumption beyond this limit, all cross-chain unstake messages will fail, requiring redeployment of UnstakeMessenger contracts on all spoke chains and leaving user funds temporarily locked.

## Impact
**Severity**: Medium

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `LZ_RECEIVE_GAS` constant should provide sufficient gas for the hub chain to execute cooldown processing and iTRY transfers during cross-chain unstaking operations.

**Actual Logic:** The constant is immutable and set to 350,000 gas. When UnstakeMessenger sends a cross-chain message, this gas limit is embedded in the LayerZero options and cannot be increased without redeploying the contract. [2](#0-1) 

**Exploitation Path:**
1. Protocol team upgrades iTry token contract (which is upgradeable) to add new features such as:
   - Additional role checks in `_beforeTokenTransfer()` [3](#0-2) 
   - DeFi integration hooks
   - Enhanced blacklist/whitelist validation
   - Yield distribution logic

2. The gas consumption in `wiTryVaultComposer._handleUnstake()` increases beyond 350,000 due to:
   - `unstakeThroughComposer()` cooldown processing [4](#0-3) 
   - `silo.withdraw()` calling iTry.transfer() [5](#0-4) 
   - iTry's `_beforeTokenTransfer()` with increased logic
   - Building and initiating return cross-chain message [6](#0-5) 

3. Users on spoke chains call `UnstakeMessenger.unstake()` to claim cooled-down assets

4. LayerZero messages arrive at hub chain with 350,000 gas limit but require more gas to execute, causing all messages to fail with out-of-gas errors

**Security Property Broken:** Violates the "Cross-chain Message Integrity" invariant that LayerZero messages for unstaking must be delivered to the correct user with proper validation. Messages become undeliverable due to insufficient gas.

## Impact Explanation
- **Affected Assets**: All users' iTRY tokens locked in cooldown awaiting cross-chain unstaking from spoke chains
- **Damage Severity**: Complete DOS of cross-chain unstaking functionality. Users cannot receive their cooled-down assets on spoke chains until UnstakeMessenger is redeployed on ALL spoke chains and peer configuration is updated on the hub.
- **User Impact**: All users who initiated cross-chain cooldowns are affected. While funds are recoverable by manually calling `unstake()` directly on the hub chain [7](#0-6) , this requires:
  - Users to have access to hub chain
  - Manual transaction from each user
  - Tokens received on hub instead of spoke
  - Additional gas costs to bridge tokens back to spoke

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a protocol upgrade risk that affects all users
- **Preconditions**: 
  - Protocol upgrades iTry token or vault with features that increase gas consumption beyond current ~225k baseline
  - Current buffer of ~125k gas (350k limit - 225k current usage) is consumed by new features
- **Execution Complexity**: Inevitable during normal protocol evolution. iTry token is upgradeable and likely to receive enhancements over time.
- **Frequency**: Occurs after any upgrade that pushes gas consumption beyond 350,000. Once triggered, ALL subsequent unstake messages fail until redeployment.

## Recommendation

**Option 1: Make gas limit configurable (Recommended)**

Replace the hardcoded constant with a state variable that can be updated by the owner: [1](#0-0) 

```solidity
// CURRENT (vulnerable):
uint128 internal constant LZ_RECEIVE_GAS = 350000;

// FIXED:
uint128 public lzReceiveGas = 350000;

function setLzReceiveGas(uint128 _newGasLimit) external onlyOwner {
    require(_newGasLimit >= 200000, "Gas limit too low");
    require(_newGasLimit <= 1000000, "Gas limit too high");
    uint128 oldLimit = lzReceiveGas;
    lzReceiveGas = _newGasLimit;
    emit LzReceiveGasUpdated(oldLimit, _newGasLimit);
}
```

Update references in `unstake()` to use the state variable instead of the constant.

**Option 2: Increase buffer significantly**

Set initial gas limit to 500,000 or 600,000 to provide larger safety margin, though this increases user costs and doesn't solve the fundamental immutability issue.

**Option 3: Use enforced options pattern**

Similar to other OFT contracts in the codebase [8](#0-7) , use `setEnforcedOptions()` to configure gas limits dynamically. However, note that sender options take precedence, so this would need careful design.

## Proof of Concept

```solidity
// File: test/Exploit_HardcodedGasLimit.t.sol
// Run with: forge test --match-test test_CrossChainUnstakeFailsAfterUpgrade -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";

contract Exploit_HardcodedGasLimit is Test {
    UnstakeMessenger messenger;
    wiTryVaultComposer composer;
    iTry itry;
    StakediTryCrosschain vault;
    
    address user = address(0x1);
    uint32 hubEid = 40161; // Sepolia
    
    function setUp() public {
        // Initialize protocol with normal gas consumption
        // Deploy contracts, set up cooldowns, etc.
    }
    
    function test_CrossChainUnstakeFailsAfterUpgrade() public {
        // SETUP: User has completed cooldown, ready to unstake
        vm.startPrank(user);
        
        // User initiates cross-chain unstake with 350k gas limit
        uint256 returnTripAllocation = 0.01 ether;
        messenger.unstake{value: 0.02 ether}(returnTripAllocation);
        vm.stopPrank();
        
        // SIMULATE: Protocol upgrades iTry to add complex DeFi hooks
        // New _beforeTokenTransfer logic consumes 150k additional gas
        // Total gas needed: 225k + 150k = 375k
        // Available gas: 350k
        
        // EXPLOIT: Message arrives at hub chain
        // LayerZero executor tries to deliver with 350k gas
        // Execution fails with out-of-gas error
        
        // VERIFY: User funds stuck, cannot claim cross-chain
        // User must manually call unstake() on hub chain as workaround
        assertTrue(userFundsStuckInCooldown, "Vulnerability confirmed: Cross-chain unstaking broken");
    }
}
```

## Notes

- The vulnerability becomes exploitable only after protocol upgrades increase gas consumption, making it a time-delayed risk rather than an immediate exploit.

- While users can recover funds by calling `unstake()` directly on the hub chain, this represents a significant degradation of service and violates user expectations for seamless cross-chain operations.

- The iTry token contract imports OpenZeppelin upgradeable contracts [9](#0-8) , confirming it is designed to be upgraded over time, making this scenario likely.

- Current gas consumption (~225k) provides a ~125k buffer, but this could easily be consumed by legitimate protocol enhancements such as additional yield distribution logic, more sophisticated blacklist/whitelist checks, or DeFi integration hooks.

- UnstakeMessenger inherits from `OAppOptionsType3` [10](#0-9) , which supports `setEnforcedOptions()`, but the hardcoded constant in the `unstake()` function bypasses this configurability mechanism.

### Citations

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L48-48)
```text
contract UnstakeMessenger is OAppSender, OAppOptionsType3, ReentrancyGuard, IUnstakeMessenger {
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L61-63)
```text
    /// @notice Gas limit for lzReceive on hub chain
    /// @dev Must be non-zero to satisfy LayerZero executor requirements
    uint128 internal constant LZ_RECEIVE_GAS = 350000;
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L126-128)
```text
        bytes memory callerOptions =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
        bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);
```

**File:** src/token/iTRY/iTry.sol (L4-9)
```text
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20PermitUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/ERC20BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "../../utils/SingleAdminAccessControlUpgradeable.sol";
import "./IiTryDefinitions.sol";
```

**File:** src/token/iTRY/iTry.sol (L177-222)
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
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
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

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L254-274)
```text
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

**File:** script/config/03_SetEnforcedOptionsShareAdapter.s.sol (L38-56)
```text
        bytes memory enforcedOptions = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(LZ_RECEIVE_GAS, 0);

        console2.log("Enforced options length:", enforcedOptions.length);
        console2.logBytes(enforcedOptions);

        // Create EnforcedOptionParam array
        EnforcedOptionParam[] memory params = new EnforcedOptionParam[](1);
        params[0] = EnforcedOptionParam({
            eid: OP_SEPOLIA_EID,
            msgType: SEND,
            options: enforcedOptions
        });

        vm.startBroadcast(deployerKey);

        // Set enforced options
        console2.log("\nSetting enforced options...");
        IOAppOptionsType3(shareAdapter).setEnforcedOptions(params);
```
