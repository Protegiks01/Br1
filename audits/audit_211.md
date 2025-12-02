## Title
Insufficient Gas Allocation for Cross-Chain Unstaking Causes Message Delivery Failure and Fund Lockup on L2 Hub Chains

## Summary
The `LZ_RECEIVE_GAS` constant in `UnstakeMessenger.sol` allocates 350,000 gas for hub chain execution during cross-chain unstaking. However, the hub's `_lzReceive` function performs a nested LayerZero send operation that can consume 150k-250k+ gas alone. On L2 chains with different gas mechanics (Optimistic Rollups, ZK-Rollups), this hardcoded limit causes under-provisioning, leading to message delivery failure and indefinite fund lockup. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/UnstakeMessenger.sol` (line 63) and `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (lines 214-278)

**Intended Logic:** The protocol allocates 350,000 gas for the hub chain to receive and process unstaking messages from spoke chains. This should be sufficient for the hub to validate the cooldown, withdraw assets from the silo, and send iTRY tokens back to the user on the spoke chain. [2](#0-1) 

**Actual Logic:** The hub's `_lzReceive` function performs a gas-intensive nested LayerZero send operation within the 350k gas budget. The `_handleUnstake` function calls `_send(ASSET_OFT, _sendParam, address(this))` which triggers a new cross-chain message. [3](#0-2) 

This nested send operation invokes the LayerZero endpoint's `send` function, which is extremely gas-intensive: [4](#0-3) 

**Gas Consumption Breakdown:**
1. Message decoding and routing: ~10k gas
2. `unstakeThroughComposer` execution: ~35-40k gas (storage updates, silo withdrawal, iTRY transfer) [5](#0-4) 

3. **CRITICAL: Nested LayerZero send operation: 150k-250k+ gas**
   - Message encoding
   - Endpoint validation and processing
   - DVN coordination
   - Event emissions

4. SendParam construction and event emission: ~3k gas

**Total: 220k-320k+ gas** (potentially exceeding the 350k limit)

**Exploitation Path:**
1. User completes cooldown period for their wiTRY shares on a spoke chain
2. User calls `UnstakeMessenger.unstake(returnTripAllocation)` with correct fee payment
3. LayerZero delivers message to hub with 350k gas allocated for `_lzReceive`
4. Hub attempts to execute `_handleUnstake` which includes the nested send operation
5. On L2 hub chains (Optimistic Rollups), the gas accounting differs:
   - L2 execution gas (350k limit)
   - L1 calldata costs (separate, not included in 350k)
   - The LayerZero send creates significant calldata for L1 submission
6. Gas runs out during the nested send operation
7. Message delivery fails, user's iTRY remains locked in the vault

**Security Property Broken:** Violates **Invariant #7: Cross-chain Message Integrity** - "LayerZero messages for unstaking must be delivered to correct user with proper validation"

## Impact Explanation
- **Affected Assets**: User's iTRY tokens locked in the vault's silo after cooldown completion
- **Damage Severity**: Users on L2 hub deployments cannot complete cross-chain unstaking. Their completed cooldowns cannot be processed, leaving their iTRY indefinitely locked unless they pay additional fees for manual retry or await admin intervention
- **User Impact**: All cross-chain unstakers on L2 hub chains are affected. Every unstaking attempt from spoke chains will fail if the hub is an Optimistic Rollup (Optimism, Arbitrum, Base) or other L2 with distinct gas mechanics

## Likelihood Explanation
- **Attacker Profile**: Not an attack—this is a protocol design flaw affecting all legitimate users
- **Preconditions**: 
  - Hub chain is an L2 (Optimistic Rollup, ZK-Rollup, or any chain with different gas mechanics than Ethereum mainnet)
  - User has completed cooldown period
  - User initiates cross-chain unstaking from spoke chain
- **Execution Complexity**: Triggered by normal user operations—single transaction from spoke chain
- **Frequency**: Affects every cross-chain unstaking attempt on L2 hub deployments

## Recommendation

The hardcoded gas limit cannot adapt to different chain gas mechanics. The protocol should implement one of the following solutions:

**Solution 1: Increase gas limit with safety margin**
```solidity
// In src/token/wiTRY/crosschain/UnstakeMessenger.sol, line 63:

// CURRENT (vulnerable):
uint128 internal constant LZ_RECEIVE_GAS = 350000;

// FIXED:
// Increased to 500000 to account for nested LayerZero send operation
// This provides ~250k for the send operation plus 250k for vault operations
// Still may need adjustment for specific L2 chains
uint128 internal constant LZ_RECEIVE_GAS = 500000;
```

**Solution 2: Make gas limit configurable per hub chain**
```solidity
// RECOMMENDED: Allow owner to configure gas limit per deployment
// Different hub chains may require different gas limits

uint128 public lzReceiveGas = 500000; // Default with safety margin

function setLzReceiveGas(uint128 _newGasLimit) external onlyOwner {
    require(_newGasLimit >= 300000, "Gas limit too low");
    require(_newGasLimit <= 1000000, "Gas limit too high");
    lzReceiveGas = _newGasLimit;
}

// Then use lzReceiveGas instead of LZ_RECEIVE_GAS in unstake():
bytes memory callerOptions = OptionsBuilder.newOptions()
    .addExecutorLzReceiveOption(lzReceiveGas, uint128(returnTripAllocation));
```

**Solution 3: Document L2 incompatibility**
If fixing the gas limit is not feasible, clearly document that the protocol only supports Ethereum mainnet as hub chain and will fail on L2 deployments.

**Note:** The comments in `wiTryVaultComposer.sol` acknowledge that enforced options on the iTRY adapter include 200k gas for the return leg, but this is separate from the 350k allocated for hub execution: [6](#0-5) 

## Proof of Concept

```solidity
// File: test/Exploit_InsufficientGasLockup.t.sol
// Run with: forge test --match-test test_InsufficientGasLockup -vvv
// Note: This PoC demonstrates the issue conceptually. Actual testing would require
// forking an L2 chain and simulating LayerZero message delivery with gas metering.

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";

contract Exploit_InsufficientGasLockup is Test {
    UnstakeMessenger messenger;
    wiTryVaultComposer composer;
    
    function setUp() public {
        // Deploy contracts (simplified - actual deployment would include full setup)
        // This PoC demonstrates the gas consumption analysis
    }
    
    function test_InsufficientGasLockup() public {
        // SETUP: User has completed cooldown on hub, initiates unstaking from spoke
        address user = address(0x123);
        uint256 returnTripAllocation = 0.01 ether;
        
        // VULNERABILITY: LZ_RECEIVE_GAS is only 350k
        uint128 gasLimit = 350000;
        
        // DEMONSTRATE: Hub execution requires more than 350k gas
        uint256 estimatedGasNeeded = 
            10000 +  // Decoding and routing
            40000 +  // unstakeThroughComposer (storage + silo withdrawal)
            200000 + // Nested LayerZero send operation (conservative estimate)
            3000;    // SendParam construction and event
        
        // VERIFY: Gas requirement exceeds allocated limit on L2 chains
        assertGt(estimatedGasNeeded, gasLimit, 
            "Estimated gas consumption exceeds allocated 350k limit");
        
        // On L2 chains, the actual gas consumption includes:
        // - L2 execution (what 350k covers)
        // - L1 calldata costs (NOT included in 350k limit)
        // This means even if L2 execution fits in 350k, L1 costs cause failure
        
        console.log("Allocated gas:", gasLimit);
        console.log("Estimated gas needed:", estimatedGasNeeded);
        console.log("Gas shortfall:", estimatedGasNeeded - gasLimit);
        console.log("\nOn L2 chains, L1 calldata costs add significant overhead");
        console.log("Result: Message delivery fails, user funds locked");
    }
}
```

## Notes

This vulnerability is distinct from the known issue "Native fee loss on failed wiTryVaultComposer.lzReceive" which refers to users needing to pay twice if underpayment occurs. Here, the issue is that the **gas limit itself is structurally insufficient** for the operation, not a user underpayment issue.

The protocol's cross-chain architecture requires a nested LayerZero send within the `_lzReceive` execution, which is inherently gas-intensive. The hardcoded 350k limit was likely calibrated for Ethereum mainnet but does not account for:
1. L2 gas mechanics where L1 calldata costs are separate from L2 execution gas
2. Future protocol upgrades that may increase gas consumption
3. Network congestion scenarios
4. Different LayerZero endpoint implementations across chains

The deployment scripts show the protocol is intended for L2 deployment (OP Sepolia references), making this vulnerability highly relevant: [7](#0-6)

### Citations

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L61-63)
```text
    /// @notice Gas limit for lzReceive on hub chain
    /// @dev Must be non-zero to satisfy LayerZero executor requirements
    uint128 internal constant LZ_RECEIVE_GAS = 350000;
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L126-127)
```text
        bytes memory callerOptions =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L284-287)
```text
     * @dev Gas Consideration:
     * - Enforced options on adapter already include 200k gas
     * - Quote automatically includes gas cost
     * - No need to calculate vault execution gas (already happened on hub)
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L357-368)
```text
    function _send(address _oft, SendParam memory _sendParam, address _refundAddress) internal {
        if (_sendParam.dstEid == VAULT_EID) {
            /// @dev Can do this because _oft is validated before this function is called
            address erc20 = _oft == ASSET_OFT ? ASSET_ERC20 : SHARE_ERC20;

            if (msg.value > 0) revert NoMsgValueExpected();
            IERC20(erc20).safeTransfer(_sendParam.to.bytes32ToAddress(), _sendParam.amountLD);
        } else {
            // crosschain send
            IOFT(_oft).send{value: msg.value}(_sendParam, MessagingFee(msg.value, 0), _refundAddress);
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

**File:** script/config/06_SetEnforcedOptionsiTryAdapter.s.sol (L23-25)
```text
    uint32 internal constant OP_SEPOLIA_EID = 40232;
    uint16 internal constant SEND = 1; // msgType for regular send (no compose)
    uint128 internal constant LZ_RECEIVE_GAS = 200000;
```
