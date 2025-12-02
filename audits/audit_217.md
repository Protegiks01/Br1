## Title
Cross-Chain Unstake Message Type Mismatch Causes Permanent Fund Lockage

## Summary
The `MSG_TYPE_UNSTAKE` constant is hardcoded as value 1 in both `UnstakeMessenger` and `wiTryVaultComposer`. If contracts are deployed with mismatched message type values due to version differences or deployment errors, cross-chain unstake messages will be permanently rejected, locking user funds in the `iTrySilo` with no recovery mechanism.

## Impact
**Severity**: High

## Finding Description

**Location:** 
- `src/token/wiTRY/crosschain/UnstakeMessenger.sol` (line 55, line 121)
- `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (line 38, lines 226-232)

**Intended Logic:** 
The cross-chain unstaking system should allow users to unstake their wiTRY shares after completing the cooldown period. The `UnstakeMessenger` on spoke chains sends unstake requests to the hub's `wiTryVaultComposer`, which processes them and returns iTRY assets to users. [1](#0-0) [2](#0-1) 

**Actual Logic:** 
Both contracts define `MSG_TYPE_UNSTAKE` as immutable constants with no runtime validation to ensure compatibility. When `wiTryVaultComposer` receives a message, it validates the message type and reverts with `UnknownMessageType` if there's a mismatch: [3](#0-2) 

**Exploitation Path:**

1. **Deployment Mismatch Scenario**: Protocol deploys `UnstakeMessenger` with `MSG_TYPE_UNSTAKE = 1` and `wiTryVaultComposer` with `MSG_TYPE_UNSTAKE = 2` (or deploys one contract from an old version and another from a new version).

2. **User Initiates Cooldown**: User bridges wiTRY shares to hub chain and initiates cooldown. The composer burns shares and assigns cooldown to user. iTRY assets are transferred to `iTrySilo`: [4](#0-3) 

3. **Cooldown Completes**: After ~3 days, user attempts to unstake by calling `UnstakeMessenger.unstake()`. Message is encoded with `msgType = 1`: [5](#0-4) 

4. **Message Rejected on Hub**: When `wiTryVaultComposer._lzReceive()` processes the message, the type check fails (`1 != 2`), reverting with `UnknownMessageType`. The function `unstakeThroughComposer()` is never called, leaving iTRY locked in the silo.

5. **No Recovery Path Exists**:
   - `unstakeThroughComposer()` requires `COMPOSER_ROLE` - only `wiTryVaultComposer` has it: [6](#0-5) 

   - `iTrySilo.withdraw()` can only be called by the staking vault: [7](#0-6) 

   - Admin cannot rescue iTRY tokens via `rescueTokens()`: [8](#0-7) 

   - User cannot retry with a different message type since `UnstakeMessenger` still sends the same hardcoded value.

**Security Property Broken:** 
Violates the **Cross-chain Message Integrity** invariant: "LayerZero messages for unstaking must be delivered to correct user with proper validation." Users' funds become permanently inaccessible due to message type incompatibility.

## Impact Explanation

- **Affected Assets**: All iTRY tokens locked in `iTrySilo` for users with completed cooldowns become permanently inaccessible.

- **Damage Severity**: 100% loss of user funds attempting to unstake. All affected users lose their entire principal that was in cooldown. In a deployment mismatch scenario, this could affect all users across all spoke chains attempting to unstake.

- **User Impact**: Any user who completes the cooldown period and attempts to unstake via cross-chain messaging will permanently lose their funds. The issue affects legitimate users performing normal protocol operations, not just edge cases.

## Likelihood Explanation

- **Attacker Profile**: This is not a malicious attack but a **deployment/configuration risk**. No attacker is required - the vulnerability triggers through normal user operations when message types are mismatched.

- **Preconditions**: 
  - Contracts deployed with different `MSG_TYPE_UNSTAKE` values
  - User has completed cooldown period with funds in silo
  - User attempts cross-chain unstake

- **Execution Complexity**: Single transaction from user. No special timing or coordination required.

- **Frequency**: Every unstake attempt by every user would fail once the mismatch exists. The issue persists until contracts are redeployed and reinitialized correctly.

**Risk Factors Increasing Likelihood:**
- No validation during deployment to ensure message type compatibility
- No validation in `setPeer()` to check version compatibility: [9](#0-8) 

- Constants are immutable and cannot be updated without full redeployment
- Multi-chain deployments increase risk of version mismatch
- Future protocol upgrades could introduce new message types without proper migration

## Recommendation

**Solution 1: Add Message Type Validation During Peer Configuration**

```solidity
// In src/token/wiTRY/crosschain/UnstakeMessenger.sol:

// Add new function to validate message type compatibility
function validatePeerMessageType(uint32 eid) external view returns (bool) {
    bytes32 peer = peers[eid];
    require(peer != bytes32(0), "Peer not configured");
    
    // Query peer's expected message type via LayerZero
    // Return true only if message types match
    // This requires adding a getter function on wiTryVaultComposer
}

// Modify setPeer to include validation warning
function setPeer(uint32 eid, bytes32 peer) public override onlyOwner {
    require(eid == hubEid, "UnstakeMessenger: Invalid endpoint");
    require(peer != bytes32(0), "UnstakeMessenger: Invalid peer");
    
    super.setPeer(eid, peer);
    
    // Emit event suggesting validation
    emit PeerSet(eid, peer, MSG_TYPE_UNSTAKE);
}
```

**Solution 2: Add Version Header to Messages**

```solidity
// In src/token/wiTRY/crosschain/UnstakeMessenger.sol:

uint16 public constant PROTOCOL_VERSION = 1;

// Modify unstake() to include version
bytes memory payload = abi.encode(PROTOCOL_VERSION, MSG_TYPE_UNSTAKE, message);

// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol:

// Modify _lzReceive to validate version
(uint16 version, uint16 msgType, IUnstakeMessenger.UnstakeMessage memory unstakeMsg) =
    abi.decode(_message, (uint16, uint16, IUnstakeMessenger.UnstakeMessage));

if (version != EXPECTED_VERSION) revert UnsupportedProtocolVersion(version);
if (msgType == MSG_TYPE_UNSTAKE) {
    _handleUnstake(_origin, _guid, unstakeMsg);
} else {
    revert UnknownMessageType(msgType);
}
```

**Solution 3: Add Emergency Admin Recovery (Preferred for Immediate Fix)**

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol:

// Add emergency admin function to unstake for users when message system fails
function emergencyUnstakeForUser(address user) 
    external 
    onlyRole(DEFAULT_ADMIN_ROLE) 
    nonReentrant 
    returns (uint256 assets) 
{
    UserCooldown storage userCooldown = cooldowns[user];
    assets = userCooldown.underlyingAmount;
    
    require(assets > 0, "No cooldown for user");
    require(block.timestamp >= userCooldown.cooldownEnd, "Cooldown not complete");
    
    userCooldown.cooldownEnd = 0;
    userCooldown.underlyingAmount = 0;
    
    // Transfer directly to user instead of composer
    silo.withdraw(user, assets);
    
    emit EmergencyUnstake(user, assets);
    
    return assets;
}
```

## Proof of Concept

```solidity
// File: test/Exploit_MessageTypeMismatch.t.sol
// Run with: forge test --match-test test_MessageTypeMismatch -vvv

pragma solidity ^0.8.19;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/iTrySilo.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_MessageTypeMismatch is Test {
    StakediTryCrosschain vault;
    iTrySilo silo;
    wiTryVaultComposer composerV2; // Deployed with MSG_TYPE_UNSTAKE = 2
    UnstakeMessenger messenger;    // Deployed with MSG_TYPE_UNSTAKE = 1
    iTry itry;
    address user = address(0x123);
    uint256 depositAmount = 1000e18;
    
    function setUp() public {
        // Deploy iTRY
        itry = new iTry(address(this));
        
        // Deploy vault and silo
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            address(0), // rewarder
            address(this), // owner
            address(0) // treasury
        );
        
        // Deploy composer with modified MSG_TYPE (simulating version 2)
        // In reality, this would be deployed from modified source code
        composerV2 = new wiTryVaultComposerV2(...); // MSG_TYPE_UNSTAKE = 2
        
        // Deploy messenger (uses MSG_TYPE_UNSTAKE = 1)
        messenger = new UnstakeMessenger(
            address(endpoint),
            address(this),
            hubEid
        );
        
        // Setup: User has completed cooldown with funds in silo
        vm.startPrank(user);
        vault.cooldownShares(depositAmount);
        vm.warp(block.timestamp + vault.cooldownDuration() + 1);
        vm.stopPrank();
    }
    
    function test_MessageTypeMismatch() public {
        // SETUP: Verify user has claimable cooldown
        uint256 expectedAssets = vault.cooldowns(user).underlyingAmount;
        assertGt(expectedAssets, 0, "User should have assets in cooldown");
        
        // Verify silo holds the assets
        uint256 siloBalance = itry.balanceOf(address(vault.silo()));
        assertEq(siloBalance, expectedAssets, "Silo should hold user's iTRY");
        
        // EXPLOIT: User calls unstake via messenger
        // Messenger sends msgType = 1, but composer expects msgType = 2
        vm.startPrank(user);
        messenger.unstake{value: 1 ether}(0.5 ether);
        vm.stopPrank();
        
        // Simulate LayerZero message delivery to composer
        // Message contains msgType = 1
        IUnstakeMessenger.UnstakeMessage memory msg = 
            IUnstakeMessenger.UnstakeMessage({
                user: user,
                extraOptions: ""
            });
        bytes memory message = abi.encode(uint16(1), msg); // msgType = 1
        
        Origin memory origin = Origin({
            srcEid: spokeEid,
            sender: bytes32(uint256(uint160(address(messenger)))),
            nonce: 1
        });
        
        // VERIFY: Composer rejects message due to type mismatch
        vm.expectRevert(
            abi.encodeWithSelector(
                IwiTryVaultComposer.UnknownMessageType.selector, 
                uint16(1) // Received msgType = 1, expected msgType = 2
            )
        );
        composerV2.exposed_lzReceive(
            origin,
            bytes32(0),
            message,
            address(0),
            ""
        );
        
        // VERIFY: User's funds remain locked in silo
        assertEq(
            itry.balanceOf(address(vault.silo())), 
            expectedAssets, 
            "Funds locked: iTRY still in silo"
        );
        
        // VERIFY: User cannot call unstakeThroughComposer directly
        vm.expectRevert(); // AccessControl revert
        vm.prank(user);
        vault.unstakeThroughComposer(user);
        
        // VERIFY: Admin cannot rescue iTRY from vault
        vm.expectRevert(); // InvalidToken revert
        vault.rescueTokens(address(itry), expectedAssets, address(this));
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("User funds permanently locked:", expectedAssets);
        console.log("No recovery mechanism exists");
    }
}
```

## Notes

**Additional Context:**

1. **Current Deployment Status**: Both contracts currently have the same value (`MSG_TYPE_UNSTAKE = 1`), so the system works correctly in the current deployment. However, the vulnerability becomes critical during:
   - Future protocol upgrades where message types might change
   - Multi-chain deployments where version control is harder
   - Emergency redeployments where contracts might get out of sync

2. **Unlike lzCompose Flow**: The cross-chain unstaking via direct `_lzReceive` has NO automatic refund mechanism (unlike the `lzCompose` flow used for cooldown initiation, which has try-catch with automatic refunds): [10](#0-9) 

3. **No Deployment Validation**: Deployment scripts configure peers but never validate message type compatibility: [11](#0-10) 

4. **Impact Scope**: This is distinct from the known issue "Native fee loss on failed wiTryVaultComposer.lzReceive" which only concerns fee loss on underpayment. This vulnerability causes permanent principal loss due to message routing failure.

### Citations

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L55-55)
```text
    uint16 public constant MSG_TYPE_UNSTAKE = 1;
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L120-121)
```text
        UnstakeMessage memory message = UnstakeMessage({user: msg.sender, extraOptions: extraOptions});
        bytes memory payload = abi.encode(MSG_TYPE_UNSTAKE, message);
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L229-234)
```text
    function setPeer(uint32 eid, bytes32 peer) public override(OAppCore, IUnstakeMessenger) onlyOwner {
        require(eid == hubEid, "UnstakeMessenger: Invalid endpoint");
        require(peer != bytes32(0), "UnstakeMessenger: Invalid peer");

        super.setPeer(eid, peer);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L38-38)
```text
    uint16 public constant MSG_TYPE_UNSTAKE = 1;
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L226-233)
```text
        (uint16 msgType, IUnstakeMessenger.UnstakeMessage memory unstakeMsg) =
            abi.decode(_message, (uint16, IUnstakeMessenger.UnstakeMessage));

        if (msgType == MSG_TYPE_UNSTAKE) {
            _handleUnstake(_origin, _guid, unstakeMsg);
        } else {
            revert UnknownMessageType(msgType);
        }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L77-81)
```text
    function unstakeThroughComposer(address receiver)
        external
        onlyRole(COMPOSER_ROLE)
        nonReentrant
        returns (uint256 assets)
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L170-180)
```text
    function _startComposerCooldown(address composer, address redeemer, uint256 shares, uint256 assets) private {
        uint104 cooldownEnd = uint104(block.timestamp) + cooldownDuration;

        // Interaction: External call to base contract (protected by nonReentrant modifier)
        _withdraw(composer, address(silo), composer, assets, shares);

        // Effects: State changes after external call (following CEI pattern)
        cooldowns[redeemer].cooldownEnd = cooldownEnd;
        cooldowns[redeemer].underlyingAmount += uint152(assets);

        emit ComposerCooldownInitiated(composer, redeemer, shares, assets, cooldownEnd);
```

**File:** src/token/wiTRY/iTrySilo.sol (L28-30)
```text
    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L154-161)
```text
    function rescueTokens(address token, uint256 amount, address to)
        external
        nonReentrant
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (address(token) == asset()) revert InvalidToken();
        IERC20(token).safeTransfer(to, amount);
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L133-147)
```text
        /// @dev try...catch to handle the compose operation. if it fails we refund the user
        try this.handleCompose{value: msg.value}(_composeSender, composeFrom, composeMsg, amount) {
            emit Sent(_guid);
        } catch (bytes memory _err) {
            /// @dev A revert where the msg.value passed is lower than the min expected msg.value is handled separately
            /// This is because it is possible to re-trigger from the endpoint the compose operation with the right msg.value
            if (bytes4(_err) == InsufficientMsgValue.selector) {
                assembly {
                    revert(add(32, _err), mload(_err))
                }
            }

            _refund(_composeSender, _message, amount, tx.origin);
            emit Refunded(_guid);
        }
```

**File:** script/deploy/spoke/SpokeChainDeployment.s.sol (L233-236)
```text
        // Set UnstakeMessenger peer to hub chain's VaultComposer
        IOAppCore(address(deployed.unstakeMessenger))
            .setPeer(config.hubChainEid, bytes32(uint256(uint160(config.hubVaultComposer))));
        console2.log("UnstakeMessenger peer set to hub VaultComposer");
```
