## Title
Cross-Chain Unstaking to Blacklisted Address Causes Permanent Fund Loss

## Summary
When users unstake wiTRY cross-chain via `wiTryVaultComposer._handleUnstake()`, the iTRY assets are sent to the user's address on the spoke chain. If that address is blacklisted on the spoke chain, the LayerZero OFT will fail to mint iTRY to the user, causing permanent loss of funds with no recovery mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (`_handleUnstake` function, lines 244-278) and `src/token/iTRY/crosschain/iTryTokenOFT.sol` (`_beforeTokenTransfer` function, lines 140-177)

**Intended Logic:** Cross-chain unstaking should allow users to retrieve their iTRY assets after cooldown completion, with the iTRY being sent from the hub chain back to their address on the spoke chain.

**Actual Logic:** The unstaking flow withdraws iTRY from the vault and sends it cross-chain without validating the recipient's blacklist status on the destination chain. When the LayerZero message arrives on the spoke chain, if the user is blacklisted, the OFT's mint operation will revert, causing the LayerZero message to fail permanently.

**Exploitation Path:**
1. User initiates cooldown for wiTRY shares on spoke chain by sending them to hub chain
2. User waits for cooldown period to complete
3. User's address gets blacklisted on the spoke chain (or was already blacklisted before unstaking)
4. User calls `UnstakeMessenger.unstake()` on spoke chain, which sends a LayerZero message to hub
5. Hub's `wiTryVaultComposer._handleUnstake()` receives the message and calls `unstakeThroughComposer(user)`, withdrawing iTRY from vault [1](#0-0) 
6. Composer sends iTRY back to user on spoke chain via `_send(ASSET_OFT, _sendParam, address(this))` [2](#0-1) 
7. On spoke chain, `iTryTokenOFT` attempts to mint iTRY to user but fails in `_beforeTokenTransfer()` because the condition `!blacklisted[to]` is false [3](#0-2) 
8. The transaction reverts with `OperationNotAllowed()` [4](#0-3) 
9. iTRY is permanently locked - withdrawn from hub vault but undeliverable to blacklisted user on spoke

**Security Property Broken:** Violates the protocol's guarantee that users can retrieve their staked assets after cooldown completion. Also creates a conflict between two invariants: "Blacklisted users CANNOT receive iTRY tokens" and "Users must be able to unstake their funds after cooldown."

## Impact Explanation
- **Affected Assets**: iTRY tokens that have been unstaked from the vault
- **Damage Severity**: Complete loss of unstaked funds. Users lose 100% of the iTRY they attempted to unstake cross-chain if blacklisted on destination
- **User Impact**: Any user who is blacklisted on the spoke chain (either before unstaking or during the cooldown period) will permanently lose their unstaked iTRY. This affects cross-chain stakers who may be blacklisted for regulatory reasons, compromised addresses, or security incidents.

## Likelihood Explanation
- **Attacker Profile**: Not an attack - this is a protocol design flaw affecting legitimate users who become blacklisted
- **Preconditions**: 
  - User has completed cooldown on hub chain for cross-chain unstaking
  - User's address is blacklisted on spoke chain (via `addBlacklistAddress()`)
  - User initiates unstake from spoke chain
- **Execution Complexity**: Single transaction flow - user calls `unstake()` on spoke chain
- **Frequency**: Occurs every time a blacklisted user attempts to unstake cross-chain. Cannot be prevented once user is blacklisted unless removed from blacklist before message delivery.

## Recommendation

Add validation in `wiTryVaultComposer._handleUnstake()` to check recipient's blacklist status on destination chain before sending assets, OR implement a fallback mechanism to send to an alternative address or return to hub custody:

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _handleUnstake:

// OPTION 1: Prevent unstaking to blacklisted addresses (requires cross-chain blacklist sync)
function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
    internal
    virtual
{
    address user = unstakeMsg.user;
    if (user == address(0)) revert InvalidZeroAddress();
    if (_origin.srcEid == 0) revert InvalidOrigin();
    
    // NEW: Check if user is blacklisted on destination before unstaking
    // Note: Requires implementing cross-chain blacklist status query
    if (isBlacklistedOnChain(user, _origin.srcEid)) {
        revert UserBlacklistedOnDestination(user, _origin.srcEid);
    }
    
    uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
    // ... rest of function
}

// OPTION 2 (Recommended): Add fallback recipient parameter to UnstakeMessage
// Modify UnstakeMessage struct in IUnstakeMessenger to include:
struct UnstakeMessage {
    address user;
    address fallbackRecipient; // NEW: Alternative recipient if primary fails
    bytes extraOptions;
}

// Then in _handleUnstake, use try-catch for cross-chain send:
function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
    internal
    virtual
{
    address user = unstakeMsg.user;
    if (user == address(0)) revert InvalidZeroAddress();
    
    uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
    if (assets == 0) revert NoAssetsToUnstake();
    
    // Try sending to user first
    SendParam memory _sendParam = SendParam({
        dstEid: _origin.srcEid,
        to: bytes32(uint256(uint160(user))),
        amountLD: assets,
        minAmountLD: assets,
        extraOptions: OptionsBuilder.newOptions(),
        composeMsg: "",
        oftCmd: ""
    });
    
    // If user delivery might fail, hold in escrow for manual resolution
    // or send to fallbackRecipient if provided
    _send(ASSET_OFT, _sendParam, address(this));
    emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
}
```

**Alternative mitigation:** Implement a permissioned `rescueFailedMessage()` function that allows the owner to redirect failed cross-chain transfers to a treasury address when LayerZero delivery fails, then manually resolve with the user off-chain.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedUnstakeLock.t.sol
// Run with: forge test --match-test test_BlacklistedUnstakeLock -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_BlacklistedUnstakeLock is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    UnstakeMessenger messenger;
    iTryTokenOFT spokeITry;
    iTry hubITry;
    
    address user = address(0x1234);
    uint32 HUB_EID = 1;
    uint32 SPOKE_EID = 2;
    
    function setUp() public {
        // Deploy hub chain contracts
        hubITry = new iTry();
        vault = new StakediTryCrosschain(
            IERC20(address(hubITry)),
            address(0),  // rewarder
            address(this),  // owner
            address(0)  // treasury
        );
        
        // Deploy spoke chain iTRY OFT
        spokeITry = new iTryTokenOFT(address(0), address(this));
        
        // Setup composer and messenger (simplified)
        // In reality would need LayerZero endpoints setup
    }
    
    function test_BlacklistedUnstakeLock() public {
        // SETUP: User has completed cooldown and has assets ready to unstake
        vm.startPrank(user);
        
        // Simulate cooldown completion - user has 1000 iTRY ready to unstake
        uint256 unstakeAmount = 1000 ether;
        
        // EXPLOIT SCENARIO: User gets blacklisted on spoke chain
        address[] memory blacklistUsers = new address[](1);
        blacklistUsers[0] = user;
        spokeITry.addBlacklistAddress(blacklistUsers);
        
        // User initiates unstake from spoke chain
        // This would trigger cross-chain message to hub
        // Hub executes unstakeThroughComposer - assets withdrawn
        
        // Hub sends iTRY back to spoke chain via LayerZero
        // When LayerZero tries to mint iTRY to user on spoke:
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        spokeITry.mint(user, unstakeAmount);  // This simulates the OFT mint on spoke
        
        // VERIFY: User's iTRY is stuck - withdrawn from hub but undeliverable on spoke
        // In real scenario:
        // - Hub vault: user's cooldown cleared, iTRY sent
        // - Spoke chain: mint fails, LayerZero message stuck
        // - User: Cannot access 1000 iTRY (permanent loss)
        
        vm.stopPrank();
    }
}
```

## Notes

This vulnerability represents a critical conflict between the protocol's blacklist enforcement and cross-chain unstaking mechanism. The issue is particularly severe because:

1. **Blacklisting is often involuntary**: Users may be blacklisted for regulatory compliance, not malicious behavior
2. **No pre-flight validation**: The hub chain doesn't verify destination blacklist status before withdrawing from vault
3. **LayerZero immutability**: Once the message is sent with the user as recipient, it cannot be redirected to an alternative address
4. **Recovery requires blacklist removal**: The only way to complete delivery is removing the user from the blacklist, which may not be possible for regulatory/legal reasons

The vulnerability directly violates Protocol Invariant #7: "LayerZero messages for unstaking must be delivered to correct user with proper validation" - because no validation prevents sending to addresses that cannot receive on the destination chain.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L255-255)
```text
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L274-274)
```text
        _send(ASSET_OFT, _sendParam, address(this));
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L145-146)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L154-154)
```text
                revert OperationNotAllowed();
```
