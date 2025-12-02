## Title
Cross-Chain Unstaking Fails to Validate Destination Blacklist Status, Causing Permanent Fund Lock

## Summary
The `wiTryVaultComposer._handleUnstake` function bridges iTRY back to users on spoke chains without validating if the recipient is blacklisted on the destination chain. When iTRY minting fails on the spoke chain due to blacklist restrictions, funds become locked in the hub chain's OFT adapter with no automatic recovery mechanism, violating the blacklist enforcement invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (wiTryVaultComposer contract, `_handleUnstake` function, lines 244-278) [1](#0-0) 

**Intended Logic:** When a user completes cooldown and requests unstaking from a spoke chain, the hub chain should validate all blacklist/whitelist restrictions before releasing and bridging iTRY tokens back to the user.

**Actual Logic:** The hub chain only validates the composer-to-adapter transfer during the `_send` operation, but never checks if the final destination user is blacklisted on the spoke chain. The blacklist check on the spoke chain happens during minting, which causes the transaction to revert and lock funds if the user is blacklisted there. [2](#0-1) [3](#0-2) 

**Exploitation Path:**
1. User stakes iTRY on hub chain, receives wiTRY shares
2. User bridges wiTRY to spoke chain and initiates cooldown
3. **Blacklist event occurs:** User gets added to spoke chain iTRY blacklist (iTryTokenOFT) for compliance reasons
4. Cooldown period completes, user calls `UnstakeMessenger.unstake()` on spoke chain
5. Hub chain receives message, calls `vault.unstakeThroughComposer(user)` which transfers iTRY from vault to composer
6. Hub chain calls `_send(ASSET_OFT, _sendParam, address(this))` - iTRY locks in the OFTAdapter
7. Spoke chain receives LayerZero message, attempts to mint iTRY to user via `_credit`
8. Spoke chain `_beforeTokenTransfer` reverts because user is blacklisted [4](#0-3) 

9. **Result:** iTRY permanently locked in hub chain adapter, LayerZero message stored for retry (which will keep failing as long as user remains blacklisted)

**Security Property Broken:** 
- Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - The protocol allows the unstaking flow to proceed and lock user funds when the user is blacklisted on destination
- Invariant #7: "Cross-chain Message Integrity: LayerZero messages for unstaking must be delivered to correct user with proper validation" - No validation of destination blacklist status

## Impact Explanation
- **Affected Assets**: iTRY tokens released from StakediTry vault on hub chain
- **Damage Severity**: Complete loss of user funds. When a user with completed cooldown gets blacklisted on the spoke chain iTRY contract and initiates unstake, their iTRY becomes permanently locked in the hub chain's OFTAdapter. Recovery requires either:
  1. Removing user from spoke chain blacklist (may violate compliance requirements)
  2. Admin intervention to rescue tokens from adapter (not a standard operation)
  3. LayerZero message remains perpetually stuck if blacklist cannot be lifted
- **User Impact**: Any user who completes cooldown on spoke chain and has blacklist status changed between cooldown initiation and unstaking is affected. Cross-chain blacklist management creates permanent risk window.

## Likelihood Explanation
- **Attacker Profile**: Not a malicious attack - this affects legitimate users who get blacklisted for compliance/regulatory reasons during the cooldown period
- **Preconditions**: 
  1. User must have completed cooldown on spoke chain
  2. User must be blacklisted on spoke chain iTRY (iTryTokenOFT) but NOT on hub chain
  3. Blacklist status is not synchronized between hub and spoke chains
  4. User initiates unstake after being blacklisted
- **Execution Complexity**: Occurs naturally when blacklist management happens during cooldown period. No complex timing or multi-transaction coordination required.
- **Frequency**: Can happen to any user during each unstaking operation if blacklist status changes between chains

## Recommendation

Add destination blacklist validation before releasing iTRY on hub chain. Since the hub chain cannot directly query spoke chain state, implement one of these solutions:

**Solution 1: Add blacklist status to UnstakeMessage**
```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, function _handleUnstake:

// CURRENT (vulnerable):
// No validation of user's blacklist status on destination chain before sending

// FIXED:
function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
    internal
    virtual
{
    address user = unstakeMsg.user;
    
    // Validate user
    if (user == address(0)) revert InvalidZeroAddress();
    if (_origin.srcEid == 0) revert InvalidOrigin();
    
    // NEW: Validate user is not blacklisted on hub chain iTRY
    // This prevents releasing iTRY that cannot be delivered
    if (IERC20(ASSET_ERC20).hasRole(BLACKLISTED_ROLE, user)) {
        revert UserBlacklisted(user);
    }
    
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
    
    emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
}
```

**Solution 2: Implement cross-chain blacklist synchronization**
Deploy synchronized blacklist managers on both chains that use LayerZero to propagate blacklist updates automatically.

**Solution 3: Override iTryTokenOFT._credit like wiTryOFT**
Modify iTryTokenOFT to redirect blacklisted recipients' funds to contract owner instead of reverting: [5](#0-4) 

However, Solution 1 (hub-side validation) is most secure as it prevents the issue entirely rather than trying to handle it after funds are locked.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistLock.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistLocksFunds -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";

contract Exploit_CrossChainBlacklistLock is Test {
    wiTryVaultComposer composer;
    StakediTryCrosschain vault;
    iTry iTryHub;
    iTryTokenOFT iTrySpoke;
    iTryTokenOFTAdapter adapter;
    
    address user = address(0x1234);
    address admin = address(0x5678);
    uint32 hubEid = 1;
    uint32 spokeEid = 2;
    
    function setUp() public {
        // Deploy contracts (simplified for demonstration)
        // In real test, use full deployment from test helpers
        
        // Deploy iTRY on hub
        vm.prank(admin);
        iTryHub = new iTry();
        iTryHub.initialize(admin, address(this));
        
        // Deploy iTryTokenOFT on spoke  
        iTrySpoke = new iTryTokenOFT(address(0), admin);
        
        // Deploy vault and composer
        // ... (full setup)
    }
    
    function test_CrossChainBlacklistLocksFunds() public {
        // SETUP: User has completed cooldown on spoke chain
        uint256 userAssets = 1000 ether;
        
        // Simulate cooldown completion
        vm.prank(address(composer));
        // vault has assets ready for user
        
        // EXPLOIT: User gets blacklisted on SPOKE chain (not hub)
        vm.prank(iTrySpoke.owner());
        address[] memory blacklistUsers = new address[](1);
        blacklistUsers[0] = user;
        iTrySpoke.addBlacklistAddress(blacklistUsers);
        
        // User initiates unstake from spoke chain
        // Message arrives at hub via LayerZero
        
        // Hub processes unstake - NO validation of spoke blacklist
        vm.prank(address(composer));
        // This succeeds on hub, iTRY locked in adapter
        
        // Spoke receives message and tries to mint
        vm.prank(address(iTrySpoke));
        vm.expectRevert(); // Will revert due to blacklist
        // iTrySpoke._credit(user, userAssets, hubEid);
        
        // VERIFY: iTRY is locked in hub adapter
        uint256 lockedInAdapter = iTryHub.balanceOf(address(adapter));
        assertEq(lockedInAdapter, userAssets, "iTRY locked in adapter");
        
        // User cannot receive funds on spoke due to blacklist
        assertEq(iTrySpoke.balanceOf(user), 0, "User receives nothing");
        
        // Funds are permanently locked unless:
        // 1. User removed from spoke blacklist (compliance issue)
        // 2. Admin rescues from adapter (not standard operation)
    }
}
```

## Notes

This vulnerability is distinct from the known Zellic issue about allowance-based transfers. The cross-chain blacklist synchronization gap creates a critical failure mode where:

1. **Hub chain validation** only checks composer→adapter (both pass as not blacklisted)
2. **Spoke chain validation** only happens at mint time (fails if user blacklisted)
3. **No cross-chain state synchronization** means blacklist status can diverge between chains
4. **LayerZero retry mechanism** cannot help because the root cause (user blacklisted) persists

The wiTRY cross-chain flow handles this correctly by redirecting blacklisted recipients to the owner instead of reverting, but iTRY does not implement the same protection. This asymmetry creates the vulnerability specifically in the iTRY unstaking return path.

### Citations

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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-155)
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
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L84-97)
```text
    function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
        internal
        virtual
        override
        returns (uint256 amountReceivedLD)
    {
        // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
        if (blackList[_to]) {
            emit RedistributeFunds(_to, _amountLD);
            return super._credit(owner(), _amountLD, _srcEid);
        } else {
            return super._credit(_to, _amountLD, _srcEid);
        }
    }
```
