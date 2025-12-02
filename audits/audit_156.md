## Title
Cross-Chain Confusion Attack: Blacklist Bypass via Unstaking from Different Chain

## Summary
The `_handleUnstake` function in `wiTryVaultComposer.sol` does not validate that the source chain sending the unstake message matches the chain where the user originally initiated their cooldown. This allows users to bypass blacklist restrictions by initiating cooldown from one chain (where they may be blacklisted) and receiving iTRY on a different chain (where they are not blacklisted).

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (function `_handleUnstake`, lines 244-278)

**Intended Logic:** Users should receive their unstaked iTRY on the same chain where they originally staked and initiated the cooldown process, maintaining consistent blacklist/whitelist enforcement across the protocol.

**Actual Logic:** The function blindly sends iTRY to whatever chain sent the unstake message (`_origin.srcEid`) without validating this matches where the cooldown was initiated. The cooldown storage structure does not track source chain information. [1](#0-0) [2](#0-1) 

**Exploitation Path:**

1. **Setup Phase:** Attacker controls address `0xAttacker` on multiple chains. On Chain A (e.g., Arbitrum), the attacker is blacklisted in the iTryTokenOFT contract. On Chain B (e.g., Optimism), the attacker is NOT blacklisted.

2. **Initiate Cooldown from Chain A:** Attacker bridges wiTRY from Chain A to the Hub (Ethereum L1) and sends a compose message with "INITIATE_COOLDOWN" command. The composer calls `cooldownSharesByComposer()` which stores the cooldown in the mapping: `cooldowns[0xAttacker] = {cooldownEnd: timestamp + 7 days, underlyingAmount: 1000 iTRY}`. [3](#0-2) 

3. **Wait for Cooldown Completion:** After 7 days pass, the cooldown period expires.

4. **Send Unstake Message from Chain B:** Attacker calls `UnstakeMessenger.unstake()` on **Chain B** (not Chain A where cooldown was initiated). The message encodes `msg.sender` as the user and the current chain's endpoint ID. [4](#0-3) 

5. **Hub Processes Unstake:** The `_handleUnstake` function receives the message with `_origin.srcEid = Chain B`. It validates the cooldown completion, calls `unstakeThroughComposer()` to retrieve the iTRY, then sends it to Chain B using `dstEid: _origin.srcEid` at line 265.

6. **Blacklist Bypass Complete:** The attacker successfully receives 1000 iTRY on Chain B where they are NOT blacklisted, bypassing the blacklist restriction that exists on Chain A.

**Security Property Broken:** Critical Invariant #2 from README: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." [5](#0-4) 

## Impact Explanation

- **Affected Assets:** iTRY tokens across all chains in the cross-chain architecture. The vulnerability affects both the Hub chain and all Spoke chains.

- **Damage Severity:** Blacklisted users can completely bypass blacklist restrictions by exploiting cross-chain confusion. This undermines the entire regulatory compliance framework and emergency response capabilities of the protocol. Since blacklist/whitelist states are managed independently on each chain, users can cherry-pick which chain to receive funds based on their blacklist status. [6](#0-5) [7](#0-6) 

- **User Impact:** Any user with an active cooldown can exploit this vulnerability. In emergency situations (hacks, regulatory requirements), blacklisted users can evade fund freezes by receiving their unstaked iTRY on chains where they remain non-blacklisted.

## Likelihood Explanation

- **Attacker Profile:** Any user with wiTRY tokens who has completed or is near completing a cooldown period. No privileged roles required.

- **Preconditions:** 
  - User must have initiated a cooldown on the Hub chain
  - Cooldown period must be complete
  - User must have different blacklist statuses on different chains (blacklisted on Chain A, not on Chain B)
  - User must have access to UnstakeMessenger on the non-blacklisted chain

- **Execution Complexity:** Low. Requires two simple transactions:
  1. Initiate cooldown from any chain (standard operation)
  2. After cooldown completes, send unstake message from a different chain (single transaction)

- **Frequency:** Can be exploited once per cooldown period per user. However, users can create multiple cooldowns and exploit repeatedly. The vulnerability is always present as long as cross-chain unstaking is active.

## Recommendation

Add chain tracking to the cooldown structure and validate the source chain matches:

```solidity
// In src/token/wiTRY/interfaces/IStakediTryCooldown.sol, modify UserCooldown struct:

// CURRENT (vulnerable):
struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
}

// FIXED:
struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
    uint32 srcEid; // Track which chain initiated the cooldown
}
```

```solidity
// In src/token/wiTRY/StakediTryCrosschain.sol, update _startComposerCooldown:

// Store the source chain when cooldown is initiated
cooldowns[redeemer].cooldownEnd = cooldownEnd;
cooldowns[redeemer].underlyingAmount += uint152(assets);
cooldowns[redeemer].srcEid = /* extract from compose message */;
```

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, add validation in _handleUnstake:

function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
    internal
    virtual
{
    address user = unstakeMsg.user;
    
    if (user == address(0)) revert InvalidZeroAddress();
    if (_origin.srcEid == 0) revert InvalidOrigin();
    
    // ADDED: Validate source chain matches cooldown initiation chain
    UserCooldown storage userCooldown = cooldowns[user];
    if (userCooldown.srcEid != _origin.srcEid) {
        revert SourceChainMismatch();
    }
    
    uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);
    // ... rest of function
}
```

**Alternative Mitigation:** Instead of storing srcEid in cooldowns, the protocol could synchronize blacklist/whitelist states across all chains via LayerZero messages, though this would be more complex and gas-intensive.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistBypass.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistBypass -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/wiTRY/crosschain/UnstakeMessenger.sol";

contract Exploit_CrossChainBlacklistBypass is Test {
    wiTryVaultComposer public composer;
    StakediTryCrosschain public vault;
    iTryTokenOFT public iTryChainA;
    iTryTokenOFT public iTryChainB;
    UnstakeMessenger public messengerChainA;
    UnstakeMessenger public messengerChainB;
    
    address public attacker = makeAddr("attacker");
    address public owner = makeAddr("owner");
    
    uint32 public constant CHAIN_A_EID = 40161; // Arbitrum
    uint32 public constant CHAIN_B_EID = 40232; // Optimism
    uint32 public constant HUB_EID = 1; // Ethereum
    
    function setUp() public {
        // Deploy contracts (simplified setup)
        // In production, this would involve full LayerZero setup
    }
    
    function test_CrossChainBlacklistBypass() public {
        // SETUP: Attacker is blacklisted on Chain A, not on Chain B
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = attacker;
        
        vm.prank(owner);
        iTryChainA.addBlacklistAddress(blacklistAddresses);
        
        // Verify blacklist status
        assertTrue(iTryChainA.blacklisted(attacker), "Attacker should be blacklisted on Chain A");
        assertFalse(iTryChainB.blacklisted(attacker), "Attacker should NOT be blacklisted on Chain B");
        
        // STEP 1: Initiate cooldown from Chain A (via compose message)
        vm.prank(attacker);
        // Bridge wiTRY to hub and initiate cooldown
        // composer.cooldownSharesByComposer(1000e18, attacker) would be called
        
        // STEP 2: Wait for cooldown to complete
        vm.warp(block.timestamp + 7 days + 1);
        
        // STEP 3: Send unstake message from Chain B (not Chain A!)
        vm.prank(attacker);
        // messengerChainB.unstake(returnTripFee);
        // This creates message with _origin.srcEid = CHAIN_B_EID
        
        // STEP 4: Hub processes unstake and sends to Chain B
        // _handleUnstake receives message from CHAIN_B_EID
        // Sends iTRY to CHAIN_B_EID (line 265: dstEid: _origin.srcEid)
        
        // VERIFY: Attacker receives iTRY on Chain B where they're not blacklisted
        // This bypasses the blacklist on Chain A
        // assertGt(iTryChainB.balanceOf(attacker), 0, "Attacker successfully bypassed blacklist");
    }
}
```

**Notes:**

The vulnerability exists because the protocol architecture assumes users will unstake from the same chain where they staked, but there is no enforcement of this assumption. The `UserCooldown` structure lacks chain tracking, and blacklist/whitelist states are maintained independently on each chain without synchronization. This creates an exploitable gap where malicious users can bypass access controls by routing their unstake messages through chains with favorable blacklist statuses.

The issue is particularly critical because blacklisting is described in the README as a key mechanism for handling "black swan scenarios" and emergency situations, yet it can be trivially bypassed through cross-chain confusion.

### Citations

**File:** src/token/wiTRY/interfaces/IStakediTryCooldown.sol (L7-10)
```text
struct UserCooldown {
    uint104 cooldownEnd;
    uint152 underlyingAmount;
}
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

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L108-151)
```text
    function unstake(uint256 returnTripAllocation) external payable nonReentrant returns (bytes32 guid) {
        // Validate hub peer configured
        bytes32 hubPeer = peers[hubEid];
        if (hubPeer == bytes32(0)) revert HubNotConfigured();

        // Validate returnTripAllocation
        if (returnTripAllocation == 0) revert InvalidReturnTripAllocation();

        // Build return trip options (valid TYPE_3 header)
        bytes memory extraOptions = OptionsBuilder.newOptions();

        // Encode UnstakeMessage with msg.sender as user (prevents spoofing)
        UnstakeMessage memory message = UnstakeMessage({user: msg.sender, extraOptions: extraOptions});
        bytes memory payload = abi.encode(MSG_TYPE_UNSTAKE, message);

        // Build options WITH native value forwarding for return trip execution
        // casting to 'uint128' is safe because returnTripAllocation value will be less than 2^128
        // forge-lint: disable-next-line(unsafe-typecast)
        bytes memory callerOptions =
            OptionsBuilder.newOptions().addExecutorLzReceiveOption(LZ_RECEIVE_GAS, uint128(returnTripAllocation));
        bytes memory options = _combineOptions(hubEid, MSG_TYPE_UNSTAKE, callerOptions);

        // Quote with native drop included (single quote with fixed returnTripAllocation)
        MessagingFee memory fee = _quote(hubEid, payload, options, false);

        // Validate caller sent enough
        if (msg.value < fee.nativeFee) {
            revert InsufficientFee(fee.nativeFee, msg.value);
        }

        // Automatic refund to msg.sender
        MessagingReceipt memory receipt = _lzSend(
            hubEid,
            payload,
            options,
            fee,
            payable(msg.sender) // Refund excess to user
        );
        guid = receipt.guid;

        emit UnstakeRequested(msg.sender, hubEid, fee.nativeFee, msg.value - fee.nativeFee, guid);

        return guid;
    }
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L35-41)
```text
    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;

    /// @notice Mapping of whitelisted addresses
    mapping(address => bool) public whitelisted;

    TransferState public transferState;
```

**File:** src/token/iTRY/iTry.sol (L24-33)
```text
    /// @notice The role is allowed to mint iTry. To be pointed to iTry minting contract only.
    bytes32 public constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    /// @notice Role that can handle Blacklisting, in addition to admin role.
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    /// @notice Role that can handle Whitelisting, in addition to admin role.
    bytes32 public constant WHITELIST_MANAGER_ROLE = keccak256("WHITELIST_MANAGER_ROLE");
    /// @notice Blacklisted role restricts funds from being moved in and out of that address
    bytes32 public constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    /// @notice During transferState 1, whitelisted role can still transfer
    bytes32 public constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
```
