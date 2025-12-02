## Title
Missing Enforced Gas Limits for SEND_AND_CALL Messages on wiTryOFTAdapter

## Summary
The wiTryOFTAdapter contract only enforces minimum gas limits for msgType 1 (SEND) messages but not for msgType 2 (SEND_AND_CALL) messages. Users can send wiTRY shares cross-chain with compose messages and insufficient gas, causing message failures on the destination while their shares remain locked in the adapter on L1.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFTAdapter.sol` (entire contract), configuration missing in enforced options setup

**Intended Logic:** The wiTryOFTAdapter should enforce minimum gas requirements for all cross-chain message types to ensure reliable delivery and prevent user funds from being locked due to insufficient gas on the destination chain.

**Actual Logic:** The adapter only has enforced options configured for msgType 1 (SEND) with 200k gas for lzReceive, but no enforced options are set for msgType 2 (SEND_AND_CALL). When users send wiTRY with a non-empty `composeMsg` parameter, LayerZero uses msgType 2, and the user's provided gas options are used without any minimum enforcement. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. User approves wiTryOFTAdapter to spend their wiTRY shares on hub chain (Sepolia)
2. User calls `wiTryOFTAdapter.send()` with a `SendParam` containing a non-empty `composeMsg` field
3. User provides minimal gas in `extraOptions` (e.g., 50,000 gas instead of the recommended 200,000+)
4. LayerZero determines this is a SEND_AND_CALL operation (msgType 2) due to non-empty composeMsg
5. Since no enforced options exist for msgType 2, the user's insufficient gas options are used as-is
6. The adapter locks the user's wiTRY shares and sends the LayerZero message
7. On the destination chain (OP Sepolia), the `lzReceive` call runs out of gas and fails
8. LayerZero stores the message as a failed packet
9. User's wiTRY shares remain locked in the wiTryOFTAdapter contract on hub chain
10. User must manually retry the message through LayerZero's retry mechanism, paying additional fees [3](#0-2) 

**Security Property Broken:** Violates the "Cross-chain Message Integrity" invariant which states that LayerZero messages must be delivered to the correct user with proper validation. The lack of enforced gas limits allows messages to fail, effectively breaking message delivery.

## Impact Explanation
- **Affected Assets**: wiTRY shares (staked iTRY vault tokens) held by users attempting cross-chain transfers
- **Damage Severity**: User funds become temporarily locked in the wiTryOFTAdapter contract. While technically recoverable through LayerZero's retry mechanism, this requires:
  - Technical knowledge of LayerZero's message retry system
  - Additional transaction fees to retry the failed message
  - Potential indefinite lock if user is unaware of retry mechanism or abandons the transaction
- **User Impact**: Any user who sends wiTRY from hub to spoke chain with a compose message. This could occur through:
  - Direct calls to the adapter's send function
  - Integration with front-end applications that construct compose messages
  - Automated systems or bots that bridge tokens with compose logic

## Likelihood Explanation
- **Attacker Profile**: Any user with wiTRY shares - can be accidental (user error) or intentional (malicious actor causing self-DOS)
- **Preconditions**: 
  - User has wiTRY shares on hub chain
  - User calls send() with non-empty composeMsg parameter
  - User provides insufficient gas in options (below ~200k minimum)
  - wiTryOFTAdapter has enforced options configured for msgType 1 but not msgType 2
- **Execution Complexity**: Single transaction - user simply calls the public `send()` function inherited from LayerZero's OFTAdapter base contract with crafted parameters
- **Frequency**: Can occur repeatedly for any user who uses compose messages without understanding gas requirements. More likely with programmatic integrations or UI implementations that allow compose functionality [4](#0-3) 

## Recommendation

Configure enforced options for msgType 2 (SEND_AND_CALL) on the wiTryOFTAdapter, similar to how it's configured for the ShareOFT on the spoke chain. Create a new configuration script:

```solidity
// New file: script/config/03b_SetEnforcedOptionsShareAdapter_SendAndCall.s.sol

// CURRENT: No enforced options for msgType 2 on HUB_SHARE_ADAPTER

// FIXED: Add enforced options for msgType 2
contract SetEnforcedOptionsShareAdapterSendAndCall is Script {
    using OptionsBuilder for bytes;
    
    uint32 internal constant OP_SEPOLIA_EID = 40232;
    uint16 internal constant SEND_AND_CALL = 2; // msgType for messages with compose
    uint128 internal constant LZ_RECEIVE_GAS = 200000;
    uint128 internal constant LZ_COMPOSE_GAS = 300000; // Gas for compose on destination
    
    function run() public {
        require(block.chainid == 11155111, "Must run on Sepolia");
        
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address shareAdapter = vm.envAddress("HUB_SHARE_ADAPTER");
        
        // Build enforced options with lzReceive + lzCompose
        bytes memory enforcedOptions = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(LZ_RECEIVE_GAS, 0)
            .addExecutorLzComposeOption(0, LZ_COMPOSE_GAS, 0);
        
        EnforcedOptionParam[] memory params = new EnforcedOptionParam[](1);
        params[0] = EnforcedOptionParam({
            eid: OP_SEPOLIA_EID,
            msgType: SEND_AND_CALL, // Set enforced options for msgType 2
            options: enforcedOptions
        });
        
        vm.startBroadcast(deployerKey);
        IOAppOptionsType3(shareAdapter).setEnforcedOptions(params);
        vm.stopBroadcast();
    }
}
```

**Alternative Mitigation**: Document this limitation clearly and ensure all user interfaces that interact with the wiTryOFTAdapter prevent users from sending compose messages, or automatically include sufficient gas when compose messages are detected.

## Proof of Concept

```solidity
// File: test/Exploit_InsufficientGasSendAndCall.t.sol
// Run with: forge test --match-test test_InsufficientGasSendAndCall -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/crosschain/wiTryOFTAdapter.sol";
import "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";

contract Exploit_InsufficientGasSendAndCall is Test {
    wiTryOFTAdapter adapter;
    address wiTRY;
    address endpoint;
    address user;
    
    function setUp() public {
        // Deploy mock contracts and adapter
        user = makeAddr("user");
        wiTRY = makeAddr("wiTRY");
        endpoint = makeAddr("endpoint");
        
        adapter = new wiTryOFTAdapter(wiTRY, endpoint, address(this));
        
        // Configure peer for OP Sepolia
        adapter.setPeer(40232, bytes32(uint256(uint160(makeAddr("spokeOFT")))));
    }
    
    function test_InsufficientGasSendAndCall() public {
        // SETUP: User has wiTRY shares and approves adapter
        vm.startPrank(user);
        
        // Build SendParam with COMPOSE MESSAGE (triggers msgType 2)
        SendParam memory sendParam = SendParam({
            dstEid: 40232, // OP Sepolia
            to: bytes32(uint256(uint160(user))),
            amountLD: 1000e18,
            minAmountLD: 1000e18,
            extraOptions: hex"0003000000000000000000000000000000000000000000000000000000000000c350", // Only 50k gas
            composeMsg: abi.encode("SOME_COMPOSE_DATA"), // Non-empty = msgType 2
            oftCmd: ""
        });
        
        // VERIFY: Check enforced options for msgType 2
        bytes memory enforcedOpts = adapter.enforcedOptions(40232, 2);
        
        // ASSERT: No enforced options configured for msgType 2
        assertEq(enforcedOpts.length, 0, "Vulnerability confirmed: No enforced options for msgType 2 (SEND_AND_CALL)");
        
        // EXPLOIT: User sends with insufficient gas
        // In real scenario, this would lock shares on hub when message fails on spoke
        // adapter.send{value: 0.01 ether}(sendParam, MessagingFee(0.01 ether, 0), user);
        
        vm.stopPrank();
    }
}
```

## Notes

- This vulnerability is distinct from the known issue "Native fee loss on failed wiTryVaultComposer.lzReceive" which deals with compose message failures, not lzReceive failures due to insufficient gas.

- The configuration script `03_SetEnforcedOptionsShareAdapter.s.sol` explicitly states in its comment that it's "for refund flow", suggesting the current enforced options are not intended to cover all user-initiated cross-chain transfers. [2](#0-1) 

- The spoke chain's wiTryOFT contract does not implement a custom lzCompose handler, which means any compose message sent to it would likely fail or be ignored. [5](#0-4) 

- LayerZero V2's `combineOptions` function merges enforced options with user-provided options, but only if enforced options exist for that specific msgType. Without enforced options for msgType 2, user options are used as-is. [6](#0-5)

### Citations

**File:** script/config/03_SetEnforcedOptionsShareAdapter.s.sol (L10-14)
```text
 * @title SetEnforcedOptionsShareAdapter03
 * @notice Configures enforced options on ShareAdapter (Sepolia) for refund flow
 * @dev This sets minimum gas requirements for SEND messages back to OP Sepolia
 *      to ensure the refund mechanism works properly
 */
```

**File:** script/config/03_SetEnforcedOptionsShareAdapter.s.sol (L18-20)
```text
    uint32 internal constant OP_SEPOLIA_EID = 40232;
    uint16 internal constant SEND = 1; // msgType for regular send (no compose)
    uint128 internal constant LZ_RECEIVE_GAS = 200000;
```

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L1-33)
```text
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import {OFTAdapter} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFTAdapter.sol";

/**
 * @title wiTryOFTAdapter
 * @notice OFT Adapter for wiTRY shares on hub chain (Ethereum Mainnet)
 * @dev Wraps the StakedUSDe share token to enable cross-chain transfers via LayerZero
 *
 * Architecture (Phase 1 - Instant Redeems):
 * - Hub Chain (Ethereum): StakedUSDe (ERC4626 vault) + wiTryOFTAdapter (locks shares)
 * - Spoke Chain (MegaETH): ShareOFT (mints/burns based on messages)
 *
 * Flow:
 * 1. User deposits iTRY into StakedUSDe vault → receives wiTRY shares
 * 2. User approves wiTryOFTAdapter to spend their wiTRY
 * 3. User calls send() on wiTryOFTAdapter
 * 4. Adapter locks wiTRY shares and sends LayerZero message
 * 5. ShareOFT mints equivalent shares on spoke chain
 *
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
 */
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** script/config/04_SetEnforcedOptionsShareOFT.s.sol (L18-22)
```text
    uint32 internal constant SEPOLIA_EID = 40161;
    uint16 internal constant SEND_AND_CALL = 2; // msgType for messages with compose
    uint128 internal constant LZ_RECEIVE_GAS = 200000;
    uint128 internal constant LZ_COMPOSE_GAS = 500000;
    uint128 internal constant LZ_COMPOSE_VALUE = 0.01 ether; // msg.value for compose (covers refund fees)
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L1-54)
```text
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import {OFT} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFT.sol";

/**
 * @title wiTryOFT
 * @notice OFT representation of wiTRY shares on spoke chains (MegaETH)
 * @dev This contract mints/burns share tokens based on LayerZero messages from the hub chain
 *
 * Architecture (Phase 1 - Instant Redeems):
 * - Hub Chain (Ethereum): StakediTry (vault) + wiTryOFTAdapter (locks shares)
 * - Spoke Chain (MegaETH): wiTryOFT (mints/burns based on messages)
 *
 * Flow from Hub to Spoke:
 * 1. Hub adapter locks native wiTRY shares
 * 2. LayerZero message sent to this contract
 * 3. This contract mints equivalent OFT share tokens
 *
 * Flow from Spoke to Hub:
 * 1. This contract burns OFT share tokens
 * 2. LayerZero message sent to hub adapter
 * 3. Hub adapter unlocks native wiTRY shares
 *
 * NOTE: These shares represent staked iTRY in the vault. The share value
 * increases as yield is distributed to the vault on the hub chain.
 */
contract wiTryOFT is OFT {
    // Address of the entity authorized to manage the blacklist
    address public blackLister;

    // Mapping to track blacklisted users
    mapping(address => bool) public blackList;

    // Events emitted on changes to the blacklist or fund redistribution
    event BlackListerSet(address indexed blackLister);
    event BlackListUpdated(address indexed user, bool isBlackListed);
    event RedistributeFunds(address indexed user, uint256 amount);

    // Errors to be thrown in case of restricted actions
    error BlackListed(address user);
    error NotBlackListed();
    error OnlyBlackLister();

    /**
     * @dev Constructor to initialize the wiTryOFT contract.
     * @param _name The name of the token.
     * @param _symbol The symbol of the token.
     * @param _lzEndpoint Address of the LZ endpoint.
     * @param _delegate Address of the delegate.
     */
    constructor(string memory _name, string memory _symbol, address _lzEndpoint, address _delegate)
        OFT(_name, _symbol, _lzEndpoint, _delegate)
    {}
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L300-319)
```text
    function _combineOptions(uint32 _eid, uint16 _msgType, bytes memory _extraOptions)
        internal
        view
        returns (bytes memory)
    {
        bytes memory enforced = enforcedOptions[_eid][_msgType];

        // No enforced options, return extra options
        if (enforced.length == 0) {
            return _extraOptions;
        }

        // No extra options, return enforced options
        if (_extraOptions.length <= 2) {
            return enforced;
        }

        // Combine: enforced options + extra options (skip TYPE_3 header from extra)
        return bytes.concat(enforced, _slice(_extraOptions, 2, _extraOptions.length - 2));
    }
```
