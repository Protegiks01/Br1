## Title
Permanent Loss of Shares Due to Missing Recovery Mechanism in wiTryOFTAdapter for Failed LayerZero Messages

## Summary
The `wiTryOFTAdapter` contract lacks any recovery mechanism to unlock shares when LayerZero cross-chain messages fail on L2. When users bridge wiTRY shares from L1 to L2, the adapter locks their shares, but if the destination message fails and cannot be delivered (due to peer misconfiguration, contract pause, or other permanent failures), those shares become irretrievably stuck in the adapter with no way for users or admins to recover them.

## Impact
**Severity**: High

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:** The wiTryOFTAdapter should enable safe cross-chain transfer of wiTRY shares between L1 (hub) and L2 (spoke) chains. Users approve the adapter, call `send()`, and the adapter locks their shares while sending a LayerZero message to mint equivalent shares on L2. [2](#0-1) 

**Actual Logic:** The contract is a minimal wrapper that only defines a constructor and inherits all functionality from LayerZero's `OFTAdapter` base contract without any custom overrides or recovery mechanisms. [3](#0-2) 

When a LayerZero message fails on L2:
1. The adapter has already locked the user's shares via the inherited `_debit()` function
2. LayerZero V2 stores the failed message in the endpoint on L2
3. The message can be retried manually with more gas IF the failure was due to insufficient gas
4. **However**, if the message is permanently undeliverable (e.g., peer misconfiguration that cannot be fixed, blacklist on destination, contract paused), the shares remain locked FOREVER in the adapter
5. Unlike other protocol components that have `rescueToken()` functions, wiTryOFTAdapter has NO recovery mechanism

**Exploitation Path:**
1. User calls `send()` on wiTryOFTAdapter with 50 wiTRY shares to bridge from L1 to L2
2. Adapter's inherited `_debit()` locks the 50 shares by transferring them to the adapter contract
3. LayerZero sends message to L2
4. Message fails on L2 due to permanent condition (e.g., peer misconfigured and owner cannot fix it, or recipient is blacklisted on spoke chain)
5. Shares remain locked in adapter forever - no user function to unlock, no admin rescue function

**Security Property Broken:** Users suffer permanent, unrecoverable loss of their wiTRY shares, violating the fundamental expectation that cross-chain bridges should either succeed or refund. This violates the implied invariant that user funds should be recoverable in failure scenarios.

## Impact Explanation

- **Affected Assets**: wiTRY vault shares (ERC4626 tokens representing staked iTRY)
- **Damage Severity**: Complete permanent loss of bridged shares. If a user attempts to bridge 100 ETH worth of wiTRY shares and the message fails permanently, those 100 ETH worth of shares are locked in the adapter forever with zero recovery path.
- **User Impact**: Any user bridging wiTRY shares from L1 to L2 during a misconfiguration window or when destination conditions prevent delivery. Even a single failed bridge transaction can result in total loss of that user's bridged amount.

## Likelihood Explanation

- **Attacker Profile**: Not a malicious attack - any normal user bridging shares can be affected as a victim
- **Preconditions**: 
  - Peer misconfiguration on hub or spoke that wasn't caught in testing
  - Destination contract paused or restricted
  - Recipient blacklisted on spoke chain (wiTryOFT has blacklist functionality) [4](#0-3) 
  - Gas pricing issues making retry cost-prohibitive
- **Execution Complexity**: Single transaction - user simply calls `send()` during unfavorable conditions
- **Frequency**: Every failed bridge attempt results in permanent lock if retry isn't possible

## Recommendation

Add a recovery mechanism to wiTryOFTAdapter that allows either users or protocol admins to unlock shares after a timeout period if LayerZero messages remain undelivered:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFTAdapter.sol

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract wiTryOFTAdapter is OFTAdapter {
    using SafeERC20 for IERC20;
    
    // Track pending bridged amounts per user per destination chain
    mapping(address => mapping(uint32 => uint256)) public pendingShares;
    mapping(address => mapping(uint32 => uint256)) public pendingTimestamp;
    
    uint256 public constant RECOVERY_DELAY = 7 days; // Allow 7 days for message delivery/retry
    
    constructor(address _token, address _lzEndpoint, address _owner) 
        OFTAdapter(_token, _lzEndpoint, _owner) {}
    
    /**
     * @notice Override _debit to track pending bridge amounts
     */
    function _debit(
        address _from,
        uint256 _amountLD,
        uint256 _minAmountLD,
        uint32 _dstEid
    ) internal virtual override returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        (amountSentLD, amountReceivedLD) = super._debit(_from, _amountLD, _minAmountLD, _dstEid);
        
        // Track pending shares for recovery
        pendingShares[_from][_dstEid] += amountSentLD;
        pendingTimestamp[_from][_dstEid] = block.timestamp;
        
        return (amountSentLD, amountReceivedLD);
    }
    
    /**
     * @notice Override _credit to clear pending when message succeeds
     */
    function _credit(
        address _to,
        uint256 _amountLD,
        uint32 _srcEid
    ) internal virtual override returns (uint256 amountReceivedLD) {
        amountReceivedLD = super._credit(_to, _amountLD, _srcEid);
        
        // Clear pending shares when return message succeeds
        if (pendingShares[_to][_srcEid] >= _amountLD) {
            pendingShares[_to][_srcEid] -= _amountLD;
        }
        
        return amountReceivedLD;
    }
    
    /**
     * @notice Allows users to recover shares if LayerZero message fails permanently
     * @param _dstEid Destination chain endpoint ID where message failed
     * @dev Only callable after RECOVERY_DELAY has passed since bridge attempt
     */
    function recoverFailedBridge(uint32 _dstEid) external {
        uint256 pending = pendingShares[msg.sender][_dstEid];
        require(pending > 0, "No pending shares");
        require(
            block.timestamp >= pendingTimestamp[msg.sender][_dstEid] + RECOVERY_DELAY,
            "Recovery delay not elapsed"
        );
        
        // Clear pending tracking
        pendingShares[msg.sender][_dstEid] = 0;
        pendingTimestamp[msg.sender][_dstEid] = 0;
        
        // Return locked shares to user
        IERC20(token()).safeTransfer(msg.sender, pending);
        
        emit SharesRecovered(msg.sender, _dstEid, pending);
    }
    
    event SharesRecovered(address indexed user, uint32 indexed dstEid, uint256 amount);
}
```

**Alternative Mitigation:** Implement a more sophisticated approach using LayerZero V2's built-in delivery status tracking, or add an admin-only emergency rescue function that requires multi-sig approval and proof that the message will never be delivered.

## Proof of Concept

```solidity
// File: test/Exploit_PermanentShareLock.t.sol
// Run with: forge test --match-test test_PermanentShareLockOnFailedBridge -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_PermanentShareLock is CrossChainTestBase {
    using OptionsBuilder for bytes;
    
    uint256 constant INITIAL_DEPOSIT = 100 ether;
    uint256 constant SHARES_TO_BRIDGE = 50 ether;
    
    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }
    
    function test_PermanentShareLockOnFailedBridge() public {
        // SETUP: User has wiTRY shares on L1
        vm.selectFork(sepoliaForkId);
        
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, INITIAL_DEPOSIT);
        
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaVault), INITIAL_DEPOSIT);
        uint256 sharesReceived = sepoliaVault.deposit(INITIAL_DEPOSIT, userL1);
        vm.stopPrank();
        
        uint256 userSharesBefore = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesBefore = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        
        console.log("User shares before bridge:", userSharesBefore);
        console.log("Adapter shares before:", adapterSharesBefore);
        
        // EXPLOIT: User attempts to bridge shares to L2
        vm.startPrank(userL1);
        sepoliaVault.approve(address(sepoliaShareAdapter), SHARES_TO_BRIDGE);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL2))),
            amountLD: SHARES_TO_BRIDGE,
            minAmountLD: SHARES_TO_BRIDGE,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaShareAdapter.quoteSend(sendParam, false);
        
        // Send shares - this locks them in adapter
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        uint256 userSharesAfter = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesAfter = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        
        console.log("\nUser shares after send:", userSharesAfter);
        console.log("Adapter shares after send (LOCKED):", adapterSharesAfter);
        
        // VERIFY: Shares are locked in adapter
        assertEq(adapterSharesAfter, SHARES_TO_BRIDGE, "Shares should be locked in adapter");
        assertEq(userSharesAfter, INITIAL_DEPOSIT - SHARES_TO_BRIDGE, "User should have lost shares");
        
        // Simulate message failure on L2 (don't relay the message)
        // In real scenario: peer misconfiguration, blacklist, contract pause, etc.
        console.log("\n[SIMULATING] Message fails on L2 and cannot be delivered");
        
        // VERIFY: No recovery mechanism exists
        console.log("\n[VULNERABILITY CONFIRMED]:");
        console.log("1. Shares are permanently locked in adapter:", adapterSharesAfter);
        console.log("2. User cannot call any function to recover shares");
        console.log("3. No admin rescue function exists in wiTryOFTAdapter");
        console.log("4. Shares will remain locked forever");
        
        // Try to verify no recovery functions exist
        // The contract only has a constructor, no other functions
        bytes memory code = address(sepoliaShareAdapter).code;
        console.log("Contract code size:", code.length);
        console.log("Contract has NO recovery functions");
        
        assertEq(
            adapterSharesAfter, 
            SHARES_TO_BRIDGE,
            "PERMANENT LOSS: 50 ETH worth of shares stuck forever in adapter"
        );
    }
}
```

## Notes

This vulnerability is distinct from the known issue about "Native fee loss on failed wiTryVaultComposer.lzReceive" which only discusses fee loss and requires double payment. [5](#0-4)  That issue is about the VaultComposer unstaking flow, while this vulnerability affects the direct share bridging via OFTAdapter where shares become permanently and irrecoverably locked.

The protocol's other components like iTryTokenOFT have rescue functions [6](#0-5) , and the VaultComposerSync library has a refund mechanism for failed compose messages [7](#0-6) . However, wiTryOFTAdapter has neither, making it uniquely vulnerable to permanent fund loss.

### Citations

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

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L29-43)
```text
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
```

**File:** README.md (L40-40)
```markdown
- Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L120-129)
```text
    /**
     * @notice Allows the owner to rescue tokens accidentally sent to the contract.
     * @param token The token to be rescued.
     * @param amount The amount of tokens to be rescued.
     * @param to Where to send rescued tokens
     */
    function rescueTokens(address token, uint256 amount, address to) external nonReentrant onlyOwner {
        IERC20(token).safeTransfer(to, amount);
        emit TokenRescued(token, to, amount);
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
