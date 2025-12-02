## Title
Cross-Chain Share/Token Transfer to Blacklisted Recipient Causes Permanent Fund Lock in OFTAdapter

## Summary
The `wiTryOFTAdapter` and `iTryTokenOFTAdapter` contracts lack blacklist validation when unlocking shares/tokens for cross-chain recipients on L1. When users send wiTRY shares or iTRY tokens from L2 back to L1 with a blacklisted recipient address, the underlying token's `_beforeTokenTransfer` hook reverts the transfer, causing the LayerZero message to fail and permanently locking the funds in the adapter contract with no recovery mechanism.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/token/wiTRY/crosschain/wiTryOFTAdapter.sol` [1](#0-0) 
- `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` [2](#0-1) 

**Intended Logic:** When shares/tokens are sent from L2 back to L1, the OFTAdapter should unlock them from the adapter contract and transfer them to the specified recipient address. The protocol should enforce blacklist restrictions to prevent blacklisted users from receiving funds in any scenario.

**Actual Logic:** The adapters inherit from LayerZero's base `OFTAdapter` contract without overriding the `_credit` function. When the base implementation attempts to transfer unlocked shares/tokens to a blacklisted recipient, the underlying token's `_beforeTokenTransfer` hook reverts:

- For wiTRY: `StakediTry._beforeTokenTransfer` reverts when recipient has `FULL_RESTRICTED_STAKER_ROLE` [3](#0-2) 
- For iTRY: `iTry._beforeTokenTransfer` reverts when recipient has `BLACKLISTED_ROLE` [4](#0-3) 

The revert causes the entire LayerZero message to fail. Unlike the spoke chain contracts which have `_credit` overrides to redirect funds to the owner [5](#0-4) , the hub chain adapters lack this protection and also lack any rescue function to recover locked tokens.

**Exploitation Path:**
1. User holds wiTRY shares or iTRY tokens on L2 (OP Sepolia/MegaETH)
2. User initiates cross-chain transfer back to L1, specifying a recipient address (could be their own address or another address)
3. Between transaction initiation and L1 arrival, the recipient gets blacklisted by protocol admins (OR recipient was already blacklisted intentionally/accidentally)
4. LayerZero message arrives at L1 adapter, base `OFTAdapter._credit` attempts to transfer shares/tokens to recipient
5. Token's `_beforeTokenTransfer` hook checks blacklist status and reverts
6. LayerZero message fails, shares/tokens remain permanently locked in adapter
7. No rescue mechanism exists to recover the locked funds

**Security Property Broken:** 
- Violates Critical Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - The system allows initiation of transfers to blacklisted recipients on L1, but the transfer fails silently, locking funds
- Causes permanent loss of user funds, violating the fundamental security property of fund custody

## Impact Explanation
- **Affected Assets**: wiTRY shares and iTRY tokens locked in the respective OFTAdapter contracts on L1 (Ethereum mainnet)
- **Damage Severity**: Complete and permanent loss of all shares/tokens sent in the failed cross-chain transfer. Users cannot recover their funds as the adapters lack rescue functions (unlike other protocol contracts that implement `rescueTokens` functionality).
- **User Impact**: Any user performing L2→L1 transfers with a blacklisted recipient loses 100% of the transferred amount. This affects both intentional transfers to blacklisted addresses (e.g., user doesn't know recipient was blacklisted) and race conditions where the recipient is blacklisted between transaction submission on L2 and execution on L1.

## Likelihood Explanation
- **Attacker Profile**: Any user performing cross-chain transfers, no special privileges required. Can also be exploited maliciously by sending funds to known blacklisted addresses to cause loss to others.
- **Preconditions**: 
  - Recipient address must have blacklist role (`FULL_RESTRICTED_STAKER_ROLE` for wiTRY or `BLACKLISTED_ROLE` for iTRY)
  - User must initiate L2→L1 cross-chain transfer via LayerZero
  - LayerZero message successfully relayed (standard operation)
- **Execution Complexity**: Single transaction on L2 initiating the send. The vulnerability manifests automatically when the message is processed on L1.
- **Frequency**: Can occur on every L2→L1 transfer to a blacklisted recipient. Given that blacklisting is an active protocol feature for compliance and security, this scenario is realistic and expected to occur.

## Recommendation

Override the `_credit` function in both adapter contracts to match the protection implemented in the spoke chain OFT contracts:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFTAdapter.sol:

// ADD IMPORTS:
import {StakediTry} from "../../StakediTry.sol";

// ADD STATE VARIABLE:
bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");

// ADD OVERRIDE:
/**
 * @notice Credits tokens to recipient, redirecting to owner if recipient is blacklisted
 * @param _to The address of the recipient
 * @param _amountLD The amount to credit
 * @param _srcEid The source endpoint ID
 * @return amountReceivedLD The amount actually credited
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    StakediTry token = StakediTry(address(innerToken));
    
    // If recipient is blacklisted, redirect to owner instead
    if (token.hasRole(FULL_RESTRICTED_STAKER_ROLE, _to)) {
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol:

// ADD IMPORTS:
import {iTry} from "../iTry.sol";

// ADD STATE VARIABLE:
bytes32 private constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");

// ADD OVERRIDE:
/**
 * @notice Credits tokens to recipient, redirecting to owner if recipient is blacklisted
 * @param _to The address of the recipient
 * @param _amountLD The amount to credit
 * @param _srcEid The source endpoint ID
 * @return amountReceivedLD The amount actually credited
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    iTry token = iTry(address(innerToken));
    
    // If recipient is blacklisted, redirect to owner instead
    if (token.hasRole(BLACKLISTED_ROLE, _to)) {
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative mitigation:** Add a `rescueTokens` function to both adapters following the pattern used in other protocol contracts, allowing the owner to recover tokens locked due to failed transfers. However, the `_credit` override is the preferred solution as it prevents the issue proactively rather than requiring manual recovery.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedRecipientLock.t.sol
// Run with: forge test --match-test test_BlacklistedRecipientCausesLock -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_BlacklistedRecipientLock is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant INITIAL_DEPOSIT = 100 ether;
    uint256 constant SHARES_TO_BRIDGE = 50 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_BlacklistedRecipientCausesLock() public {
        console.log("\n=== Exploit: Blacklisted Recipient Causes Permanent Lock ===");

        // SETUP: Create shares on L1 and bridge to L2
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, INITIAL_DEPOSIT);

        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaVault), INITIAL_DEPOSIT);
        sepoliaVault.deposit(INITIAL_DEPOSIT, userL1);
        
        // Bridge shares to L2
        sepoliaVault.approve(address(sepoliaShareAdapter), SHARES_TO_BRIDGE);
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
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
        vm.recordLogs();
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();

        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);

        // Verify shares are on L2
        vm.selectFork(opSepoliaForkId);
        uint256 userL2Shares = opSepoliaShareOFT.balanceOf(userL2);
        assertEq(userL2Shares, SHARES_TO_BRIDGE, "User should have shares on L2");
        console.log("Shares on L2:", userL2Shares);

        // ATTACK: Blacklist userL1 on L1 before sending shares back
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaVault.addToBlacklist(userL1, true); // Full blacklist
        console.log("userL1 blacklisted on L1");

        // Try to send shares back from L2 to blacklisted L1 address
        vm.selectFork(opSepoliaForkId);
        vm.startPrank(userL2);
        sendParam.dstEid = SEPOLIA_EID;
        sendParam.to = bytes32(uint256(uint160(userL1))); // Blacklisted recipient
        sendParam.amountLD = SHARES_TO_BRIDGE;
        sendParam.minAmountLD = SHARES_TO_BRIDGE;

        fee = opSepoliaShareOFT.quoteSend(sendParam, false);
        vm.recordLogs();
        opSepoliaShareOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL2));
        vm.stopPrank();

        // Verify shares burned on L2
        assertEq(opSepoliaShareOFT.balanceOf(userL2), 0, "Shares should be burned on L2");
        console.log("Shares burned on L2");

        // Relay message to L1 - THIS WILL FAIL
        message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        vm.selectFork(sepoliaForkId);
        
        // Capture state before failed relay
        uint256 userL1SharesBefore = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesBefore = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        console.log("Before relay - userL1 shares:", userL1SharesBefore);
        console.log("Before relay - adapter locked shares:", adapterSharesBefore);

        // Try to relay - this should revert due to blacklist check
        vm.expectRevert(); // The transfer will revert in _beforeTokenTransfer
        relayMessage(message);

        // VERIFY EXPLOIT: Shares are permanently locked in adapter
        uint256 userL1SharesAfter = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesAfter = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        
        console.log("\n=== EXPLOIT SUCCESS ===");
        console.log("After failed relay - userL1 shares:", userL1SharesAfter);
        console.log("After failed relay - adapter locked shares:", adapterSharesAfter);
        console.log("Shares permanently locked:", adapterSharesAfter);
        
        // Shares remain locked in adapter, user received nothing
        assertEq(userL1SharesAfter, userL1SharesBefore, "User received no shares on L1");
        assertEq(adapterSharesAfter, SHARES_TO_BRIDGE, "Shares locked in adapter");
        
        console.log("\nVulnerability confirmed: 50 ether shares permanently locked in adapter");
        console.log("No rescue function available to recover funds");
    }
}
```

## Notes

This vulnerability affects both the wiTRY share bridging system and the iTRY token bridging system. The spoke chain contracts (`wiTryOFT` and `iTryTokenOFT`) correctly implement `_credit` overrides that redirect funds to the owner when the recipient is blacklisted, but the hub chain adapters lack this protection. This architectural inconsistency creates a one-way blacklist enforcement gap that leads to permanent fund loss. The issue is particularly severe because blacklisting is an active compliance feature of the protocol, making this scenario highly likely to occur in production.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L26-33)
```text
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-28)
```text
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/wiTRY/StakediTry.sol (L292-299)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
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
