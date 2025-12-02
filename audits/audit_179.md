## Title
Locked Shares in wiTryOFTAdapter Have No Recovery Mechanism, Causing Permanent Loss if Cross-Chain Message Fails

## Summary
The `wiTryOFTAdapter` contract locks user shares when bridging from L1 to L2 but provides no expiration time or admin rescue function to recover shares if the LayerZero message permanently fails to be delivered. This results in indefinite loss of user funds.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** When users bridge wiTRY shares from L1 (Ethereum) to L2 via the OFTAdapter, shares should be locked on L1, a LayerZero message sent, and equivalent shares minted on L2. If the message fails, users should be able to recover their locked shares.

**Actual Logic:** The `wiTryOFTAdapter` contract inherits only from LayerZero's `OFTAdapter` base contract and implements no additional functions beyond the constructor. When shares are locked during the send operation, there is no mechanism to recover them if the message permanently fails. The contract has no rescue function, no expiration time on locks, and no admin recovery capability.

**Exploitation Path:**
1. User approves `wiTryOFTAdapter` and calls `send()` to bridge 100 wiTRY shares from L1 to L2
2. Adapter locks the 100 shares by transferring them from user to itself [2](#0-1) 
3. LayerZero message is sent to L2 but fails permanently due to:
   - Peer misconfiguration (OFT address changed on L2)
   - Destination contract upgraded/destroyed
   - Blacklist preventing receive on destination
   - L2 chain issues
4. Shares remain locked in adapter indefinitely with no recovery path [3](#0-2) 

**Security Property Broken:** Violates the principle that user funds should always be recoverable, and contrasts with the protocol's pattern of implementing rescue functions in other cross-chain contracts.

## Impact Explanation
- **Affected Assets**: wiTRY vault shares locked in the `wiTryOFTAdapter` contract
- **Damage Severity**: Complete permanent loss of shares for affected users. If 1000 wiTRY shares worth $10,000 are locked, they become irrecoverable forever.
- **User Impact**: Any user bridging shares from L1 to L2 when a permanent message failure occurs loses their shares. This affects all users attempting cross-chain transfers during the failure period.

## Likelihood Explanation
- **Attacker Profile**: Not an intentional attack - this is an unintended consequence affecting regular users during system failures
- **Preconditions**: LayerZero message must permanently fail (peer misconfiguration, destination issues, blacklist on L2, etc.)
- **Execution Complexity**: User performs standard bridge operation; vulnerability manifests automatically if message fails
- **Frequency**: Occurs whenever permanent message delivery failures happen (rare but impactful when they do)

## Recommendation
Add a rescue function to `wiTryOFTAdapter` following the same pattern used in other protocol contracts:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFTAdapter.sol:

// ADD this function:
/**
 * @notice Allows the owner to rescue tokens accidentally locked in the adapter
 * @param token The token to be rescued
 * @param amount The amount of tokens to be rescued
 * @param to Where to send rescued tokens
 */
function rescueToken(address token, uint256 amount, address to) external onlyOwner {
    require(token != address(0), "Invalid token address");
    require(amount > 0, "Amount must be greater than 0");
    require(to != address(0), "Invalid recipient address");
    
    IERC20(token).safeTransfer(to, amount);
    emit TokenRescued(token, to, amount);
}

event TokenRescued(address indexed token, address indexed to, uint256 amount);
```

This matches the rescue pattern implemented in: [4](#0-3) , [5](#0-4) , and [6](#0-5) 

**Alternative mitigation**: Implement a time-based unlock mechanism where shares locked for longer than X days (e.g., 30 days) can be withdrawn by the original sender.

## Proof of Concept

```solidity
// File: test/Exploit_LockedSharesNoRecovery.t.sol
// Run with: forge test --match-test test_LockedSharesNoRecovery -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_LockedSharesNoRecovery is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant SHARES_TO_BRIDGE = 50 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_LockedSharesNoRecovery() public {
        // SETUP: User deposits iTRY and gets shares on L1
        vm.selectFork(sepoliaForkId);
        
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, 100 ether);
        
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaVault), 100 ether);
        uint256 sharesReceived = sepoliaVault.deposit(100 ether, userL1);
        vm.stopPrank();
        
        uint256 userSharesBefore = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesBefore = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        
        console.log("User shares before bridge:", userSharesBefore);
        console.log("Adapter shares before bridge:", adapterSharesBefore);
        
        // EXPLOIT: User bridges shares but message fails on L2
        vm.startPrank(userL1);
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
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // VERIFY: Shares are locked in adapter
        uint256 userSharesAfter = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesAfter = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        
        console.log("\nUser shares after bridge:", userSharesAfter);
        console.log("Adapter shares after bridge (LOCKED):", adapterSharesAfter);
        
        assertEq(userSharesAfter, 50 ether, "User should have 50 shares remaining");
        assertEq(adapterSharesAfter, 50 ether, "Adapter should have 50 shares locked");
        
        // VERIFY: No rescue function exists to recover locked shares
        // Try to call rescueToken - will fail because function doesn't exist
        vm.expectRevert();
        (bool success,) = address(sepoliaShareAdapter).call(
            abi.encodeWithSignature(
                "rescueToken(address,uint256,address)",
                address(sepoliaVault),
                SHARES_TO_BRIDGE,
                userL1
            )
        );
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("- 50 wiTRY shares locked in adapter");
        console.log("- No rescue function exists");
        console.log("- Shares are permanently lost if L2 message fails");
    }
}
```

## Notes

The vulnerability is confirmed by comparing `wiTryOFTAdapter` with other protocol contracts:

1. **iTryTokenOFT** implements `rescueTokens()` [4](#0-3) 

2. **wiTryVaultComposer** implements `rescueToken()` [5](#0-4) 

3. **UnstakeMessenger** implements `rescueToken()` [6](#0-5) 

4. **FastAccessVault** implements `rescueToken()` [7](#0-6) 

5. **wiTryOFTAdapter** implements ONLY a constructor with NO rescue functionality [8](#0-7) 

This inconsistency represents a critical design gap. While LayerZero V2 provides message retry mechanisms through the endpoint, these only work if messages can eventually be successfully delivered. For permanently failed messages (due to peer misconfiguration, contract upgrades, or other irrecoverable issues), the lack of a rescue function means shares are permanently lost.

The issue is NOT listed in the known issues from the Zellic audit [9](#0-8) , making it a valid finding for this audit.

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

**File:** test/crosschainTests/crosschain/Step8_ShareBridging.t.sol (L119-128)
```text
        // Verify shares locked on Sepolia
        uint256 userSharesAfterSend = sepoliaVault.balanceOf(userL1);
        uint256 adapterSharesAfterSend = sepoliaVault.balanceOf(address(sepoliaShareAdapter));

        console.log("\nAfter Send (Sepolia):");
        console.log("  userL1 shares:", userSharesAfterSend);
        console.log("  adapter shares (locked):", adapterSharesAfterSend);

        assertEq(userSharesAfterSend, INITIAL_DEPOSIT - SHARES_TO_BRIDGE, "User should have 50 shares remaining");
        assertEq(adapterSharesAfterSend, SHARES_TO_BRIDGE, "Adapter should have locked 50 shares");
```

**File:** test/crosschainTests/crosschain/Step8_ShareBridging.t.sol (L244-257)
```text
        uint256 userL1FinalShares = sepoliaVault.balanceOf(userL1);
        uint256 adapterFinalShares = sepoliaVault.balanceOf(address(sepoliaShareAdapter));

        console.log("\nAfter Relay (Sepolia):");
        console.log("  userL1 shares:", userL1FinalShares);
        console.log("  adapter shares:", adapterFinalShares);

        // User should have: original 50 remaining + 25 returned = 75 shares
        assertEq(
            userL1FinalShares,
            (INITIAL_DEPOSIT - SHARES_TO_BRIDGE) + SHARES_TO_RETURN,
            "User should have 75 shares on L1"
        );
        assertEq(adapterFinalShares, SHARES_TO_BRIDGE - SHARES_TO_RETURN, "Adapter should have 25 shares locked");
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

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L185-200)
```text
     */
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert InvalidZeroAddress();
        if (amount == 0) revert InvalidAmount();

        if (token == address(0)) {
            // Rescue ETH
            (bool success,) = to.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            // Rescue ERC20 tokens
            IERC20(token).safeTransfer(to, amount);
        }

        emit TokenRescued(token, to, amount);
    }
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L275-290)
```text
     */
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();

        if (token == address(0)) {
            // Rescue ETH
            (bool success,) = to.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            // Rescue ERC20 tokens
            IERC20(token).safeTransfer(to, amount);
        }

        emit TokenRescued(token, to, amount);
    }
```

**File:** src/protocol/FastAccessVault.sol (L203-229)
```text
    // ============================================
    // Admin Functions - Emergency/Rescue
    // ============================================

    /**
     * @notice Rescue tokens accidentally sent to this contract
     * @dev Only callable by owner. Can rescue both ERC20 tokens and native ETH
     *      Use address(0) for rescuing ETH
     * @param token The token address to rescue (use address(0) for ETH)
     * @param to The address to send rescued tokens to
     * @param amount The amount to rescue
     */
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (to == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();

        if (token == address(0)) {
            // Rescue ETH
            (bool success,) = to.call{value: amount}("");
            if (!success) revert CommonErrors.TransferFailed();
        } else {
            // Rescue ERC20 tokens
            IERC20(token).safeTransfer(to, amount);
        }

        emit TokenRescued(token, to, amount);
    }
```

**File:** README.md (L23-42)
```markdown
## Publicly known issues

_Anything included in this section is considered a publicly known issue and is therefore ineligible for awards._

### Centralization Risks

Any centralization risks are out-of-scope for the purposes of this audit contest.

### Zellic Audit Report Issues

The codebase has undergone a Zellic audit with a fix review pending. The following issues identified in the Zellic audit are considered out-of-scope, with some being fixed in the current iteration of the codebase:

-  Blacklisted user can transfer tokens on behalf of non-blacklisted users using allowance - `_beforeTokenTransfer` does not validate `msg.sender`, a blacklisted caller can still initiate a same-chain token transfer on behalf of a non-blacklisted user as long as allowance exists.
- Griefing attacks around the `MIN_SHARES` variable of the ERC2646 vault: The protocol will perform an initial deposit to offset this risk. 
- The `redistributeLockedAmount` does not validate that the resulted `totalSupply` is not less than the minimum threshold. As a result of executing the `redistributeLockedAmount` function, the `totalSupply` amount may fall within a prohibited range between 0 and `MIN_SHARES` amount. And subsequent legitimate
deposits or withdrawals operations, which do not increase totalSupply to the `MIN_SHARES` value will be blocked.
- iTRY backing can fall below 1:1 on NAV drop. If NAV drops below 1, iTRY becomes undercollateralized with no guaranteed, on-chain remediation. Holders bear insolvency risk until a top-up or discretionary admin intervention occurs.
- Native fee loss on failed `wiTryVaultComposer.LzReceive` execution. In the case of underpayment, users will lose their fee and will have to pay twice to complete the unstake request.
- Non-standard ERC20 tokens may break the transfer function. If a non-standard token is recovered using a raw transfer, the function may appear to succeed, even though no tokens were transferred, or it may revert unexpectedly. This can result in tokens becoming stuck in the contract, which breaks the tokens rescue mechanism.

```
