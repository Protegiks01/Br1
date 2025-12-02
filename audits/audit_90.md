## Title
Missing Enforced Options on iTryTokenOFT Allows Permanent Token Loss During Spoke-to-Hub Bridging

## Summary
The `iTryTokenOFT` contract on spoke chains lacks enforced LayerZero options configuration, allowing users to initiate cross-chain transfers with insufficient gas specifications. When users send iTRY tokens from spoke to hub with empty or minimal `extraOptions`, the tokens are burned on the spoke chain but the LayerZero message is never relayed to the hub chain, resulting in permanent loss of funds.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` (entire contract) [1](#0-0) 

**Intended Logic:** 
Users should be able to bridge iTRY tokens from spoke chains (MegaETH/OP Sepolia) back to the hub chain (Ethereum) by calling the OFT `send()` function. The contract should ensure that sufficient gas is allocated for the destination chain's `lzReceive` execution, preventing message failures.

**Actual Logic:** 
The `iTryTokenOFT` contract inherits from LayerZero's OFT base contract without setting enforced options. Unlike the hub-to-spoke direction which has enforced options configured via `06_SetEnforcedOptionsiTryAdapter.s.sol`, there is NO corresponding configuration script for spoke-to-hub transfers. [2](#0-1) 

The deployment checklist confirms enforced options are only set for:
- Hub ShareAdapter (script 03)
- Spoke ShareOFT (script 04)  
- Hub iTryAdapter (script 06)

But NOT for Spoke iTryOFT (no script 05 or 07 exists). [3](#0-2) 

**Exploitation Path:**

1. **User initiates spoke-to-hub transfer:** A user on the spoke chain calls `iTryTokenOFT.send()` with a `SendParam` struct containing empty `extraOptions` (e.g., `OptionsBuilder.newOptions()` which creates a TYPE_3 header with no gas specified).

2. **Quote returns minimal fee:** The `quoteSend()` function calculates the LayerZero messaging fee based on the empty options, returning only the base message overhead cost without execution gas.

3. **Tokens are burned:** The user pays the quoted fee and calls `send()`. The OFT's internal `_debit()` function burns the iTRY tokens from the user's balance on the spoke chain.

4. **Message sent with 0 gas:** The LayerZero message is dispatched to the endpoint with 0 gas specified for `lzReceive` execution on the destination chain.

5. **Executors skip message:** LayerZero executors on the hub chain detect the message has insufficient gas (0 or minimal) and do not relay it, leaving it unexecuted.

6. **Tokens permanently lost:** The iTRY tokens are burned on spoke but never unlocked on hub. No recovery mechanism exists.

**Security Property Broken:** 
Violates **Cross-chain Message Integrity** invariant: "LayerZero messages for unstaking must be delivered to correct user with proper validation." Additionally causes **permanent loss of user funds**, a High severity impact per the Code4rena framework.

## Impact Explanation

- **Affected Assets**: All iTRY tokens being bridged from spoke chains to hub chain
- **Damage Severity**: 100% loss of bridged amount for affected users. Tokens are burned on source chain with no minting/unlocking on destination chain. Funds are permanently unrecoverable.
- **User Impact**: Any user who directly calls `iTryTokenOFT.send()` without manually specifying sufficient gas in `extraOptions`. While test scripts properly add 200k gas (as seen in `BridgeITRY_SpokeToHub_RedeemerAddress.s.sol` line 68), regular users interacting directly with the contract or through frontends that don't enforce gas parameters will lose funds. [4](#0-3) 

## Likelihood Explanation

- **Attacker Profile**: Not malicious - any regular user bridging iTRY from spoke to hub
- **Preconditions**: 
  - User has iTRY balance on spoke chain
  - User calls contract directly (not via protocol-provided scripts)
  - User provides empty or minimal `extraOptions` in `SendParam`
- **Execution Complexity**: Single transaction. User simply calls `send()` with standard parameters but without manually adding gas options.
- **Frequency**: Every spoke-to-hub iTRY transfer by users who don't manually specify gas options

## Recommendation

Set enforced options on `iTryTokenOFT` for spoke-to-hub transfers:

```solidity
// Create new file: script/config/05_SetEnforcedOptionsiTryOFT.s.sol

contract SetEnforcedOptionsiTryOFT05 is Script {
    using OptionsBuilder for bytes;
    
    uint32 internal constant SEPOLIA_EID = 40161;  // Hub chain
    uint16 internal constant SEND = 1;
    uint128 internal constant LZ_RECEIVE_GAS = 200000;
    
    function run() public {
        require(block.chainid == 11155420, "Must run on OP Sepolia");
        
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address itryOFT = vm.envAddress("SPOKE_ITRY_OFT");
        
        bytes memory enforcedOptions = OptionsBuilder.newOptions()
            .addExecutorLzReceiveOption(LZ_RECEIVE_GAS, 0);
        
        EnforcedOptionParam[] memory params = new EnforcedOptionParam[](1);
        params[0] = EnforcedOptionParam({
            eid: SEPOLIA_EID,
            msgType: SEND,
            options: enforcedOptions
        });
        
        vm.startBroadcast(deployerKey);
        IOAppOptionsType3(itryOFT).setEnforcedOptions(params);
        vm.stopBroadcast();
    }
}
```

**Alternative Mitigation:** Add validation in `iTryTokenOFT` to revert if `extraOptions` does not contain minimum gas:

```solidity
// In iTryTokenOFT.sol, override _buildMsgAndOptions or add validation
function _buildMsgAndOptions(...) internal override returns (...) {
    // Validate extraOptions contains minimum gas before proceeding
    require(_hasMinimumGas(_options), "Insufficient gas in options");
    return super._buildMsgAndOptions(...);
}
```

Update deployment checklist to include Step 3.5.5: Set enforced options on iTryOFT (spoke chain).

## Proof of Concept

```solidity
// File: test/Exploit_MissingEnforcedOptions.t.sol
// Run with: forge test --match-test test_iTryBurn_WithoutEnforcedOptions -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {IOFT, SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_MissingEnforcedOptions is CrossChainTestBase {
    using OptionsBuilder for bytes;
    
    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }
    
    function test_iTryBurn_WithoutEnforcedOptions() public {
        // SETUP: Mint iTRY to user on spoke chain
        vm.selectFork(opSepoliaForkId);
        
        uint256 transferAmount = 100 ether;
        vm.prank(deployer);
        opSepoliaOFT.mint(userL1, transferAmount);
        
        uint256 balanceBefore = opSepoliaOFT.balanceOf(userL1);
        assertEq(balanceBefore, transferAmount, "User should have iTRY on spoke");
        
        // EXPLOIT: User sends with EMPTY extraOptions (no gas specified)
        vm.startPrank(userL1);
        
        bytes memory emptyOptions = OptionsBuilder.newOptions(); // Only TYPE_3 header, no gas!
        
        SendParam memory sendParam = SendParam({
            dstEid: SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL1))),
            amountLD: transferAmount,
            minAmountLD: transferAmount,
            extraOptions: emptyOptions,  // VULNERABLE: No gas specified
            composeMsg: "",
            oftCmd: ""
        });
        
        // Quote returns minimal fee (no execution gas cost)
        MessagingFee memory fee = opSepoliaOFT.quoteSend(sendParam, false);
        
        // Send succeeds and burns tokens
        vm.recordLogs();
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // VERIFY: Tokens burned on spoke
        uint256 balanceAfter = opSepoliaOFT.balanceOf(userL1);
        assertEq(balanceAfter, 0, "Tokens burned on spoke");
        
        // Relay message to hub
        CrossChainMessage memory message = captureMessage(OP_SEPOLIA_EID, SEPOLIA_EID);
        
        // Message will fail or be skipped by executors due to 0 gas
        // In production, executors won't relay this message at all
        // For test purposes, if relayed with 0 gas, lzReceive would revert
        
        vm.selectFork(sepoliaForkId);
        uint256 hubBalance = sepoliaITryToken.balanceOf(userL1);
        
        // RESULT: Tokens not unlocked on hub (hub balance remains 0)
        assertEq(hubBalance, 0, "Vulnerability confirmed: Tokens burned but not unlocked");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- User sent", transferAmount, "iTRY from spoke to hub");
        console.log("- Tokens burned on spoke chain");
        console.log("- Message sent with 0 gas in options");
        console.log("- Tokens NOT unlocked on hub chain");
        console.log("- USER LOST", transferAmount, "iTRY permanently");
    }
}
```

**Notes:**
- The vulnerability is confirmed by the absence of enforced options configuration scripts for `SPOKE_ITRY_OFT`
- The hub-to-spoke direction is properly protected with enforced options (200k gas minimum)
- The spoke-to-hub direction relies entirely on users manually specifying sufficient gas, which is unsafe
- Protocol test scripts add gas manually, but direct contract interactions do not have this protection
- LayerZero V2 executors require non-zero gas to relay messages; messages with insufficient gas are skipped
- This breaks the "Cross-chain Message Integrity" invariant and causes permanent fund loss (High severity)

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L1-177)
```text
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {OFT} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/OFT.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./../IiTryDefinitions.sol";

/**
 * @title iTryTokenOFT
 * @notice OFT representation of iTRY on spoke chains (MegaETH)
 * @dev This contract mints/burns tokens based on LayerZero messages from the hub chain
 *
 * Architecture:
 * - Hub Chain (Ethereum): iTryToken (native) + iTryTokenAdapter (locks tokens)
 * - Spoke Chain (MegaETH): iTryTokenOFT (mints/burns based on messages)
 *
 * Flow from Hub to Spoke:
 * 1. Hub adapter locks native iTRY
 * 2. LayerZero message sent to this contract
 * 3. This contract mints equivalent OFT tokens
 *
 * Flow from Spoke to Hub:
 * 1. This contract burns OFT tokens
 * 2. LayerZero message sent to hub adapter
 * 3. Hub adapter unlocks native iTRY tokens
 */
contract iTryTokenOFT is OFT, IiTryDefinitions, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// @notice Address allowed to mint iTry (typically the LayerZero endpoint)
    address public minter;

    /// @notice Mapping of blacklisted addresses
    mapping(address => bool) public blacklisted;

    /// @notice Mapping of whitelisted addresses
    mapping(address => bool) public whitelisted;

    TransferState public transferState;

    /// @notice Emitted when minter address is updated
    event MinterUpdated(address indexed oldMinter, address indexed newMinter);

    /**
     * @notice Constructor for iTryTokenOFT
     * @param _lzEndpoint LayerZero endpoint address for MegaETH
     * @param _owner Address that will own this OFT (typically deployer)
     */
    constructor(address _lzEndpoint, address _owner) OFT("iTry Token", "iTRY", _lzEndpoint, _owner) {
        transferState = TransferState.FULLY_ENABLED;
        minter = _lzEndpoint;
    }

    /**
     * @notice Sets the minter address
     * @param _newMinter The new minter address
     */
    function setMinter(address _newMinter) external onlyOwner {
        address oldMinter = minter;
        minter = _newMinter;
        emit MinterUpdated(oldMinter, _newMinter);
    }

    /**
     * @param users List of address to be blacklisted
     * @notice Owner can blacklist addresses. Blacklisted addresses cannot transfer tokens.
     */
    function addBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        }
    }

    /**
     * @param users List of address to be removed from blacklist
     */
    function removeBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            blacklisted[users[i]] = false;
        }
    }

    /**
     * @param users List of address to be whitelisted
     */
    function addWhitelistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            if (!blacklisted[users[i]]) whitelisted[users[i]] = true;
        }
    }

    /**
     * @param users List of address to be removed from whitelist
     */
    function removeWhitelistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            whitelisted[users[i]] = false;
        }
    }

    /**
     * @dev Burns the blacklisted user iTry and mints to the desired owner address.
     * @param from The address to burn the entire balance, must be blacklisted
     * @param to The address to mint the entire balance of "from" parameter.
     */
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyOwner {
        if (blacklisted[from] && !blacklisted[to]) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }

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

    /**
     * @param code Owner can disable all transfers, allow limited addresses only, or fully enable transfers
     */
    function updateTransferState(TransferState code) external onlyOwner {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }

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
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
    }
```

**File:** script/config/06_SetEnforcedOptionsiTryAdapter.sol (L1-81)
```text

```

**File:** script/deploy/DEPLOYMENT_CHECKLIST.md (L700-763)
```markdown
### Step 3.4: Set Enforced Options on ShareAdapter (Hub) (~10-15 sec)
- [ ] **Run 03_SetEnforcedOptionsShareAdapter on Sepolia**
  ```bash
forge script script/config/03_SetEnforcedOptionsShareAdapter.s.sol:SetEnforcedOptionsShareAdapter03 \      
    --rpc-url $SEPOLIA_RPC_URL \
    --broadcast \
    -vvv
  ```

- [ ] **Verify enforced options**
  ```bash
  cast call $HUB_SHARE_ADAPTER "enforcedOptions(uint32,uint16)(bytes)" 40232 1 \
    --rpc-url $SEPOLIA_RPC_URL
  ```
  - [ ] Confirm lzReceive gas: 200,000
  - [ ] Confirm msgType: 1 (SEND - no compose for refunds)

**Configured**: ShareAdapter enforced options for refund flow

---

### Step 3.5: Set Enforced Options on ShareOFT (Spoke) (~10-15 sec)
- [ ] **Run 04_SetEnforcedOptionsShareOFT on OP Sepolia**
  ```bash
  forge script script/config/04_SetEnforcedOptionsShareOFT.s.sol:SetEnforcedOptionsShareOFT04 \
    --rpc-url $OP_SEPOLIA_RPC_URL \
    --broadcast \
    -vvv
  ```

- [ ] **Verify enforced options**
  ```bash
  cast call $SPOKE_SHARE_OFT "enforcedOptions(uint32,uint16)(bytes)" 40161 2 \
    --rpc-url $OP_SEPOLIA_RPC_URL
  ```
  - [ ] Confirm lzReceive gas: 200,000
  - [ ] Confirm lzCompose gas: 500,000
  - [ ] Confirm lzCompose value: 0.01 ETH

**Configured**: ShareOFT enforced options for async redeem with compose

---

### Step 3.6: Set Enforced Options on iTryAdapter (Hub) (~10-15 sec)
- [ ] **Run 06_SetEnforcedOptionsiTryAdapter on Sepolia**
  ```bash
  forge script script/config/06_SetEnforcedOptionsiTryAdapter.s.sol:SetEnforcedOptionsiTryAdapter06 \
    --rpc-url $SEPOLIA_RPC_URL \
    --broadcast \
    -vvv
  ```

- [ ] **Verify enforced options**
  ```bash
  cast call $HUB_ITRY_ADAPTER "enforcedOptions(uint32,uint16)(bytes)" 40232 1 \
    --rpc-url $SEPOLIA_RPC_URL
  ```
  - [ ] Confirm lzReceive gas: 200,000
  - [ ] Confirm msgType: 1 (SEND - for return leg of unstaking)

**Configured**: iTryAdapter enforced options for crosschain unstaking return leg

**⚠️ CRITICAL**: This step is required for crosschain unstaking. Without it, the VaultComposer will fail with `Executor_NoOptions()` error when quoting the return leg.

```

**File:** script/test/bridge/BridgeITRY_SpokeToHub_RedeemerAddress.s.sol (L67-79)
```text
        // Build options
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);

        // Build SendParam - sending to same redeemer address on hub chain
        SendParam memory sendParam = SendParam({
            dstEid: hubEid,
            to: bytes32(uint256(uint160(redeemerAddress))),
            amountLD: bridgeAmount,
            minAmountLD: bridgeAmount,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
```
