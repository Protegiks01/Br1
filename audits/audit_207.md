## Title
LayerZero Endpoint Blacklist Check in `_beforeTokenTransfer` Can Cause Complete DoS of Cross-Chain wiTRY Receives

## Summary
The `wiTryOFT._beforeTokenTransfer` hook checks if `msg.sender` is blacklisted without special handling for LayerZero endpoint operations. During cross-chain receives, `msg.sender` is the LayerZero endpoint. If the endpoint is accidentally blacklisted, all cross-chain receives will permanently fail, breaking the protocol's cross-chain functionality.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** The `_beforeTokenTransfer` hook should prevent blacklisted users from transferring wiTRY OFT tokens on the spoke chain. It should allow LayerZero's internal operations (minting during cross-chain receives) to proceed regardless of user blacklist status, while the `_credit` override handles blacklisted recipients by redirecting funds to the owner.

**Actual Logic:** The hook checks if `msg.sender` is blacklisted at line 108 without distinguishing between user-initiated transfers and LayerZero system operations. During cross-chain receives, `msg.sender` is the LayerZero endpoint. If the endpoint is blacklisted (even accidentally), ALL cross-chain receives will revert.

**Exploitation Path:**
1. **Accidental Blacklisting**: Owner or blackLister accidentally blacklists the LayerZero endpoint address (could happen during bulk blacklist operations or through address confusion)
2. **User Initiates Cross-Chain Transfer**: User on hub chain sends wiTRY shares to spoke chain via LayerZero
3. **Message Delivery Fails**: When LayerZero endpoint attempts to deliver message on spoke chain:
   - Endpoint calls `lzReceive` → `_credit` → `_mint(recipient, amount)`
   - `_mint` triggers `_beforeTokenTransfer(address(0), recipient, amount)`
   - Line 108: `if (blackList[msg.sender]) revert BlackListed(msg.sender);` where `msg.sender = endpoint`
   - Transaction reverts with `BlackListed(endpoint)` error
4. **Complete DoS**: ALL subsequent cross-chain receives fail until endpoint is removed from blacklist

**Security Property Broken:** Violates Cross-chain Message Integrity invariant: "LayerZero messages for unstaking must be delivered to correct user with proper validation." The protocol's cross-chain functionality becomes completely non-functional due to an admin configuration error.

**Comparison with iTryTokenOFT:** The sister contract `iTryTokenOFT` explicitly handles this scenario correctly: [2](#0-1) [3](#0-2) 

These lines allow the minter (LayerZero endpoint) to mint/burn tokens without checking if the minter itself is blacklisted. `wiTryOFT` lacks this critical safeguard.

## Impact Explanation
- **Affected Assets**: All wiTRY shares being bridged cross-chain become locked on the source chain (hub) if endpoint is blacklisted on destination (spoke)
- **Damage Severity**: 
  - Complete DoS of cross-chain wiTRY functionality
  - Users cannot bridge shares from hub to spoke chain
  - Funds locked in OFT adapters until endpoint is unblacklisted
  - Protocol's Layer 2 scaling strategy becomes non-functional
- **User Impact**: ALL users attempting cross-chain transfers are affected. Once endpoint is blacklisted, no cross-chain receives can complete until the issue is discovered and remediated.

## Likelihood Explanation
- **Attacker Profile**: No attacker needed - this is triggered by admin error
- **Preconditions**: 
  - LayerZero endpoint address is added to the blacklist mapping
  - Can happen accidentally during batch blacklist operations
  - Higher risk if blacklist addresses are imported from external sources without validation
- **Execution Complexity**: Single admin transaction accidentally blacklisting the endpoint
- **Frequency**: Once triggered, affects ALL subsequent cross-chain operations until fixed

## Recommendation

Add explicit handling for LayerZero endpoint operations in `_beforeTokenTransfer`, similar to `iTryTokenOFT`:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, function _beforeTokenTransfer, lines 105-110:

// CURRENT (vulnerable):
function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
    if (blackList[_from]) revert BlackListed(_from);
    if (blackList[_to]) revert BlackListed(_to);
    if (blackList[msg.sender]) revert BlackListed(msg.sender);
    super._beforeTokenTransfer(_from, _to, _amount);
}

// FIXED:
function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
    // Allow LayerZero endpoint to mint (receive from other chains) and burn (send to other chains)
    // This prevents DoS if endpoint is accidentally blacklisted
    address endpoint = this.endpoint();
    
    if (msg.sender == endpoint && _from == address(0) && !blackList[_to]) {
        // LayerZero minting operation (cross-chain receive) - allow if recipient not blacklisted
        // Note: _credit already handles blacklisted recipients by redirecting to owner
        return;
    } else if (msg.sender == endpoint && _to == address(0) && !blackList[_from]) {
        // LayerZero burning operation (cross-chain send) - allow if sender not blacklisted
        return;
    }
    
    // Standard blacklist checks for user-initiated transfers
    if (blackList[_from]) revert BlackListed(_from);
    if (blackList[_to]) revert BlackListed(_to);
    if (blackList[msg.sender]) revert BlackListed(msg.sender);
    
    super._beforeTokenTransfer(_from, _to, _amount);
}
```

**Alternative mitigation**: Add validation in `updateBlackList` to prevent blacklisting of the LayerZero endpoint address:

```solidity
function updateBlackList(address _user, bool _isBlackListed) external {
    if (msg.sender != blackLister && msg.sender != owner()) revert OnlyBlackLister();
    require(_user != this.endpoint(), "Cannot blacklist LayerZero endpoint");
    blackList[_user] = _isBlackListed;
    emit BlackListUpdated(_user, _isBlackListed);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_EndpointBlacklistDoS.t.sol
// Run with: forge test --match-test test_EndpointBlacklistCausesDoS -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_EndpointBlacklistDoS is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant INITIAL_DEPOSIT = 100 ether;
    uint256 constant SHARES_TO_BRIDGE = 50 ether;
    uint128 constant GAS_LIMIT = 200000;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_EndpointBlacklistCausesDoS() public {
        console.log("\n=== PoC: LayerZero Endpoint Blacklist Causes DoS ===\n");

        // SETUP: Mint iTRY and deposit into vault on Sepolia to get shares
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, INITIAL_DEPOSIT);
        
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaVault), INITIAL_DEPOSIT);
        sepoliaVault.deposit(INITIAL_DEPOSIT, userL1);
        console.log("Step 1: User deposited iTRY into vault, received shares:", INITIAL_DEPOSIT);

        // Approve adapter and prepare cross-chain transfer
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
        
        // Send shares cross-chain from Sepolia to OP Sepolia
        vm.recordLogs();
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        uint256 adapterShares = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        console.log("Step 2: Shares locked in adapter on Sepolia:", adapterShares);
        assertEq(adapterShares, SHARES_TO_BRIDGE, "Adapter should lock shares");

        // Capture the LayerZero message
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        console.log("Step 3: LayerZero message captured\n");

        // EXPLOIT: Blacklist the LayerZero endpoint on OP Sepolia
        vm.selectFork(opSepoliaForkId);
        address endpoint = OP_SEPOLIA_ENDPOINT;
        
        vm.prank(deployer);
        opSepoliaShareOFT.setBlackLister(deployer);
        
        vm.prank(deployer);
        opSepoliaShareOFT.updateBlackList(endpoint, true);
        
        bool isEndpointBlacklisted = opSepoliaShareOFT.blackList(endpoint);
        console.log("Step 4: LayerZero endpoint blacklisted on OP Sepolia:", isEndpointBlacklisted);
        assertEq(isEndpointBlacklisted, true, "Endpoint should be blacklisted");

        // VERIFY: Attempt to relay message - should fail due to endpoint being blacklisted
        console.log("\nStep 5: Attempting to relay message...");
        
        vm.expectRevert(
            abi.encodeWithSignature("BlackListed(address)", endpoint)
        );
        relayMessage(message);
        
        console.log("Step 6: Message relay REVERTED with BlackListed(endpoint) error\n");

        // Verify shares still locked on Sepolia, not minted on OP Sepolia
        vm.selectFork(sepoliaForkId);
        uint256 adapterSharesAfter = sepoliaVault.balanceOf(address(sepoliaShareAdapter));
        assertEq(adapterSharesAfter, SHARES_TO_BRIDGE, "Shares still locked in adapter");
        
        vm.selectFork(opSepoliaForkId);
        uint256 userL2Shares = opSepoliaShareOFT.balanceOf(userL2);
        assertEq(userL2Shares, 0, "No shares minted on OP Sepolia");
        
        console.log("=== VULNERABILITY CONFIRMED ===");
        console.log("- Shares locked on Sepolia:", adapterSharesAfter);
        console.log("- Shares minted on OP Sepolia:", userL2Shares);
        console.log("- Impact: Complete DoS of cross-chain wiTRY receives");
        console.log("- Root cause: _beforeTokenTransfer checks msg.sender (endpoint) blacklist");
        console.log("- Fix needed: Add explicit LayerZero endpoint handling like iTryTokenOFT");
    }
}
```

**Notes:**
- This vulnerability is distinct from the known Zellic issue about blacklisted users using allowances. That issue is about user-to-user transfers, while this is about LayerZero system operations.
- The `_credit` override at lines 84-97 attempts to handle blacklisted recipients by redirecting to owner, but this protection is bypassed if the endpoint itself is blacklisted (line 108 reverts before `_credit` logic even executes the mint).
- The fix should mirror `iTryTokenOFT`'s approach which explicitly allows the minter (endpoint) to perform mint/burn operations without checking the minter's own blacklist status.
- This is a design flaw rather than an exploitable attack, but it represents a critical availability risk that violates the protocol's cross-chain integrity guarantees.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L105-110)
```text
    function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
        if (blackList[_from]) revert BlackListed(_from);
        if (blackList[_to]) revert BlackListed(_to);
        if (blackList[msg.sender]) revert BlackListed(msg.sender);
        super._beforeTokenTransfer(_from, _to, _amount);
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L143-146)
```text
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L158-161)
```text
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```
