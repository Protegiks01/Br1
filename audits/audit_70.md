## Title
OFT Burn Mechanism Mismatch Allows Complete Bridge DOS via address(0) Blacklist

## Summary
The `_beforeTokenTransfer` logic in `iTryTokenOFT.sol` expects `msg.sender == minter` for burn operations [1](#0-0) , but when users call OFT `send()` to bridge tokens from spoke to hub, `msg.sender` is the user (not the minter/endpoint). Burns must fall through to the "normal case" check at line 151 which validates that all addresses including `to` (address(0)) are not blacklisted. If the owner accidentally or intentionally blacklists address(0), all OFT send operations will revert, causing permanent DOS of the spoke→hub bridge.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFT.sol` - `_beforeTokenTransfer()` function (lines 140-177)

**Intended Logic:** The minter check at line 143 [1](#0-0)  is designed to authorize burn operations during redemption, similar to the hub chain's iTry.sol implementation [2](#0-1) . On the hub chain, the iTryIssuer contract (which has MINTER_CONTRACT role) calls `_burn()`, making `msg.sender` the authorized minter during redemption [3](#0-2) .

**Actual Logic:** In LayerZero OFT architecture, when a user calls `send()` to bridge tokens from spoke to hub, the OFT contract's internal `_debit()` function burns tokens directly from the user's balance. During this burn operation in `_beforeTokenTransfer()`, `msg.sender` is the user who initiated the `send()` call, NOT the minter (endpoint address) [4](#0-3) . 

The minter check at line 143 can NEVER be satisfied during normal OFT operations. Instead, burns must pass through the "normal case" check at line 151 [5](#0-4) , which requires `!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]`. When burning, `to` is address(0), so this check validates that address(0) is not blacklisted.

**Exploitation Path:**
1. Owner calls `addBlacklistAddress([address(0)])` [6](#0-5)  to blacklist address(0) (this could be accidental or intentional)
2. User on spoke chain attempts to bridge iTRY back to hub by calling `send()` on iTryTokenOFT
3. OFT's `_debit()` calls `_burn(user, amount)` which triggers `_beforeTokenTransfer(user, address(0), amount)`
4. Minter check at line 143 fails because `msg.sender == user`, not minter
5. "Normal case" check at line 151 evaluates to `!blacklisted[user] && !blacklisted[user] && !blacklisted[address(0)]` = `false` (because address(0) is blacklisted)
6. Transaction reverts with `OperationNotAllowed()` [7](#0-6) 
7. ALL users are permanently unable to bridge tokens from spoke to hub, causing complete DOS

**Security Property Broken:** Violates **Cross-chain Message Integrity** invariant - LayerZero messages cannot be sent because token burns fail. Also violates **Blacklist Enforcement** invariant indirectly - the blacklist mechanism is being misapplied to address(0), breaking core OFT functionality.

## Impact Explanation
- **Affected Assets**: All iTRY tokens on spoke chains (OP Sepolia/MegaETH). Users cannot retrieve their tokens back to the hub chain.
- **Damage Severity**: Complete loss of bridging functionality from spoke to hub. All iTRY tokens on spoke chains become effectively locked and non-transferrable back to hub. This is a **permanent DOS** unless address(0) is removed from blacklist.
- **User Impact**: ALL users holding iTRY on spoke chains are affected. Any attempt to bridge tokens back to hub will fail. The test suite demonstrates this flow works currently [8](#0-7) , but would break if address(0) is blacklisted.

## Likelihood Explanation
- **Attacker Profile**: The owner/blacklist manager (trusted role). However, this vulnerability can manifest through **accidental misconfiguration** rather than malicious intent, making it a valid security concern.
- **Preconditions**: 
  1. iTRY OFT deployed on spoke chain
  2. Users holding iTRY tokens on spoke chain
  3. Owner blacklists address(0) (accidentally or due to misunderstanding of the system)
- **Execution Complexity**: Single transaction by owner to blacklist address(0). No complex attack choreography needed.
- **Frequency**: Once address(0) is blacklisted, EVERY subsequent OFT send operation fails. This is a systemic failure, not a per-user exploit.

## Recommendation

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, function _beforeTokenTransfer, lines 140-155:

// CURRENT (vulnerable):
function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
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
    }
    // ...
}

// FIXED:
function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
    if (transferState == TransferState.FULLY_ENABLED) {
        if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
            // redeeming via minter (not used in OFT but kept for consistency)
        } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
            // minting
        } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
            // redistributing - burn
        } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
            // redistributing - mint
        } else if (!blacklisted[msg.sender] && !blacklisted[from] && to == address(0)) {
            // User-initiated burn via OFT send() - validate user and from, but NOT to (address(0))
        } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
            // normal transfers
        } else {
            revert OperationNotAllowed();
        }
    }
    // ...
}
```

**Alternative Mitigation:** Add validation in `addBlacklistAddress()` to prevent address(0) from being blacklisted:

```solidity
function addBlacklistAddress(address[] calldata users) external onlyOwner {
    for (uint8 i = 0; i < users.length; i++) {
        require(users[i] != address(0), "Cannot blacklist zero address");
        if (whitelisted[users[i]]) whitelisted[users[i]] = false;
        blacklisted[users[i]] = true;
    }
}
```

## Proof of Concept

```solidity
// File: test/Exploit_OFTBurnDOS.t.sol
// Run with: forge test --match-test test_OFT_Burn_DOS_Via_ZeroAddress_Blacklist -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_OFTBurnDOS is CrossChainTestBase {
    using OptionsBuilder for bytes;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_OFT_Burn_DOS_Via_ZeroAddress_Blacklist() public {
        uint256 AMOUNT = 100 ether;
        uint128 GAS_LIMIT = 200000;
        
        // SETUP: Transfer iTRY from L1 to L2 (this works fine)
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, AMOUNT);
        
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaAdapter), AMOUNT);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL1))),
            amountLD: AMOUNT,
            minAmountLD: AMOUNT,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaAdapter.quoteSend(sendParam, false);
        vm.recordLogs();
        sepoliaAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        // Verify tokens are on L2
        vm.selectFork(opSepoliaForkId);
        assertEq(opSepoliaOFT.balanceOf(userL1), AMOUNT, "User should have tokens on L2");
        
        console.log("\n=== EXPLOIT: Owner blacklists address(0) ===");
        
        // EXPLOIT: Owner accidentally/intentionally blacklists address(0)
        address[] memory toBlacklist = new address[](1);
        toBlacklist[0] = address(0);
        
        vm.prank(deployer); // deployer is owner
        opSepoliaOFT.addBlacklistAddress(toBlacklist);
        
        console.log("address(0) is now blacklisted:", opSepoliaOFT.blacklisted(address(0)));
        
        // VERIFY: User cannot bridge back to L1 anymore
        console.log("\n=== Attempting to bridge back to L1 (should revert) ===");
        
        vm.startPrank(userL1);
        sendParam.dstEid = SEPOLIA_EID;
        fee = opSepoliaOFT.quoteSend(sendParam, false);
        
        // This will revert because _beforeTokenTransfer checks !blacklisted[to]
        // where to = address(0) during burn
        vm.expectRevert(bytes4(keccak256("OperationNotAllowed()")));
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("- address(0) blacklisted: ALL OFT burns fail");
        console.log("- Users CANNOT bridge tokens from L2 to L1");
        console.log("- Complete DOS of spoke->hub bridge");
        console.log("- Tokens effectively locked on spoke chain");
        
        // Verify tokens are still on L2 (couldn't be burned/bridged)
        assertEq(opSepoliaOFT.balanceOf(userL1), AMOUNT, "Tokens still locked on L2");
    }
}
```

## Notes

This vulnerability stems from a **design mismatch** between the hub chain implementation (`iTry.sol`) and spoke chain implementation (`iTryTokenOFT.sol`). The `_beforeTokenTransfer` logic was copied from the hub chain but doesn't account for the OFT architecture where users directly call `send()` to burn tokens, rather than going through a minter contract.

The WHITELIST_ENABLED mode has explicit handling for user-initiated burns at line 166 [9](#0-8) , but FULLY_ENABLED mode relies on the "normal case" which inappropriately includes address(0) in the blacklist check. This inconsistency indicates the minter check at line 143 is **dead code** in the OFT context - it can never execute during normal OFT send operations.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L53-53)
```text
        minter = _lzEndpoint;
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L70-74)
```text
    function addBlacklistAddress(address[] calldata users) external onlyOwner {
        for (uint8 i = 0; i < users.length; i++) {
            if (whitelisted[users[i]]) whitelisted[users[i]] = false;
            blacklisted[users[i]] = true;
        }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L143-144)
```text
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L151-152)
```text
            } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
                // normal case
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L154-154)
```text
                revert OperationNotAllowed();
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L166-167)
```text
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
```

**File:** src/token/iTRY/iTry.sol (L180-181)
```text
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
```

**File:** src/protocol/iTryIssuer.sol (L351-351)
```text
        _burn(msg.sender, iTRYAmount);
```

**File:** test/crosschainTests/crosschain/Step5_BasicOFTTransfer.t.sol (L201-213)
```text
        opSepoliaOFT.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();

        // Verify tokens burned on L2
        uint256 userL1BalanceAfterSendL2 = opSepoliaOFT.balanceOf(userL1);
        uint256 totalSupplyAfterSendL2 = opSepoliaOFT.totalSupply();

        console.log("\nAfter Send (OP Sepolia):");
        console.log("  userL1 balance:", userL1BalanceAfterSendL2);
        console.log("  Total supply:", totalSupplyAfterSendL2);

        assertEq(userL1BalanceAfterSendL2, 0, "User should have 0 iTRY on L2 after send");
        assertEq(totalSupplyAfterSendL2, 0, "Total supply on L2 should be 0 (burned)");
```
