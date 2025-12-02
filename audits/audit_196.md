## Title
Cross-Chain Share Precision Loss Due to LayerZero Shared Decimals Mismatch

## Summary
The `wiTryOFT` and `wiTryOFTAdapter` contracts do not override LayerZero's default `sharedDecimals()` function, causing systematic precision loss during cross-chain share transfers. While wiTRY shares use 18 decimals, LayerZero's default shared decimals of 6 truncates amounts during cross-chain messaging, resulting in users losing up to 999,999,999,999 wei per transfer.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFT.sol` (entire contract, particularly the inherited OFT decimal conversion logic) and `src/token/wiTRY/crosschain/wiTryOFTAdapter.sol`

**Intended Logic:** wiTRY shares should be transferred cross-chain without any loss, preserving the exact share amount. [1](#0-0) 

**Actual Logic:** LayerZero OFT V2 uses a default `sharedDecimals` value of 6 decimals for cross-chain message normalization. Since neither `wiTryOFT` [2](#0-1)  nor `wiTryOFTAdapter` [3](#0-2)  override this function, the conversion process is:

1. Hub chain: `amountLD` (18 decimals) → `amountSD` (6 decimals) via division by 10^12
2. Spoke chain: `amountSD` (6 decimals) → `amountLD` (18 decimals) via multiplication by 10^12

Any share amount not divisible by 10^12 wei loses precision in step 1 (integer division truncation), which is not recovered in step 2.

**Exploitation Path:**
1. User bridges 1.000000000001 wiTRY shares (1,000,000,000,001 wei) from hub to spoke chain
2. LayerZero's `_debit` converts: 1,000,000,000,001 ÷ 10^12 = 1 (rounded down, loses 1 wei)
3. LayerZero message carries amountSD = 1 (in shared decimals)
4. On spoke chain, `_credit` receives: 1 × 10^12 = 1,000,000,000,000 wei [4](#0-3) 
5. User receives 1,000,000,000,000 wei instead of 1,000,000,000,001 wei (1 wei lost)

**Security Property Broken:** Tests explicitly verify "no shares lost during transfers" [5](#0-4) , but this invariant is violated for any non-aligned amounts.

## Impact Explanation
- **Affected Assets**: wiTRY shares bridged cross-chain
- **Damage Severity**: Users lose up to 999,999,999,999 wei (approximately 10^-6 shares) per cross-chain transfer. While individual loss is small (~$0.000001 if 1 share = $1), it's systematic and accumulates over all users and transactions. Lost shares remain locked in the adapter contract on the hub chain.
- **User Impact**: Any user bridging shares with precision below 10^12 wei experiences loss. With high transaction volume, the accumulated locked shares could become significant.

## Likelihood Explanation
- **Attacker Profile**: Any user performing cross-chain share transfers (no special permissions required)
- **Preconditions**: Share amount must not be perfectly divisible by 10^12 wei (affects most real-world amounts)
- **Execution Complexity**: Single cross-chain transaction via standard OFT send
- **Frequency**: Occurs on every cross-chain transfer where `amount % 10^12 != 0`

## Recommendation

Both contracts should override `sharedDecimals()` to match the token's 18 decimals, eliminating the conversion:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol, add:

/**
 * @dev Override to use 18 shared decimals (matching wiTRY token decimals)
 * This prevents precision loss during cross-chain transfers
 */
function sharedDecimals() public pure override returns (uint8) {
    return 18;
}
```

```solidity
// In src/token/wiTRY/crosschain/wiTryOFTAdapter.sol, add:

/**
 * @dev Override to use 18 shared decimals (matching wiTRY token decimals)
 * This prevents precision loss during cross-chain transfers
 */
function sharedDecimals() public view override returns (uint8) {
    return 18;
}
```

**Alternative mitigation:** If different chains must use different decimals, implement explicit rounding handling and document the expected precision loss to users.

## Proof of Concept

```solidity
// File: test/Exploit_SharePrecisionLoss.t.sol
// Run with: forge test --match-test test_SharePrecisionLoss -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {SendParam, MessagingFee} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_SharePrecisionLoss is CrossChainTestBase {
    using OptionsBuilder for bytes;

    function setUp() public override {
        super.setUp();
        deployAllContracts();
    }

    function test_SharePrecisionLoss() public {
        // SETUP: Mint iTRY and deposit to get shares on hub chain
        vm.selectFork(sepoliaForkId);
        
        uint256 initialDeposit = 100 ether;
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, initialDeposit);
        
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaVault), initialDeposit);
        sepoliaVault.deposit(initialDeposit, userL1);
        vm.stopPrank();
        
        // EXPLOIT: Bridge non-aligned amount (not divisible by 10^12)
        // Using 50 ether + 1 wei = 50000000000000000001 wei
        uint256 sharesToBridge = 50 ether + 1;
        
        vm.startPrank(userL1);
        sepoliaVault.approve(address(sepoliaShareAdapter), sharesToBridge);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(200000, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL2))),
            amountLD: sharesToBridge,
            minAmountLD: sharesToBridge - 999999999999, // Allow up to 10^12-1 wei loss
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaShareAdapter.quoteSend(sendParam, false);
        vm.recordLogs();
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // Relay message to spoke chain
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        // VERIFY: Precision loss occurred
        vm.selectFork(opSepoliaForkId);
        uint256 receivedShares = opSepoliaShareOFT.balanceOf(userL2);
        
        console.log("Shares sent:", sharesToBridge);
        console.log("Shares received:", receivedShares);
        console.log("Precision lost:", sharesToBridge - receivedShares);
        
        // User should receive exactly what they sent, but due to decimal conversion they receive less
        assertLt(receivedShares, sharesToBridge, "Precision loss should occur");
        assertEq(receivedShares, 50 ether, "Should truncate to 50 ether exactly");
        assertEq(sharesToBridge - receivedShares, 1, "Should lose exactly 1 wei");
    }
}
```

## Notes

- The vulnerability stems from LayerZero V2 OFT's default `sharedDecimals` of 6, designed to reduce cross-chain message costs. However, for high-precision tokens like wiTRY shares (18 decimals), this creates systematic precision loss.

- The test suite only uses round amounts (100 ether, 50 ether) that are perfectly divisible by 10^12, masking this issue in testing. Real-world usage with fractional share amounts will trigger the loss.

- The `_credit` function itself doesn't cause the issue—it correctly handles the `_amountLD` it receives. However, that amount has already been truncated by LayerZero's decimal conversion before `_credit` is invoked.

- This is distinct from the known "dust amount" issues mentioned in fuzzing tests, which deal with amounts < 1e6 wei. This vulnerability affects amounts up to 10^12 wei (1 million times larger).

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L214-216)
```text
    function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
        return 18;
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L28-54)
```text
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

**File:** test/crosschainTests/crosschain/Step8_ShareBridging.t.sol (L500-501)
```text
        console.log("  [OK] No shares lost during transfers");
        console.log("  [OK] Mathematical invariant maintained");
```
