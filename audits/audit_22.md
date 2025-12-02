# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the YieldForwarder contract's ETH handling mechanism, I conclude that **no exploitable vulnerability exists**. Here's why:

### How ETH Can Arrive

The YieldForwarder contract has no payable functions, no `receive()`, and no `fallback()` functions [1](#0-0) . ETH can only arrive through force-send mechanisms:
- Selfdestruct from another contract
- COINBASE/block rewards (theoretical)

### rescueToken Implementation Analysis

The `rescueToken` function correctly handles ETH rescue at lines 160-163 [2](#0-1) :
- Uses `onlyOwner` modifier for access control [3](#0-2) 
- Protected by `nonReentrant` guard [3](#0-2) 
- Validates recipient address and amount [4](#0-3) 
- Uses low-level call with success check [5](#0-4) 

### Protocol Impact Assessment

The contract's core functionality only deals with `yieldToken` (iTRY) [6](#0-5) . The `processNewYield` function transfers yield tokens to the recipient [7](#0-6) , with no dependency on ETH balance.

### Griefing Scenario Analysis

While an attacker could force-send ETH via selfdestruct:
- **Cost to attacker**: ~50k+ gas for contract deployment and selfdestruct
- **Cost to defender**: ~30k gas for one `rescueToken` call
- **Impact**: None - no protocol disruption, fund loss, or DOS
- **Severity**: Does not meet Medium/High criteria (no significant loss, no fund theft, no invariant violation)

### Intentional Design

The test suite includes comprehensive ETH rescue tests [8](#0-7) , confirming this is intentional defensive programming, not an oversight.

## Notes

The `rescueToken` function's ETH handling capability is a **security feature**, not a vulnerability. It provides a recovery mechanism for edge cases where ETH arrives via force-send methods that bypass normal payable checks. This is considered best practice in smart contract development to prevent permanent fund loss.

### Citations

**File:** src/protocol/YieldForwarder.sol (L27-28)
```text
contract YieldForwarder is IYieldProcessor, Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
```

**File:** src/protocol/YieldForwarder.sol (L35-35)
```text
    IERC20 public immutable yieldToken;
```

**File:** src/protocol/YieldForwarder.sol (L97-107)
```text
    function processNewYield(uint256 _newYieldAmount) external override {
        if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
        if (yieldRecipient == address(0)) revert RecipientNotSet();

        // Transfer yield tokens to the recipient
        if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
            revert CommonErrors.TransferFailed();
        }

        emit YieldForwarded(yieldRecipient, _newYieldAmount);
    }
```

**File:** src/protocol/YieldForwarder.sol (L156-156)
```text
    function rescueToken(address token, address to, uint256 amount) external onlyOwner nonReentrant {
```

**File:** src/protocol/YieldForwarder.sol (L157-158)
```text
        if (to == address(0)) revert CommonErrors.ZeroAddress();
        if (amount == 0) revert CommonErrors.ZeroAmount();
```

**File:** src/protocol/YieldForwarder.sol (L160-163)
```text
        if (token == address(0)) {
            // Rescue ETH
            (bool success,) = to.call{value: amount}("");
            if (!success) revert CommonErrors.TransferFailed();
```

**File:** test/YieldForwarder.t.sol (L268-296)
```text
    /// @notice Tests that rescueToken rescues ETH successfully
    function test_rescueToken_whenETH_rescuesETH() public {
        // Arrange: Send ETH to forwarder
        address to = makeAddr("to");
        uint256 amount = 1 ether;
        vm.deal(address(forwarder), amount);

        uint256 toBalanceBefore = to.balance;

        // Act
        vm.prank(owner);
        forwarder.rescueToken(address(0), to, amount);

        // Assert
        assertEq(to.balance, toBalanceBefore + amount, "ETH should be rescued");
    }

    /// @notice Tests that rescueToken emits TokensRescued event for ETH
    function test_rescueToken_whenETH_emitsEvent() public {
        address to = makeAddr("to");
        uint256 amount = 1 ether;
        vm.deal(address(forwarder), amount);

        vm.expectEmit(true, true, false, true);
        emit TokensRescued(address(0), to, amount);

        vm.prank(owner);
        forwarder.rescueToken(address(0), to, amount);
    }
```
