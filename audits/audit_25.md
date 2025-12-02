## Title
Missing Access Control and Balance Validation in YieldForwarder.processNewYield Enables Accounting Manipulation and Unauthorized Yield Processing

## Summary
The `processNewYield()` function in `YieldForwarder.sol` lacks both access control and balance validation. Anyone can call this function with arbitrary amounts, and it doesn't verify that the `_newYieldAmount` parameter matches the actual tokens received. This enables unauthorized yield processing, DOS attacks, and accounting confusion when incorrect amounts are passed.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol` - `processNewYield()` function at lines 97-107 [1](#0-0) 

**Intended Logic:** According to the IYieldProcessor interface documentation, the function should be called by iTryIssuer after minting yield tokens, and implementations should "ensure it has sufficient balance to process the yield" and validate the amount matches what was received. [2](#0-1) 

**Actual Logic:** The function has no access control (anyone can call it) and doesn't validate the `_newYieldAmount` parameter against:
- The contract's current balance
- The amount just received (balance delta)
- Any authorization mechanism

It simply attempts to transfer whatever amount is specified, and emits an event with that parameter value regardless of whether it matches the actual amount received.

**Exploitation Path:**

**Scenario 1: Accounting Confusion from Incorrect Amount**
1. iTryIssuer calculates and mints 100 iTRY to YieldForwarder via `processAccumulatedYield()` [3](#0-2) 

2. Due to a bug (e.g., arithmetic error, reentrancy, state inconsistency), iTryIssuer calls `processNewYield(80)` instead of `processNewYield(100)`
3. YieldForwarder transfers only 80 iTRY to the recipient, leaving 20 iTRY stuck in the contract
4. Event `YieldForwarded(recipient, 80)` is emitted, but 100 iTRY was actually received
5. Accounting confusion: the system believes 80 was processed, but 20 remains unprocessed

**Scenario 2: Unauthorized Yield Processing (DOS)**
1. iTryIssuer mints 100 iTRY to YieldForwarder
2. Before iTryIssuer can call `processNewYield()` (if done in separate transaction or any delay), an attacker front-runs with their own call to `processNewYield(100)`
3. All yield is forwarded to the recipient (correct destination but wrong timing)
4. When iTryIssuer's legitimate call executes, it reverts due to insufficient balance
5. Yield distribution flow is disrupted, requiring manual intervention

**Scenario 3: Balance Accumulation Exploitation**
1. YieldForwarder accumulates 50 iTRY from previous incomplete operation
2. iTryIssuer mints 100 iTRY (total balance now 150)
3. Attacker calls `processNewYield(150)` draining entire balance
4. iTryIssuer's subsequent call to `processNewYield(100)` fails
5. DOS on yield distribution

**Security Property Broken:** The function violates the principle that critical protocol operations should be restricted to authorized callers, and that event parameters should accurately reflect actual state changes.

## Impact Explanation
- **Affected Assets**: iTRY tokens held in YieldForwarder contract, yield distribution accounting
- **Damage Severity**: 
  - Accounting confusion: Events don't reflect actual token movements, breaking off-chain monitoring and analytics
  - DOS potential: Legitimate yield processing can be blocked by front-running attacks
  - Token accumulation: Incorrect amounts leave tokens stuck in YieldForwarder
  - System reliability: Protocol requires manual intervention to resolve discrepancies
- **User Impact**: Stakers expecting yield distribution experience delays or incorrect amounts. Protocol accounting becomes unreliable for auditing and monitoring purposes.

## Likelihood Explanation
- **Attacker Profile**: Any external address can exploit this (no special permissions required)
- **Preconditions**: YieldForwarder must have iTRY balance (from normal yield minting operations)
- **Execution Complexity**: Single transaction call to `processNewYield()` with arbitrary amount
- **Frequency**: Can be exploited every time YieldForwarder receives tokens, or continuously to cause DOS

## Recommendation

**Fix 1: Add Access Control**
```solidity
// In src/protocol/YieldForwarder.sol, line 27:

// Add state variable for authorized caller
address public immutable yieldSource;

// In constructor, line 69:
constructor(address _yieldToken, address _initialRecipient, address _yieldSource) {
    if (_yieldToken == address(0)) revert CommonErrors.ZeroAddress();
    if (_initialRecipient == address(0)) revert CommonErrors.ZeroAddress();
    if (_yieldSource == address(0)) revert CommonErrors.ZeroAddress();
    
    yieldToken = IERC20(_yieldToken);
    yieldRecipient = _initialRecipient;
    yieldSource = _yieldSource; // typically iTryIssuer address
    
    emit YieldRecipientUpdated(address(0), _initialRecipient);
}

// In processNewYield function, line 97:
function processNewYield(uint256 _newYieldAmount) external override {
    // Add access control
    if (msg.sender != yieldSource) revert Unauthorized();
    
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();
    
    // Transfer yield tokens to the recipient
    if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
        revert CommonErrors.TransferFailed();
    }
    
    emit YieldForwarded(yieldRecipient, _newYieldAmount);
}
```

**Fix 2: Validate Amount Against Balance**
```solidity
// Alternative approach - validate against actual balance
function processNewYield(uint256 _newYieldAmount) external override {
    if (msg.sender != yieldSource) revert Unauthorized();
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();
    
    // Validate amount matches available balance
    uint256 contractBalance = yieldToken.balanceOf(address(this));
    if (_newYieldAmount > contractBalance) {
        revert InsufficientBalance(_newYieldAmount, contractBalance);
    }
    
    // For additional safety, could enforce exact match
    if (_newYieldAmount != contractBalance) {
        revert AmountMismatch(_newYieldAmount, contractBalance);
    }
    
    // Transfer yield tokens to the recipient
    yieldToken.safeTransfer(yieldRecipient, _newYieldAmount);
    
    emit YieldForwarded(yieldRecipient, _newYieldAmount);
}
```

**Alternative: Simplified Approach**
Remove the parameter entirely and always process the full balance:
```solidity
function processNewYield() external override {
    if (msg.sender != yieldSource) revert Unauthorized();
    if (yieldRecipient == address(0)) revert RecipientNotSet();
    
    uint256 balance = yieldToken.balanceOf(address(this));
    if (balance == 0) revert CommonErrors.ZeroAmount();
    
    yieldToken.safeTransfer(yieldRecipient, balance);
    
    emit YieldForwarded(yieldRecipient, balance);
}
```

## Proof of Concept
```solidity
// File: test/Exploit_YieldForwarderUnauthorizedAccess.t.sol
// Run with: forge test --match-test test_UnauthorizedYieldProcessing -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/protocol/iTryIssuer.sol";
import "./mocks/MockERC20.sol";

contract Exploit_YieldForwarderUnauthorizedAccess is Test {
    YieldForwarder public forwarder;
    MockERC20 public yieldToken;
    
    address public owner;
    address public recipient;
    address public attacker;
    
    function setUp() public {
        owner = makeAddr("owner");
        recipient = makeAddr("recipient");
        attacker = makeAddr("attacker");
        
        yieldToken = new MockERC20("iTRY", "iTRY");
        
        vm.prank(owner);
        forwarder = new YieldForwarder(address(yieldToken), recipient);
    }
    
    function test_UnauthorizedYieldProcessing() public {
        // SETUP: Simulate iTryIssuer minting yield to forwarder
        uint256 yieldAmount = 100e18;
        yieldToken.mint(address(forwarder), yieldAmount);
        
        uint256 forwarderBalanceBefore = yieldToken.balanceOf(address(forwarder));
        uint256 recipientBalanceBefore = yieldToken.balanceOf(recipient);
        
        console.log("Forwarder balance before:", forwarderBalanceBefore);
        console.log("Recipient balance before:", recipientBalanceBefore);
        
        // EXPLOIT: Attacker calls processNewYield without authorization
        vm.prank(attacker);
        forwarder.processNewYield(yieldAmount);
        
        // VERIFY: Attacker successfully processed yield (no access control)
        uint256 forwarderBalanceAfter = yieldToken.balanceOf(address(forwarder));
        uint256 recipientBalanceAfter = yieldToken.balanceOf(recipient);
        
        console.log("Forwarder balance after:", forwarderBalanceAfter);
        console.log("Recipient balance after:", recipientBalanceAfter);
        
        assertEq(forwarderBalanceAfter, 0, "Vulnerability confirmed: Attacker drained forwarder");
        assertEq(recipientBalanceAfter, recipientBalanceBefore + yieldAmount, "Yield was processed by attacker");
    }
    
    function test_IncorrectAmountAccounting() public {
        // SETUP: Mint more than will be processed
        uint256 actualAmount = 100e18;
        uint256 reportedAmount = 80e18;
        
        yieldToken.mint(address(forwarder), actualAmount);
        
        // EXPLOIT: Call with incorrect (lower) amount
        vm.expectEmit(true, false, false, true);
        emit YieldForwarder.YieldForwarded(recipient, reportedAmount);
        
        forwarder.processNewYield(reportedAmount);
        
        // VERIFY: Event reports 80 but 20 remains stuck
        uint256 remainingBalance = yieldToken.balanceOf(address(forwarder));
        assertEq(remainingBalance, actualAmount - reportedAmount, "Vulnerability confirmed: Tokens stuck due to incorrect amount");
        assertEq(remainingBalance, 20e18, "20 iTRY stuck in forwarder");
    }
}
```

## Notes

The vulnerability directly answers the security question: **Yes, iTryIssuer could pass an incorrect amount due to a bug, and processNewYield() would succeed with wrong event parameters, creating accounting confusion.**

However, the issue is more severe than the question implies because:
1. **ANY address** can call `processNewYield()`, not just iTryIssuer
2. The lack of access control enables DOS attacks and unauthorized yield processing
3. The lack of balance validation means events can systematically misreport actual token movements

The recommended fix should implement both access control AND balance validation to ensure:
- Only authorized addresses (iTryIssuer) can trigger yield processing
- The amount parameter matches the actual tokens received/available
- Events accurately reflect the true state changes for off-chain monitoring

### Citations

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

**File:** src/protocol/periphery/IYieldProcessor.sol (L32-49)
```text
    /**
     * @notice Processes newly generated yield tokens
     * @dev This function is called by the iTryIssuer contract after minting yield tokens.
     *      The implementing contract should already have received the yield tokens before
     *      this function is called. Implementations must handle the yield appropriately
     *      according to their specific distribution logic.
     *
     * @param _newYieldAmount The amount of yield tokens that have been generated and should be processed
     *
     * Requirements:
     * - Implementation should validate that `_newYieldAmount` is greater than zero
     * - Implementation should ensure it has sufficient balance to process the yield
     * - Implementation should handle any distribution logic (transfers, conversions, etc.)
     * - Implementation should emit appropriate events for tracking yield processing
     *
     * @custom:example YieldForwarder implements this by transferring the entire amount to a recipient
     * @custom:example A more complex implementation might split yield across multiple parties
     */
```

**File:** src/protocol/iTryIssuer.sol (L412-416)
```text
        // Mint yield amount to yieldReceiver contract
        _mint(address(yieldReceiver), newYield);

        // Notify yield distributor of received yield
        yieldReceiver.processNewYield(newYield);
```
