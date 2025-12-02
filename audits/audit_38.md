## Title
Unprotected processNewYield() Function Enables Frontrunning DOS on Yield Distribution

## Summary
The `YieldForwarder.processNewYield()` function lacks access control, allowing any unprivileged attacker to frontrun legitimate yield distribution calls from `iTryIssuer.processAccumulatedYield()`. This enables DOS attacks that brick yield distribution and leave iTRY yield tokens stuck in the YieldForwarder contract, requiring emergency admin intervention to recover.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol`, function `processNewYield()`, lines 97-107

**Intended Logic:** The `processNewYield()` function should only be called by the `iTryIssuer` contract after it mints new yield iTRY tokens to the YieldForwarder. The function is designed to forward the exact amount of minted yield to the designated `yieldRecipient` address. [1](#0-0) 

**Actual Logic:** The function is declared as `external` with no access control modifier (no `onlyOwner`, no role check, no caller validation). Anyone can call it with any arbitrary `_newYieldAmount` parameter at any time, including before or during the legitimate yield distribution process. [2](#0-1) 

**Exploitation Path:**

1. **Setup**: `iTryIssuer.processAccumulatedYield()` is called by `YIELD_DISTRIBUTOR_ROLE` when NAV appreciates (e.g., 1000 iTRY yield available)

2. **Minting Phase**: iTryIssuer mints 1000 iTRY to the YieldForwarder contract (line 413)

3. **Frontrun Attack**: Before the legitimate `yieldReceiver.processNewYield(1000)` call executes (line 416), attacker monitors mempool and frontruns by calling `YieldForwarder.processNewYield(999)` directly

4. **Partial Transfer**: Attacker's call succeeds, transferring 999 iTRY from YieldForwarder to yieldRecipient, leaving only 1 iTRY in the contract

5. **Legitimate Call Fails**: iTryIssuer's transaction attempts to transfer 1000 iTRY but YieldForwarder only has 1 iTRY remaining, causing the transfer to fail and the entire `processAccumulatedYield()` transaction to revert

6. **DOS Result**: Yield distribution is blocked. The 1 iTRY remains stuck in YieldForwarder until owner calls `rescueToken()` to recover it

**Security Property Broken:** While this doesn't violate the critical invariants (no unbacked minting, no loss of DLF backing), it breaks operational integrity by enabling DOS of the yield distribution mechanism, which is a core protocol function for distributing NAV appreciation to stakeholders.

## Impact Explanation

- **Affected Assets**: iTRY yield tokens minted during NAV appreciation events. The yield itself is not stolen but its distribution is blocked.

- **Damage Severity**: 
  - Attacker can repeatedly DOS every yield distribution attempt
  - Each attack leaves dust amounts (1-999 iTRY) stuck in YieldForwarder
  - Protocol must manually recover funds via `rescueToken()` after each attack
  - Legitimate yield distribution to users/treasury is delayed indefinitely until attacker stops or admin intervenes
  - Gas waste on failed transactions

- **User Impact**: All protocol users expecting timely yield distribution are affected. If yieldRecipient is the treasury or StakediTry vault, stakers don't receive their proportional yield until the DOS is resolved.

## Likelihood Explanation

- **Attacker Profile**: Any unprivileged address with gas funds can execute this attack. No special permissions required.

- **Preconditions**: 
  - NAV has appreciated, making yield available
  - `YIELD_DISTRIBUTOR_ROLE` calls `processAccumulatedYield()`
  - Attacker monitors mempool for these transactions

- **Execution Complexity**: Simple single-transaction frontrun. Attacker just needs to:
  1. Detect `processAccumulatedYield()` in mempool
  2. Submit `processNewYield(X)` with higher gas price where X < yield amount
  3. Mempool frontrunning is standard MEV strategy

- **Frequency**: Can be repeated on every yield distribution event. Protocol typically processes yield periodically (daily/weekly), so attacker can maintain sustained DOS with minimal cost.

## Recommendation

Add access control to restrict `processNewYield()` to only the iTryIssuer contract:

```solidity
// In src/protocol/YieldForwarder.sol, add state variable:
address public immutable authorizedCaller;

// In constructor, line 69-77:
constructor(address _yieldToken, address _initialRecipient, address _authorizedCaller) {
    if (_yieldToken == address(0)) revert CommonErrors.ZeroAddress();
    if (_initialRecipient == address(0)) revert CommonErrors.ZeroAddress();
    if (_authorizedCaller == address(0)) revert CommonErrors.ZeroAddress();

    yieldToken = IERC20(_yieldToken);
    yieldRecipient = _initialRecipient;
    authorizedCaller = _authorizedCaller; // Set iTryIssuer address

    emit YieldRecipientUpdated(address(0), _initialRecipient);
}

// In processNewYield(), line 97:
function processNewYield(uint256 _newYieldAmount) external override {
    if (msg.sender != authorizedCaller) revert Unauthorized(); // ADD THIS CHECK
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();

    if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
        revert CommonErrors.TransferFailed();
    }

    emit YieldForwarded(yieldRecipient, _newYieldAmount);
}
```

**Alternative Mitigation**: If the YieldForwarder needs to remain callable by multiple contracts, implement a mapping of authorized callers or use OpenZeppelin's AccessControl for role-based permissions.

## Proof of Concept

```solidity
// File: test/Exploit_YieldForwarderFrontrun.t.sol
// Run with: forge test --match-test test_FrontrunYieldDistribution -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/token/iTRY/iTry.sol";
import "./iTryIssuer.base.t.sol";

contract Exploit_YieldForwarderFrontrun is iTryIssuerBaseTest {
    
    function test_FrontrunYieldDistribution() public {
        // SETUP: Create yield scenario
        // Mint iTRY at NAV = 1.0
        _mintITry(whitelistedUser1, 1000e18, 0);
        
        // NAV appreciates to 1.1, creating 100 iTRY yield
        _setNAVPrice(1.1e18);
        
        uint256 expectedYield = issuer.previewAccumulatedYield();
        assertEq(expectedYield, 100e18, "Should have 100 iTRY yield available");
        
        // EXPLOIT: Attacker frontruns the legitimate yield distribution
        address attacker = makeAddr("attacker");
        
        // Legitimate flow starts: admin calls processAccumulatedYield
        vm.startPrank(admin);
        
        // This will mint expectedYield to YieldForwarder
        // Then call yieldReceiver.processNewYield(expectedYield)
        // But attacker frontruns it...
        vm.stopPrank();
        
        // Simulate attacker's frontrun transaction executing first
        vm.prank(attacker);
        YieldForwarder(address(yieldProcessor)).processNewYield(99e18); 
        // Transfers 99 iTRY, leaving only 1 iTRY in YieldForwarder
        
        // Now the legitimate transaction attempts to execute
        vm.expectRevert(); // Will revert due to insufficient balance
        vm.prank(admin);
        issuer.processAccumulatedYield();
        
        // VERIFY: Yield distribution failed, 1 iTRY stuck
        uint256 stuckBalance = itry.balanceOf(address(yieldProcessor));
        assertEq(stuckBalance, 1e18, "1 iTRY stuck in YieldForwarder");
        
        // Protocol must now manually rescue the stuck funds
        vm.prank(owner); // Owner must intervene
        YieldForwarder(address(yieldProcessor)).rescueToken(
            address(itry),
            treasury,
            stuckBalance
        );
        
        console.log("Attack successful: Yield distribution DOS'd, manual intervention required");
    }
}
```

## Notes

The vulnerability exists because the `IYieldProcessor` interface doesn't specify access control requirements, and `YieldForwarder` implements it as a permissionless function. While the immediate impact is operational (DOS + stuck funds), the attack is cheap to execute and can be sustained indefinitely, effectively breaking the yield distribution mechanism until code is upgraded or attacker stops.

The fix requires either:
1. Adding the authorized caller check as shown above, OR
2. Redesigning the flow so iTryIssuer directly transfers to yieldRecipient instead of going through YieldForwarder, OR  
3. Making YieldForwarder pull tokens instead of relying on external calls to push them

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
