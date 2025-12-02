## Title
Yield Distribution DOS Due to iTRY Transfer Restrictions in YieldForwarder

## Summary
The `YieldForwarder.processNewYield()` function can be permanently blocked when iTRY token transfer restrictions are applied, preventing yield distribution to stakers. While the question asks about pausable recipients, the actual vulnerability stems from iTRY's blacklist/whitelist mechanisms and transfer state controls that can cause the yield transfer to revert.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol` (function `processNewYield`, lines 97-107) and `src/token/iTRY/iTry.sol` (function `_beforeTokenTransfer`, lines 177-222)

**Intended Logic:** When `processNewYield()` is called by iTryIssuer after minting yield, the YieldForwarder should transfer iTRY tokens to the `yieldRecipient` (StakediTry) to distribute yield to stakers. [1](#0-0) 

**Actual Logic:** The transfer can fail and revert when iTRY token's transfer restrictions are active. The iTRY token enforces transfer controls through its `_beforeTokenTransfer` hook, which validates:
- In `WHITELIST_ENABLED` state: ALL of `msg.sender`, `from`, and `to` must be whitelisted
- In `FULLY_ENABLED` state: None of `msg.sender`, `from`, or `to` can be blacklisted  
- In `FULLY_DISABLED` state: ALL transfers are blocked [2](#0-1) 

When YieldForwarder calls `yieldToken.transfer(yieldRecipient, amount)`, the validation checks:
- `msg.sender` = YieldForwarder contract
- `from` = YieldForwarder contract (token holder)
- `to` = StakediTry contract (yieldRecipient)

**Exploitation Path:**
1. Admin legitimately changes iTRY transfer state to `WHITELIST_ENABLED` for regulatory compliance using `updateTransferState()` [3](#0-2) 

2. YieldForwarder or StakediTry contracts are not added to the whitelist (common oversight for infrastructure contracts)

3. iTryIssuer's `processAccumulatedYield()` is called by YIELD_DISTRIBUTOR_ROLE:
   - Mints iTRY to YieldForwarder
   - Calls `yieldReceiver.processNewYield(newYield)` [4](#0-3) 

4. YieldForwarder attempts to transfer iTRY to StakediTry, but `_beforeTokenTransfer` reverts at line 216 because YieldForwarder/StakediTry lack `WHITELISTED_ROLE` [5](#0-4) 

5. Entire yield distribution transaction reverts, blocking all future yield distribution until addresses are whitelisted

**Security Property Broken:** Protocol invariant that yield generated from DLF custody should be distributable to wiTRY stakers is violated. Stakers cannot receive earned yield despite it being legitimately generated.

## Impact Explanation
- **Affected Assets**: iTRY yield tokens stuck in YieldForwarder, wiTRY stakers unable to receive earned yield
- **Damage Severity**: Complete DOS of yield distribution mechanism. Stakers do not receive yield until admin intervention (adding contracts to whitelist or reverting transfer state). Yield accumulates in YieldForwarder but cannot be distributed.
- **User Impact**: ALL wiTRY stakers are affected. They cannot receive protocol yield during the DOS period. The issue triggers whenever legitimate transfer restrictions are applied without whitelisting infrastructure contracts.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a design flaw triggered by legitimate admin operations
- **Preconditions**: 
  - iTRY `transferState` is changed to `WHITELIST_ENABLED` (regulatory requirement)
  - YieldForwarder or StakediTry are not whitelisted (infrastructure oversight)
  - Alternatively: Either contract is blacklisted, or `transferState` is set to `FULLY_DISABLED`
- **Execution Complexity**: Occurs automatically on next `processAccumulatedYield()` call after transfer restrictions are applied
- **Frequency**: Persists until admin manually whitelists contracts or removes restrictions

## Recommendation
Modify `YieldForwarder.processNewYield()` to handle transfer failures gracefully with a fallback mechanism:

```solidity
// In src/protocol/YieldForwarder.sol, function processNewYield, line 97-107:

// CURRENT (vulnerable):
// Direct transfer that reverts on failure, blocking entire yield distribution

// FIXED:
function processNewYield(uint256 _newYieldAmount) external override {
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();

    // Attempt transfer with try-catch to handle transfer restrictions gracefully
    try yieldToken.transfer(yieldRecipient, _newYieldAmount) returns (bool success) {
        if (!success) revert CommonErrors.TransferFailed();
        emit YieldForwarded(yieldRecipient, _newYieldAmount);
    } catch {
        // If transfer fails due to restrictions, emit event for admin awareness
        // Yield remains in contract and can be rescued or retried after fixing restrictions
        emit YieldTransferFailed(yieldRecipient, _newYieldAmount);
    }
}
```

**Alternative mitigation:** Ensure YieldForwarder and StakediTry contracts are permanently added to iTRY whitelist during deployment, with documentation requiring whitelist inclusion before any transfer state changes.

## Proof of Concept
```solidity
// File: test/Exploit_YieldDistributionDOS.t.sol
// Run with: forge test --match-test test_YieldDistributionDOSWithWhitelist -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/wiTRY/StakediTry.sol";

contract Exploit_YieldDistributionDOS is Test {
    iTryIssuer issuer;
    iTry itry;
    StakediTry stakediTry;
    YieldForwarder yieldForwarder;
    
    address admin = address(0x1);
    address whitelistManager = address(0x2);
    address yieldDistributor = address(0x3);
    
    function setUp() public {
        // Deploy contracts
        vm.startPrank(admin);
        itry = new iTry();
        itry.initialize(admin, address(issuer));
        
        stakediTry = new StakediTry(IERC20(address(itry)), admin, admin);
        yieldForwarder = new YieldForwarder(address(itry), address(stakediTry));
        
        // Grant roles
        itry.grantRole(itry.WHITELIST_MANAGER_ROLE(), whitelistManager);
        issuer.grantRole(issuer._YIELD_DISTRIBUTOR_ROLE(), yieldDistributor);
        vm.stopPrank();
    }
    
    function test_YieldDistributionDOSWithWhitelist() public {
        // SETUP: Mint some iTRY to YieldForwarder to simulate yield
        vm.prank(admin);
        itry.mint(address(yieldForwarder), 1000 ether);
        
        // Admin changes transfer state to WHITELIST_ENABLED for regulatory compliance
        vm.prank(admin);
        itry.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // YieldForwarder and StakediTry are NOT whitelisted (oversight)
        
        // EXPLOIT: Attempt to process yield distribution
        vm.prank(yieldDistributor);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        yieldForwarder.processNewYield(1000 ether);
        
        // VERIFY: Yield is stuck in YieldForwarder, cannot be distributed
        assertEq(itry.balanceOf(address(yieldForwarder)), 1000 ether, "Yield stuck in YieldForwarder");
        assertEq(itry.balanceOf(address(stakediTry)), 0, "StakediTry received no yield");
    }
}
```

## Notes
While the question specifically asks about "pausable" recipient contracts, StakediTry does not implement any pause functionality. However, the actual vulnerability is more severe - it stems from iTRY token's built-in transfer restrictions (`WHITELIST_ENABLED`, `FULLY_DISABLED` states, and blacklisting) that create the same DOS effect.

The issue arises because `YieldForwarder` is designed as a simple passthrough forwarder without any error handling for transfer failures. When legitimate regulatory controls are applied to iTRY (whitelist-only transfers or full transfer disable), infrastructure contracts like YieldForwarder and StakediTry can be inadvertently blocked from transfers, preventing yield distribution entirely.

This is not a malicious admin attack but a design flaw where normal protocol operations (transfer restrictions for compliance) can inadvertently break critical functionality (yield distribution). Recovery requires admin intervention to whitelist infrastructure contracts or temporarily disable restrictions.

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

**File:** src/token/iTRY/iTry.sol (L171-175)
```text
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L177-222)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
        }
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
