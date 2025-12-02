## Title
Direct iTRY Token Burns Bypass iTryIssuer Accounting and Permanently Lock DLF Collateral

## Summary
Users can directly call `burn()` or `burnFrom()` on the iTry token contract, bypassing the iTryIssuer redemption flow. This decreases the iTry token supply but does not update iTryIssuer's internal accounting (`_totalIssuedITry`) or release DLF from custody, permanently locking collateral and breaking the core supply tracking invariant.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (lines 15, 177-222) and `src/protocol/iTryIssuer.sol` (lines 587-591)

**Intended Logic:** Users should only burn iTRY tokens through iTryIssuer's `redeemFor()` function, which properly decrements `_totalIssuedITry`, decreases `_totalDLFUnderCustody`, and transfers DLF back to the user.

**Actual Logic:** The iTry contract inherits from `ERC20BurnableUpgradeable`, providing public `burn()` and `burnFrom()` functions. The `_beforeTokenTransfer` hook allows direct burns in two scenarios:

1. **FULLY_ENABLED state**: Non-blacklisted users can burn (lines 189-193 allow transfers when `to == address(0)`) [1](#0-0) 

2. **WHITELIST_ENABLED state**: Whitelisted users can explicitly burn (lines 208-209) [2](#0-1) 

When users directly burn iTRY tokens, iTryIssuer is never notified, leaving its accounting variables unchanged.

**Exploitation Path:**
1. User holds iTRY tokens (obtained via legitimate minting through iTryIssuer)
2. In FULLY_ENABLED state: User calls `iTry.burn(amount)` directly on the iTry token contract
3. iTry's `totalSupply()` decreases by `amount` (standard ERC20 burn behavior)
4. iTryIssuer's `_totalIssuedITry` remains unchanged (no callback to iTryIssuer) [3](#0-2) 
5. iTryIssuer's `_totalDLFUnderCustody` remains unchanged (DLF stays locked)
6. User permanently loses iTRY tokens without receiving DLF back

**Security Property Broken:** 
- **Critical Invariant Violation**: "Total issued iTRY in iTryIssuer MUST ALWAYS equal iTRY token's totalSupply" 
- The invariant test explicitly verifies this: [4](#0-3) 

## Impact Explanation
- **Affected Assets**: iTRY tokens and DLF collateral
- **Damage Severity**: 
  - Users who directly burn lose 100% of burned iTRY value without receiving DLF
  - DLF collateral backing those tokens remains permanently locked in custody
  - Over time, accumulated locked DLF grows with each direct burn
  - System's core accounting becomes permanently corrupted: `getTotalIssuedITry() > totalSupply()`
- **User Impact**: Any non-blacklisted user (FULLY_ENABLED state) or any whitelisted user (WHITELIST_ENABLED state) who mistakenly calls `burn()` instead of `redeemFor()` permanently loses funds

## Likelihood Explanation
- **Attacker Profile**: Not malicious intent required - any regular user can accidentally trigger this by calling the wrong function
- **Preconditions**: 
  - FULLY_ENABLED state (default operational mode) OR WHITELIST_ENABLED state
  - User has iTRY balance
  - No special roles or permissions required
- **Execution Complexity**: Single transaction calling `iTry.burn(amount)`
- **Frequency**: Can occur every time any user mistakes `burn()` for redemption, or uses a wallet interface that exposes the burn function

## Recommendation

**Option 1 (Recommended): Override burn functions to prevent direct burns**

```solidity
// In src/token/iTRY/iTry.sol, add after line 222:

/**
 * @notice Override burn to prevent direct burns - users must redeem through iTryIssuer
 * @dev This ensures DLF custody accounting remains synchronized
 */
function burn(uint256) public pure override {
    revert OperationNotAllowed();
}

/**
 * @notice Override burnFrom to prevent direct burns - users must redeem through iTryIssuer  
 * @dev This ensures DLF custody accounting remains synchronized
 */
function burnFrom(address, uint256) public pure override {
    revert OperationNotAllowed();
}
```

**Option 2: Modify _beforeTokenTransfer to block non-issuer burns**

```solidity
// In src/token/iTRY/iTry.sol, modify _beforeTokenTransfer at line 180, 199:

// Change line 180 from:
if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {

// To:
if (hasRole(MINTER_CONTRACT, msg.sender) && msg.sender == from && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {

// And remove lines 208-210 entirely (whitelisted user burn clause)
```

**Option 3: Implement callback mechanism**

Add a callback to iTryIssuer when burns occur, but this requires modifying both contracts and adds complexity. Option 1 is cleaner and safer.

## Proof of Concept

```solidity
// File: test/Exploit_DirectBurnLocksDLF.t.sol
// Run with: forge test --match-test test_DirectBurnLocksDLF -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import "./iTryIssuer.base.t.sol";

contract Exploit_DirectBurnLocksDLF is iTryIssuerBaseTest {
    address user;
    uint256 mintAmount = 100_000e18; // 100k DLF
    
    function setUp() public override {
        super.setUp();
        user = whitelistedUser1;
        
        // Mint iTRY tokens to user through proper flow
        collateralToken.mint(user, mintAmount);
        vm.startPrank(user);
        collateralToken.approve(address(issuer), mintAmount);
        issuer.mintFor(user, mintAmount, 0);
        vm.stopPrank();
    }
    
    function test_DirectBurnLocksDLF() public {
        // SETUP: Record initial state
        uint256 initialTotalIssued = issuer.getTotalIssuedITry();
        uint256 initialTokenSupply = iTryToken.totalSupply();
        uint256 initialDLFCustody = issuer.getCollateralUnderCustody();
        uint256 userITryBalance = iTryToken.balanceOf(user);
        
        assertEq(initialTotalIssued, initialTokenSupply, "Initially synchronized");
        assertGt(userITryBalance, 0, "User has iTRY");
        
        // EXPLOIT: User directly burns iTRY tokens (bypassing iTryIssuer)
        uint256 burnAmount = userITryBalance / 2; // Burn half
        vm.prank(user);
        iTryToken.burn(burnAmount);
        
        // VERIFY: Invariant is broken
        uint256 finalTotalIssued = issuer.getTotalIssuedITry();
        uint256 finalTokenSupply = iTryToken.totalSupply();
        uint256 finalDLFCustody = issuer.getCollateralUnderCustody();
        
        // Critical invariant violation: totalIssued > actualSupply
        assertEq(finalTotalIssued, initialTotalIssued, 
            "iTryIssuer accounting unchanged - BROKEN!");
        assertEq(finalTokenSupply, initialTokenSupply - burnAmount,
            "Token supply decreased");
        assertGt(finalTotalIssued, finalTokenSupply,
            "INVARIANT BROKEN: tracked supply > actual supply");
        
        // DLF remains locked
        assertEq(finalDLFCustody, initialDLFCustody,
            "DLF custody unchanged - collateral permanently locked!");
        
        // User lost iTRY without getting DLF back
        assertEq(iTryToken.balanceOf(user), userITryBalance - burnAmount,
            "User lost iTRY tokens");
        assertEq(collateralToken.balanceOf(user), 0,
            "User received no DLF - FUNDS LOST!");
    }
}
```

## Notes

This vulnerability exists because the iTry contract inherits `ERC20BurnableUpgradeable` which provides public `burn()` functions, while the `_beforeTokenTransfer` hook was designed to control transfers but inadvertently allows direct burns in standard operational states.

The invariant tests do not catch this because the test handler only calls `issuer.redeemFor()` (the proper redemption path) and never directly calls `iTry.burn()`. In production, users might accidentally call `burn()` thinking it's equivalent to redemption, or wallet interfaces might expose this function, leading to permanent fund loss. [5](#0-4) [6](#0-5)

### Citations

**File:** src/token/iTRY/iTry.sol (L15-21)
```text
contract iTry is
    ERC20BurnableUpgradeable,
    ERC20PermitUpgradeable,
    IiTryDefinitions,
    ReentrancyGuardUpgradeable,
    SingleAdminAccessControlUpgradeable
{
```

**File:** src/token/iTRY/iTry.sol (L189-193)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
```

**File:** src/token/iTRY/iTry.sol (L208-210)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
```

**File:** src/protocol/iTryIssuer.sol (L318-370)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (bool fromBuffer)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();

        // Validate iTRYAmount > 0
        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();

        if (iTRYAmount > _totalIssuedITry) {
            revert AmountExceedsITryIssuance(iTRYAmount, _totalIssuedITry);
        }

        // Get NAV price from oracle
        uint256 navPrice = oracle.price();
        if (navPrice == 0) revert InvalidNAVPrice(navPrice);

        // Calculate gross DLF amount: iTRYAmount * 1e18 / navPrice
        uint256 grossDlfAmount = iTRYAmount * 1e18 / navPrice;

        if (grossDlfAmount == 0) revert CommonErrors.ZeroAmount();

        uint256 feeAmount = _calculateRedemptionFee(grossDlfAmount);
        uint256 netDlfAmount = grossDlfAmount - feeAmount;

        // Check if output meets minimum requirement
        if (netDlfAmount < minAmountOut) {
            revert OutputBelowMinimum(netDlfAmount, minAmountOut);
        }

        _burn(msg.sender, iTRYAmount);

        // Check if buffer pool has enough DLF balance
        uint256 bufferBalance = liquidityVault.getAvailableBalance();

        if (bufferBalance >= grossDlfAmount) {
            // Buffer has enough - serve from buffer
            _redeemFromVault(recipient, netDlfAmount, feeAmount);

            fromBuffer = true;
        } else {
            // Buffer insufficient - serve from custodian
            _redeemFromCustodian(recipient, netDlfAmount, feeAmount);

            fromBuffer = false;
        }

        // Emit redemption event
        emit ITRYRedeemed(recipient, iTRYAmount, netDlfAmount, fromBuffer, redemptionFeeInBPS);
    }
```

**File:** src/protocol/iTryIssuer.sol (L587-591)
```text
    function _burn(address from, uint256 amount) internal {
        // Burn user's iTRY tokens
        _totalIssuedITry -= amount;
        iTryToken.burnFrom(from, amount);
    }
```

**File:** test/iTryIssuer.invariant.t.sol (L40-45)
```text
    function invariant_totalIssuedMatchesTokenSupply() public {
        uint256 totalIssued = handler.issuer().getTotalIssuedITry();
        uint256 tokenSupply = handler.iTryToken().totalSupply();

        assertEq(totalIssued, tokenSupply, "Total issued must always equal actual token supply");
    }
```
