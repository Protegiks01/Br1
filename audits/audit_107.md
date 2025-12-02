## Title
Non-Whitelisted iTRY Holders Face Permanent Fund Lock When Transfer State Changes to WHITELIST_ENABLED

## Summary
When the iTRY token's transfer state changes from FULLY_ENABLED to WHITELIST_ENABLED, holders who lack both the WHITELISTED_ROLE in the iTry token contract AND the WHITELISTED_USER_ROLE in the iTryIssuer contract become permanently unable to transfer, burn, or redeem their iTRY tokens, resulting in irreversible fund lock without admin intervention.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0) 

**Intended Logic:** According to the protocol's documented invariant, "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" [2](#0-1) . The system should allow holders to exit their positions through redemption via iTryIssuer.

**Actual Logic:** The protocol implements TWO separate whitelist systems:
1. `WHITELISTED_ROLE` in the iTry token contract [3](#0-2) 
2. `_WHITELISTED_USER_ROLE` in the iTryIssuer contract [4](#0-3) 

These are independent access control systems. When the transfer state is WHITELIST_ENABLED, the `_beforeTokenTransfer` function enforces strict restrictions:

- **For direct transfers**: Requires all parties (msg.sender, from, to) to have WHITELISTED_ROLE [5](#0-4) 
- **For direct burns**: Requires both msg.sender and from to have WHITELISTED_ROLE [6](#0-5) 
- **For redemption via iTryIssuer**: The `redeemFor` function requires caller to have WHITELISTED_USER_ROLE in iTryIssuer [7](#0-6) 

**Exploitation Path:**
1. A user or contract holds iTRY tokens during FULLY_ENABLED transfer state
2. The holder is NOT whitelisted in iTryIssuer (lacks WHITELISTED_USER_ROLE)
3. The holder is NOT whitelisted in iTry token (lacks WHITELISTED_ROLE)
4. Admin changes transfer state to WHITELIST_ENABLED via `updateTransferState()` [8](#0-7) 
5. Holder attempts to exit their position but finds all paths blocked:
   - Cannot transfer tokens to another address (fails whitelist check in _beforeTokenTransfer)
   - Cannot burn tokens directly (fails whitelist check requiring WHITELISTED_ROLE)
   - Cannot redeem through iTryIssuer (fails access control requiring WHITELISTED_USER_ROLE)
6. Tokens are permanently locked until admin either: (a) changes transfer state back to FULLY_ENABLED, (b) whitelists the holder in iTry token, or (c) whitelists the holder in iTryIssuer

**Security Property Broken:** Violates the principle that users should be able to exit their positions and withdraw their funds. Creates a scenario where legitimate holders lose access to their assets due to administrative state changes rather than malicious behavior.

## Impact Explanation
- **Affected Assets**: All iTRY tokens held by addresses lacking both whitelist roles
- **Damage Severity**: 100% permanent fund lock for affected holders. Users cannot transfer, trade, or redeem their iTRY tokens without admin intervention to either restore FULLY_ENABLED state or grant appropriate whitelist roles
- **User Impact**: Any holder who:
  - Acquired iTRY during FULLY_ENABLED state (e.g., through secondary market, DEX swaps, or peer-to-peer transfers)
  - Never completed KYC/whitelist process for iTryIssuer
  - Never received WHITELISTED_ROLE in iTry token
  
  These users face total fund lock when transfer state changes. This particularly affects smart contracts (DEX pools, lending protocols, bridges) that hold iTRY but may not be easily whitelisted.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a systemic vulnerability affecting legitimate users
- **Preconditions**: 
  - Transfer state changes from FULLY_ENABLED to WHITELIST_ENABLED
  - Holders exist who lack both WHITELISTED_ROLE (iTry) and WHITELISTED_USER_ROLE (iTryIssuer)
  - This is a realistic scenario for users who acquired iTRY through secondary markets or DeFi protocols
- **Execution Complexity**: None - the lock occurs automatically upon transfer state change
- **Frequency**: Affects all non-whitelisted holders simultaneously when transfer state changes

## Recommendation

**Option 1: Allow MINTER_CONTRACT to redeem from any non-blacklisted address**

Modify the WHITELIST_ENABLED redemption check to not require the holder to have WHITELISTED_ROLE: [9](#0-8) 

This path already permits redemption when iTryIssuer (with MINTER_CONTRACT role) burns tokens, regardless of whether `from` has WHITELISTED_ROLE. This is correct behavior but relies on the user having WHITELISTED_USER_ROLE in iTryIssuer.

**Option 2: Separate whitelist systems should be unified or clearly documented**

Create a function that allows non-whitelisted holders to at least burn their tokens or transfer them to whitelisted addresses during WHITELIST_ENABLED state. For example:

```solidity
// Add after line 210:
} else if (!hasRole(WHITELISTED_ROLE, from) && hasRole(WHITELISTED_ROLE, to) && !hasRole(BLACKLISTED_ROLE, from)) {
    // Allow non-whitelisted to transfer to whitelisted addresses (exit path)
```

**Option 3: Grace period before WHITELIST_ENABLED takes effect**

Implement a time-delayed state change that gives holders notice and opportunity to exit their positions before restrictions take effect.

**Option 4: Emergency exit function**

Add an emergency burn function that allows any non-blacklisted holder to burn their tokens during WHITELIST_ENABLED state (without redemption rights), at minimum preventing permanent fund lock:

```solidity
function emergencyBurn(uint256 amount) external {
    require(transferState == TransferState.WHITELIST_ENABLED, "Only during whitelist mode");
    require(!hasRole(BLACKLISTED_ROLE, msg.sender), "Blacklisted");
    _burn(msg.sender, amount);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistLockup.t.sol
// Run with: forge test --match-test test_NonWhitelistedHolderLockedOnStateChange -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {iTry} from "../src/token/iTRY/iTry.sol";
import {IiTryDefinitions} from "../src/token/iTRY/IiTryDefinitions.sol";
import {DLFToken} from "../src/external/DLFToken.sol";
import {iTryIssuer} from "../src/protocol/iTryIssuer.sol";
import {IFastAccessVault} from "../src/protocol/interfaces/IFastAccessVault.sol";
import "./mocks/MockERC20.sol";
import "./iTryIssuer.base.t.sol";

contract Exploit_WhitelistLockup is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    DLFToken public dlfToken;
    MockOracle public oracle;
    iTryIssuer public issuer;
    IFastAccessVault public vault;
    
    address public admin;
    address public whitelistedUser;
    address public nonWhitelistedHolder;
    address public treasury;
    address public custodian;
    
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    bytes32 constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
    
    uint256 constant INITIAL_NAV_PRICE = 1e18;
    uint256 constant MINT_AMOUNT = 1000e18;
    
    function setUp() public {
        admin = address(this);
        whitelistedUser = makeAddr("whitelistedUser");
        nonWhitelistedHolder = makeAddr("nonWhitelistedHolder");
        treasury = makeAddr("treasury");
        custodian = makeAddr("custodian");
        
        // Deploy oracle
        oracle = new MockOracle(INITIAL_NAV_PRICE);
        
        // Deploy DLF token
        dlfToken = new DLFToken(admin);
        
        // Deploy iTry with proxy
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Deploy iTryIssuer
        issuer = new iTryIssuer(
            address(itryToken),
            address(dlfToken),
            address(oracle),
            treasury,
            address(1), // yieldReceiver placeholder
            custodian,
            admin,
            0,
            0,
            500,
            0
        );
        
        vault = issuer.liquidityVault();
        
        // Grant MINTER_CONTRACT role to issuer
        itryToken.grantRole(MINTER_CONTRACT, address(issuer));
        
        // Whitelist only one user in iTryIssuer
        issuer.addToWhitelist(whitelistedUser);
        
        // Whitelist only one user in iTry token
        itryToken.addWhitelistAddress(_toArray(whitelistedUser));
        
        // Mint DLF to whitelisted user
        dlfToken.mint(whitelistedUser, 10_000e18);
    }
    
    function test_NonWhitelistedHolderLockedOnStateChange() public {
        console.log("\n=== EXPLOIT: Non-Whitelisted Holder Gets Locked ===\n");
        
        // PHASE 1: Normal operations in FULLY_ENABLED state
        console.log("Phase 1: Initial state - FULLY_ENABLED");
        console.log("Transfer state:", uint(itryToken.transferState()));
        
        // Whitelisted user mints iTRY
        vm.startPrank(whitelistedUser);
        dlfToken.approve(address(issuer), MINT_AMOUNT);
        uint256 itryMinted = issuer.mintITRY(MINT_AMOUNT, 0);
        console.log("Whitelisted user minted iTRY:", itryMinted);
        
        // Whitelisted user transfers to non-whitelisted holder (allowed in FULLY_ENABLED)
        itryToken.transfer(nonWhitelistedHolder, itryMinted);
        vm.stopPrank();
        
        uint256 holderBalance = itryToken.balanceOf(nonWhitelistedHolder);
        console.log("Non-whitelisted holder balance:", holderBalance);
        console.log("Holder is whitelisted in iTry?", itryToken.hasRole(WHITELISTED_ROLE, nonWhitelistedHolder));
        console.log("Holder is whitelisted in Issuer?", issuer.isWhitelistedUser(nonWhitelistedHolder));
        
        // PHASE 2: Admin changes transfer state to WHITELIST_ENABLED
        console.log("\nPhase 2: Admin changes state to WHITELIST_ENABLED");
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        console.log("New transfer state:", uint(itryToken.transferState()));
        
        // PHASE 3: Verify all exit paths are blocked
        console.log("\nPhase 3: Verify holder is completely locked");
        
        // Attempt 1: Try to transfer tokens
        console.log("\nAttempt 1: Transfer to whitelisted user");
        vm.prank(nonWhitelistedHolder);
        vm.expectRevert(abi.encodeWithSignature("OperationNotAllowed()"));
        itryToken.transfer(whitelistedUser, holderBalance);
        console.log("BLOCKED: Transfer failed as expected");
        
        // Attempt 2: Try to burn tokens directly
        console.log("\nAttempt 2: Burn tokens directly");
        vm.prank(nonWhitelistedHolder);
        vm.expectRevert(abi.encodeWithSignature("OperationNotAllowed()"));
        itryToken.burn(holderBalance);
        console.log("BLOCKED: Direct burn failed as expected");
        
        // Attempt 3: Try to redeem through iTryIssuer
        console.log("\nAttempt 3: Redeem through iTryIssuer");
        vm.startPrank(nonWhitelistedHolder);
        itryToken.approve(address(issuer), holderBalance);
        vm.expectRevert(); // Will revert with AccessControl error
        issuer.redeemITRY(holderBalance, 0);
        vm.stopPrank();
        console.log("BLOCKED: Redemption failed (no WHITELISTED_USER_ROLE in issuer)");
        
        // Attempt 4: Try to approve and have someone else burn on their behalf
        console.log("\nAttempt 4: Approve whitelisted user to burn on behalf");
        vm.prank(nonWhitelistedHolder);
        itryToken.approve(whitelistedUser, holderBalance);
        
        vm.prank(whitelistedUser);
        vm.expectRevert(abi.encodeWithSignature("OperationNotAllowed()"));
        itryToken.burnFrom(nonWhitelistedHolder, holderBalance);
        console.log("BLOCKED: burnFrom failed (requires both parties whitelisted)");
        
        // VERIFICATION: Holder still has tokens but cannot access them
        uint256 finalBalance = itryToken.balanceOf(nonWhitelistedHolder);
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Holder balance still locked:", finalBalance);
        console.log("Tokens are permanently inaccessible without admin intervention");
        
        assertEq(finalBalance, holderBalance, "Tokens remain locked in holder's address");
        assertTrue(finalBalance > 0, "Holder has funds but cannot access them");
    }
    
    function _toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }
}
```

**Notes**

1. **Dual Whitelist System**: The protocol uses two independent whitelist systems - one in the iTry token contract and another in the iTryIssuer contract. This creates a vulnerability window where holders can be locked out if they lack either whitelist role when the state changes.

2. **Real-World Impact**: This particularly affects:
   - Users who acquired iTRY on secondary markets (DEXs, P2P)
   - Smart contracts (liquidity pools, lending protocols) holding iTRY
   - Users who haven't completed KYC/onboarding for whitelist inclusion
   - Cross-chain bridge contracts that may hold iTRY temporarily

3. **No Malicious Actor Required**: This is not an attack by a malicious user but a systemic flaw where legitimate users lose access to their funds due to administrative state changes.

4. **Admin Dependency**: The only recovery paths require admin intervention to either revert the transfer state or manually whitelist affected addresses, which may not be feasible for smart contracts or users in restricted jurisdictions.

### Citations

**File:** src/token/iTRY/iTry.sol (L33-33)
```text
    bytes32 public constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
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

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/protocol/iTryIssuer.sol (L110-110)
```text
    bytes32 private constant _WHITELISTED_USER_ROLE = keccak256("WHITELISTED_USER_ROLE");
```

**File:** src/protocol/iTryIssuer.sol (L318-322)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (bool fromBuffer)
```
