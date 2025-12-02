## Title
Whitelisted Users Can Mint iTRY to Non-Whitelisted Addresses in WHITELIST_ENABLED State, Violating Whitelist Enforcement Invariant

## Summary
The `mintFor` function in iTryIssuer allows whitelisted users to mint iTRY tokens to any non-blacklisted recipient, including non-whitelisted addresses. When the iTry token is in `WHITELIST_ENABLED` state, this violates the documented invariant that "ONLY whitelisted users can send/receive/burn iTRY" by allowing non-whitelisted addresses to receive tokens.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/iTryIssuer.sol` (mintFor function, lines 270-306) and `src/token/iTRY/iTry.sol` (_beforeTokenTransfer function, lines 177-222)

**Intended Logic:** In WHITELIST_ENABLED state, iTRY tokens should only circulate among whitelisted addresses. The minting process should enforce that recipients are whitelisted to maintain the integrity of the whitelist system.

**Actual Logic:** The mintFor function only checks that the caller has `_WHITELISTED_USER_ROLE` but does not validate the recipient's whitelist status. [1](#0-0) 

The iTry token's `_beforeTokenTransfer` function permits minting to any non-blacklisted address when called by a MINTER_CONTRACT, regardless of whether the recipient is whitelisted in WHITELIST_ENABLED state. [2](#0-1) 

**Exploitation Path:**
1. Protocol is in WHITELIST_ENABLED state (TransferState = 1) where only whitelisted users should be able to send/receive/burn iTRY tokens
2. A whitelisted user calls `mintFor(nonWhitelistedAddress, dlfAmount, minAmountOut)` with a non-whitelisted but non-blacklisted recipient
3. The function passes access control (caller is whitelisted) and mints iTRY directly to the non-whitelisted address
4. The non-whitelisted recipient now holds iTRY tokens but cannot transfer them (requires all parties to be whitelisted) or burn them (requires whitelisted status), resulting in permanently locked tokens

**Security Property Broken:** Violates Critical Invariant #3: "**Whitelist Enforcement**: In WHITELIST_ENABLED state, ONLY whitelisted users can send/receive/burn iTRY." The "receive" component of this invariant is not enforced during minting operations.

## Impact Explanation
- **Affected Assets**: iTRY tokens minted to non-whitelisted addresses become permanently locked and unusable
- **Damage Severity**: The tokens cannot be transferred, burned, or recovered by normal means. This defeats the purpose of WHITELIST_ENABLED mode, which is designed to restrict iTRY circulation to a controlled set of addresses
- **User Impact**: Any whitelisted user can trigger this. Non-whitelisted recipients inadvertently receive locked tokens. The protocol's ability to enforce whitelist-only circulation is compromised

## Likelihood Explanation
- **Attacker Profile**: Any whitelisted user can exploit this, either maliciously (griefing) or accidentally
- **Preconditions**: Protocol must be in WHITELIST_ENABLED state, which is one of the three documented transfer states
- **Execution Complexity**: Single transaction - simply call `mintFor()` with a non-whitelisted recipient address
- **Frequency**: Can be repeated continuously until detected, with each occurrence locking more iTRY tokens

## Recommendation
Add recipient whitelist validation in the mintFor function when WHITELIST_ENABLED state is active:

```solidity
// In src/protocol/iTryIssuer.sol, function mintFor, after line 277:

// CURRENT (vulnerable):
// Only validates recipient != address(0)

// FIXED:
function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
    public
    onlyRole(_WHITELISTED_USER_ROLE)
    nonReentrant
    returns (uint256 iTRYAmount)
{
    // Validate recipient address
    if (recipient == address(0)) revert CommonErrors.ZeroAddress();
    
    // Add validation: recipient must be whitelisted when protocol enforces whitelist
    // Query iTry token's current transfer state and whitelist status
    IiTryToken.TransferState currentState = iTryToken.transferState();
    if (currentState == IiTryToken.TransferState.WHITELIST_ENABLED) {
        if (!iTryToken.hasRole(iTryToken.WHITELISTED_ROLE(), recipient)) {
            revert RecipientNotWhitelisted(recipient);
        }
    }
    
    // ... rest of function
}
```

Alternative mitigation: Enhance the iTry token's `_beforeTokenTransfer` to validate recipient whitelist status during minting operations when in WHITELIST_ENABLED state:

```solidity
// In src/token/iTRY/iTry.sol, line 201-202:

// CURRENT (vulnerable):
else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
    // minting
}

// FIXED:
else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - recipient must be whitelisted in WHITELIST_ENABLED state
}
```

## Proof of Concept
```solidity
// File: test/Exploit_WhitelistBypassMinting.t.sol
// Run with: forge test --match-test test_whitelistBypassViaMintFor -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockOracle} from "./iTryIssuer.base.t.sol";

contract Exploit_WhitelistBypassMinting is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    iTryIssuer public issuer;
    MockERC20 public dlfToken;
    MockOracle public oracle;
    
    address public admin;
    address public whitelistedUser;
    address public nonWhitelistedUser;
    address public treasury;
    address public custodian;
    
    bytes32 constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    
    function setUp() public {
        admin = address(this);
        whitelistedUser = makeAddr("whitelistedUser");
        nonWhitelistedUser = makeAddr("nonWhitelistedUser");
        treasury = makeAddr("treasury");
        custodian = makeAddr("custodian");
        
        // Deploy iTry token with proxy
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(proxy));
        
        // Deploy dependencies
        dlfToken = new MockERC20("DLF", "DLF");
        oracle = new MockOracle(1e18); // 1:1 NAV
        
        // Deploy iTryIssuer
        issuer = new iTryIssuer(
            address(itryToken),
            address(dlfToken),
            address(oracle),
            treasury,
            makeAddr("yieldReceiver"),
            custodian,
            admin,
            0, 0, 500, 50_000e18
        );
        
        // Wire contracts
        itryToken.grantRole(MINTER_CONTRACT, address(issuer));
        
        // Whitelist user and setup balances
        issuer.addToWhitelist(whitelistedUser);
        itryToken.addWhitelistAddress(_toArray(whitelistedUser));
        dlfToken.mint(whitelistedUser, 10_000e18);
        
        vm.prank(whitelistedUser);
        dlfToken.approve(address(issuer), type(uint256).max);
    }
    
    function test_whitelistBypassViaMintFor() public {
        // SETUP: Set iTry to WHITELIST_ENABLED state
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // VERIFY: nonWhitelistedUser is NOT whitelisted
        assertFalse(itryToken.hasRole(WHITELISTED_ROLE, nonWhitelistedUser), "User should not be whitelisted");
        
        // EXPLOIT: Whitelisted user mints iTRY to non-whitelisted address
        uint256 mintAmount = 1000e18;
        vm.prank(whitelistedUser);
        uint256 itryMinted = issuer.mintFor(nonWhitelistedUser, mintAmount, 0);
        
        // VERIFY: Non-whitelisted user received iTRY (INVARIANT VIOLATED)
        assertGt(itryToken.balanceOf(nonWhitelistedUser), 0, "Non-whitelisted user received iTRY in WHITELIST_ENABLED state");
        
        // VERIFY: Tokens are locked - non-whitelisted user cannot transfer
        vm.prank(nonWhitelistedUser);
        vm.expectRevert(); // OperationNotAllowed
        itryToken.transfer(whitelistedUser, itryMinted);
        
        // VERIFY: Tokens are locked - non-whitelisted user cannot burn
        vm.prank(nonWhitelistedUser);
        vm.expectRevert(); // OperationNotAllowed
        itryToken.burn(itryMinted);
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- Whitelisted user minted iTRY to non-whitelisted address");
        console.log("- Non-whitelisted user received:", itryMinted);
        console.log("- Tokens are permanently locked (cannot transfer or burn)");
        console.log("- Invariant violated: Non-whitelisted user received iTRY in WHITELIST_ENABLED state");
    }
    
    function _toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }
}
```

## Notes

This vulnerability specifically affects the WHITELIST_ENABLED transfer state, which is one of three documented operational modes for the iTry token. [3](#0-2) 

The issue arises from a disconnect between the access control model in iTryIssuer (which uses `_WHITELISTED_USER_ROLE` from the issuer's role system) and the transfer restrictions in iTry (which uses `WHITELISTED_ROLE` from the token's role system). While the caller must be whitelisted in the issuer to execute `mintFor`, the recipient's whitelist status in the token contract is not validated. [4](#0-3) 

The minted tokens become permanently locked because in WHITELIST_ENABLED state, normal transfers require all three parties (msg.sender, from, to) to be whitelisted, and burning requires the caller and from address to be whitelisted. [5](#0-4) 

This is distinct from the known issue about blacklisted users transferring via allowance, which concerns the validation of msg.sender rather than the recipient's status during minting operations.

### Citations

**File:** src/protocol/iTryIssuer.sol (L270-277)
```text
    function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (uint256 iTRYAmount)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L208-214)
```text
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
                // normal case
```

**File:** src/token/iTRY/IiTryDefinitions.sol (L5-9)
```text
    enum TransferState {
        FULLY_DISABLED,
        WHITELIST_ENABLED,
        FULLY_ENABLED
    }
```
