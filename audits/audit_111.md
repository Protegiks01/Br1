## Title
Whitelist Enforcement Bypass During Minting in WHITELIST_ENABLED State

## Summary
The `_beforeTokenTransfer` hook in `iTry.sol` fails to verify that the recipient has the `WHITELISTED_ROLE` when minting tokens in `WHITELIST_ENABLED` transfer state. While the hook properly blocks blacklisted addresses from receiving mints (answering the original question: **MINTER_CONTRACT cannot bypass blacklist checks**), it allows minting to non-whitelisted addresses, violating the protocol's core invariant that only whitelisted users can receive iTRY in this state.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (lines 201-202) and `src/token/iTRY/crosschain/iTryTokenOFT.sol` (lines 160-161)

**Intended Logic:** According to the protocol invariants documented in the README, "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state." This should apply to ALL methods of receiving tokens, including minting operations.

**Actual Logic:** The `_beforeTokenTransfer` hook checks different conditions for minting operations:
- In `FULLY_ENABLED` state: Correctly allows minting to any non-blacklisted address [1](#0-0) 
- In `WHITELIST_ENABLED` state: Only checks that recipient is NOT blacklisted, but fails to verify they have `WHITELISTED_ROLE` [2](#0-1) 

For comparison, normal transfers in `WHITELIST_ENABLED` state correctly require all parties (msg.sender, from, to) to be whitelisted [3](#0-2) 

**Exploitation Path:**
1. Admin sets transfer state to `WHITELIST_ENABLED` using `updateTransferState(TransferState.WHITELIST_ENABLED)` [4](#0-3) 
2. A whitelisted user with access to `iTryIssuer` calls `mintFor(non_whitelisted_recipient, dlfAmount, minAmountOut)` [5](#0-4) 
3. The issuer calls `iTryToken.mint(receiver, amount)` where receiver is the non-whitelisted address [6](#0-5) 
4. The `_beforeTokenTransfer` hook only checks `!hasRole(BLACKLISTED_ROLE, to)` but not `hasRole(WHITELISTED_ROLE, to)`, allowing the mint to succeed
5. Non-whitelisted address now holds iTRY tokens in `WHITELIST_ENABLED` state, violating the invariant

**Security Property Broken:** Violates Invariant 3 from README: "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" [7](#0-6) 

## Impact Explanation
- **Affected Assets**: iTRY tokens can be received by non-whitelisted addresses during `WHITELIST_ENABLED` state
- **Damage Severity**: Access control bypass - non-whitelisted addresses can accumulate iTRY balances when the protocol intends to restrict token holding to whitelisted entities only. While these recipients cannot subsequently transfer tokens (transfers still require whitelist), they can hold them indefinitely.
- **User Impact**: Affects protocol-level access control during regulatory compliance modes where only approved addresses should hold tokens. The same vulnerability exists in the cross-chain OFT implementation [8](#0-7) 

## Likelihood Explanation
- **Attacker Profile**: Any whitelisted user with minting privileges through `iTryIssuer` can exploit this
- **Preconditions**: Transfer state must be set to `WHITELIST_ENABLED` (TransferState enum value 1)
- **Execution Complexity**: Single transaction calling `mintFor()` with a non-whitelisted recipient address
- **Frequency**: Can be exploited continuously while in `WHITELIST_ENABLED` state

## Recommendation

In `src/token/iTRY/iTry.sol`, modify the minting check in `WHITELIST_ENABLED` state to verify the recipient is whitelisted:

```solidity
// CURRENT (line 201-202):
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
    // minting

// FIXED:
} else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to) && hasRole(WHITELISTED_ROLE, to)) {
    // minting - requires recipient to be whitelisted in WHITELIST_ENABLED state
```

Apply the same fix to `src/token/iTRY/crosschain/iTryTokenOFT.sol` at lines 160-161, changing from:
```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
```
to:
```solidity
} else if (msg.sender == minter && from == address(0) && !blacklisted[to] && whitelisted[to]) {
```

## Proof of Concept
```solidity
// File: test/Exploit_WhitelistBypassMinting.t.sol
// Run with: forge test --match-test test_WhitelistBypassMinting -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";
import "../src/protocol/iTryIssuer.sol";
import "./mocks/MockERC20.sol";

contract MockOracle {
    function price() external pure returns (uint256) {
        return 1e18; // 1:1 NAV
    }
}

contract Exploit_WhitelistBypassMinting is Test {
    iTry public itryToken;
    iTryIssuer public issuer;
    MockERC20 public dlfToken;
    MockOracle public oracle;
    
    address admin = address(this);
    address treasury = makeAddr("treasury");
    address custodian = makeAddr("custodian");
    address whitelistedUser = makeAddr("whitelistedUser");
    address nonWhitelistedUser = makeAddr("nonWhitelistedUser");
    
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    bytes32 constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
    
    function setUp() public {
        // Deploy iTry
        iTry implementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        itryToken = iTry(address(proxy));
        
        // Deploy mock contracts
        dlfToken = new MockERC20("DLF", "DLF", 18);
        oracle = new MockOracle();
        
        // Deploy issuer
        issuer = new iTryIssuer(
            address(itryToken),
            address(dlfToken),
            address(oracle),
            treasury,
            treasury, // yieldReceiver
            custodian,
            admin,
            0, // initialIssued
            0, // initialDLFUnderCustody
            500, // buffer target 5%
            0 // min buffer
        );
        
        // Grant MINTER_CONTRACT role to issuer
        itryToken.grantRole(MINTER_CONTRACT, address(issuer));
        
        // Whitelist the user who will mint
        issuer.addToWhitelist(whitelistedUser);
        
        // Give DLF to whitelisted user
        dlfToken.mint(whitelistedUser, 10000e18);
    }
    
    function test_WhitelistBypassMinting() public {
        // SETUP: Set transfer state to WHITELIST_ENABLED
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        // Verify nonWhitelistedUser does NOT have WHITELISTED_ROLE
        assertFalse(itryToken.hasRole(WHITELISTED_ROLE, nonWhitelistedUser), "Recipient should not be whitelisted");
        
        // EXPLOIT: Whitelisted user mints to non-whitelisted recipient
        vm.startPrank(whitelistedUser);
        dlfToken.approve(address(issuer), 1000e18);
        
        // This should fail according to invariant but succeeds due to missing whitelist check
        uint256 mintedAmount = issuer.mintFor(nonWhitelistedUser, 1000e18, 0);
        vm.stopPrank();
        
        // VERIFY: Non-whitelisted user received iTRY tokens in WHITELIST_ENABLED state
        assertGt(itryToken.balanceOf(nonWhitelistedUser), 0, "Vulnerability confirmed: Non-whitelisted user received tokens in WHITELIST_ENABLED state");
        assertEq(itryToken.balanceOf(nonWhitelistedUser), mintedAmount, "Non-whitelisted user holds minted tokens");
        
        // Verify transfer state is still WHITELIST_ENABLED
        assertEq(uint256(itryToken.transferState()), uint256(IiTryDefinitions.TransferState.WHITELIST_ENABLED), "State is WHITELIST_ENABLED");
        
        console.log("Vulnerability: Non-whitelisted user received", mintedAmount, "iTRY tokens in WHITELIST_ENABLED state");
    }
}
```

## Notes

**Direct Answer to Security Question**: The `_beforeTokenTransfer` hook at lines 182-183 DOES properly block minting to blacklisted addresses. The check `!hasRole(BLACKLISTED_ROLE, to)` ensures that any blacklisted address will cause the mint to revert. MINTER_CONTRACT cannot bypass the blacklist check.

**Additional Finding**: While investigating the blacklist enforcement, I discovered a related access control vulnerability where the whitelist requirement is not enforced during minting in `WHITELIST_ENABLED` state. This represents a different but related security issue that violates the protocol's documented invariants.

### Citations

**File:** src/token/iTRY/iTry.sol (L171-175)
```text
    function updateTransferState(TransferState code) external onlyRole(DEFAULT_ADMIN_ROLE) {
        TransferState prevState = transferState;
        transferState = code;
        emit TransferStateUpdated(prevState, code);
    }
```

**File:** src/token/iTRY/iTry.sol (L182-183)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L201-202)
```text
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
```

**File:** src/token/iTRY/iTry.sol (L210-213)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
```

**File:** src/protocol/iTryIssuer.sol (L270-306)
```text
    function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (uint256 iTRYAmount)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();

        // Validate dlfAmount > 0
        if (dlfAmount == 0) revert CommonErrors.ZeroAmount();

        // Get NAV price from oracle
        uint256 navPrice = oracle.price();
        if (navPrice == 0) revert InvalidNAVPrice(navPrice);

        uint256 feeAmount = _calculateMintFee(dlfAmount);
        uint256 netDlfAmount = feeAmount > 0 ? (dlfAmount - feeAmount) : dlfAmount;

        // Calculate iTRY amount: netDlfAmount * navPrice / 1e18
        iTRYAmount = netDlfAmount * navPrice / 1e18;

        if (iTRYAmount == 0) revert CommonErrors.ZeroAmount();

        // Check if output meets minimum requirement
        if (iTRYAmount < minAmountOut) {
            revert OutputBelowMinimum(iTRYAmount, minAmountOut);
        }

        // Transfer collateral into vault BEFORE minting (CEI pattern)
        _transferIntoVault(msg.sender, netDlfAmount, feeAmount);

        _mint(recipient, iTRYAmount);

        // Emit event
        emit ITRYIssued(recipient, netDlfAmount, iTRYAmount, navPrice, mintFeeInBPS);
    }
```

**File:** src/protocol/iTryIssuer.sol (L576-579)
```text
    function _mint(address receiver, uint256 amount) internal {
        _totalIssuedITry += amount;
        iTryToken.mint(receiver, amount);
    }
```

**File:** README.md (L125-125)
```markdown
- Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state.
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L160-161)
```text
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
```
