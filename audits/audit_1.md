## Title
iTRY Blacklist Bypass via FastAccessVault.processTransfer - Sanctioned Addresses Can Receive DLF Through Proxy Redemption

## Summary
The `FastAccessVault.processTransfer` function does not validate whether the receiver is blacklisted in the iTRY token system before transferring DLF collateral tokens. This allows a non-blacklisted user to redeem their iTRY tokens and send the resulting DLF directly to a blacklisted address, effectively bypassing the protocol's blacklist enforcement and enabling sanctioned addresses to receive economic value from the protocol.

## Impact
**Severity**: High

## Finding Description

**Location:** `src/protocol/FastAccessVault.sol` (function `processTransfer`, lines 144-158) and `src/protocol/iTryIssuer.sol` (function `redeemFor`, lines 318-370; function `_redeemFromVault`, lines 627-635)

**Intended Logic:** The iTRY blacklist system is designed to prevent sanctioned/restricted addresses from accessing protocol value in any form. When users redeem iTRY for DLF collateral, the system should ensure that blacklisted addresses cannot receive the underlying collateral tokens.

**Actual Logic:** The redemption flow only validates that the iTRY burner (msg.sender) is not blacklisted, but completely ignores whether the DLF recipient is blacklisted. The `processTransfer` function in FastAccessVault performs basic validation (non-zero address, not self) but never checks if the receiver has the `BLACKLISTED_ROLE` in the iTRY token contract.

**Exploitation Path:**

1. **Setup**: Address A is blacklisted in iTRY (has `BLACKLISTED_ROLE` via `iTry.addBlacklistAddress`). Address B is a non-blacklisted user with iTRY tokens and `WHITELISTED_USER_ROLE`.

2. **Exploitation**: Address B calls `iTryIssuer.redeemFor(addressA, amount, minOut)` [1](#0-0) 

3. **Burn Validation Passes**: The function burns iTRY from B via `_burn(msg.sender, iTRYAmount)` [2](#0-1)  which succeeds because B is not blacklisted (checked in iTRY's `_beforeTokenTransfer` hook) [3](#0-2) 

4. **Unvalidated DLF Transfer**: The function calls `_redeemFromVault(recipient, netDlfAmount, feeAmount)` where recipient is the blacklisted addressA [4](#0-3) 

5. **No Blacklist Check**: `_redeemFromVault` calls `liquidityVault.processTransfer(receiver, receiveAmount)` [5](#0-4)  without any blacklist validation on the receiver.

6. **Direct DLF Transfer**: `processTransfer` transfers DLF tokens directly to the blacklisted address with only basic validations (non-zero, not vault itself) [6](#0-5)  - **NO BLACKLIST CHECK PERFORMED**.

7. **Bypass Complete**: The blacklisted addressA now holds DLF tokens (the underlying collateral backing iTRY), successfully accessing protocol value despite being blacklisted.

**Security Property Broken:** This violates the critical invariant: "**Blacklist Enforcement: Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case.**" While technically the blacklisted address doesn't receive iTRY tokens, they receive the economic equivalent (DLF collateral), defeating the compliance and security purpose of the blacklist system.

## Impact Explanation

- **Affected Assets**: DLF collateral tokens held in FastAccessVault, and by extension, the entire protocol's collateral base and compliance framework.

- **Damage Severity**: Complete bypass of iTRY blacklist enforcement. Sanctioned addresses can receive 100% of the economic value they would have received through normal redemption. If a blacklisted entity controls non-blacklisted proxy addresses (or colludes with them), they can freely convert any amount of iTRY into DLF tokens, making the blacklist ineffective.

- **User Impact**: Affects all protocol stakeholders:
  - **Compliance Risk**: Protocol fails regulatory requirements if sanctioned entities can receive value
  - **Reputation Risk**: Undermines the blacklist's credibility for institutional users
  - **Economic Risk**: Blacklisted addresses meant to be excluded from the protocol can extract full collateral value

## Likelihood Explanation

- **Attacker Profile**: Any non-blacklisted user with `WHITELISTED_USER_ROLE` can execute this on behalf of a blacklisted address. The blacklisted entity can either control a non-blacklisted proxy address or collude with a legitimate user.

- **Preconditions**: 
  - Attacker needs iTRY tokens to burn
  - Attacker needs `WHITELISTED_USER_ROLE` to call `redeemFor`
  - Target blacklisted address must exist in the system
  - FastAccessVault must have sufficient DLF balance (or redemption occurs via custodian with same lack of validation) [7](#0-6) 

- **Execution Complexity**: Single transaction. No complex timing, multi-block, or cross-chain coordination required. Simply call `redeemFor(blacklistedAddress, amount, minOut)`.

- **Frequency**: Can be executed continuously for any amount of iTRY, limited only by the attacker's iTRY holdings and vault liquidity.

## Recommendation

Add blacklist validation for the recipient address in the redemption flow. The fix should be implemented at the iTryIssuer level before calling vault transfer operations:

```solidity
// In src/protocol/iTryIssuer.sol, function redeemFor, after line 325:

// CURRENT (vulnerable):
// Only validates recipient != address(0)
if (recipient == address(0)) revert CommonErrors.ZeroAddress();

// FIXED:
if (recipient == address(0)) revert CommonErrors.ZeroAddress();
// Add blacklist validation for recipient
if (iTryToken.hasRole(iTryToken.BLACKLISTED_ROLE(), recipient)) {
    revert RecipientIsBlacklisted(recipient);
}
```

Alternative mitigation: Add the check in `FastAccessVault.processTransfer` by querying the iTRY token contract, though this creates a dependency on the iTRY contract from the vault. The iTryIssuer-level check is preferred as it centralizes validation logic.

Additionally, apply the same validation in `_redeemFromCustodian` since it emits events for off-chain processing but should also reject blacklisted recipients.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypass.t.sol
// Run with: forge test --match-test test_BlacklistBypassViaRedeemFor -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/protocol/FastAccessVault.sol";
import "../src/external/DLFToken.sol";

contract Exploit_BlacklistBypass is Test {
    iTryIssuer issuer;
    iTry itry;
    DLFToken dlf;
    FastAccessVault vault;
    
    address admin = address(0x1);
    address legitUser = address(0x2);
    address blacklistedUser = address(0x3);
    address treasury = address(0x4);
    
    function setUp() public {
        // Deploy contracts (simplified setup)
        vm.startPrank(admin);
        
        dlf = new DLFToken(admin);
        // Deploy iTRY, issuer, vault...
        // Grant roles to legitUser and blacklist blacklistedUser
        
        itry.addBlacklistAddress([blacklistedUser]);
        issuer.addToWhitelist(legitUser);
        
        // Mint DLF to vault
        dlf.mint(address(vault), 1000e18);
        
        // Mint iTRY to legitUser
        dlf.mint(legitUser, 100e18);
        vm.stopPrank();
        
        vm.prank(legitUser);
        dlf.approve(address(issuer), type(uint256).max);
        
        vm.prank(legitUser);
        issuer.mintITRY(100e18, 0);
    }
    
    function test_BlacklistBypassViaRedeemFor() public {
        // SETUP: Verify blacklistedUser cannot receive iTRY
        vm.prank(legitUser);
        vm.expectRevert();
        itry.transfer(blacklistedUser, 10e18); // This should fail
        
        uint256 blacklistedBalanceBefore = dlf.balanceOf(blacklistedUser);
        assertEq(blacklistedBalanceBefore, 0, "Blacklisted user should have no DLF initially");
        
        // EXPLOIT: LegitUser redeems iTRY and sends DLF to blacklisted address
        vm.prank(legitUser);
        issuer.redeemFor(blacklistedUser, 50e18, 0);
        
        // VERIFY: Blacklisted user received DLF tokens!
        uint256 blacklistedBalanceAfter = dlf.balanceOf(blacklistedUser);
        assertGt(blacklistedBalanceAfter, 0, "Vulnerability confirmed: Blacklisted user received DLF");
        
        console.log("Blacklisted user DLF balance:", blacklistedBalanceAfter);
        console.log("Blacklist bypass successful - sanctioned address received collateral!");
    }
}
```

## Notes

The vulnerability exists because the protocol implements two conceptually different validation checks:
1. **iTRY transfer restrictions** (enforced via `_beforeTokenTransfer` in iTry.sol checking sender, receiver, and msg.sender)
2. **Redemption access control** (enforced via `WHITELISTED_USER_ROLE` on the caller only)

The redemption flow validates WHO can redeem (the caller) but not WHERE the redeemed collateral goes (the recipient). This asymmetry creates the bypass vector. The issue is particularly severe because:

- The DLF token itself may have its own blacklist [8](#0-7)  but this is out of scope and represents a **separate blacklist system** from iTRY's. An address can be blacklisted in iTRY but NOT in DLF, allowing the exploit.

- The known issue about "blacklisted user can transfer tokens using allowance" is different - that's about msg.sender validation, while this finding is about recipient validation in a different code path (redemption).

- This affects both vault-based redemptions [9](#0-8)  and custodian-based redemptions [7](#0-6) .

### Citations

**File:** src/protocol/iTryIssuer.sol (L318-325)
```text
    function redeemFor(address recipient, uint256 iTRYAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (bool fromBuffer)
    {
        // Validate recipient address
        if (recipient == address(0)) revert CommonErrors.ZeroAddress();
```

**File:** src/protocol/iTryIssuer.sol (L351-351)
```text
        _burn(msg.sender, iTRYAmount);
```

**File:** src/protocol/iTryIssuer.sol (L358-358)
```text
            _redeemFromVault(recipient, netDlfAmount, feeAmount);
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

**File:** src/protocol/iTryIssuer.sol (L644-658)
```text
    function _redeemFromCustodian(address receiver, uint256 receiveAmount, uint256 feeAmount) internal {
        _totalDLFUnderCustody -= (receiveAmount + feeAmount);

        // Signal that fast access vault needs top-up from custodian
        uint256 topUpAmount = receiveAmount + feeAmount;
        emit FastAccessVaultTopUpRequested(topUpAmount);

        if (feeAmount > 0) {
            // Emit event for off-chain custodian to process
            emit CustodianTransferRequested(treasury, feeAmount);
        }

        // Emit event for off-chain custodian to process
        emit CustodianTransferRequested(receiver, receiveAmount);
    }
```

**File:** src/token/iTRY/iTry.sol (L180-181)
```text
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
```

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

**File:** src/external/DLFToken.sol (L10-43)
```text
    mapping(address => bool) private _isBlacklisted;

    constructor(address owner) ERC20("Digital Liquiditiy Fund Token Mock", "DLF") {
        _transferOwnership(owner);
        _mint(owner, 1000e18); // Test mint
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused {
        require(!_isBlacklisted[from], "ERC20: sender is blacklisted");
        require(!_isBlacklisted[to], "ERC20: recipient is blacklisted");
        super._beforeTokenTransfer(from, to, amount);
    }

    function blacklist(address account) public onlyOwner {
        require(account != address(0), "Blacklist: account is the zero address");
        _isBlacklisted[account] = true;
    }

    function unblacklist(address account) public onlyOwner {
        require(account != address(0), "Blacklist: account is the zero address");
        _isBlacklisted[account] = false;
    }

    function isBlacklisted(address account) public view returns (bool) {
        return _isBlacklisted[account];
    }
```
