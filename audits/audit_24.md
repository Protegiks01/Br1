## Title
Yield Bypasses Vesting Mechanism When Forwarded During Active Vesting Period, Causing Immediate Share Price Jumps

## Summary
When `YieldForwarder` is configured with `StakediTry` as the `yieldRecipient`, new yield tokens forwarded via `processNewYield()` bypass the gradual vesting mechanism if previous vesting is still ongoing. The tokens are transferred directly to `StakediTry` but cannot be added to vesting via `transferInRewards()` (which requires `getUnvestedAmount() == 0`), yet they immediately affect `totalAssets()` and share price calculations, violating the intended gradual yield distribution design.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/protocol/YieldForwarder.sol` (processNewYield function, lines 97-107) and `src/token/wiTRY/StakediTry.sol` (transferInRewards and totalAssets functions)

**Intended Logic:** 
The protocol implements a gradual vesting mechanism where yield distributed to stakers vests linearly over a configurable period (1 hour to 30 days). [1](#0-0)  This ensures smooth share price appreciation and prevents manipulation from timing-based staking/unstaking strategies. Yield should only be added to vesting when the previous vesting completes.

**Actual Logic:**
The vulnerability occurs due to a mismatch between how `YieldForwarder` delivers yield and how `StakediTry` tracks vesting:

1. `YieldForwarder.processNewYield()` performs a simple token transfer to the `yieldRecipient` address [2](#0-1) 

2. `StakediTry.transferInRewards()` is the designated function to add yield to vesting, but it includes a critical constraint: [3](#0-2) 

3. The `_updateVestingAmount()` internal function enforces that new vesting can only start when previous vesting is complete: [4](#0-3) 

4. However, `totalAssets()` calculates vested assets as the contract's entire balance minus only the tracked unvested amount: [5](#0-4) 

**Exploitation Path:**

1. **Initial State (T=0):** `transferInRewards(1000e18)` is called, starting 8-hour vesting
   - `vestingAmount = 1000e18`
   - `lastDistributionTimestamp = block.timestamp`
   - `getUnvestedAmount()` starts at 1000e18, decreases linearly to 0

2. **Midpoint (T=4 hours):** Vesting is 50% complete
   - `getUnvestedAmount() = 500e18` (50% still unvested)
   - `totalAssets()` reflects only the 500e18 vested so far
   - Share price has appreciated by ~50% of expected full amount

3. **New Yield Arrives (T=4 hours):** `iTryIssuer.processAccumulatedYield()` mints 800e18 new yield and calls `yieldReceiver.processNewYield(800e18)` [6](#0-5) 
   - `YieldForwarder` transfers 800e18 directly to `StakediTry` via `transfer()`
   - `StakediTry` balance increases by 800e18
   - **Critical:** `transferInRewards()` CANNOT be called because `getUnvestedAmount() = 500e18 > 0`, it would revert with `StillVesting()`

4. **Immediate Impact (T=4 hours):** Share price jumps instantly instead of vesting gradually
   - Previous balance: `X + 1000e18` (original + first vesting amount)
   - New balance: `X + 1800e18` (original + both yields)
   - `getUnvestedAmount()` remains `500e18` (unchanged, still from first vesting)
   - `totalAssets() = (X + 1800e18) - 500e18 = X + 1300e18`
   - **The new 800e18 is immediately counted in totalAssets, bypassing vesting!**
   - Share price jumps by the full 800e18 instantly, not gradually over 8 hours

5. **Consequence:** The 800e18 tokens sit in the contract balance but are never added to the vesting tracking system. They affect share price immediately rather than vesting gradually as intended.

**Security Property Broken:** 
The gradual yield distribution mechanism is violated. The protocol comments explicitly state that vesting ensures rewards "increasingly become available to stakers" over the vesting period, [7](#0-6)  but new yield bypasses this when delivered during active vesting.

## Impact Explanation

**Affected Assets:** 
- wiTRY stakers' share values (immediate price jumps vs. intended gradual appreciation)
- iTRY yield tokens (800e18 in the example scenario)
- Protocol's yield distribution fairness mechanism

**Damage Severity:**
- **Timing-Based Exploitation:** Users who stake immediately before yield arrives (but after `transferInRewards()` cannot be called) receive full share appreciation instantly, while the design intended gradual vesting.
- **Unfair Advantage:** Sophisticated actors monitoring pending yield distributions can time their stakes to capture immediate appreciation rather than gradual vesting.
- **Permanent State Corruption:** Once yield arrives via `YieldForwarder.transfer()` during active vesting, those tokens can never be properly added to vesting tracking. The next `transferInRewards()` call (when vesting completes) will add NEW yield, but the tokens that arrived mid-vesting remain in a limbo state—counted in `totalAssets()` but never tracked in `vestingAmount`.
- **Broken Invariant:** The entire vesting mechanism design assumes ALL yield goes through `transferInRewards()`, but `YieldForwarder` creates a backdoor that bypasses this.

**User Impact:**
- **All wiTRY stakers** experience unfair share price volatility
- **Early stakers** lose value relative to strategic late entrants who time the yield distribution
- **Protocol reputation** damaged as the advertised "gradual vesting" feature is broken

## Likelihood Explanation

**Attacker Profile:** 
Not a traditional "attacker" but rather:
- Any sophisticated user monitoring the mempool can time stakes around `processAccumulatedYield()` calls
- Protocol operators attempting to use `YieldForwarder` as intended will trigger this automatically
- The issue is structural—it occurs whenever the configuration uses `YieldForwarder` → `StakediTry`

**Preconditions:**
1. `YieldForwarder.yieldRecipient` must be set to `StakediTry` address (possible via `setYieldRecipient()` owner function)
2. Active vesting must be ongoing (`getUnvestedAmount() > 0`)
3. `iTryIssuer.processAccumulatedYield()` must be called by a user with `YIELD_DISTRIBUTOR_ROLE`

**Execution Complexity:**
- **Automatic:** Once `YieldForwarder` is configured with `StakediTry` as recipient, every yield distribution during active vesting triggers the vulnerability
- **No user action required:** This is a protocol-level design flaw in the interaction between two contracts

**Frequency:**
- Occurs on **every yield distribution** if:
  - Yield is distributed more frequently than the vesting period (e.g., daily distributions with 8-hour vesting)
  - Multiple yield events occur before vesting completes
- Default vesting period is 1 hour [8](#0-7) , so any yield distribution within 1 hour of the previous one triggers this issue

## Recommendation

**Primary Fix - Modify YieldForwarder to support vesting integration:**

```solidity
// In src/protocol/YieldForwarder.sol, add a flag to determine transfer method:

bool public useVestingTransfer; // New state variable

function processNewYield(uint256 _newYieldAmount) external override {
    if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
    if (yieldRecipient == address(0)) revert RecipientNotSet();

    if (useVestingTransfer) {
        // Approve and let recipient pull via transferInRewards()
        if (!yieldToken.approve(yieldRecipient, _newYieldAmount)) {
            revert CommonErrors.TransferFailed();
        }
        // Recipient must implement IStakediTry.transferInRewards()
        IStakediTry(yieldRecipient).transferInRewards(_newYieldAmount);
    } else {
        // Original simple transfer for non-vesting recipients
        if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
            revert CommonErrors.TransferFailed();
        }
    }

    emit YieldForwarded(yieldRecipient, _newYieldAmount);
}

// Add owner function to configure the flag
function setUseVestingTransfer(bool _useVestingTransfer) external onlyOwner {
    useVestingTransfer = _useVestingTransfer;
}
```

**Alternative Fix - Queue yield in StakediTry:**

Modify `StakediTry` to accept and queue incoming yield transfers, automatically processing them when vesting completes. This is more complex but preserves `YieldForwarder`'s simplicity.

**Immediate Mitigation:**
Never configure `YieldForwarder.yieldRecipient` to point directly at `StakediTry`. Instead, use an intermediate contract or manual process that calls `transferInRewards()` only when `getUnvestedAmount() == 0`.

## Proof of Concept

```solidity
// File: test/Exploit_VestingBypass.t.sol
// Run with: forge test --match-test test_YieldBypassesVestingMechanism -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/protocol/YieldForwarder.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "../src/token/iTRY/iTry.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockITry is ERC20 {
    constructor() ERC20("iTRY", "iTRY") {
        _mint(msg.sender, 1000000e18);
    }
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract Exploit_VestingBypass is Test {
    YieldForwarder forwarder;
    StakediTry staking;
    MockITry itry;
    
    address admin = address(0x1);
    address staker = address(0x2);
    
    function setUp() public {
        // Deploy iTRY token
        itry = new MockITry();
        
        // Deploy StakediTry vault
        vm.prank(admin);
        staking = new StakediTry(
            IERC20(address(itry)),
            admin, // initialRewarder
            admin  // owner
        );
        
        // Deploy YieldForwarder pointing to StakediTry
        forwarder = new YieldForwarder(
            address(itry),
            address(staking) // yieldRecipient = StakediTry
        );
        
        // Grant REWARDER_ROLE to forwarder
        vm.prank(admin);
        staking.grantRole(keccak256("REWARDER_ROLE"), address(forwarder));
        
        // Setup initial stake
        itry.transfer(staker, 10000e18);
        vm.startPrank(staker);
        itry.approve(address(staking), 10000e18);
        staking.deposit(10000e18, staker);
        vm.stopPrank();
    }
    
    function test_YieldBypassesVestingMechanism() public {
        // PHASE 1: Start initial vesting
        console.log("\n=== PHASE 1: Start Initial Vesting ===");
        
        itry.transfer(address(forwarder), 1000e18);
        
        vm.prank(admin);
        staking.transferInRewards(1000e18); // Start 1-hour vesting
        
        uint256 assetsAfterFirstVesting = staking.totalAssets();
        console.log("Total assets after first vesting starts:", assetsAfterFirstVesting / 1e18);
        console.log("Unvested amount:", staking.getUnvestedAmount() / 1e18);
        
        // PHASE 2: Fast forward to 50% vesting completion
        console.log("\n=== PHASE 2: 50% Through Vesting ===");
        vm.warp(block.timestamp + 30 minutes); // 50% of 1 hour
        
        uint256 unvestedMidpoint = staking.getUnvestedAmount();
        uint256 assetsMidpoint = staking.totalAssets();
        console.log("Unvested at midpoint:", unvestedMidpoint / 1e18);
        console.log("Total assets at midpoint:", assetsMidpoint / 1e18);
        assertApproxEqAbs(unvestedMidpoint, 500e18, 1e18, "Should be ~50% unvested");
        
        // PHASE 3: New yield arrives via YieldForwarder (VULNERABILITY)
        console.log("\n=== PHASE 3: New Yield Arrives Mid-Vesting ===");
        
        itry.mint(address(forwarder), 800e18);
        forwarder.processNewYield(800e18); // Transfers to StakediTry
        
        // Try to call transferInRewards() - should REVERT
        vm.prank(admin);
        vm.expectRevert(); // Will revert with StillVesting()
        staking.transferInRewards(800e18);
        
        console.log("transferInRewards() REVERTED as expected (still vesting)");
        
        // But totalAssets() IMMEDIATELY includes the new 800 tokens!
        uint256 assetsAfterNewYield = staking.totalAssets();
        uint256 unvestedAfterNewYield = staking.getUnvestedAmount();
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Unvested amount (unchanged):", unvestedAfterNewYield / 1e18);
        console.log("Total assets (INCREASED by 800!):", assetsAfterNewYield / 1e18);
        console.log("Expected assets (if vesting worked):", (assetsMidpoint + 0) / 1e18);
        
        // CRITICAL ASSERTION: totalAssets increased by 800 even though
        // the tokens were never added to vesting!
        assertEq(
            assetsAfterNewYield,
            assetsMidpoint + 800e18,
            "Vulnerability confirmed: 800 tokens bypassed vesting!"
        );
        
        // The unvested amount didn't change because transferInRewards() never ran
        assertEq(
            unvestedAfterNewYield,
            unvestedMidpoint,
            "Unvested amount unchanged - new yield not tracked!"
        );
        
        // PHASE 4: Share price impact
        console.log("\n=== PHASE 4: Share Price Impact ===");
        
        uint256 sharesBefore = staking.balanceOf(staker);
        uint256 shareValueBefore = staking.convertToAssets(sharesBefore);
        
        console.log("Staker's share value jumped to:", shareValueBefore / 1e18);
        console.log("This is an INSTANT jump, not gradual vesting!");
        
        // Prove that the 800 tokens are permanently in limbo:
        // Even after full vesting completes, they remain untracked
        vm.warp(block.timestamp + 1 hours);
        
        console.log("\n=== After First Vesting Completes ===");
        console.log("Unvested amount:", staking.getUnvestedAmount() / 1e18);
        console.log("Total assets:", staking.totalAssets() / 1e18);
        
        // Now transferInRewards() can be called again for NEW yield
        // but the 800 tokens from PHASE 3 remain permanently untracked
        assertEq(staking.getUnvestedAmount(), 0, "First vesting complete");
        assertEq(
            staking.totalAssets(),
            10000e18 + 1000e18 + 800e18,
            "800 tokens permanently counted but never vested"
        );
    }
}
```

## Notes

The vulnerability is structural in how `YieldForwarder` and `StakediTry` interact. While the deployment script shows `YieldForwarder` is initialized with `treasuryAddress` as the recipient [9](#0-8) , the owner can change this via `setYieldRecipient()` [10](#0-9) . If configured to send yield directly to `StakediTry`, the vesting bypass occurs automatically on every yield distribution during active vesting.

The issue is exacerbated by `StakediTry`'s minimum vesting period of 1 hour and maximum of 30 days [1](#0-0) —any yield distribution frequency shorter than the vesting period triggers this vulnerability repeatedly.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L33-36)
```text
    /// @notice Minimum allowed vesting period (1 hour)
    uint256 private constant MIN_VESTING_PERIOD = 1 hours;
    /// @notice Maximum allowed vesting period (30 days)
    uint256 private constant MAX_VESTING_PERIOD = 30 days;
```

**File:** src/token/wiTRY/StakediTry.sol (L40-48)
```text
    /// @notice The amount of the last asset distribution from the controller contract into this
    /// contract + any unvested remainder at that time
    uint256 public vestingAmount;

    /// @notice The timestamp of the last asset distribution from the controller contract into this contract
    uint256 public lastDistributionTimestamp;

    /// @notice The vesting period of lastDistributionAmount over which it increasingly becomes available to stakers
    uint256 private vestingPeriod;
```

**File:** src/token/wiTRY/StakediTry.sol (L82-82)
```text
        vestingPeriod = MIN_VESTING_PERIOD;
```

**File:** src/token/wiTRY/StakediTry.sol (L113-119)
```text
    function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
        _updateVestingAmount(amount);
        // transfer assets from rewarder to this contract
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);

        emit RewardsReceived(amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L280-285)
```text
    function _updateVestingAmount(uint256 newVestingAmount) internal {
        if (getUnvestedAmount() > 0) revert StillVesting();

        vestingAmount = newVestingAmount;
        lastDistributionTimestamp = block.timestamp;
    }
```

**File:** src/protocol/YieldForwarder.sol (L97-107)
```text
    function processNewYield(uint256 _newYieldAmount) external override {
        if (_newYieldAmount == 0) revert CommonErrors.ZeroAmount();
        if (yieldRecipient == address(0)) revert RecipientNotSet();

        // Transfer yield tokens to the recipient
        if (!yieldToken.transfer(yieldRecipient, _newYieldAmount)) {
            revert CommonErrors.TransferFailed();
        }

        emit YieldForwarded(yieldRecipient, _newYieldAmount);
    }
```

**File:** src/protocol/YieldForwarder.sol (L124-131)
```text
    function setYieldRecipient(address _newRecipient) external onlyOwner {
        if (_newRecipient == address(0)) revert CommonErrors.ZeroAddress();

        address oldRecipient = yieldRecipient;
        yieldRecipient = _newRecipient;

        emit YieldRecipientUpdated(oldRecipient, _newRecipient);
    }
```

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

**File:** script/deploy/hub/02_DeployProtocol.s.sol (L188-195)
```text
    function _getYieldForwarderBytecode(address itryToken) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(YieldForwarder).creationCode,
            abi.encode(
                itryToken, // yieldToken
                treasuryAddress // initialRecipient
            )
        );
```
