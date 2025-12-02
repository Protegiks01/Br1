# NoVulnerability found for this question.

## Analysis Summary

After comprehensive investigation of the yield distribution mechanism and its interaction with the cooldown system, I found that the accounting is **correct** and **no vulnerability exists**.

### Key Findings:

**1. totalAssets() Correctly Excludes Silo-Held iTRY** [1](#0-0) 

The `totalAssets()` function only counts iTRY held by the StakediTry vault contract itself (`address(this)`), not the separate iTrySilo contract. When users initiate cooldowns, iTRY is transferred from the vault to the silo, removing it from the vault's balance and thus from `totalAssets()` calculations.

**2. Yield Distribution Uses Vesting to Prevent Manipulation** [2](#0-1) 

When `transferInRewards()` is called, the yield is immediately marked as "vesting" and gradually becomes available over the vesting period. The `totalAssets()` calculation subtracts unvested amounts, preventing instant share price manipulation. [3](#0-2) 

**3. Cooldown Entitlements Are Fixed at Initiation** [4](#0-3) 

When users call `cooldownAssets()` or `cooldownShares()`, their entitlement is calculated using the **current** share price (based on `totalAssets()` at that moment) and stored in `cooldowns[msg.sender].underlyingAmount`. This amount is fixed and does not change with subsequent yield distributions. [5](#0-4) 

When `unstake()` is called, users receive exactly the amount recorded in their cooldown storage—no more, no less.

**4. Silo Access Control is Properly Restricted** [6](#0-5) 

The silo's `withdraw()` function can only be called by the staking vault contract, preventing unauthorized drainage.

### Accounting Verification:

The system maintains correct accounting throughout all scenarios:
- Users who cooldown **before** yield distribution: Lock in lower share price (correct—no yield benefit)
- Users who cooldown **after** yield vests: Lock in higher share price (correct—earned yield while staking)  
- Users who cooldown **during** vesting: Lock in partial yield benefit based on vesting progress (correct—proportional reward)

**System Invariant Maintained:** Total iTRY = Vault Balance + Silo Balance = Starting Balance + Distributed Yield

### Notes:

The design intentionally separates cooldown iTRY from active vault iTRY to ensure users in cooldown don't benefit from (or dilute) yield distributed to active stakers. This is expected behavior, not a vulnerability. The vesting mechanism further protects against manipulation by gradually releasing yield over time rather than instantly affecting the share price.

### Citations

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

**File:** src/token/wiTRY/StakediTry.sol (L199-211)
```text
    function getUnvestedAmount() public view returns (uint256) {
        uint256 timeSinceLastDistribution = block.timestamp - lastDistributionTimestamp;

        if (timeSinceLastDistribution >= vestingPeriod) {
            return 0;
        }

        uint256 deltaT;
        unchecked {
            deltaT = (vestingPeriod - timeSinceLastDistribution);
        }
        return (deltaT * vestingAmount) / vestingPeriod;
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L80-92)
```text
    function unstake(address receiver) external {
        UserCooldown storage userCooldown = cooldowns[msg.sender];
        uint256 assets = userCooldown.underlyingAmount;

        if (block.timestamp >= userCooldown.cooldownEnd || cooldownDuration == 0) {
            userCooldown.cooldownEnd = 0;
            userCooldown.underlyingAmount = 0;

            silo.withdraw(receiver, assets);
        } else {
            revert InvalidCooldown();
        }
    }
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L96-105)
```text
    function cooldownAssets(uint256 assets) external ensureCooldownOn returns (uint256 shares) {
        if (assets > maxWithdraw(msg.sender)) revert ExcessiveWithdrawAmount();

        shares = previewWithdraw(assets);

        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
    }
```

**File:** src/token/wiTRY/iTrySilo.sol (L23-30)
```text
    modifier onlyStakingVault() {
        if (msg.sender != STAKING_VAULT) revert OnlyStakingVault();
        _;
    }

    function withdraw(address to, uint256 amount) external onlyStakingVault {
        iTry.transfer(to, amount);
    }
```
