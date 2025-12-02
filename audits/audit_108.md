## Title
Whitelist Enforcement Breaks DeFi Composability and Can Lock User Funds in Non-Whitelisted Contracts

## Summary
The iTRY token's `_beforeTokenTransfer` function in WHITELIST_ENABLED state requires `msg.sender`, `from`, and `to` to all be whitelisted for normal transfers. This prevents whitelisted users from interacting with any non-whitelisted smart contracts (DEX routers, lending protocols, staking vaults), and can lock user funds if the transfer state changes after users have deposited into DeFi protocols.

## Impact
**Severity**: Medium

## Finding Description

**Location:** `src/token/iTRY/iTry.sol`, function `_beforeTokenTransfer`, lines 210-213 [1](#0-0) 

**Intended Logic:** The protocol documentation states "Only whitelisted user can send/receive/burn iTry tokens in a WHITELIST_ENABLED transfer state" which suggests restricting token senders and receivers to whitelisted addresses.

**Actual Logic:** The implementation requires ALL THREE parties in a transfer to be whitelisted: `msg.sender` (caller), `from` (token owner), and `to` (recipient). This means any intermediary contract facilitating a transfer on behalf of a user must also be whitelisted, even if both the user and final recipient are whitelisted.

**Exploitation Path:**

1. **Fund Lock Scenario**: User deposits iTRY into a lending protocol (e.g., Aave) during FULLY_ENABLED state
   - User is whitelisted and can freely interact with DeFi
   - Lending protocol holds user's iTRY tokens

2. **State Change**: Protocol admin changes transfer state to WHITELIST_ENABLED
   - This can happen for regulatory compliance or security reasons
   - Lending protocol contract address is not whitelisted

3. **Withdrawal Attempt**: User tries to withdraw iTRY from lending protocol
   - Lending protocol calls `transfer(user, amount)` or user calls withdrawal function
   - In `_beforeTokenTransfer`: `msg.sender` = lending protocol (❌ not whitelisted), `from` = lending protocol (❌ not whitelisted), `to` = user (✅ whitelisted)
   - Transaction reverts with `OperationNotAllowed()`

4. **Fund Lock**: User's iTRY remains stuck in the lending protocol until:
   - Admin whitelists the lending protocol contract, OR
   - Admin changes state back to FULLY_ENABLED

**Security Property Broken:** While technically not violating the stated invariant, this implementation creates a more severe restriction than documented and locks user funds temporarily when transfer state changes.

## Impact Explanation

- **Affected Assets**: iTRY tokens held by users in any non-whitelisted smart contract (DEXes, lending protocols, yield aggregators, bridges)

- **Damage Severity**: 
  - All whitelisted users lose the ability to use DeFi protocols in WHITELIST_ENABLED state
  - Users who deposited into DeFi protocols before state change cannot withdraw until admin intervention
  - The StakediTry vault must be whitelisted or users cannot stake iTRY [2](#0-1) 
  - Temporary fund lock requiring manual admin intervention for each DeFi integration

- **User Impact**: All users who interact with DeFi protocols, potentially thousands of users across multiple integrations

## Likelihood Explanation

- **Attacker Profile**: Not an active attack - this is a design flaw affecting all users when WHITELIST_ENABLED state is active

- **Preconditions**: 
  - Protocol is in WHITELIST_ENABLED state (activated by admin for compliance)
  - Users have previously deposited iTRY into non-whitelisted contracts, OR
  - Users attempt to use non-whitelisted DeFi protocols

- **Execution Complexity**: No complex execution needed - normal user operations (withdraw, trade, stake) automatically fail

- **Frequency**: Affects every transaction involving non-whitelisted contracts whenever WHITELIST_ENABLED state is active

## Recommendation

Modify the whitelist check to only validate the token sender (`from`) and recipient (`to`), not the intermediary caller (`msg.sender`). This aligns with the stated invariant and standard ERC20 behavior:

```solidity
// In src/token/iTRY/iTry.sol, function _beforeTokenTransfer, lines 210-213:

// CURRENT (vulnerable):
} else if (
    hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
        && hasRole(WHITELISTED_ROLE, to)
) {
    // normal case

// FIXED:
} else if (
    hasRole(WHITELISTED_ROLE, from) && hasRole(WHITELISTED_ROLE, to)
) {
    // normal case - only validate token sender and receiver, not intermediary caller
```

**Alternative Mitigation**: If validating `msg.sender` is intentional for compliance, document this behavior clearly and implement:
1. An emergency whitelist function to quickly add DeFi integrations
2. A grace period when changing to WHITELIST_ENABLED to allow withdrawals
3. Pre-emptive whitelisting of major DeFi protocols before activating WHITELIST_ENABLED

**Note on Cross-chain**: The same issue exists in the OFT implementation on spoke chains: [3](#0-2) 

## Proof of Concept

```solidity
// File: test/Exploit_WhitelistDeFiLock.t.sol
// Run with: forge test --match-test test_WhitelistDeFiLock -vvv

pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {IiTryDefinitions} from "../src/token/iTRY/IiTryDefinitions.sol";

// Mock DeFi Protocol (e.g., lending protocol)
contract MockLendingProtocol {
    iTry public token;
    mapping(address => uint256) public deposits;
    
    constructor(address _token) {
        token = iTry(_token);
    }
    
    function deposit(uint256 amount) external {
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
    }
    
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        deposits[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}

contract Exploit_WhitelistDeFiLock is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    MockLendingProtocol public lendingProtocol;
    
    address public admin;
    address public user;
    
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    bytes32 constant WHITELISTED_ROLE = keccak256("WHITELISTED_ROLE");
    bytes32 constant WHITELIST_MANAGER_ROLE = keccak256("WHITELIST_MANAGER_ROLE");
    
    function setUp() public {
        admin = address(this);
        user = makeAddr("user");
        
        // Deploy iTry token
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Grant roles
        itryToken.grantRole(WHITELIST_MANAGER_ROLE, admin);
        
        // Deploy mock lending protocol
        lendingProtocol = new MockLendingProtocol(address(itryToken));
        
        // Mint iTRY to user
        itryToken.mint(user, 1000e18);
    }
    
    function test_WhitelistDeFiLock() public {
        console.log("\n=== TEST: Whitelist Enforcement Locks Funds in DeFi ===\n");
        
        // SETUP: User deposits into lending protocol during FULLY_ENABLED
        vm.startPrank(user);
        itryToken.approve(address(lendingProtocol), 1000e18);
        lendingProtocol.deposit(1000e18);
        vm.stopPrank();
        
        assertEq(lendingProtocol.deposits(user), 1000e18, "Deposit successful");
        assertEq(itryToken.balanceOf(address(lendingProtocol)), 1000e18, "Protocol holds tokens");
        
        console.log("Step 1: User deposited 1000 iTRY into lending protocol");
        console.log("User balance:", itryToken.balanceOf(user));
        console.log("Protocol balance:", itryToken.balanceOf(address(lendingProtocol)));
        
        // EXPLOIT: Protocol changes to WHITELIST_ENABLED
        itryToken.addWhitelistAddress(_toArray(user));
        itryToken.updateTransferState(IiTryDefinitions.TransferState.WHITELIST_ENABLED);
        
        console.log("\nStep 2: Protocol changed to WHITELIST_ENABLED");
        console.log("User is whitelisted:", itryToken.hasRole(WHITELISTED_ROLE, user));
        console.log("Protocol is whitelisted:", itryToken.hasRole(WHITELISTED_ROLE, address(lendingProtocol)));
        
        // VERIFY: User cannot withdraw from lending protocol
        vm.startPrank(user);
        vm.expectRevert(IiTryDefinitions.OperationNotAllowed.selector);
        lendingProtocol.withdraw(1000e18);
        vm.stopPrank();
        
        console.log("\nStep 3: Withdrawal FAILED - funds locked!");
        console.log("User balance (still 0):", itryToken.balanceOf(user));
        console.log("Protocol balance (still has funds):", itryToken.balanceOf(address(lendingProtocol)));
        
        // User funds remain locked until admin whitelists the protocol
        assertEq(itryToken.balanceOf(user), 0, "User cannot recover funds");
        assertEq(itryToken.balanceOf(address(lendingProtocol)), 1000e18, "Funds locked in protocol");
        
        console.log("\n=== VULNERABILITY CONFIRMED: User funds locked in non-whitelisted protocol ===");
    }
    
    function _toArray(address addr) internal pure returns (address[] memory) {
        address[] memory arr = new address[](1);
        arr[0] = addr;
        return arr;
    }
}
```

## Notes

- This issue is distinct from the known issue about blacklisted users using allowances, which specifically states that `msg.sender` is NOT validated for blacklists in FULLY_ENABLED state. The whitelist implementation DOES validate `msg.sender`, creating this DeFi integration problem.

- The same restriction applies to the StakediTry vault - it must be whitelisted for users to stake iTRY in WHITELIST_ENABLED state, as the vault calls `transferFrom` on behalf of users during deposits.

- The issue exists on both hub chain (iTry.sol) and spoke chains (iTryTokenOFT.sol), affecting cross-chain DeFi integrations as well.

- While this may be intentional for regulatory compliance, the temporary fund lock when state changes represents a medium-severity issue requiring admin intervention to resolve.

### Citations

**File:** src/token/iTRY/iTry.sol (L210-213)
```text
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
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

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L168-169)
```text
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
```
