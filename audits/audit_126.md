## Title
Admin `redistributeLockedAmount` Function Blocked in FULLY_DISABLED State, Preventing Fund Recovery During Emergency

## Summary
The `redistributeLockedAmount` admin function in iTry.sol cannot execute when `transferState` is set to `FULLY_DISABLED` because the `_beforeTokenTransfer` hook unconditionally reverts all operations in this state, including admin burn/mint operations required for fund redistribution. This blocks critical fund recovery operations during emergency situations when they are most needed.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` (function `redistributeLockedAmount` lines 112-121, `_beforeTokenTransfer` hook lines 219-220)

**Intended Logic:** The `redistributeLockedAmount` function allows admins with `DEFAULT_ADMIN_ROLE` to rescue funds from blacklisted accounts by burning their tokens and minting to a new recipient. This should work in all transfer states to enable emergency fund recovery. [1](#0-0) 

**Actual Logic:** When `transferState` is `FULLY_DISABLED`, the `_beforeTokenTransfer` hook unconditionally reverts ALL operations without checking for admin privileges or special operations. [2](#0-1) 

In contrast, both `FULLY_ENABLED` and `WHITELIST_ENABLED` states have explicit allowances for admin redistribution operations: [3](#0-2) [4](#0-3) 

**Exploitation Path:**
1. Protocol enters emergency state and admin sets `transferState` to `FULLY_DISABLED` to halt all transfers
2. During this period, a user's account is identified as needing blacklisting (e.g., compromised account, regulatory requirement)
3. Admin blacklists the user and attempts to call `redistributeLockedAmount(blacklistedUser, safeRecipient)` to rescue their funds
4. The function calls `_burn(blacklistedUser, amount)` which internally calls `_beforeTokenTransfer(blacklistedUser, address(0), amount)`
5. The hook reverts at line 220 with `OperationNotAllowed()` because state is `FULLY_DISABLED`
6. Admin cannot redistribute funds until transferState is changed back to `FULLY_ENABLED` or `WHITELIST_ENABLED`, temporarily defeating the purpose of the emergency lockdown

**Security Property Broken:** The protocol's ability to perform critical admin fund recovery operations is blocked during emergency situations, creating a deadlock where blacklisted users' funds remain inaccessible longer than necessary.

## Impact Explanation
- **Affected Assets**: iTRY tokens held by blacklisted users during FULLY_DISABLED emergency periods
- **Damage Severity**: Temporary fund lock - funds remain in blacklisted accounts until transferState is changed, then redistribution can proceed. No permanent loss, but delays recovery operations during emergencies.
- **User Impact**: Blacklisted users whose funds need redistribution during a FULLY_DISABLED emergency must wait for state change before admin can rescue their tokens. This also affects protocol operations that depend on timely fund redistribution.

## Likelihood Explanation
- **Attacker Profile**: No attacker required - this is a protocol design flaw affecting admin operations
- **Preconditions**: 
  1. `transferState` is set to `FULLY_DISABLED` (emergency scenario)
  2. A user account is blacklisted and needs fund redistribution
- **Execution Complexity**: The issue manifests when admin attempts normal fund recovery operations during emergency lockdown
- **Frequency**: Occurs whenever fund redistribution is needed during FULLY_DISABLED state

## Recommendation

Add the same admin operation checks in the FULLY_DISABLED state that exist in the other states:

```solidity
// In src/token/iTRY/iTry.sol, function _beforeTokenTransfer, line 219:

// CURRENT (vulnerable):
} else if (transferState == TransferState.FULLY_DISABLED) {
    revert OperationNotAllowed();
}

// FIXED:
} else if (transferState == TransferState.FULLY_DISABLED) {
    // Allow admin to redistribute locked amounts even when fully disabled
    if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // redeeming - allow minter operations
    } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // minting - allow minter operations
    } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
        // redistributing - burn (admin emergency operation)
    } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
        // redistributing - mint (admin emergency operation)
    } else {
        revert OperationNotAllowed();
    }
}
```

**Alternative mitigation:** Document that `redistributeLockedAmount` cannot be used during FULLY_DISABLED state and establish emergency procedures requiring state changes for fund recovery. However, this is less secure as it requires temporarily relaxing the emergency lockdown.

## Proof of Concept

```solidity
// File: test/Exploit_RedistributeBlockedInFullyDisabled.t.sol
// Run with: forge test --match-test test_redistributeBlockedInFullyDisabled -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/IiTryDefinitions.sol";

contract RedistributeBlockedInFullyDisabledTest is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    
    address public admin;
    address public minter;
    address public blacklistedUser;
    address public recipient;
    
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    bytes32 public constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    
    function setUp() public {
        admin = address(this);
        minter = makeAddr("minter");
        blacklistedUser = makeAddr("blacklistedUser");
        recipient = makeAddr("recipient");
        
        // Deploy iTry
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            minter
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Setup roles
        itryToken.grantRole(BLACKLIST_MANAGER_ROLE, admin);
        
        // Mint tokens to blacklisted user
        vm.prank(minter);
        itryToken.mint(blacklistedUser, 1000e18);
        
        // Blacklist the user
        address[] memory users = new address[](1);
        users[0] = blacklistedUser;
        itryToken.addBlacklistAddress(users);
    }
    
    function test_redistributeBlockedInFullyDisabled() public {
        // SETUP: Verify user is blacklisted and has tokens
        assertEq(itryToken.balanceOf(blacklistedUser), 1000e18, "Blacklisted user should have tokens");
        assertTrue(itryToken.hasRole(BLACKLISTED_ROLE, blacklistedUser), "User should be blacklisted");
        
        // SETUP: Set transfer state to FULLY_DISABLED (emergency scenario)
        itryToken.updateTransferState(IiTryDefinitions.TransferState.FULLY_DISABLED);
        assertEq(uint256(itryToken.transferState()), uint256(IiTryDefinitions.TransferState.FULLY_DISABLED), "State should be FULLY_DISABLED");
        
        // EXPLOIT: Admin tries to redistribute locked funds during emergency
        // This should work (admin emergency operation) but will fail
        vm.expectRevert(abi.encodeWithSelector(IiTryDefinitions.OperationNotAllowed.selector));
        itryToken.redistributeLockedAmount(blacklistedUser, recipient);
        
        // VERIFY: Funds remain locked with blacklisted user
        assertEq(itryToken.balanceOf(blacklistedUser), 1000e18, "Funds still locked with blacklisted user");
        assertEq(itryToken.balanceOf(recipient), 0, "Recipient did not receive funds");
        
        // DEMONSTRATE WORKAROUND: Admin must change state back to perform redistribution
        itryToken.updateTransferState(IiTryDefinitions.TransferState.FULLY_ENABLED);
        itryToken.redistributeLockedAmount(blacklistedUser, recipient);
        
        // Now it works
        assertEq(itryToken.balanceOf(blacklistedUser), 0, "Blacklisted user funds redistributed");
        assertEq(itryToken.balanceOf(recipient), 1000e18, "Recipient received funds");
    }
}
```

## Notes

The same vulnerability exists in the cross-chain variant `iTryTokenOFT.sol`: [5](#0-4) 

The OFT contract's `redistributeLockedAmount` function at lines 109-118 will also fail when `transferState` is `FULLY_DISABLED` for the same reason. [6](#0-5) 

Both contracts should be patched with the same fix to ensure admin emergency operations work across all deployment chains.

### Citations

**File:** src/token/iTRY/iTry.sol (L112-121)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L184-188)
```text
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
```

**File:** src/token/iTRY/iTry.sol (L203-207)
```text
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
```

**File:** src/token/iTRY/iTry.sol (L219-220)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L109-118)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyOwner {
        if (blacklisted[from] && !blacklisted[to]) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L174-175)
```text
        } else if (transferState == TransferState.FULLY_DISABLED) {
            revert OperationNotAllowed();
```
