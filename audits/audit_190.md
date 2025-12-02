## Title
wiTryOFTAdapter Permanently Locks Shares When Crediting to Blacklisted Users

## Summary
The `wiTryOFTAdapter` contract does not override the `_credit()` function to handle blacklisted recipients during cross-chain message receipt. When shares are bridged back to L1 for a user who was blacklisted after initially sending shares cross-chain, the adapter's unlock attempt will revert, permanently locking those shares in the adapter contract with no recovery mechanism available.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFTAdapter.sol` [1](#0-0) 

**Intended Logic:** The wiTryOFTAdapter should safely handle cross-chain transfers of wiTRY shares using a lock/unlock pattern, ensuring shares can always be returned to legitimate users or redistributed if users become blacklisted.

**Actual Logic:** The adapter uses the base LayerZero `OFTAdapter._credit()` implementation which performs a simple `safeTransfer()` to unlock shares. When the recipient has `FULL_RESTRICTED_STAKER_ROLE` (blacklisted), the transfer reverts due to StakediTry's `_beforeTokenTransfer` hook, causing shares to become permanently locked in the adapter. [2](#0-1) 

**Exploitation Path:**
1. User (Alice) bridges 100 wiTRY shares from L1 (Ethereum) to L2 (MegaETH) via `wiTryOFTAdapter.send()`
   - Adapter locks shares by transferring from Alice to adapter address
   - LayerZero message sent to L2, wiTryOFT mints shares to Alice on L2

2. Alice gets blacklisted on L1 (admin grants `FULL_RESTRICTED_STAKER_ROLE` due to regulatory reasons)

3. Alice attempts to bridge shares back from L2 to L1
   - L2 wiTryOFT burns Alice's shares
   - LayerZero message delivered to L1 adapter's `lzReceive()`
   - Adapter calls `_credit(alice, 100 shares)` to unlock

4. The `_credit()` internal call attempts `IERC20(token).safeTransfer(alice, 100 shares)`
   - StakediTry's `_beforeTokenTransfer` hook checks if recipient (`to`) has `FULL_RESTRICTED_STAKER_ROLE`
   - Since Alice is blacklisted, the hook reverts with `OperationNotAllowed()`
   - The LayerZero message fails, shares remain locked in adapter
   - No rescue function exists in the adapter to recover these shares

**Security Property Broken:** Violates the protocol's invariant that blacklisted users' funds can be managed through the `redistributeLockedAmount` function, as that function only works on user balances, not shares locked in the adapter contract. [3](#0-2) 

## Impact Explanation
- **Affected Assets**: wiTRY shares (ERC4626 vault shares representing staked iTRY)
- **Damage Severity**: Complete permanent loss of bridged shares for any user blacklisted after initiating cross-chain transfer. The shares are locked in the adapter with no owner-accessible rescue function, and cannot be redistributed via `redistributeLockedAmount` since that only operates on user balances.
- **User Impact**: Any user who bridges wiTRY shares cross-chain and subsequently gets blacklisted loses those shares permanently. This affects legitimate users who may be blacklisted for regulatory compliance reasons after their shares are already in transit or locked on L2.

## Likelihood Explanation
- **Attacker Profile**: Not an intentional attack - affects any legitimate user who gets blacklisted after bridging shares
- **Preconditions**: 
  - User must have bridged wiTRY shares from L1 to L2 (shares locked in adapter)
  - User must be added to `FULL_RESTRICTED_STAKER_ROLE` blacklist on L1 before returning shares
  - User attempts to bridge shares back from L2 to L1
- **Execution Complexity**: Not an exploit - occurs through normal protocol operation when administrative action (blacklisting) occurs during cross-chain transfer lifecycle
- **Frequency**: Can occur for every user who gets blacklisted while having shares on L2, which could be multiple users given regulatory requirements for blacklisting

## Recommendation

The wiTryOFTAdapter should override `_credit()` to mirror the protection logic already implemented in wiTryOFT on spoke chains: [4](#0-3) 

**Recommended Fix:**

```solidity
// In src/token/wiTRY/crosschain/wiTryOFTAdapter.sol:

// Add import for StakediTry interface to check blacklist status
import {IStakediTry} from "../interfaces/IStakediTry.sol";

// Override _credit to handle blacklisted recipients
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // Check if recipient is blacklisted
    IStakediTry vault = IStakediTry(address(innerToken));
    if (vault.hasRole(vault.FULL_RESTRICTED_STAKER_ROLE(), _to)) {
        // Redirect to owner instead of reverting
        emit FundsRedirectedFromBlacklistedUser(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    
    return super._credit(_to, _amountLD, _srcEid);
}

event FundsRedirectedFromBlacklistedUser(address indexed blacklistedUser, address indexed redirectedTo, uint256 amount);
```

**Alternative Mitigation:**

Add a rescue function that allows the owner to manually unlock shares for blacklisted users and redirect to protocol-controlled address:

```solidity
function rescueBlacklistedShares(address blacklistedUser, uint256 amount) 
    external 
    onlyOwner 
{
    IStakediTry vault = IStakediTry(address(innerToken));
    require(vault.hasRole(vault.FULL_RESTRICTED_STAKER_ROLE(), blacklistedUser), "User not blacklisted");
    
    // Transfer to owner for redistribution
    IERC20(innerToken).safeTransfer(owner(), amount);
    emit BlacklistedSharesRecovered(blacklistedUser, amount);
}
```

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedUserSharesLocked.t.sol
// Run with: forge test --match-test test_BlacklistedUserSharesLockedInAdapter -vvv

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {StakediTry} from "../src/token/wiTRY/StakediTry.sol";
import {wiTryOFTAdapter} from "../src/token/wiTRY/crosschain/wiTryOFTAdapter.sol";
import {wiTryOFT} from "../src/token/wiTRY/crosschain/wiTryOFT.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Exploit_BlacklistedUserSharesLocked is Test {
    StakediTry public vault;
    wiTryOFTAdapter public adapter;
    iTry public itry;
    
    address public owner;
    address public alice;
    address public blacklistManager;
    address public lzEndpoint;
    
    bytes32 public constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
    bytes32 public constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    
    function setUp() public {
        owner = makeAddr("owner");
        alice = makeAddr("alice");
        blacklistManager = makeAddr("blacklistManager");
        lzEndpoint = makeAddr("lzEndpoint");
        
        // Deploy iTry token
        vm.startPrank(owner);
        iTry itryImpl = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            owner
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(itryImpl), initData);
        itry = iTry(address(proxy));
        
        // Deploy StakediTry vault
        vault = new StakediTry(IERC20(address(itry)), owner, owner);
        vault.grantRole(BLACKLIST_MANAGER_ROLE, blacklistManager);
        
        // Deploy wiTryOFTAdapter
        adapter = new wiTryOFTAdapter(address(vault), lzEndpoint, owner);
        
        // Mint iTry and initial deposit to vault
        itry.mint(owner, 1 ether);
        itry.approve(address(vault), 1 ether);
        vault.deposit(1 ether, owner);
        vm.stopPrank();
        
        // Setup Alice with wiTRY shares
        vm.startPrank(owner);
        itry.mint(alice, 100 ether);
        vm.stopPrank();
        
        vm.startPrank(alice);
        itry.approve(address(vault), 100 ether);
        vault.deposit(100 ether, alice);
        vm.stopPrank();
    }
    
    function test_BlacklistedUserSharesLockedInAdapter() public {
        console.log("\n=== Demonstrating wiTRY Shares Locked in Adapter for Blacklisted User ===\n");
        
        // STEP 1: Alice bridges shares to L2 (simulated by transferring to adapter)
        console.log("STEP 1: Alice sends shares cross-chain (L1->L2)");
        uint256 aliceShares = vault.balanceOf(alice);
        console.log("  Alice's wiTRY shares:", aliceShares);
        
        vm.startPrank(alice);
        vault.approve(address(adapter), aliceShares);
        // Simulate the adapter locking shares during send()
        vault.transfer(address(adapter), aliceShares);
        vm.stopPrank();
        
        uint256 adapterBalance = vault.balanceOf(address(adapter));
        console.log("  Shares locked in adapter:", adapterBalance);
        assertEq(adapterBalance, aliceShares, "Shares should be locked in adapter");
        
        // STEP 2: Alice gets blacklisted on L1
        console.log("\nSTEP 2: Alice gets blacklisted on L1");
        vm.prank(blacklistManager);
        vault.addToBlacklist(alice, true); // Full blacklist
        
        bool isBlacklisted = vault.hasRole(FULL_RESTRICTED_STAKER_ROLE, alice);
        console.log("  Alice blacklisted:", isBlacklisted);
        assertTrue(isBlacklisted, "Alice should be blacklisted");
        
        // STEP 3: Attempt to unlock shares back to Alice (simulating L2->L1 bridge)
        console.log("\nSTEP 3: Attempt to return shares to Alice");
        console.log("  Attempting transfer from adapter to Alice...");
        
        // This should revert because Alice is blacklisted
        vm.prank(address(adapter));
        vm.expectRevert(bytes4(keccak256("OperationNotAllowed()")));
        vault.transfer(alice, adapterBalance);
        
        console.log("  [FAILED] Transfer reverted due to blacklist check");
        console.log("  Shares remain locked in adapter:", vault.balanceOf(address(adapter)));
        
        // STEP 4: Verify shares are permanently stuck
        console.log("\nSTEP 4: Verify permanent lock - no recovery mechanism");
        
        // redistributeLockedAmount only works on user balances, not adapter
        vm.prank(owner);
        vm.expectRevert(bytes4(keccak256("OperationNotAllowed()")));
        vault.redistributeLockedAmount(address(adapter), owner);
        console.log("  [FAILED] redistributeLockedAmount cannot recover from adapter");
        
        // Verify adapter is not blacklisted (so redistribution wouldn't work anyway)
        bool adapterBlacklisted = vault.hasRole(FULL_RESTRICTED_STAKER_ROLE, address(adapter));
        console.log("  Adapter blacklisted:", adapterBlacklisted);
        assertFalse(adapterBlacklisted, "Adapter is not blacklisted");
        
        // Verify no rescue function exists in adapter
        console.log("  wiTryOFTAdapter has no rescue function for locked shares");
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Result: ", adapterBalance / 1e18, "wiTRY shares permanently locked");
        console.log("Impact: User funds permanently lost with no recovery path");
        
        assertGt(vault.balanceOf(address(adapter)), 0, "Shares permanently stuck in adapter");
    }
}
```

## Notes

**Critical Asymmetry Identified:**
- The spoke chain implementation (`wiTryOFT`) has blacklist protection in `_credit()` that redirects tokens to the owner when crediting blacklisted users
- The hub chain implementation (`wiTryOFTAdapter`) lacks this protection entirely
- This asymmetry creates a permanent fund loss scenario unique to the hub chain

**Why Standard Recovery Mechanisms Fail:**
1. `redistributeLockedAmount` requires the source address to have `FULL_RESTRICTED_STAKER_ROLE` and uses `balanceOf(from)` - the adapter itself is not blacklisted
2. The adapter contract has no rescue or emergency withdrawal functions
3. LayerZero's base OFTAdapter does not include token recovery mechanisms

**Comparison with Similar Implementation:**
The `wiTryOFT` contract on spoke chains correctly handles this scenario by checking blacklist status and redirecting to owner, demonstrating that the developers were aware of this risk but failed to implement the same protection on the hub chain adapter. [4](#0-3)

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L26-33)
```text
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/wiTRY/StakediTry.sol (L168-185)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && !hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            uint256 iTryToVest = previewRedeem(amountToDistribute);
            _burn(from, amountToDistribute);
            _checkMinShares();
            // to address of address(0) enables burning
            if (to == address(0)) {
                _updateVestingAmount(iTryToVest);
            } else {
                _mint(to, amountToDistribute);
            }

            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L292-299)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, from) && to != address(0)) {
            revert OperationNotAllowed();
        }
        if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L84-97)
```text
    function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
        internal
        virtual
        override
        returns (uint256 amountReceivedLD)
    {
        // If the recipient is blacklisted, emit an event, redistribute funds, and credit the owner
        if (blackList[_to]) {
            emit RedistributeFunds(_to, _amountLD);
            return super._credit(owner(), _amountLD, _srcEid);
        } else {
            return super._credit(_to, _amountLD, _srcEid);
        }
    }
```
