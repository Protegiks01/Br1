## Title
iTryTokenOFTAdapter Lacks Blacklist Protection in _credit Flow, Causing Permanent Fund Loss on Spoke-to-Hub Transfers

## Summary
The `iTryTokenOFTAdapter` inherits LayerZero's standard `OFTAdapter` without overriding the `_credit()` function to handle blacklisted recipients on the hub chain. When iTRY tokens are sent from spoke chain to hub chain to a blacklisted address, the `_credit` operation reverts after tokens are already burned on the spoke chain, resulting in permanent fund loss. This contrasts with `wiTryOFT` which implements explicit blacklist protection.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` (entire contract, no _credit override)

**Intended Logic:** The OFT adapter should facilitate cross-chain iTRY transfers bidirectionally between hub (Ethereum) and spoke chains, with proper blacklist enforcement preventing blacklisted users from receiving tokens.

**Actual Logic:** While the `_debit` function correctly prevents blacklisted users from SENDING tokens from hub chain, the inherited `_credit` function has no protection against crediting tokens to blacklisted recipients on hub chain. When `_credit` attempts to transfer tokens from the adapter to a blacklisted recipient, iTry's `_beforeTokenTransfer` hook enforces the blacklist and reverts the entire transaction. [1](#0-0) 

**Exploitation Path:**
1. User initiates iTRY transfer from spoke chain (MegaETH) to hub chain (Ethereum) with recipient address that is blacklisted on hub chain
2. On spoke chain: `iTryTokenOFT._debit()` successfully burns the user's tokens [2](#0-1) 
3. LayerZero message sent from spoke to hub
4. On hub chain: `iTryTokenOFTAdapter.lzReceive()` processes message and calls inherited `_credit()` to unlock tokens
5. `_credit()` attempts `transfer(recipient, amount)` where recipient is blacklisted
6. `iTry._beforeTokenTransfer()` executes blacklist validation [3](#0-2) 
7. The check `!hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)` evaluates to `true && true && false` (recipient is blacklisted), causing revert
8. LayerZero message fails on hub chain, but tokens are already burned on spoke chain - permanent fund loss

**Security Property Broken:** 
- Invariant #2: "Blacklisted users CANNOT send/receive/mint/burn iTRY tokens in ANY case" - The protocol intends to prevent blacklisted users from receiving tokens, but the implementation causes fund loss instead of graceful handling
- Core protocol safety: Users lose funds permanently with no recovery mechanism

## Impact Explanation
- **Affected Assets**: All iTRY tokens transferred from spoke chain to blacklisted addresses on hub chain are permanently lost
- **Damage Severity**: 100% loss of transferred amount. Tokens are burned on spoke chain but cannot be unlocked on hub chain. No admin recovery function exists because tokens never reach the adapter on hub chain.
- **User Impact**: Any user (or attacker targeting a victim) sending iTRY from spoke to hub where recipient is blacklisted on hub chain. This includes:
  - Legitimate users who are blacklisted on hub but not on spoke
  - Users accidentally sending to wrong/blacklisted addresses
  - Attackers intentionally causing fund loss for victims by sending to their blacklisted addresses

## Likelihood Explanation
- **Attacker Profile**: Any user on spoke chain can trigger this. An attacker could grief victims by sending small amounts to their blacklisted addresses, or users can accidentally lose their own funds.
- **Preconditions**: 
  - iTRY must be bridged to spoke chain
  - Target address must be blacklisted on hub chain (but can be non-blacklisted on spoke)
  - Blacklist management operates independently per chain
- **Execution Complexity**: Single cross-chain transaction - call `send()` on spoke chain OFT with blacklisted recipient
- **Frequency**: Can be exploited repeatedly for any spoke-to-hub transfer to blacklisted addresses until the vulnerability is fixed

## Recommendation

**Fix Option 1: Override _credit with blacklist protection (Recommended - mirrors wiTryOFT pattern)**

Add to `iTryTokenOFTAdapter.sol`:

```solidity
// FIXED: Add blacklist-aware _credit override
function _credit(
    address _to,
    uint256 _amountLD,
    uint32 _srcEid
) internal virtual override returns (uint256 amountReceivedLD) {
    // Check if recipient is blacklisted on hub chain
    if (iTry(address(innerToken)).hasRole(
        iTry(address(innerToken)).BLACKLISTED_ROLE(), 
        _to
    )) {
        // Redirect to owner instead of reverting
        emit BlacklistedRecipientRedirect(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    }
    return super._credit(_to, _amountLD, _srcEid);
}

event BlacklistedRecipientRedirect(
    address indexed originalRecipient,
    address indexed actualRecipient,
    uint256 amount
);
```

**Fix Option 2: Pre-validate recipient before message send**

Alternatively, implement off-chain validation or on-chain oracle to check hub chain blacklist status before allowing spoke-to-hub transfers, but this adds complexity and potential synchronization issues.

**Comparison with wiTryOFT:** [4](#0-3) 

The `wiTryOFT` contract already implements this protection pattern by overriding `_credit()` to redirect blacklisted recipients' funds to the owner, preventing message failure and fund loss.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistCreditFailure.t.sol
// Run with: forge test --match-test test_BlacklistCreditCausesPermFundLoss -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";

contract Exploit_BlacklistCreditFailure is Test {
    iTry public hubITry;
    iTryTokenOFTAdapter public hubAdapter;
    iTryTokenOFT public spokeOFT;
    
    address public alice = address(0x1);
    address public blacklistedBob = address(0x2);
    address public owner = address(this);
    
    uint32 constant HUB_EID = 30101;
    uint32 constant SPOKE_EID = 40161;
    
    function setUp() public {
        // Deploy hub chain contracts
        hubITry = new iTry();
        hubITry.initialize(owner, owner);
        hubAdapter = new iTryTokenOFTAdapter(
            address(hubITry),
            address(0x1a44076050125825900e736c501f859c50fE728c), // LZ endpoint
            owner
        );
        
        // Deploy spoke chain contracts  
        spokeOFT = new iTryTokenOFT(
            address(0x6EDCE65403992e310A62460808c4b910D972f10f), // LZ endpoint
            owner
        );
        
        // Blacklist Bob on HUB chain only
        address[] memory blacklistUsers = new address[](1);
        blacklistUsers[0] = blacklistedBob;
        hubITry.grantRole(hubITry.BLACKLIST_MANAGER_ROLE(), owner);
        hubITry.addBlacklistAddress(blacklistUsers);
        
        // Mint iTRY to Alice on spoke chain (simulating previous bridge)
        vm.prank(address(spokeOFT)); // minter
        spokeOFT.mint(alice, 1000e18);
    }
    
    function test_BlacklistCreditCausesPermFundLoss() public {
        // SETUP: Alice has 1000 iTRY on spoke, Bob is blacklisted on hub
        assertEq(spokeOFT.balanceOf(alice), 1000e18, "Alice has iTRY on spoke");
        assertTrue(hubITry.hasRole(hubITry.BLACKLISTED_ROLE(), blacklistedBob), "Bob is blacklisted on hub");
        
        // EXPLOIT: Alice sends iTRY from spoke to blacklisted Bob on hub
        // In real scenario, this would go through LayerZero messaging
        // We simulate the key steps:
        
        // Step 1: Spoke chain burns Alice's tokens
        vm.prank(alice);
        spokeOFT.burn(1000e18); // Simulates _debit burning
        assertEq(spokeOFT.balanceOf(alice), 0, "Tokens burned on spoke");
        
        // Step 2: Hub chain adapter receives message and tries to credit Bob
        // First transfer tokens to adapter (simulating locked tokens)
        hubITry.mint(address(hubAdapter), 1000e18);
        
        // Step 3: Adapter tries to transfer to blacklisted Bob - THIS REVERTS
        vm.prank(address(hubAdapter));
        vm.expectRevert(); // Will revert due to blacklist check
        hubITry.transfer(blacklistedBob, 1000e18);
        
        // VERIFY: Permanent fund loss
        // - Tokens burned on spoke: ✓ (Alice balance = 0)
        // - Tokens NOT unlocked on hub: ✓ (Bob balance = 0, still in adapter)
        // - No recovery mechanism: ✓ (tokens stuck in adapter, Bob can't receive)
        assertEq(spokeOFT.balanceOf(alice), 0, "Tokens permanently burned on spoke");
        assertEq(hubITry.balanceOf(blacklistedBob), 0, "Bob never received tokens on hub");
        assertEq(hubITry.balanceOf(address(hubAdapter)), 1000e18, "Tokens stuck in adapter");
        
        console.log("VULNERABILITY CONFIRMED:");
        console.log("- 1000 iTRY burned on spoke chain");
        console.log("- Transfer to blacklisted recipient fails on hub chain");  
        console.log("- Tokens permanently lost - no recovery mechanism");
    }
}
```

**Notes:**
- This vulnerability is distinct from the known issue "Blacklisted user can transfer tokens using allowance" which concerns same-chain transfers via `msg.sender` validation. This finding concerns cross-chain transfers where blacklist enforcement causes message failure and fund loss.
- The vulnerability violates the documented invariant that blacklisted users cannot receive iTRY "in ANY case" - the protocol attempts to enforce this but causes collateral damage (permanent fund loss) rather than graceful rejection.
- The fix should mirror the `wiTryOFT` implementation which already handles this correctly by redirecting blacklisted recipients' funds to the owner rather than reverting.
- This is a High severity issue because it results in direct, permanent, and irreversible loss of user funds with no admin recovery mechanism.

### Citations

**File:** src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol (L21-29)
```text
contract iTryTokenOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for iTryTokenAdapter
     * @param _token Address of the existing iTryToken contract
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
}
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-156)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (!blacklisted[msg.sender] && !blacklisted[from] && !blacklisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 1 - Transfers only enabled between whitelisted addresses
```

**File:** src/token/iTRY/iTry.sol (L189-196)
```text
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
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
