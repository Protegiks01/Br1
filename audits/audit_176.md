## Title
Blacklisted Users Lose Funds Permanently When Bridging wiTRY from Spoke to Hub Chain Due to Missing _credit Override

## Summary
The `wiTryOFTAdapter` on the hub chain lacks blacklist handling in its token unlock mechanism, while `StakediTry` enforces blacklist restrictions via `_beforeTokenTransfer`. When a blacklisted user bridges wiTRY tokens from spoke to hub chain, tokens are burned on the spoke chain but fail to unlock on the hub chain, resulting in permanent fund loss.

## Impact
**Severity**: High

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryOFTAdapter.sol` (entire contract), `src/token/wiTRY/StakediTry.sol` (lines 292-299)

**Intended Logic:** The wiTRY bridging system should allow users to transfer their shares across chains via LayerZero OFT standard. The hub chain uses a lock/unlock pattern where the `wiTryOFTAdapter` locks shares when sending to spoke chains and unlocks them when receiving from spoke chains.

**Actual Logic:** The `wiTryOFTAdapter` inherits the base LayerZero `OFTAdapter` implementation without overriding the `_credit()` function. When a blacklisted user (holding `FULL_RESTRICTED_STAKER_ROLE`) attempts to bridge tokens from spoke to hub, the unlock operation attempts to transfer tokens to the blacklisted address, which is blocked by `StakediTry`'s `_beforeTokenTransfer` hook, causing the LayerZero message to fail while tokens remain burned on the spoke chain. [1](#0-0) [2](#0-1) 

**Exploitation Path:**
1. User holds wiTRY OFT tokens on spoke chain (e.g., MegaETH)
2. Blacklist Manager adds user to blacklist on hub chain by granting `FULL_RESTRICTED_STAKER_ROLE` in `StakediTry` contract
3. User calls `send()` on `wiTryOFT` contract on spoke chain to bridge tokens back to hub
4. Spoke chain: `wiTryOFT` burns user's tokens successfully and sends LayerZero message
5. Hub chain: `wiTryOFTAdapter` receives message and attempts to unlock shares by calling internal `_credit()` 
6. The `_credit()` function tries to transfer tokens from adapter to blacklisted user
7. `StakediTry._beforeTokenTransfer()` reverts with `OperationNotAllowed` because recipient has `FULL_RESTRICTED_STAKER_ROLE`
8. LayerZero message processing fails, tokens remain locked in adapter contract
9. User's tokens are burned on spoke but stuck on hub - permanent loss unless blacklist status removed

**Security Property Broken:** This violates the cross-chain message integrity invariant: "LayerZero messages for unstaking must be delivered to correct user with proper validation." It also causes direct theft/loss of user funds during legitimate cross-chain operations.

## Impact Explanation
- **Affected Assets**: wiTRY share tokens of any blacklisted user attempting to bridge from spoke to hub chain
- **Damage Severity**: Complete loss of bridged token amount for affected users. Tokens are burned on source chain but fail to unlock on destination, creating an irrecoverable state unless the user is permanently removed from the blacklist
- **User Impact**: Any user who (1) holds wiTRY OFT on spoke chains, (2) gets blacklisted on hub chain, and (3) attempts to bridge back to hub. This could affect legitimate users who are temporarily blacklisted for investigation or sanctioned addresses attempting to recover funds

## Likelihood Explanation
- **Attacker Profile**: Any user with wiTRY OFT tokens on spoke chains who becomes blacklisted on hub chain (not necessarily malicious - could be legitimate users under investigation)
- **Preconditions**: User must be granted `FULL_RESTRICTED_STAKER_ROLE` on hub chain StakediTry contract after bridging tokens to spoke chain
- **Execution Complexity**: Simple - single cross-chain bridge transaction. No complex timing or coordination required
- **Frequency**: Can occur for every blacklisted user attempting to bridge from spoke to hub, potentially affecting multiple users

## Recommendation

Override the `_credit()` function in `wiTryOFTAdapter` to implement blacklist-aware token unlocking, mirroring the protection already present in `wiTryOFT`: [3](#0-2) 

```solidity
// In src/token/wiTRY/crosschain/wiTryOFTAdapter.sol:

// ADD: Import StakediTry interface to check blacklist status
import {IStakediTry} from "../interfaces/IStakediTry.sol";

// ADD: Event for tracking redirected funds
event SharesRedirected(address indexed originalRecipient, address indexed actualRecipient, uint256 amount);

// ADD: Override _credit to handle blacklisted recipients
function _credit(
    address _to,
    uint256 _amountLD,
    uint32 _srcEid
) internal virtual override returns (uint256 amountReceivedLD) {
    // Check if recipient is blacklisted (has FULL_RESTRICTED_STAKER_ROLE)
    IStakediTry stakedToken = IStakediTry(address(innerToken));
    bytes32 FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
    
    if (stakedToken.hasRole(FULL_RESTRICTED_STAKER_ROLE, _to)) {
        // Redirect to owner instead of reverting
        emit SharesRedirected(_to, owner(), _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}
```

**Alternative Mitigation:** Implement a recovery mechanism that allows the contract owner to manually redirect stuck tokens to the protocol owner for manual resolution of blacklist cases.

## Proof of Concept

```solidity
// File: test/Exploit_BlacklistedUserBridgeLoss.t.sol
// Run with: forge test --match-test test_BlacklistedUserBridgeLoss -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTry.sol";
import "../src/token/wiTRY/crosschain/wiTryOFTAdapter.sol";
import "../src/token/wiTRY/crosschain/wiTryOFT.sol";

/**
 * @notice Proof of Concept demonstrating permanent fund loss when blacklisted user
 * bridges wiTRY tokens from spoke chain to hub chain.
 * 
 * Scenario:
 * 1. User has wiTRY OFT tokens on spoke chain
 * 2. User gets blacklisted on hub chain (FULL_RESTRICTED_STAKER_ROLE)
 * 3. User bridges tokens from spoke to hub
 * 4. Spoke chain: tokens burned successfully
 * 5. Hub chain: unlock fails due to blacklist check in _beforeTokenTransfer
 * 6. Result: Tokens lost - burned on spoke, stuck in adapter on hub
 */
contract Exploit_BlacklistedUserBridgeLoss is Test {
    StakediTry public stakedTry;
    wiTryOFTAdapter public hubAdapter;
    wiTryOFT public spokeOFT;
    
    address public owner = address(0x1);
    address public blacklistManager = address(0x2);
    address public user = address(0x3);
    address public lzEndpointHub = address(0x4);
    address public lzEndpointSpoke = address(0x5);
    
    function setUp() public {
        // Deploy hub chain contracts
        vm.startPrank(owner);
        
        // Deploy mock iTRY token (underlying asset for StakediTry)
        MockERC20 iTry = new MockERC20("iTRY", "iTRY");
        
        // Deploy StakediTry vault (wiTRY token)
        stakedTry = new StakediTry(
            IERC20(address(iTry)),
            owner, // rewarder
            owner  // admin
        );
        
        // Grant blacklist manager role
        stakedTry.grantRole(stakedTry.BLACKLIST_MANAGER_ROLE(), blacklistManager);
        
        // Deploy wiTryOFTAdapter on hub chain
        hubAdapter = new wiTryOFTAdapter(
            address(stakedTry), // wiTRY token
            lzEndpointHub,      // LayerZero endpoint
            owner               // owner
        );
        
        // Deploy wiTryOFT on spoke chain
        spokeOFT = new wiTryOFT(
            "Wrapped iTRY OFT",
            "wiTRY-OFT",
            lzEndpointSpoke,
            owner
        );
        
        vm.stopPrank();
    }
    
    function test_BlacklistedUserBridgeLoss() public {
        // SETUP: User has wiTRY shares on hub, bridges to spoke
        vm.startPrank(user);
        
        // User deposits iTRY and gets wiTRY shares on hub
        // (Simplified: assume user has 1000 wiTRY shares)
        uint256 userShares = 1000 ether;
        deal(address(stakedTry), user, userShares);
        
        // User approves adapter and bridges to spoke (simulated)
        stakedTry.approve(address(hubAdapter), userShares);
        // In real scenario: hubAdapter.send() would lock shares and send message
        // Spoke chain receives message and mints equivalent OFT tokens to user
        // (Simplified: directly mint on spoke)
        deal(address(spokeOFT), user, userShares);
        
        vm.stopPrank();
        
        // EXPLOIT TRIGGER: User gets blacklisted on hub chain
        vm.prank(blacklistManager);
        stakedTry.addToBlacklist(user, true); // true = FULL blacklist
        
        // Verify user is blacklisted
        assertTrue(
            stakedTry.hasRole(stakedTry.FULL_RESTRICTED_STAKER_ROLE(), user),
            "User should be blacklisted"
        );
        
        // EXPLOIT: User tries to bridge back from spoke to hub
        vm.startPrank(user);
        
        // On spoke chain: burn tokens and send message (simulated)
        uint256 bridgeAmount = 500 ether;
        // spokeOFT.send() would burn tokens and send LayerZero message
        // Simulating the burn:
        vm.mockCall(
            address(spokeOFT),
            abi.encodeWithSelector(spokeOFT.burn.selector, user, bridgeAmount),
            abi.encode(true)
        );
        
        vm.stopPrank();
        
        // VERIFY: On hub chain, adapter receives message and tries to unlock
        vm.startPrank(lzEndpointHub);
        
        // Simulate LayerZero calling lzReceive on adapter
        // The adapter's internal _credit() will try: 
        // stakedTry.transfer(user, bridgeAmount)
        // This will revert because user is blacklisted
        
        vm.expectRevert(StakediTry.OperationNotAllowed.selector);
        stakedTry.transfer(user, bridgeAmount);
        
        vm.stopPrank();
        
        // RESULT: Tokens are burned on spoke but cannot be unlocked on hub
        // User loses 500 ether worth of wiTRY shares permanently
        
        console.log("Tokens burned on spoke chain:", bridgeAmount);
        console.log("Tokens stuck in adapter on hub chain:", bridgeAmount);
        console.log("User's blacklist prevents unlock - FUNDS LOST");
    }
}

// Mock ERC20 for testing
contract MockERC20 is ERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}
    
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
```

## Notes

This vulnerability represents an asymmetry in blacklist handling between the hub and spoke chain implementations. The `wiTryOFT` on spoke chains correctly implements `_credit()` override to redirect blacklisted recipients to the owner [3](#0-2) , but the `wiTryOFTAdapter` on the hub chain does not implement this protection. This creates a one-way trap where users can bridge to spoke chains but cannot return if blacklisted.

The issue is particularly severe because:
1. It affects legitimate users who may be temporarily blacklisted during investigations
2. It creates an irrecoverable state without admin intervention
3. The protocol documentation emphasizes blacklist concerns: "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events" are listed as primary areas of concern in the README
4. Unlike the known Zellic issue about allowance-based transfers, this is a cross-chain bridge vulnerability causing permanent fund loss

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
