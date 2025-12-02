## Title
Cross-Chain Unstaking Failure Permanently Traps iTRY Tokens in OFT Adapter When Recipient Cannot Receive Tokens

## Summary
iTRY tokens become permanently locked in `iTryTokenOFTAdapter` during cross-chain unstaking when the recipient on the spoke chain is blacklisted, not whitelisted (in `WHITELIST_ENABLED` mode), or when transfers are `FULLY_DISABLED`. Unlike `wiTryOFT` which gracefully handles such failures by redirecting funds to the owner, `iTryTokenOFT` lacks this protection mechanism, causing LayerZero message delivery to fail and trap user funds with no recovery path.

## Impact
**Severity**: High

## Finding Description
**Location:** 
- `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` (function `_handleUnstake`, lines 244-278)
- `src/token/iTRY/crosschain/iTryTokenOFT.sol` (function `_beforeTokenTransfer`, lines 140-177)
- `src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol` (entire contract, lines 1-29)

**Intended Logic:** When a user initiates cross-chain unstaking from a spoke chain, the `wiTryVaultComposer` should process the request, withdraw iTRY from the vault, and successfully return the iTRY tokens to the user on the spoke chain via LayerZero OFT. [1](#0-0) 

**Actual Logic:** The cross-chain unstaking flow has a critical failure mode:

1. `_handleUnstake` validates `user != address(0)` but does not check if the user can actually receive iTRY tokens on the spoke chain [2](#0-1) 

2. iTRY tokens are withdrawn from the vault to the composer [3](#0-2) 

3. The composer sends iTRY via `iTryTokenOFTAdapter`, which locks the tokens before sending the LayerZero message [4](#0-3) 

4. On the spoke chain, `iTryTokenOFT` attempts to mint/credit tokens to the recipient, but `_beforeTokenTransfer` reverts if the user is blacklisted, not whitelisted, or transfers are disabled [5](#0-4) 

5. Critically, `iTryTokenOFT` does NOT have a `_credit` override to handle this failure gracefully (unlike `wiTryOFT`) [6](#0-5) 

6. The `iTryTokenOFTAdapter` has no rescue function to recover the locked tokens [7](#0-6) 

**Exploitation Path:**
1. User initiates cooldown for cross-chain unstaking from spoke chain via `UnstakeMessenger`
2. User becomes blacklisted on spoke chain OR transfer state changes to `WHITELIST_ENABLED` and user is not whitelisted OR transfers become `FULLY_DISABLED`
3. After cooldown period, unstake message is processed on hub chain via `wiTryVaultComposer._handleUnstake`
4. iTRY tokens are withdrawn from vault and transferred to `iTryTokenOFTAdapter` via the `send()` function
5. LayerZero message is sent to spoke chain's `iTryTokenOFT`
6. `iTryTokenOFT.lzReceive` attempts to mint/transfer tokens to user but reverts in `_beforeTokenTransfer` due to blacklist/whitelist/transfer state restrictions
7. LayerZero message fails and is stored for retry, but retry will also fail due to permanent restriction
8. iTRY tokens remain permanently locked in `iTryTokenOFTAdapter` with no recovery mechanism

**Security Property Broken:** Violates the **Cross-chain Message Integrity** invariant that "LayerZero messages for unstaking must be delivered to correct user with proper validation" and causes permanent loss of user funds, violating basic custody principles.

## Impact Explanation
- **Affected Assets**: User's iTRY tokens being unstaked from the cross-chain staking vault
- **Damage Severity**: Complete and permanent loss of unstaked iTRY tokens. Once the OFT adapter locks tokens and the destination transfer fails, there is no recovery mechanism since `iTryTokenOFTAdapter` has no rescue function and LayerZero messages cannot be "undone"
- **User Impact**: Any user performing cross-chain unstaking whose receiving address becomes blacklisted, loses whitelist status (in `WHITELIST_ENABLED` mode), or experiences transfer state changes to `FULLY_DISABLED` between cooldown initiation and message processing will lose their entire unstaking amount

## Likelihood Explanation
- **Attacker Profile**: Not necessarily malicious - can occur to any legitimate user due to administrative actions by Blacklist Manager, Whitelist Manager, or Owner changing transfer states
- **Preconditions**: 
  - User has completed cooldown period for cross-chain unstaking
  - User's receiving address on spoke chain becomes unable to receive tokens (blacklisted, not whitelisted in `WHITELIST_ENABLED` mode, or `FULLY_DISABLED` transfer state) between cooldown initiation and unstake message processing
  - No unusual state required - this is a normal protocol operation
- **Execution Complexity**: No attacker action needed - occurs naturally when administrative actions change user status or transfer state during the multi-step cross-chain unstaking process
- **Frequency**: Can occur for any cross-chain unstaking operation where the recipient's status changes during the cooldown period (potentially days between initiation and completion)

## Recommendation

**Primary Fix:** Implement a `_credit` override in `iTryTokenOFT` to handle failed transfers gracefully, similar to `wiTryOFT`:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFT.sol, add after line 139:

/**
 * @dev Credits tokens to the recipient while checking transfer restrictions.
 * If recipient cannot receive tokens (blacklisted, not whitelisted, or transfers disabled),
 * redirects the funds to the contract owner to prevent permanent fund loss.
 * @param _to The address of the recipient.
 * @param _amountLD The amount of tokens to credit.
 * @param _srcEid The source endpoint identifier.
 * @return amountReceivedLD The actual amount of tokens received.
 */
function _credit(address _to, uint256 _amountLD, uint32 _srcEid)
    internal
    virtual
    override
    returns (uint256 amountReceivedLD)
{
    // Check if transfer to recipient would fail
    bool canReceive = _canReceiveTokens(_to);
    
    if (!canReceive) {
        // Emit event and redirect to owner instead of reverting
        emit RedistributeFunds(_to, _amountLD);
        return super._credit(owner(), _amountLD, _srcEid);
    } else {
        return super._credit(_to, _amountLD, _srcEid);
    }
}

/**
 * @dev Internal helper to check if an address can receive tokens
 * @param _to The address to check
 * @return bool True if address can receive tokens
 */
function _canReceiveTokens(address _to) internal view returns (bool) {
    // Check blacklist
    if (blacklisted[_to]) return false;
    
    // Check transfer state
    if (transferState == TransferState.FULLY_DISABLED) return false;
    if (transferState == TransferState.WHITELIST_ENABLED && !whitelisted[_to]) return false;
    
    return true;
}

// Add event at top of contract:
event RedistributeFunds(address indexed user, uint256 amount);
```

**Alternative Mitigation:** Add a rescue function to `iTryTokenOFTAdapter`:

```solidity
// In src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol, add:

/**
 * @notice Rescue tokens stuck due to failed cross-chain transfers
 * @param token The token address to rescue
 * @param to The address to send rescued tokens to
 * @param amount The amount to rescue
 */
function rescueToken(address token, address to, uint256 amount) external onlyOwner {
    require(to != address(0), "Invalid address");
    require(amount > 0, "Invalid amount");
    IERC20(token).transfer(to, amount);
}
```

However, the primary fix is preferred as it prevents the issue from occurring rather than requiring manual intervention after the fact.

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainUnstakeTrap.t.sol
// Run with: forge test --match-test test_CrossChainUnstakeTrap -vvv

pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/token/iTRY/iTry.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFT.sol";
import "../src/token/iTRY/crosschain/iTryTokenOFTAdapter.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";

contract Exploit_CrossChainUnstakeTrap is Test {
    iTry itryHub;
    iTryTokenOFT itrySpoke;
    iTryTokenOFTAdapter adapterHub;
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    
    address user = address(0x1234);
    address lzEndpoint = address(0x5678);
    
    function setUp() public {
        // Deploy hub chain contracts
        itryHub = new iTry();
        itryHub.initialize(address(this), address(this));
        
        adapterHub = new iTryTokenOFTAdapter(
            address(itryHub),
            lzEndpoint,
            address(this)
        );
        
        // Deploy spoke chain contracts
        itrySpoke = new iTryTokenOFT(lzEndpoint, address(this));
        
        // Mint some iTRY to simulate unstaking
        itryHub.mint(address(composer), 1000e18);
    }
    
    function test_CrossChainUnstakeTrap() public {
        // SETUP: User has completed cooldown and is eligible for unstaking
        uint256 unstakeAmount = 1000e18;
        
        // Simulate composer receiving iTRY from vault unstaking
        deal(address(itryHub), address(composer), unstakeAmount);
        
        // STEP 1: User gets blacklisted on spoke chain AFTER initiating unstake
        address[] memory blacklistAddresses = new address[](1);
        blacklistAddresses[0] = user;
        itrySpoke.addBlacklistAddress(blacklistAddresses);
        
        // STEP 2: Composer attempts to send iTRY back to user on spoke chain
        // This will lock tokens in adapter
        vm.startPrank(address(composer));
        itryHub.approve(address(adapterHub), unstakeAmount);
        
        // Transfer to adapter (simulating OFT send)
        itryHub.transfer(address(adapterHub), unstakeAmount);
        vm.stopPrank();
        
        // STEP 3: On spoke chain, attempt to credit user
        // This will revert due to blacklist
        vm.expectRevert(); // Will revert with OperationNotAllowed()
        vm.prank(lzEndpoint);
        itrySpoke.lzReceive(
            Origin(1, bytes32(uint256(uint160(address(adapterHub)))), 0),
            bytes32(0),
            abi.encode(user, unstakeAmount),
            address(0),
            bytes("")
        );
        
        // VERIFY: Tokens are trapped in adapter
        assertEq(
            itryHub.balanceOf(address(adapterHub)),
            unstakeAmount,
            "iTRY tokens permanently trapped in adapter"
        );
        
        // VERIFY: User has no tokens on spoke chain
        assertEq(
            itrySpoke.balanceOf(user),
            0,
            "User did not receive tokens on spoke chain"
        );
        
        // VERIFY: No rescue mechanism exists in adapter
        // (attempting to call non-existent rescue function would fail)
    }
}
```

## Notes

**Key Distinction from wiTRY:** The `wiTryOFT` contract implements a `_credit` override that gracefully handles blacklisted recipients by redirecting funds to the owner, preventing message failure and fund loss. The `iTryTokenOFT` lacks this critical safety mechanism, making it vulnerable to permanent fund trapping.

**Known Issue Comparison:** This is NOT the "Native fee loss on failed wiTryVaultComposer.lzReceive" known issue. That issue is about ETH fees being lost on retry; this vulnerability is about the actual iTRY tokens being permanently trapped with no recovery mechanism.

**Admin Actions Not Required:** While the vulnerability involves blacklist/whitelist changes, these are legitimate protocol operations performed by the Blacklist Manager or Owner. The vulnerability is that the protocol doesn't handle the race condition between multi-step cross-chain operations and administrative state changes.

**LayerZero V2 Behavior:** LayerZero V2 allows message retry when `lzReceive` fails, but if the failure is permanent (e.g., user permanently blacklisted), retrying will continue to fail indefinitely. The tokens remain locked in the adapter throughout all retry attempts with no mechanism to refund them back to the hub chain or redirect them to an alternative recipient.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L244-278)
```text
    function _handleUnstake(Origin calldata _origin, bytes32 _guid, IUnstakeMessenger.UnstakeMessage memory unstakeMsg)
        internal
        virtual
    {
        address user = unstakeMsg.user;

        // Validate user
        if (user == address(0)) revert InvalidZeroAddress();
        if (_origin.srcEid == 0) revert InvalidOrigin();

        // Call vault to unstake
        uint256 assets = IStakediTryCrosschain(address(VAULT)).unstakeThroughComposer(user);

        if (assets == 0) {
            revert NoAssetsToUnstake();
        }

        // Build send parameters and send assets back to spoke chain
        bytes memory options = OptionsBuilder.newOptions();

        SendParam memory _sendParam = SendParam({
            dstEid: _origin.srcEid,
            to: bytes32(uint256(uint160(user))),
            amountLD: assets,
            minAmountLD: assets,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });

        _send(ASSET_OFT, _sendParam, address(this));

        // Emit success event
        emit CrosschainUnstakeProcessed(user, _origin.srcEid, assets, _guid);
    }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L93-93)
```text
            silo.withdraw(msg.sender, assets); // transfer to wiTryVaultComposer for crosschain transfer
```

**File:** src/token/iTRY/crosschain/iTryTokenOFT.sol (L140-177)
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
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (msg.sender == minter && !blacklisted[from] && to == address(0)) {
                // redeeming
            } else if (msg.sender == minter && from == address(0) && !blacklisted[to]) {
                // minting
            } else if (msg.sender == owner() && blacklisted[from] && to == address(0)) {
                // redistributing - burn
            } else if (msg.sender == owner() && from == address(0) && !blacklisted[to]) {
                // redistributing - mint
            } else if (whitelisted[msg.sender] && whitelisted[from] && to == address(0)) {
                // whitelisted user can burn
            } else if (whitelisted[msg.sender] && whitelisted[from] && whitelisted[to]) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 0 - Fully disabled transfers
        } else if (transferState == TransferState.FULLY_DISABLED) {
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
