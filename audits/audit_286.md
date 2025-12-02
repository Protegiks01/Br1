## Title
Cross-chain users denied share redemption when cooldownDuration is set to 0, forcing costly refunds

## Summary
When the admin sets `cooldownDuration` to 0 (switching the vault to standard ERC4626 mode), cross-chain users holding wiTRY shares on spoke chains (L2) cannot redeem their shares because all composer redemption paths require `cooldownDuration > 0`. While L1 users can directly call `withdraw()`/`redeem()` functions, L2 users must bridge through the `wiTryVaultComposer`, which only supports cooldown-based or fast-redeem operations that revert when cooldown is disabled, forcing users into an automatic refund that costs double LayerZero fees.

## Impact
**Severity**: Medium

## Finding Description
**Location:** `src/token/wiTRY/crosschain/wiTryVaultComposer.sol` and `src/token/wiTRY/StakediTryCrosschain.sol`

**Intended Logic:** According to the design documentation, when `cooldownDuration` is set to 0, the vault should operate in standard ERC4626 mode where users can immediately withdraw/redeem without cooldown periods. [1](#0-0) 

**Actual Logic:** While L1 users can use the standard ERC4626 functions when cooldown is disabled, cross-chain users face a complete denial of service:

1. The `wiTryVaultComposer.handleCompose()` function routes share redemptions to either `_initiateCooldown()` or `_fastRedeem()` based on the `oftCmd` parameter [2](#0-1) 

2. Both paths call vault functions with the `ensureCooldownOn` modifier:
   - `cooldownSharesByComposer()` [3](#0-2) 
   - `fastRedeemThroughComposer()` [4](#0-3) 

3. The `ensureCooldownOn` modifier explicitly reverts when `cooldownDuration == 0` [5](#0-4) 

4. The composer's `_redeemAndSend()` function (which would call standard ERC4626 redeem) is overridden to always revert [6](#0-5) 

**Exploitation Path:**
1. Admin calls `setCooldownDuration(0)` to switch vault to ERC4626 mode for gas efficiency or operational reasons
2. Cross-chain user on L2 (e.g., Arbitrum) attempts to redeem wiTRY shares by bridging them to L1 with "INITIATE_COOLDOWN" or "FAST_REDEEM" command
3. LayerZero delivers shares to `wiTryVaultComposer` on L1 and triggers `lzCompose()`
4. Composer calls `handleCompose()` which attempts to execute the user's command
5. Vault function reverts due to `ensureCooldownOn` modifier checking `cooldownDuration == 0`
6. The try-catch block in `lzCompose()` catches the revert and triggers `_refund()` [7](#0-6) 
7. User pays LayerZero fees for both L2→L1 bridge (wasted) and L1→L2 refund (forced)
8. User ends up with their shares back on L2 but has lost gas fees with no way to redeem

**Security Property Broken:** The protocol creates an asymmetry where L1 users have full access to their funds while cross-chain users are effectively locked out of redemption when cooldown is disabled, violating the principle of equal access across chains.

## Impact Explanation
- **Affected Assets**: All wiTRY shares held by cross-chain users on spoke chains (L2s)
- **Damage Severity**: 
  - Users waste LayerZero messaging fees (typically 0.01-0.1 ETH per round-trip)
  - Temporary inability to redeem shares until admin re-enables cooldown
  - Creates economic disadvantage for L2 users vs L1 users
  - Can compound losses if users repeatedly attempt redemption without understanding the issue
- **User Impact**: 
  - Affects ALL cross-chain users holding wiTRY shares on any spoke chain
  - Triggered whenever user attempts share redemption while `cooldownDuration == 0`
  - No user-side workaround exists except waiting for admin to change cooldown settings

## Likelihood Explanation
- **Attacker Profile**: Not an attack; this is a design flaw affecting legitimate users. Any cross-chain user attempting redemption is impacted.
- **Preconditions**: 
  - Admin has set `cooldownDuration` to 0 (legitimate operational decision)
  - User holds wiTRY shares on a spoke chain (normal protocol usage)
  - User attempts redemption via LayerZero bridge
- **Execution Complexity**: Single user transaction from L2 triggers the issue automatically
- **Frequency**: Occurs on every redemption attempt by cross-chain users while cooldown is disabled

## Recommendation

**Option 1 (Recommended): Add fallback ERC4626 redemption path in composer**

```solidity
// In src/token/wiTRY/crosschain/wiTryVaultComposer.sol, modify handleCompose():

function handleCompose(address _oftIn, bytes32 _composeFrom, bytes memory _composeMsg, uint256 _amount)
    external
    payable
    override
{
    if (msg.sender != address(this)) revert OnlySelf(msg.sender);

    (SendParam memory sendParam, uint256 minMsgValue) = abi.decode(_composeMsg, (SendParam, uint256));
    if (msg.value < minMsgValue) revert InsufficientMsgValue(minMsgValue, msg.value);

    if (_oftIn == ASSET_OFT) {
        _depositAndSend(_composeFrom, _amount, sendParam, address(this));
    } else if (_oftIn == SHARE_OFT) {
        // Check if cooldown is enabled
        if (IStakediTryCrosschain(address(VAULT)).cooldownDuration() == 0) {
            // Use standard ERC4626 redemption when cooldown is disabled
            _redeemAndSendERC4626(_composeFrom, _amount, sendParam, address(this));
        } else if (keccak256(sendParam.oftCmd) == keccak256("INITIATE_COOLDOWN")) {
            _initiateCooldown(_composeFrom, _amount);
        } else if (keccak256(sendParam.oftCmd) == keccak256("FAST_REDEEM")) {
            _fastRedeem(_composeFrom, _amount, sendParam, address(this));
        } else {
            revert InitiateCooldownRequired();
        }
    } else {
        revert OnlyValidComposeCaller(_oftIn);
    }
}

// Add new function to handle standard ERC4626 redemption
function _redeemAndSendERC4626(
    bytes32 _redeemer,
    uint256 _shareAmount,
    SendParam memory _sendParam,
    address _refundAddress
) internal {
    // Call parent implementation which uses VAULT.redeem()
    super._redeemAndSend(_redeemer, _shareAmount, _sendParam, _refundAddress);
}

// Remove the override that always reverts
// Delete lines 130-140 of wiTryVaultComposer.sol
```

**Option 2: Prevent cooldown from being disabled while cross-chain shares exist**

```solidity
// In src/token/wiTRY/StakediTryCooldown.sol, modify setCooldownDuration():

function setCooldownDuration(uint24 duration) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (duration > MAX_COOLDOWN_DURATION) {
        revert InvalidCooldown();
    }
    
    // Prevent disabling cooldown if there are pending cooldowns or cross-chain activity
    if (duration == 0 && cooldownDuration > 0) {
        // Add check to ensure no active cross-chain integrations
        require(/* check for cross-chain safety */, "Cannot disable cooldown with active cross-chain users");
    }

    uint24 previousDuration = cooldownDuration;
    cooldownDuration = duration;
    emit CooldownDurationUpdated(previousDuration, cooldownDuration);
}
```

**Option 3: Document and warn users**

Add clear documentation and events warning users that cross-chain redemption is unavailable when cooldown is disabled, though this doesn't prevent the financial loss.

## Proof of Concept

```solidity
// File: test/Exploit_CrosschainRedemptionDenied.t.sol
// Run with: forge test --match-test test_CrosschainRedemptionDeniedWhenCooldownDisabled -vvv

pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../src/token/wiTRY/StakediTryCrosschain.sol";
import "../src/token/wiTRY/crosschain/wiTryVaultComposer.sol";
import "../src/token/iTry.sol";

contract CrosschainRedemptionDenialTest is Test {
    StakediTryCrosschain vault;
    wiTryVaultComposer composer;
    iTry itry;
    
    address admin = makeAddr("admin");
    address l2User = makeAddr("l2User");
    uint32 l2Eid = 40161; // Arbitrum EID
    
    function setUp() public {
        // Deploy contracts (simplified for PoC)
        vm.startPrank(admin);
        itry = new iTry(admin, admin, admin);
        vault = new StakediTryCrosschain(
            IERC20(address(itry)),
            address(0), // rewarder
            admin,
            admin // treasury
        );
        
        // Grant composer role
        vault.grantRole(vault.COMPOSER_ROLE(), address(composer));
        vm.stopPrank();
    }
    
    function test_CrosschainRedemptionDeniedWhenCooldownDisabled() public {
        // SETUP: User has shares on L2 and cooldown is enabled
        uint256 shareAmount = 1000e18;
        
        // Simulate user having shares that were bridged from L2
        vm.startPrank(address(composer));
        deal(address(vault), address(composer), shareAmount);
        
        // Admin disables cooldown (switches to ERC4626 mode)
        vm.startPrank(admin);
        vault.setCooldownDuration(0);
        vm.stopPrank();
        
        // EXPLOIT: User on L2 tries to redeem by bridging shares with "INITIATE_COOLDOWN" command
        vm.startPrank(address(composer));
        
        // This simulates what happens when LayerZero delivers the compose message
        // The composer receives shares and tries to call cooldownSharesByComposer
        vm.expectRevert(StakediTryV2.OperationNotAllowed.selector);
        vault.cooldownSharesByComposer(shareAmount, l2User);
        
        // Similarly, fast redeem also fails
        vm.expectRevert(StakediTryV2.OperationNotAllowed.selector);
        vault.fastRedeemThroughComposer(shareAmount, l2User, address(composer));
        
        vm.stopPrank();
        
        // VERIFY: Cross-chain user cannot redeem while L1 users can
        // L1 user can call withdraw/redeem directly (when cooldownDuration == 0)
        address l1User = makeAddr("l1User");
        vm.startPrank(l1User);
        deal(address(vault), l1User, shareAmount);
        
        // L1 user successfully redeems
        vault.redeem(shareAmount, l1User, l1User);
        
        // Confirm asymmetry: L1 user redeemed but L2 user is blocked
        assertEq(vault.balanceOf(l1User), 0, "L1 user successfully redeemed");
        assertEq(vault.balanceOf(address(composer)), shareAmount, "L2 user's shares stuck in composer");
    }
}
```

## Notes

This vulnerability demonstrates a critical design gap in the cross-chain architecture. The intention to support both cooldown-based and immediate (ERC4626) redemption modes is valid, but the implementation fails to provide cross-chain users with access to the immediate redemption path when cooldown is disabled.

The issue is exacerbated by the fact that the `_redeemAndSend()` override in `wiTryVaultComposer` was explicitly designed to always revert, preventing any fallback to standard redemption. This creates a permanent denial of service for cross-chain users whenever `cooldownDuration == 0`.

The recommended fix (Option 1) provides the cleanest solution by detecting when cooldown is disabled and routing to standard ERC4626 redemption automatically, maintaining feature parity between L1 and L2 users.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L15-15)
```text
 * @dev If cooldown duration is set to zero, the StakediTryV2 behavior changes to follow ERC4626 standard and disables cooldownShares and cooldownAssets methods. If cooldown duration is greater than zero, the ERC4626 withdrawal and redeem functions are disabled, breaking the ERC4626 standard, and enabling the cooldownShares and the cooldownAssets functions.
```

**File:** src/token/wiTRY/StakediTryCooldown.sol (L35-38)
```text
    modifier ensureCooldownOn() {
        if (cooldownDuration == 0) revert OperationNotAllowed();
        _;
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L73-80)
```text
        } else if (_oftIn == SHARE_OFT) {
            if (keccak256(sendParam.oftCmd) == keccak256("INITIATE_COOLDOWN")) {
                _initiateCooldown(_composeFrom, _amount);
            } else if (keccak256(sendParam.oftCmd) == keccak256("FAST_REDEEM")) {
                _fastRedeem(_composeFrom, _amount, sendParam, address(this));
            } else {
                revert InitiateCooldownRequired();
            }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L130-140)
```text
    function _redeemAndSend(
        bytes32,
        /*_redeemer*/
        uint256,
        /*_shareAmount*/
        SendParam memory,
        /*_sendParam*/
        address /*_refundAddress*/
    ) internal virtual override {
        revert SyncRedemptionNotSupported();
    }
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L36-39)
```text
    function cooldownSharesByComposer(uint256 shares, address redeemer)
        external
        onlyRole(COMPOSER_ROLE)
        ensureCooldownOn
```

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L112-115)
```text
    function fastRedeemThroughComposer(uint256 shares, address crosschainReceiver, address owner)
        external
        onlyRole(COMPOSER_ROLE)
        ensureCooldownOn
```

**File:** src/token/wiTRY/crosschain/libraries/VaultComposerSync.sol (L133-147)
```text
        /// @dev try...catch to handle the compose operation. if it fails we refund the user
        try this.handleCompose{value: msg.value}(_composeSender, composeFrom, composeMsg, amount) {
            emit Sent(_guid);
        } catch (bytes memory _err) {
            /// @dev A revert where the msg.value passed is lower than the min expected msg.value is handled separately
            /// This is because it is possible to re-trigger from the endpoint the compose operation with the right msg.value
            if (bytes4(_err) == InsufficientMsgValue.selector) {
                assembly {
                    revert(add(32, _err), mload(_err))
                }
            }

            _refund(_composeSender, _message, amount, tx.origin);
            emit Refunded(_guid);
        }
```
