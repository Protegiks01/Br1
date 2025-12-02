# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the Brix Money Protocol's cross-chain architecture and ERC4626 implementation, I found that **the question's premise does not match the actual system design**.

### Architectural Reality

The protocol uses a **hub-and-spoke architecture** with a single ERC4626 vault:

**Hub Chain (Ethereum):**
- `StakediTryCrosschain` - The ONLY ERC4626 vault instance [1](#0-0) 
- `wiTryOFTAdapter` - Locks/unlocks wiTRY shares for bridging [2](#0-1) 

**Spoke Chains (e.g., MegaETH):**
- `wiTryOFT` - ERC20 OFT tokens representing share count (NOT an ERC4626 vault) [3](#0-2) 
- `UnstakeMessenger` - Initiates cross-chain redemption messages [4](#0-3) 

### Why No Arbitrage Exists

1. **Single ERC4626 Implementation**: All `previewRedeem`, `previewWithdraw`, `convertToAssets`, and `convertToShares` functions execute on the same OpenZeppelin ERC4626 vault instance on the hub chain. [5](#0-4) 

2. **No Spoke Chain Vaults**: Spoke chains do not perform ERC4626 conversions. They only hold OFT token representations of share counts. [6](#0-5) 

3. **Unified Redemption Path**: All cross-chain redemptions (cooldown, fast redeem, or unstake) ultimately execute on the hub chain vault through the composer. [7](#0-6) 

4. **Consistent Rounding**: The same `totalAssets()` override and vesting logic applies to all conversions within a transaction. [8](#0-7) 

5. **1:1 Share Bridging**: When shares are bridged via OFT, the share count remains identical (no conversion or rounding occurs during bridging). [9](#0-8) 

### Cross-chain Timing Is Expected Behavior

While cross-chain messages have timing delays during which yield distribution can change the share-to-asset ratio [10](#0-9) , this represents expected price appreciation, not an exploitable arbitrage. Users receive the conversion rate at execution time on the hub chain, which is consistent with standard ERC4626 behavior.

### Notes

The question appears to assume a hypothetical deployment scenario where multiple independent StakediTry vaults exist on different chains. Such an architecture would indeed create arbitrage risks if share prices diverged. However, the actual Brix Money implementation uses a centralized hub vault design that eliminates this attack vector by ensuring all ERC4626 operations occur on a single canonical instance.

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L17-17)
```text
contract StakediTryCrosschain is StakediTryFastRedeem, IStakediTryCrosschain {
```

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L6-33)
```text
/**
 * @title wiTryOFTAdapter
 * @notice OFT Adapter for wiTRY shares on hub chain (Ethereum Mainnet)
 * @dev Wraps the StakedUSDe share token to enable cross-chain transfers via LayerZero
 *
 * Architecture (Phase 1 - Instant Redeems):
 * - Hub Chain (Ethereum): StakedUSDe (ERC4626 vault) + wiTryOFTAdapter (locks shares)
 * - Spoke Chain (MegaETH): ShareOFT (mints/burns based on messages)
 *
 * Flow:
 * 1. User deposits iTRY into StakedUSDe vault → receives wiTRY shares
 * 2. User approves wiTryOFTAdapter to spend their wiTRY
 * 3. User calls send() on wiTryOFTAdapter
 * 4. Adapter locks wiTRY shares and sends LayerZero message
 * 5. ShareOFT mints equivalent shares on spoke chain
 *
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
 */
contract wiTryOFTAdapter is OFTAdapter {
    /**
     * @notice Constructor for wiTryOFTAdapter
     * @param _token Address of the wiTRY share token from StakedUSDe
     * @param _lzEndpoint LayerZero endpoint address for Ethereum Mainnet
     * @param _owner Address that will own this adapter (typically deployer)
     */
    constructor(address _token, address _lzEndpoint, address _owner) OFTAdapter(_token, _lzEndpoint, _owner) {}
```

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L6-28)
```text
/**
 * @title wiTryOFT
 * @notice OFT representation of wiTRY shares on spoke chains (MegaETH)
 * @dev This contract mints/burns share tokens based on LayerZero messages from the hub chain
 *
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
 *
 * NOTE: These shares represent staked iTRY in the vault. The share value
 * increases as yield is distributed to the vault on the hub chain.
 */
contract wiTryOFT is OFT {
```

**File:** src/token/wiTRY/crosschain/UnstakeMessenger.sol (L14-47)
```text
/**
 * @title UnstakeMessenger
 * @notice User-facing contract on spoke chains for initiating crosschain unstaking operations
 *
 * @dev Part of the iTRY crosschain unstaking system. Key responsibilities:
 *      - Fee quoting: Provides accurate spoke→hub message fees via two quote functions
 *      - Fee validation: Ensures caller sends sufficient native tokens for round-trip messaging
 *      - Native value forwarding: Embeds returnTripAllocation in LayerZero options for hub execution
 *      - Security: Enforces msg.sender as user address (prevents authorization spoofing)
 *      - Refund handling: Returns excess msg.value to user after message dispatch
 *
 * @dev User Flow:
 *      1. Client queries wiTryVaultComposer.quoteUnstakeReturn() on hub to get hub→spoke return fee
 *      2. Client queries quoteUnstakeWithBuffer() (recommended) or quoteUnstakeWithReturnValue() (exact)
 *         - quoteUnstakeWithBuffer(): Applies feeBufferBPS safety margin (e.g., 10%) for gas fluctuations
 *         - quoteUnstakeWithReturnValue(): Returns exact fee without buffer
 *      3. User calls unstake(returnTripAllocation) with quoted total as msg.value
 *      4. Contract calculates spoke→hub fee with embedded returnTripAllocation
 *      5. Contract validates msg.value ≥ total fee, dispatches message, refunds excess to user
 *      6. Hub receives returnTripAllocation as native value for return trip execution
 *
 * @dev Fee Architecture:
 *      - Single msg.value payment covers both message directions (spoke→hub + hub→spoke)
 *      - returnTripAllocation is fixed parameter (not calculated from msg.value remainder)
 *      - Spoke→hub fee = LayerZero messaging cost + returnTripAllocation embedded in options
 *      - Contract embeds returnTripAllocation via addExecutorLzReceiveOption (native value forwarding)
 *      - Hub receives exact returnTripAllocation for return message; hub refunds excess to wiTryVaultComposer
 *      - Spoke refunds any msg.value excess (buffer) to user immediately after dispatch
 *
 * @dev Configuration:
 *      - feeBufferBPS: Recommended safety buffer (500-5000 BPS = 5-50%), adjustable by owner
 *      - hubEid: Immutable hub chain endpoint ID, set at deployment
 *      - peers[hubEid]: Trusted wiTryVaultComposer address on hub (bytes32), set via setPeer()
 */
```

**File:** src/token/wiTRY/StakediTry.sol (L19-19)
```text
contract StakediTry is SingleAdminAccessControl, ReentrancyGuard, ERC20Permit, ERC4626, IStakediTry {
```

**File:** src/token/wiTRY/StakediTry.sol (L113-119)
```text
    function transferInRewards(uint256 amount) external nonReentrant onlyRole(REWARDER_ROLE) notZero(amount) {
        _updateVestingAmount(amount);
        // transfer assets from rewarder to this contract
        IERC20(asset()).safeTransferFrom(msg.sender, address(this), amount);

        emit RewardsReceived(amount);
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L192-194)
```text
    function totalAssets() public view override returns (uint256) {
        return IERC20(asset()).balanceOf(address(this)) - getUnvestedAmount();
    }
```

**File:** src/token/wiTRY/crosschain/wiTryVaultComposer.sol (L17-26)
```text
/**
 * @title wiTryVaultComposer - Async Cooldown Vault Composer
 * @author Inverter Network
 * @notice wiTryVaultComposer that supports deposit-and-send and async cooldown-based redemption
 * @dev Extends VaultComposerSync with custom redemption logic for StakediTryCrosschain vault
 *      Deposits are instant and shares can be sent cross-chain immediately
 *      Redemptions require a cooldown period before claiming assets
 *      OApp inheritance allows direct LayerZero messages for unstake operations
 */
contract wiTryVaultComposer is VaultComposerSync, IwiTryVaultComposer, OApp {
```
