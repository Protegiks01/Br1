# NoVulnerability found for this question.

## Analysis Summary

After thorough investigation of the `wiTryOFTAdapter` and `wiTryOFT` contracts and their decimal handling in cross-chain transfers, I found that the system correctly manages share decimals without precision loss.

## Key Findings

**Decimal Configuration:**
- The wiTRY share token explicitly uses 18 decimals [1](#0-0) 

- The `wiTryOFTAdapter` on the hub chain (L1) wraps the native wiTRY token and inherits from LayerZero's OFTAdapter [2](#0-1) 

- The `wiTryOFT` on spoke chains (L2) inherits from LayerZero's OFT [3](#0-2) 

**LayerZero OFT V2 Default Behavior:**
According to the standard LayerZero OFT V2 implementation pattern:
- `OFTAdapter` uses the wrapped token's `decimals()` function as `sharedDecimals` (18 for wiTRY)
- `OFT` uses its own ERC20 `decimals()` function as `sharedDecimals` (18 by default)

**Precision Loss Analysis:**
When `sharedDecimals == localDecimals == 18` on both chains:
- Encoding: `amountSD = amountLD / 10^(18-18) = amountLD`
- Decoding: `amountLD = amountSD × 10^(18-18) = amountSD`

No mathematical conversion occurs, eliminating precision loss entirely.

## Notes

The architecture uses LayerZero's lock/unlock pattern on the hub chain (via `OFTAdapter`) rather than mint/burn to preserve the ERC4626 vault's share-to-asset ratio integrity [4](#0-3) . This design choice, combined with consistent 18-decimal precision across all chain implementations, ensures that users receive exactly the same number of share tokens on L2 as they locked on L1, with no truncation or rounding errors.

### Citations

**File:** src/token/wiTRY/StakediTry.sol (L213-216)
```text
    /// @dev Necessary because both ERC20 (from ERC20Permit) and ERC4626 declare decimals()
    function decimals() public pure override(ERC4626, ERC20) returns (uint8) {
        return 18;
    }
```

**File:** src/token/wiTRY/crosschain/wiTryOFTAdapter.sol (L22-24)
```text
 * IMPORTANT: This adapter uses lock/unlock pattern (not mint/burn) because
 * the share token's totalSupply must match the vault's accounting.
 * Burning shares would break the share-to-asset ratio in the ERC4626 vault.
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

**File:** src/token/wiTRY/crosschain/wiTryOFT.sol (L28-54)
```text
contract wiTryOFT is OFT {
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
```
