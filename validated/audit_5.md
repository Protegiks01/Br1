Based on my thorough validation following the Brix Money Protocol Validation Framework, I assess this claim as **VALID HIGH SEVERITY VULNERABILITY**.

# Validation Result: CONFIRMED VALID

## Title
wiTryOFTAdapter Permanently Locks Shares When Crediting to Blacklisted Users

## Summary
The `wiTryOFTAdapter` contract on Ethereum L1 fails to override the `_credit()` function to handle blacklisted recipients, creating a critical asymmetry with the spoke chain `wiTryOFT` implementation. When users bridge wiTRY shares from L2 back to L1 after being blacklisted, the unlock operation reverts due to StakediTry's transfer restrictions, permanently locking shares in the adapter with no recovery mechanism.

## Impact
**Severity**: High

This results in **permanent and irreversible loss of user funds**. Users who legitimately bridge wiTRY shares cross-chain and subsequently get blacklisted for regulatory compliance lose all bridged shares permanently. The shares become locked in the adapter with no owner-accessible rescue function, and cannot be recovered through `redistributeLockedAmount` since that requires the source address itself to be blacklisted, not merely holding blacklisted users' funds.

## Finding Description

**Location:** [1](#0-0) 

**Intended Logic:**
The wiTryOFTAdapter should safely handle bidirectional cross-chain transfers of wiTRY shares, ensuring shares can always be returned to legitimate users or appropriately redistributed if users become blacklisted during the transfer lifecycle.

**Actual Logic:**
The adapter relies on LayerZero's base `OFTAdapter._credit()` implementation, which performs a token transfer to unlock shares. When the recipient has `FULL_RESTRICTED_STAKER_ROLE`, StakediTry's `_beforeTokenTransfer` hook blocks the transfer: [2](#0-1) 

**Exploitation Path:**

1. **Initial Bridge (L1→L2)**: Alice bridges 100 wiTRY shares from Ethereum to L2
   - `wiTryOFTAdapter.send()` locks shares in adapter address
   - LayerZero message triggers `wiTryOFT.lzReceive()` on L2
   - wiTryOFT mints 100 shares to Alice on L2

2. **Blacklist Event**: Alice gets added to `FULL_RESTRICTED_STAKER_ROLE` on L1 due to regulatory requirements

3. **Return Bridge (L2→L1)**: Alice attempts to bridge back to Ethereum
   - `wiTryOFT.send()` burns Alice's 100 shares on L2
   - LayerZero delivers message to `wiTryOFTAdapter.lzReceive()` on L1
   - Adapter calls `_credit(alice, 100 shares)` internally
   - Base OFTAdapter attempts token transfer to alice
   - StakediTry's `_beforeTokenTransfer` reverts because recipient has `FULL_RESTRICTED_STAKER_ROLE`
   - Transaction reverts with `OperationNotAllowed()`
   - 100 shares remain permanently locked in adapter

4. **Failed Recovery**: The `redistributeLockedAmount` function cannot rescue these shares: [3](#0-2) 

This function requires the `from` address to have `FULL_RESTRICTED_STAKER_ROLE`, but the adapter itself is not blacklisted—it's merely holding shares intended for a blacklisted user.

## Impact Explanation

**Affected Assets**: wiTRY shares (ERC4626 vault shares representing staked iTRY)

**Damage Severity**:
- Complete permanent loss of all shares bridged by users who are blacklisted between outbound and inbound cross-chain transfers
- No administrative rescue function exists in the adapter contract
- Locked shares cannot be recovered, burned, or redistributed
- Each affected user loses 100% of their bridged share value

**User Impact**: Any user who bridges wiTRY shares cross-chain and subsequently gets blacklisted loses those shares permanently. This affects legitimate users who may be blacklisted for regulatory compliance reasons (AML, sanctions lists) after their shares are deployed on L2.

**Trigger Conditions**: Occurs whenever a user who has bridged shares to L2 is added to the blacklist on L1 before completing the return journey.

## Likelihood Explanation

**User Profile**: Any legitimate user participating in cross-chain operations

**Preconditions**:
1. User must have bridged wiTRY shares from L1 to L2 (shares locked in adapter)
2. User must be added to `FULL_RESTRICTED_STAKER_ROLE` blacklist on L1
3. User attempts to bridge shares back from L2 to L1

**Execution Complexity**: Not an exploit—occurs through normal protocol operation when administrative blacklisting occurs during the cross-chain transfer lifecycle

**Frequency**: Can occur for every user who gets blacklisted while having shares on L2. Given regulatory requirements for maintaining blacklists in DeFi protocols, this is not a theoretical edge case.

**Overall Likelihood**: MEDIUM-HIGH

The protocol explicitly supports blacklisting for regulatory compliance, and users will naturally use cross-chain functionality. The combination creates the permanent loss scenario.

## Recommendation

The wiTryOFTAdapter should override `_credit()` to mirror the protection logic already implemented in the spoke chain contract. This creates symmetry between hub and spoke implementations.

**Comparison with Existing Protection (Spoke Chain):** [4](#0-3) 

**Recommended Fix:**

Override `_credit()` in wiTryOFTAdapter to check if the recipient is blacklisted and redirect funds to the owner if so, matching the spoke chain implementation pattern.

## Notes

**Critical Asymmetry Identified:**

The spoke chain implementation (`wiTryOFT`) has blacklist protection in `_credit()` that redirects tokens to the owner when crediting blacklisted users, while the hub chain implementation (`wiTryOFTAdapter`) lacks this protection entirely. This asymmetry demonstrates that the development team was aware of the risk but failed to implement consistent protection across both chain types.

**Why Standard Recovery Mechanisms Fail:**

1. The `redistributeLockedAmount` function requires the source address to have `FULL_RESTRICTED_STAKER_ROLE`—but the adapter itself is not blacklisted
2. The adapter contract has no rescue or emergency withdrawal functions (verified at [1](#0-0) )
3. LayerZero's base OFTAdapter does not include token recovery mechanisms
4. StakediTry's `rescueTokens` function explicitly excludes the asset and wouldn't help with shares locked in external contracts

**Impact on Protocol Design:**

This vulnerability undermines the protocol's regulatory compliance framework by creating a scenario where legitimate blacklisting actions result in permanent fund loss rather than controlled fund redistribution.

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
