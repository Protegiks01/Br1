# NoVulnerability found for this question.

## Explanation

The security question asks: "If _withdraw() on line 117 reverts after lines 114-115 execute, are the storage changes rolled back?"

**Answer: YES, the storage changes ARE guaranteed to be rolled back.**

This is ensured by the Ethereum Virtual Machine's fundamental transaction atomicity property. In the `cooldownShares` function: [1](#0-0) 

All operations within a single transaction are atomic in Solidity/EVM. If ANY operation reverts, ALL state changes in that transaction are automatically rolled back. This means:

1. **Lines 114-115** write to storage (`cooldownEnd` and `underlyingAmount`)
2. **Line 117** calls `_withdraw()` which can revert for multiple reasons:
   - `nonReentrant` modifier check
   - `notZero` validation for assets/shares
   - `FULL_RESTRICTED_STAKER_ROLE` checks
   - OpenZeppelin ERC4626 `super._withdraw()` operations
   - `_checkMinShares()` validation [2](#0-1) 

3. **If _withdraw reverts**, the entire transaction reverts and lines 114-115 are automatically rolled back

**Why this is NOT a vulnerability:**

- EVM transaction atomicity is a core blockchain guarantee that cannot be bypassed
- There are no `delegatecall`, `selfdestruct`, or low-level calls in the execution path that could break atomicity
- The `nonReentrant` modifier prevents reentrancy attacks
- Type casts (uint104, uint152) are safe and won't silently overflow

The cooldown state remains consistent because either the entire `cooldownShares` operation succeeds (all three steps), or it fails completely (no state changes persist). This is the expected and secure behavior.

### Citations

**File:** src/token/wiTRY/StakediTryCooldown.sol (L114-117)
```text
        cooldowns[msg.sender].cooldownEnd = uint104(block.timestamp) + cooldownDuration;
        cooldowns[msg.sender].underlyingAmount += uint152(assets);

        _withdraw(msg.sender, address(silo), msg.sender, assets, shares);
```

**File:** src/token/wiTRY/StakediTry.sol (L262-278)
```text
    function _withdraw(address caller, address receiver, address _owner, uint256 assets, uint256 shares)
        internal
        override
        nonReentrant
        notZero(assets)
        notZero(shares)
    {
        if (
            hasRole(FULL_RESTRICTED_STAKER_ROLE, caller) || hasRole(FULL_RESTRICTED_STAKER_ROLE, receiver)
                || hasRole(FULL_RESTRICTED_STAKER_ROLE, _owner)
        ) {
            revert OperationNotAllowed();
        }

        super._withdraw(caller, receiver, _owner, assets, shares);
        _checkMinShares();
    }
```
