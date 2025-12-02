# NoVulnerability found for this question.

## Analysis

I investigated whether `maxRedeem` in `cooldownSharesByComposer` validates MIN_SHARES constraints and if this creates an exploitable vulnerability for blocking `redistributeLockedAmount`.

### Technical Findings

1. **maxRedeem does NOT check MIN_SHARES after burning**: The `maxRedeem` function at line 44 [1](#0-0)  only validates against the composer's balance (standard ERC4626 behavior), not whether burning would violate MIN_SHARES.

2. **MIN_SHARES validation occurs in _withdraw**: The actual MIN_SHARES check happens in the `_withdraw` function [2](#0-1)  and via `_checkMinShares()` [3](#0-2) , which allows totalSupply to equal MIN_SHARES exactly but reverts if 0 < totalSupply < MIN_SHARES.

3. **redistributeLockedAmount can fail scenario**: When `redistributeLockedAmount` burns shares from a blacklisted user [4](#0-3) , if totalSupply is at MIN_SHARES and the blacklisted user's balance is less than MIN_SHARES, the operation would revert with `MinSharesViolation`.

### Why This Is NOT a Valid Vulnerability

This scenario is **explicitly documented as a KNOWN ISSUE** in the audit specifications provided:
- "redistributeLockedAmount doesn't validate totalSupply >= MIN_SHARES threshold (operations may be blocked until MIN_SHARES restored)"
- "Griefing attacks around MIN_SHARES (protocol performs initial deposit to mitigate)"

Additionally:
- **Composer is a TRUSTED ROLE** per the trust model, and the instructions explicitly state "DO NOT assume trusted roles act maliciously"
- Any regular user (not just composer) can burn shares to MIN_SHARES via normal `cooldownShares` operations
- The impact is temporary DOS of an admin function, not theft or permanent loss of funds
- The issue is recoverable by depositing more shares to bring totalSupply above the threshold
- Does not meet the validation checklist requirement: "Not a known issue from Zellic audit or README"

### Citations

**File:** src/token/wiTRY/StakediTryCrosschain.sol (L44-44)
```text
        if (shares > maxRedeem(composer)) revert ExcessiveRedeemAmount();
```

**File:** src/token/wiTRY/StakediTry.sol (L172-173)
```text
            _burn(from, amountToDistribute);
            _checkMinShares();
```

**File:** src/token/wiTRY/StakediTry.sol (L228-231)
```text
    function _checkMinShares() internal view {
        uint256 _totalSupply = totalSupply();
        if (_totalSupply > 0 && _totalSupply < MIN_SHARES) revert MinSharesViolation();
    }
```

**File:** src/token/wiTRY/StakediTry.sol (L277-277)
```text
        _checkMinShares();
```
