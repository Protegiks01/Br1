# NoVulnerability found for this question.

**Analysis Summary:**

I conducted a thorough investigation of the `_transferIntoVault()` function in `src/protocol/iTryIssuer.sol` to determine if the custody accounting could be corrupted.

**Confirmed Observations:**

1. **Yes, the function increments before verification**: [1](#0-0) 
   The state variable `_totalDLFUnderCustody` is incremented at line 605 before the `transferFrom()` call at line 607.

2. **This follows a Check-Effects-Interactions (CEI) pattern violation**, as the state is modified before the external call completes.

3. **The contract imports SafeERC20 but doesn't use it**: [2](#0-1) 

**However, NO exploitable vulnerability exists because:**

**Transaction Atomicity Protection**: Ethereum transactions are atomic. If either `transferFrom()` call fails and causes a revert (lines 608 or 614), the entire transaction rolls back, including the custody increment at line 605. The accounting cannot become permanently corrupted.

**Immutable Collateral Token**: [3](#0-2) 
The `collateralToken` is immutable and set at deployment. An unprivileged attacker cannot substitute a malicious token that would return true without transferring.

**Reentrancy Protection**: The calling function `mintFor()` has the `nonReentrant` modifier: [4](#0-3) 

**Known Issue Coverage**: The known issues acknowledge "Non-standard ERC20 tokens may break transfer function," indicating this is a deployment configuration concern, not a runtime vulnerability.

**Notes:**

While the CEI pattern violation and lack of SafeERC20 usage are code quality issues that could be improved, they do not constitute an exploitable vulnerability for an unprivileged attacker. Any corruption scenario would require deploying the protocol with a malicious/non-standard token, which falls under deployment configuration (out of scope per the trust model). The atomic nature of Solidity transactions ensures that if any part of the transfer fails, the accounting increment is rolled back.

### Citations

**File:** src/protocol/iTryIssuer.sol (L39-39)
```text
    using SafeERC20 for IERC20;
```

**File:** src/protocol/iTryIssuer.sol (L59-59)
```text
    IERC20 public immutable collateralToken;
```

**File:** src/protocol/iTryIssuer.sol (L270-274)
```text
    function mintFor(address recipient, uint256 dlfAmount, uint256 minAmountOut)
        public
        onlyRole(_WHITELISTED_USER_ROLE)
        nonReentrant
        returns (uint256 iTRYAmount)
```

**File:** src/protocol/iTryIssuer.sol (L605-609)
```text
        _totalDLFUnderCustody += dlfAmount;
        // Transfer net DLF amount to buffer pool
        if (!collateralToken.transferFrom(from, address(liquidityVault), dlfAmount)) {
            revert CommonErrors.TransferFailed();
        }
```
