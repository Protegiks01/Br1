# NoVulnerability found for this question.

## Analysis

After thorough investigation of the `_redeemFromVault` function and the complete transaction flow, **the transaction IS rolled back atomically if the external call fails**. There is no vulnerability where `_totalDLFUnderCustody` could be permanently decremented without tokens being transferred.

### Key Findings:

**1. No Exception Handling**

The `_redeemFromVault` function contains no try-catch blocks. [1](#0-0) 

A grep search across all protocol contracts confirms zero try-catch usage, meaning all external call failures propagate and revert the entire transaction.

**2. Standard Solidity Atomicity**

In Solidity, when an external call reverts without try-catch:
- The revert propagates up the call stack
- All state changes are rolled back atomically  
- The decrement at line 628 is undone if `processTransfer` fails at line 630 or 633

**3. processTransfer Revert Conditions**

The `liquidityVault.processTransfer()` function has multiple revert paths: [2](#0-1) 

Any of these failures (zero address, zero amount, insufficient balance, transfer failure) will revert the entire redemption transaction.

**4. DLF Token Behavior**

The collateral token (DLFToken) is a standard OpenZeppelin ERC20 implementation that reverts on transfer failures. [3](#0-2) 

The defensive check at line 154-156 in FastAccessVault ensures even non-standard tokens that return false would trigger a revert.

### Conclusion

The code correctly maintains the **iTRY Backing invariant** through transaction atomicity. If token transfers fail for any reason (insufficient balance, paused token, blacklist, etc.), the custody accounting is automatically rolled back. This is the intended, secure behavior—no vulnerability exists.

### Citations

**File:** src/protocol/iTryIssuer.sol (L627-635)
```text
    function _redeemFromVault(address receiver, uint256 receiveAmount, uint256 feeAmount) internal {
        _totalDLFUnderCustody -= (receiveAmount + feeAmount);

        liquidityVault.processTransfer(receiver, receiveAmount);

        if (feeAmount > 0) {
            liquidityVault.processTransfer(treasury, feeAmount);
        }
    }
```

**File:** src/protocol/FastAccessVault.sol (L144-158)
```text
    function processTransfer(address _receiver, uint256 _amount) external onlyIssuer {
        if (_receiver == address(0)) revert CommonErrors.ZeroAddress();
        if (_receiver == address(this)) revert InvalidReceiver(_receiver);
        if (_amount == 0) revert CommonErrors.ZeroAmount();

        uint256 currentBalance = _vaultToken.balanceOf(address(this));
        if (currentBalance < _amount) {
            revert InsufficientBufferBalance(_amount, currentBalance);
        }

        if (!_vaultToken.transfer(_receiver, _amount)) {
            revert CommonErrors.TransferFailed();
        }
        emit TransferProcessed(_receiver, _amount, (currentBalance - _amount));
    }
```

**File:** src/external/DLFToken.sol (L9-29)
```text
contract DLFToken is Initializable, ERC20, Ownable, Pausable {
    mapping(address => bool) private _isBlacklisted;

    constructor(address owner) ERC20("Digital Liquiditiy Fund Token Mock", "DLF") {
        _transferOwnership(owner);
        _mint(owner, 1000e18); // Test mint
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused {
        require(!_isBlacklisted[from], "ERC20: sender is blacklisted");
        require(!_isBlacklisted[to], "ERC20: recipient is blacklisted");
        super._beforeTokenTransfer(from, to, amount);
    }
```
