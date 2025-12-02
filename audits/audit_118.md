# NoVulnerability found for this question.

## Analysis

I conducted a thorough investigation of the `redistributeLockedAmount` function in iTry.sol to determine if state changes (specifically, `to` becoming blacklisted) could occur between the burn and mint operations. [1](#0-0) 

**Key Findings:**

1. **Atomic Execution**: The function executes within a single Ethereum transaction. The EVM guarantees atomicity - no other transaction can execute between the burn (line 115) and mint (line 116) operations.

2. **No External Calls**: Between `_burn` and `_mint`, there are zero external calls:
   - OpenZeppelin's ERC20 `_burn` and `_mint` only update internal state (_balances, _totalSupply)
   - The `_beforeTokenTransfer` hook performs conditional checks but makes no external calls [2](#0-1) 

3. **ReentrancyGuard Protection**: The `nonReentrant` modifier provides additional protection against any potential reentrancy, though none exists in this flow.

4. **Role Changes Require Separate Transactions**: For `to` to become blacklisted mid-execution, `addBlacklistAddress` would need to be called, which is only possible in a separate transaction by the BLACKLIST_MANAGER_ROLE. [3](#0-2) 

5. **hasRole Implementation**: The role checks use OpenZeppelin's AccessControl `hasRole` function, which is a pure storage mapping lookup with no external calls. [4](#0-3) 

**Conclusion**: The state cannot change between the burn and mint operations in `redistributeLockedAmount`. If `to` is not blacklisted when the initial check passes (line 113), it will remain not blacklisted when the mint executes (line 116), and the `_beforeTokenTransfer` validation at line 186 will succeed. This is not a vulnerability - the code functions as intended with proper atomicity guarantees.

### Citations

**File:** src/token/iTRY/iTry.sol (L73-78)
```text
    function addBlacklistAddress(address[] calldata users) external onlyRole(BLACKLIST_MANAGER_ROLE) {
        for (uint8 i = 0; i < users.length; i++) {
            if (hasRole(WHITELISTED_ROLE, users[i])) _revokeRole(WHITELISTED_ROLE, users[i]);
            _grantRole(BLACKLISTED_ROLE, users[i]);
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L112-121)
```text
    function redistributeLockedAmount(address from, address to) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
        if (hasRole(BLACKLISTED_ROLE, from) && !hasRole(BLACKLISTED_ROLE, to)) {
            uint256 amountToDistribute = balanceOf(from);
            _burn(from, amountToDistribute);
            _mint(to, amountToDistribute);
            emit LockedAmountRedistributed(from, to, amountToDistribute);
        } else {
            revert OperationNotAllowed();
        }
    }
```

**File:** src/token/iTRY/iTry.sol (L177-222)
```text
    function _beforeTokenTransfer(address from, address to, uint256) internal virtual override {
        // State 2 - Transfers fully enabled except for blacklisted addresses
        if (transferState == TransferState.FULLY_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (
                !hasRole(BLACKLISTED_ROLE, msg.sender) && !hasRole(BLACKLISTED_ROLE, from)
                    && !hasRole(BLACKLISTED_ROLE, to)
            ) {
                // normal case
            } else {
                revert OperationNotAllowed();
            }
            // State 1 - Transfers only enabled between whitelisted addresses
        } else if (transferState == TransferState.WHITELIST_ENABLED) {
            if (hasRole(MINTER_CONTRACT, msg.sender) && !hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redeeming
            } else if (hasRole(MINTER_CONTRACT, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to)) {
                // minting
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && hasRole(BLACKLISTED_ROLE, from) && to == address(0)) {
                // redistributing - burn
            } else if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender) && from == address(0) && !hasRole(BLACKLISTED_ROLE, to))
            {
                // redistributing - mint
            } else if (hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from) && to == address(0)) {
                // whitelisted user can burn
            } else if (
                hasRole(WHITELISTED_ROLE, msg.sender) && hasRole(WHITELISTED_ROLE, from)
                    && hasRole(WHITELISTED_ROLE, to)
            ) {
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

**File:** src/utils/SingleAdminAccessControlUpgradeable.sol (L1-80)
```text
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.20;

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC5313.sol";
import "./ISingleAdminAccessControl.sol";

/**
 * @title SingleAdminAccessControlUpgradeable
 * @notice SingleAdminAccessControlUpgradeable is a contract that provides a single admin role
 * @notice This contract is a simplified alternative to OpenZeppelin's AccessControlDefaultAdminRules
 */
abstract contract SingleAdminAccessControlUpgradeable is IERC5313, ISingleAdminAccessControl, AccessControlUpgradeable {
    address private _currentDefaultAdmin;
    address private _pendingDefaultAdmin;

    modifier notAdmin(bytes32 role) {
        if (role == DEFAULT_ADMIN_ROLE) revert InvalidAdminChange();
        _;
    }

    /// @notice Transfer the admin role to a new address
    /// @notice This can ONLY be executed by the current admin
    /// @param newAdmin address
    function transferAdmin(address newAdmin) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (newAdmin == msg.sender) revert InvalidAdminChange();
        _pendingDefaultAdmin = newAdmin;
        emit AdminTransferRequested(_currentDefaultAdmin, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != _pendingDefaultAdmin) revert NotPendingAdmin();
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    /// @notice grant a role
    /// @notice can only be executed by the current single admin
    /// @notice admin role cannot be granted externally
    /// @param role bytes32
    /// @param account address
    function grantRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
        _grantRole(role, account);
    }

    /// @notice revoke a role
    /// @notice can only be executed by the current admin
    /// @notice admin role cannot be revoked
    /// @param role bytes32
    /// @param account address
    function revokeRole(bytes32 role, address account) public override onlyRole(DEFAULT_ADMIN_ROLE) notAdmin(role) {
        _revokeRole(role, account);
    }

    /// @notice renounce the role of msg.sender
    /// @notice admin role cannot be renounced
    /// @param role bytes32
    /// @param account address
    function renounceRole(bytes32 role, address account) public virtual override notAdmin(role) {
        super.renounceRole(role, account);
    }

    /**
     * @dev See {IERC5313-owner}.
     */
    function owner() public view virtual returns (address) {
        return _currentDefaultAdmin;
    }

    /**
     * @notice no way to change admin without removing old admin first
     */
    function _grantRole(bytes32 role, address account) internal override {
        if (role == DEFAULT_ADMIN_ROLE) {
            emit AdminTransferred(_currentDefaultAdmin, account);
            _revokeRole(DEFAULT_ADMIN_ROLE, _currentDefaultAdmin);
            _currentDefaultAdmin = account;
            delete _pendingDefaultAdmin;
        }
        super._grantRole(role, account);
    }
```
