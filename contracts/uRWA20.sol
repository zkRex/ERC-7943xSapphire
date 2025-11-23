// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7943Fungible} from "./interfaces/IERC7943.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {ERC20} from "solady/src/tokens/ERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";

/// @title uRWA-20 Token Contract
/// @notice An ERC-20 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-20 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers, and freezing. Managed via AccessControl.
contract uRWA20 is Context, ERC20, AccessControlEnumerable, IERC7943Fungible {
    /// @notice Role identifiers.
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant FREEZING_ROLE = keccak256("FREEZING_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");
    bytes32 public constant FORCE_TRANSFER_ROLE = keccak256("FORCE_TRANSFER_ROLE");
    bytes32 public constant VIEWER_ROLE = keccak256("VIEWER_ROLE");    

    /// @notice Mapping storing the whitelist status for each account address.
    /// @dev True indicates the account is whitelisted and allowed to interact, false otherwise.
    mapping(address account => bool whitelisted) internal _whitelist;

    /// @notice Mapping storing the freezing status of assets for each account address.
    /// @dev It gives the amount of ERC-20 tokens frozen in `account` wallet.
    mapping(address account => uint256 amount) internal _frozenTokens;

    /// @notice Encryption key for encrypting sensitive event data.
    /// @dev Generated once in constructor and used for all event encryption.
    bytes32 internal _encryptionKey;

    /// @notice Nonce counter for event encryption to ensure uniqueness.
    uint256 internal _eventNonce;

    /// @notice Emitted when an account's whitelist status is changed (encrypted).
    /// @param encryptedData Encrypted data containing account and status.
    event EncryptedWhitelisted(bytes encryptedData);

    /// @notice Emitted when tokens are transferred (encrypted).
    /// @param encryptedData Encrypted data containing from, to, and amount.
    event EncryptedTransfer(bytes encryptedData);

    /// @notice Emitted when tokens are frozen (encrypted).
    /// @param encryptedData Encrypted data containing account and amount.
    event EncryptedFrozen(bytes encryptedData);

    /// @notice Emitted when a forced transfer occurs (encrypted).
    /// @param encryptedData Encrypted data containing from, to, and amount.
    event EncryptedForcedTransfer(bytes encryptedData);

    /// @notice Error used when a zero address is provided where it is not allowed.
    error NotZeroAddress();

    /// @dev Storage slot constants from Solady ERC20 (must match for compatibility)
    uint256 private constant _TOTAL_SUPPLY_SLOT = 0x05345cdf77eb68f44c;
    uint256 private constant _BALANCE_SLOT_SEED = 0x87a211a2;
    uint256 private constant _ALLOWANCE_SLOT_SEED = 0x7f5e9f20;

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-20 token with name and symbol, and grants all roles
    /// (Admin, Minter, Burner, Freezer, Force Transfer, Whitelist, Viewer) to the `initialAdmin`.
    /// Generates an encryption key for encrypting sensitive events.
    /// @param name The name of the token.
    /// @param symbol The symbol of the token.
    /// @param initialAdmin The address to receive initial administrative and operational roles.
    constructor(string memory name, string memory symbol, address initialAdmin) ERC20(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(FREEZING_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
        _grantRole(FORCE_TRANSFER_ROLE, initialAdmin);
        _grantRole(VIEWER_ROLE, initialAdmin);
        
        // Generate encryption key for event encryption
        bytes memory randomBytes = Sapphire.randomBytes(32, abi.encodePacked("uRWA20", name, symbol));
        _encryptionKey = bytes32(randomBytes);
        _eventNonce = 0;
    }

    /// @inheritdoc IERC7943Fungible
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransfer(address from, address to, uint256 amount) public virtual override view returns (bool allowed) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        uint256 fromBalance = balanceOf(from);
        if (fromBalance < _frozenTokens[from]) return allowed;
        if (amount > fromBalance - _frozenTokens[from]) return allowed;
        if (!canTransact(from) || !canTransact(to)) return allowed;
        allowed = true;
    }

    /// @notice Internal helper to check whitelist status without access control.
    /// @dev Used internally by _update to check whitelist during transfers.
    /// @param account The address to check.
    /// @return allowed True if the account is whitelisted, false otherwise.
    function _isWhitelisted(address account) internal view returns (bool allowed) {
        allowed = _whitelist[account];
    }

    /// @inheritdoc IERC7943Fungible
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransact(address account) public virtual override view returns (bool allowed) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        allowed = _isWhitelisted(account);
    }

    /// @inheritdoc IERC7943Fungible
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function getFrozenTokens(address account) public virtual override view returns (uint256 amount) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        amount = _frozenTokens[account];
    }

    /// @notice Returns the balance of the account.
    /// @dev Overrides ERC20 balanceOf to add access control. Requires VIEWER_ROLE.
    /// @param account The address to query the balance of.
    /// @return The balance of the account.
    function balanceOf(address account) public view virtual override returns (uint256) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.balanceOf(account);
    }

    /// @notice Returns the total supply of tokens.
    /// @dev Overrides ERC20 totalSupply to add access control. Requires VIEWER_ROLE.
    /// @return The total supply of tokens.
    function totalSupply() public view virtual override returns (uint256) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.totalSupply();
    }

    /// @notice Returns the amount of tokens that an owner allowed to a spender.
    /// @dev Overrides ERC20 allowance to add access control. Requires VIEWER_ROLE.
    /// @param owner The address which owns the funds.
    /// @param spender The address which will spend the funds.
    /// @return The amount of tokens still available for the spender.
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.allowance(owner, spender);
    }

    /// @notice Internal helper to update balance without emitting Transfer event.
    /// @dev Uses Solady's storage slot pattern to update balances directly.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param amount The amount being transferred.
    function _updateBalanceWithoutEvent(address from, address to, uint256 amount) internal {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(iszero(amount)) {
                if iszero(iszero(from)) {
                    // Compute the balance slot and load its value.
                    mstore(0x0c, _BALANCE_SLOT_SEED)
                    mstore(0x00, from)
                    let fromBalanceSlot := keccak256(0x0c, 0x20)
                    let fromBalance := sload(fromBalanceSlot)
                    // Subtract and store the updated balance.
                    sstore(fromBalanceSlot, sub(fromBalance, amount))
                }
                
                if iszero(iszero(to)) {
                    // Compute the balance slot of `to`.
                    mstore(0x0c, _BALANCE_SLOT_SEED)
                    mstore(0x00, to)
                    let toBalanceSlot := keccak256(0x0c, 0x20)
                    // Add and store the updated balance of `to`.
                    sstore(toBalanceSlot, add(sload(toBalanceSlot), amount))
                }
                
                // Update total supply
                if iszero(from) {
                    // Minting: increase total supply
                    let totalSupplyBefore := sload(_TOTAL_SUPPLY_SLOT)
                    let totalSupplyAfter := add(totalSupplyBefore, amount)
                    sstore(_TOTAL_SUPPLY_SLOT, totalSupplyAfter)
                } else if iszero(to) {
                    // Burning: decrease total supply
                    sstore(_TOTAL_SUPPLY_SLOT, sub(sload(_TOTAL_SUPPLY_SLOT), amount))
                }
            }
        }
    }

    /// @notice Updates the whitelist status for a given account.
    /// @dev Can only be called by accounts holding the `WHITELIST_ROLE`.
    /// Emits an encrypted {EncryptedWhitelisted} event to protect privacy.
    /// @param account The address whose whitelist status is to be changed.
    /// @param status The new whitelist status (true or false).
    function changeWhitelist(address account, bool status) external onlyRole(WHITELIST_ROLE) {
        _whitelist[account] = status;
        
        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(account, status, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedWhitelisted(encrypted);
    }

    /// @notice Creates `amount` new tokens and assigns them to `to`.
    /// @dev Can only be called by accounts holding the `MINTER_ROLE`.
    /// Requires `to` to be allowed according to {canTransact}.
    /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    /// @param to The address that will receive the minted tokens.
    /// @param amount The amount of tokens to mint.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    /// @notice Destroys `amount` tokens from the caller's account.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    /// @param amount The amount of tokens to burn.
    function burn(uint256 amount) external onlyRole(BURNER_ROLE) {
        _burn(_msgSender(), amount);
    }

    /// @dev Overrides Solady's _mint to update balances without emitting Transfer events.
    /// @param to The address that will receive the minted tokens.
    /// @param amount The amount of tokens to mint.
    function _mint(address to, uint256 amount) internal virtual override {
        require(_isWhitelisted(to), ERC7943CannotTransact(to));
        
        // Update balances directly without emitting Transfer event
        _updateBalanceWithoutEvent(address(0), to, amount);
        
        // Emit only encrypted event
        bytes memory plaintext = abi.encode(address(0), to, amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedTransfer(encrypted);
        
        Sapphire.padGas(200000);
    }

    /// @dev Overrides Solady's _burn to update balances without emitting Transfer events.
    /// @param from The address from which tokens are burned.
    /// @param amount The amount of tokens to burn.
    function _burn(address from, uint256 amount) internal virtual override {
        _excessFrozenUpdate(from, amount);
        
        // Update balances directly without emitting Transfer event
        _updateBalanceWithoutEvent(from, address(0), amount);
        
        // Emit only encrypted event
        bytes memory plaintext = abi.encode(from, address(0), amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedTransfer(encrypted);
        
        Sapphire.padGas(200000);
    }

    /// @inheritdoc IERC7943Fungible
    /// @dev Can only be called by accounts holding the `FREEZING_ROLE`
    function setFrozenTokens(address account, uint256 amount) public virtual override onlyRole(FREEZING_ROLE) returns(bool result) {
        _frozenTokens[account] = amount;
        
        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(account, amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedFrozen(encrypted);
        
        result = true;
    }

    /// @inheritdoc IERC7943Fungible
    /// @dev Can only be called by accounts holding the `FORCE_TRANSFER_ROLE`.
    function forcedTransfer(address from, address to, uint256 amount) public virtual override onlyRole(FORCE_TRANSFER_ROLE) returns(bool result) {
        require(from != address(0) && to != address(0), NotZeroAddress());
        require(_isWhitelisted(to), ERC7943CannotTransact(to));
        uint256 fromBalance = balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        _excessFrozenUpdate(from, amount);
        
        // Update balances directly without emitting Transfer event
        _updateBalanceWithoutEvent(from, to, amount);
        
        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(from, to, amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedForcedTransfer(encrypted);
        
        Sapphire.padGas(200000);
        result = true;
    }

    /// @notice Updates frozen token amount when a forced transfer or burn exceeds the unfrozen balance.
    /// @dev This function reduces the frozen token amount to ensure consistency when tokens are forcibly
    /// moved or burned beyond the unfrozen balance. Emits an encrypted {EncryptedFrozen} event when frozen amount is reduced.
    /// @param account The address whose frozen tokens may need adjustment.
    /// @param amount The amount being forcibly transferred or burned.
    function _excessFrozenUpdate(address account, uint256 amount) internal {
        uint256 unfrozenBalance = _unfrozenBalance(account);
        uint256 accountBalance = balanceOf(account);
        if(amount > unfrozenBalance && amount <= accountBalance) {
            _frozenTokens[account] -= amount - unfrozenBalance;
            
            // Encrypt sensitive event data
            bytes memory plaintext = abi.encode(account, _frozenTokens[account], _eventNonce++);
            bytes32 nonce = bytes32(_eventNonce);
            bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
            emit EncryptedFrozen(encrypted);
        }
    }

    /// @notice Calculates the unfrozen token balance for an account.
    /// @dev Returns the amount of tokens that are available for transfer, which is the total balance
    /// minus the frozen amount. If frozen tokens exceed the balance, returns 0 to prevent underflow.
    /// This is a helper function used throughout the contract for transfer validation.
    /// @param account The address to calculate unfrozen balance for.
    /// @return unfrozenBalance The amount of tokens available for transfer.
    function _unfrozenBalance(address account) internal view returns(uint256 unfrozenBalance) {
        uint256 accountBalance = balanceOf(account);
        unfrozenBalance = accountBalance < _frozenTokens[account] ? 0 : accountBalance - _frozenTokens[account];
    }

    /// @notice Hook that is called during any token transfer, including minting and burning.
    /// @dev Overrides the ERC-20 `_update` hook. Enforces transfer restrictions based on {canTransfer} and {canTransact} logic.
    /// Updates balances directly without emitting standard Transfer events (only encrypted events for privacy).
    /// Reverts with {ERC7943InsufficientUnfrozenBalance} | {ERC7943CannotTransact} if any `canTransfer` check fails.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param amount The amount being transferred.
    function _update(address from, address to, uint256 amount) internal virtual override {
        bool isTransfer = (from != address(0) && to != address(0));
        bool isMint = (from == address(0));
        bool isBurn = (to == address(0));
        
        if (isTransfer) { // Transfer
            uint256 fromBalance = balanceOf(from);
            require(fromBalance >= amount, InsufficientBalance());
            uint256 unfrozenFromBalance = _unfrozenBalance(from);
            require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));
            require(_isWhitelisted(from), ERC7943CannotTransact(from));
            require(_isWhitelisted(to), ERC7943CannotTransact(to));
        } else if (isMint) { // Mint
            require(_isWhitelisted(to), ERC7943CannotTransact(to));
        } else if (isBurn) { // Burn
            _excessFrozenUpdate(from, amount);
        }

        // Update balances directly without emitting standard Transfer events
        _updateBalanceWithoutEvent(from, to, amount);
        
        // Emit encrypted transfer event for privacy (using Sapphire precompile)
        bytes memory plaintext = abi.encode(from, to, amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedTransfer(encrypted);
        
        // Pad gas to prevent side-channel leakage from conditional branches
        // Estimate worst-case gas: ~150k for transfer with all checks and encryption
        Sapphire.padGas(200000);
    }

    /// @dev Overrides Solady's transfer to enforce whitelist and frozen token checks.
    /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        address from = _msgSender();
        require(_isWhitelisted(from), ERC7943CannotTransact(from));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));
        
        uint256 fromBalance = balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        uint256 unfrozenFromBalance = _unfrozenBalance(from);
        require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));
        
        // Update balances directly without emitting Transfer event
        _updateBalanceWithoutEvent(from, to, amount);
        
        // Emit only encrypted event
        bytes memory plaintext = abi.encode(from, to, amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedTransfer(encrypted);
        
        Sapphire.padGas(200000);
        return true;
    }

    /// @dev Overrides Solady's transferFrom to enforce whitelist and frozen token checks.
    /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        require(_isWhitelisted(from), ERC7943CannotTransact(from));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));
        
        uint256 fromBalance = balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        uint256 unfrozenFromBalance = _unfrozenBalance(from);
        require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));
        
        // Check and update allowance
        address spender = _msgSender();
        uint256 currentAllowance = allowance(from, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, InsufficientAllowance());
            /// @solidity memory-safe-assembly
            assembly {
                mstore(0x20, spender)
                mstore(0x0c, or(shl(96, from), _ALLOWANCE_SLOT_SEED))
                let allowanceSlot := keccak256(0x0c, 0x34)
                sstore(allowanceSlot, sub(sload(allowanceSlot), amount))
            }
        }
        
        // Update balances directly without emitting Transfer event
        _updateBalanceWithoutEvent(from, to, amount);
        
        // Emit only encrypted event
        bytes memory plaintext = abi.encode(from, to, amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedTransfer(encrypted);
        
        Sapphire.padGas(200000);
        return true;
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IERC7943Fungible} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, IERC165) returns (bool) {
        return interfaceId == type(IERC7943Fungible).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}

