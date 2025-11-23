// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7943MultiToken} from "./interfaces/IERC7943.sol";
import {ERC1155} from "solady/src/tokens/ERC1155.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";

/// @title uRWA-1155 Token Contract
/// @notice An ERC-1155 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-1155 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers and freezing. Managed via AccessControl.
contract uRWA1155 is Context, ERC1155, AccessControlEnumerable, IERC7943MultiToken {
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
    /// @dev It gives the amount of tokens corresponding to a `tokenId` that are frozen in `account` wallet.
    mapping(address account => mapping(uint256 tokenId => uint256 amount)) internal _frozenTokens;

    /// @notice Encryption key for encrypting sensitive event data.
    /// @dev Generated once in constructor and used for all event encryption.
    bytes32 internal _encryptionKey;

    /// @notice Nonce counter for event encryption to ensure uniqueness.
    uint256 internal _eventNonce;

    /// @notice Struct for storing decrypted transfer data.
    /// @dev Used to temporarily store decrypted data for authorized viewers.
    /// For batch transfers, stores arrays of ids and values.
    struct DecryptedTransferData {
        address from;
        address to;
        uint256[] ids;
        uint256[] values;
        string action;
        uint256 timestamp;
        uint256 nonce;
        bool exists;
    }

    /// @notice Mapping storing decrypted data for each authorized viewer.
    /// @dev Data is temporarily stored after successful decryption for retrieval.
    mapping(address => DecryptedTransferData) private _lastDecryptedData;

    /// @notice Emitted when an account's whitelist status is changed (encrypted).
    /// @param encryptedData Encrypted data containing account and status.
    event EncryptedWhitelisted(bytes encryptedData);

    /// @notice Emitted when tokens are transferred (encrypted).
    /// @param encryptedData Encrypted data containing from, to, ids, and values.
    event EncryptedTransfer(bytes encryptedData);

    /// @notice Emitted when tokens are frozen (encrypted).
    /// @param encryptedData Encrypted data containing account, tokenId, and amount.
    event EncryptedFrozen(bytes encryptedData);

    /// @notice Emitted when a forced transfer occurs (encrypted).
    /// @param encryptedData Encrypted data containing from, to, tokenId, and amount.
    event EncryptedForcedTransfer(bytes encryptedData);

    /// @notice Token URI base.
    /// @dev Used for returning token URIs.
    string private _uri;

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-1155 token with a URI and grants all roles
    /// (Admin, Minter, Burner, Freezer, Force Transfer, Whitelist, Viewer) to the `initialAdmin`.
    /// Generates an encryption key for encrypting sensitive events.
    /// @param uri_ The URI for the token metadata.
    /// @param initialAdmin The address to receive initial administrative and operational roles.
    constructor(string memory uri_, address initialAdmin) {
        _uri = uri_;
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(FREEZING_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
        _grantRole(FORCE_TRANSFER_ROLE, initialAdmin);
        _grantRole(VIEWER_ROLE, initialAdmin);
        
        // Generate encryption key for event encryption
        bytes memory randomBytes = Sapphire.randomBytes(32, abi.encodePacked("uRWA1155", uri_));
        _encryptionKey = bytes32(randomBytes);
        _eventNonce = 0;
    }

    /// @inheritdoc IERC7943MultiToken
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransfer(address from, address to, uint256 tokenId, uint256 amount) public view virtual override returns (bool allowed) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        uint256 fromBalance = balanceOf(from, tokenId);
        if (fromBalance < _frozenTokens[from][tokenId]) return allowed;
        if (amount > fromBalance - _frozenTokens[from][tokenId]) return allowed;
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

    /// @inheritdoc IERC7943MultiToken
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransact(address account) public view virtual override returns (bool allowed) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        allowed = _isWhitelisted(account);
    }

    /// @inheritdoc IERC7943MultiToken
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function getFrozenTokens(address account, uint256 tokenId) external view returns (uint256 amount) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        amount = _frozenTokens[account][tokenId];
    }

    /// @notice Returns the balance of `account` for token `id`.
    /// @dev Overrides ERC1155 balanceOf to add access control. Requires VIEWER_ROLE.
    /// @param account The address to query the balance of.
    /// @param id The token ID to query.
    /// @return The balance of the account for the token ID.
    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.balanceOf(account, id);
    }

    /// @notice Returns the balance of multiple accounts for multiple token IDs.
    /// @dev Overrides ERC1155 balanceOfBatch to add access control. Requires VIEWER_ROLE.
    /// @param accounts The addresses to query balances for.
    /// @param ids The token IDs to query.
    /// @return The balances of the accounts for the token IDs.
    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids) public view virtual override returns (uint256[] memory) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.balanceOfBatch(accounts, ids);
    }

    /// @notice Returns the URI for token `id`.
    /// @dev Overrides ERC1155 uri to add access control. Requires VIEWER_ROLE.
    /// @param id The token ID to query.
    /// @return The URI string for the token.
    function uri(uint256 id) public view virtual override returns (string memory) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        // Solady ERC1155 uses a virtual uri() function that can be overridden
        // Return the base URI (can be extended to support per-token URIs)
        return _uri;
    }

    /// @notice Returns if the operator is allowed to manage all of the assets of `account`.
    /// @dev Overrides ERC1155 isApprovedForAll to add access control. Requires VIEWER_ROLE.
    /// @param account The address that owns the tokens.
    /// @param operator The address that acts on behalf of the owner.
    /// @return True if operator is approved to manage account's tokens.
    function isApprovedForAll(address account, address operator) public view virtual override returns (bool) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.isApprovedForAll(account, operator);
    }

    /// @notice Processes and decrypts encrypted event data.
    /// @dev Decrypts event data and stores it for the caller if authorized.
    /// Authorization: sender, receiver, or VIEWER_ROLE holder can decrypt.
    /// @param encryptedData The encrypted event data to decrypt.
    /// @return success True if decryption and authorization succeeded.
    function processDecryption(bytes memory encryptedData) external returns (bool success) {
        // Decrypt the data using contract address as additional data
        bytes memory decryptedData = Sapphire.decrypt(
            _encryptionKey,
            bytes32(0), // Nonce is embedded in plaintext for verification
            encryptedData,
            abi.encode(address(this)) // Bind to this contract address
        );

        // Decode the decrypted data
        (
            address from,
            address to,
            uint256[] memory ids,
            uint256[] memory values,
            string memory action,
            uint256 timestamp,
            uint256 nonce
        ) = abi.decode(decryptedData, (address, address, uint256[], uint256[], string, uint256, uint256));

        // Authorization check: caller must be sender, receiver, or have VIEWER_ROLE
        bool isAuthorized =
            msg.sender == from ||
            msg.sender == to ||
            hasRole(VIEWER_ROLE, msg.sender);

        require(isAuthorized, "Not authorized to decrypt");

        // Store decrypted data for caller
        _lastDecryptedData[msg.sender] = DecryptedTransferData(
            from, to, ids, values, action, timestamp, nonce, true
        );

        success = true;
    }

    /// @notice Retrieves the last decrypted data for the caller.
    /// @dev Returns the decrypted transfer data that was previously processed.
    /// @return from The sender address.
    /// @return to The receiver address.
    /// @return ids The array of token IDs transferred.
    /// @return values The array of amounts transferred.
    /// @return action The action type (e.g., "transfer", "mint", "burn").
    /// @return timestamp The timestamp of the event.
    /// @return nonce The nonce used for encryption.
    function viewLastDecryptedData() external view returns (
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values,
        string memory action,
        uint256 timestamp,
        uint256 nonce
    ) {
        require(_lastDecryptedData[msg.sender].exists, "No decrypted data");
        DecryptedTransferData memory data = _lastDecryptedData[msg.sender];
        return (data.from, data.to, data.ids, data.values, data.action, data.timestamp, data.nonce);
    }

    /// @notice Clears the last decrypted data for the caller.
    /// @dev Allows users to clear their decrypted data from storage.
    function clearLastDecryptedData() external {
        delete _lastDecryptedData[msg.sender];
    }

    /// @notice Updates the whitelist status for a given account.
    /// @dev Can only be called by accounts holding the `WHITELIST_ROLE`.
    /// Emits an encrypted {EncryptedWhitelisted} event to protect privacy.
    /// @param account The address whose whitelist status is to be changed.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    function changeWhitelist(address account, bool status) external onlyRole(WHITELIST_ROLE) {
        _whitelist[account] = status;

        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(account, status, _eventNonce);
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this)) // Bind to contract address
        );
        emit EncryptedWhitelisted(encrypted);
    }

    /// @notice Safely creates `amount` new tokens of `id` and assigns them to `to`.
    /// @dev Can only be called by accounts holding the `MINTER_ROLE`.
    /// Requires `to` to be allowed according to {canTransact}.
    /// Emits a {TransferSingle} event with `operator` set to the caller.
    /// @param to The address that will receive the minted tokens.
    /// @param id The ID of the token to mint.
    /// @param amount The amount of tokens to mint.
    function mint(address to, uint256 id, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, id, amount, "");
    }

    /// @notice Destroys `amount` tokens of `id` from the caller's account.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Emits a {TransferSingle} event with `to` set to the zero address.
    /// @param id The ID of the token to burn.
    /// @param amount The amount of tokens to burn.
    function burn(uint256 id, uint256 amount) external onlyRole(BURNER_ROLE) {
        _burn(_msgSender(), id, amount);
    }

    /// @inheritdoc IERC7943MultiToken
    /// @dev Can only be called by accounts holding the `FREEZING_ROLE`.
    /// Emits an encrypted {EncryptedFrozen} event to protect privacy.
    function setFrozenTokens(address account, uint256 tokenId, uint256 amount) public onlyRole(FREEZING_ROLE) returns(bool result) {
        _frozenTokens[account][tokenId] = amount;

        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(account, tokenId, amount, _eventNonce);
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this)) // Bind to contract address
        );
        emit EncryptedFrozen(encrypted);

        result = true;
    }

    /// @notice Checks if an address has code (i.e., is a contract).
    /// @param account The address to check.
    /// @return True if the address has code, false otherwise.
    function _hasContractCode(address account) internal view returns (bool) {
        return account.code.length > 0;
    }

    /// @notice Checks if the recipient contract implements IERC1155Receiver and calls onERC1155Received.
    /// @param operator The address which initiated the transfer.
    /// @param from The address which previously owned the token.
    /// @param to The address which will receive the token.
    /// @param id The ID of the token being transferred.
    /// @param amount The amount of tokens being transferred.
    /// @param data Additional data with no specified format.
    function _checkOnERC1155Received(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal {
        if (to.code.length > 0) {
            try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 retval) {
                if (retval != IERC1155Receiver.onERC1155Received.selector) {
                    revert("ERC1155: transfer to non-ERC1155Receiver implementer");
                }
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC1155: transfer to non-ERC1155Receiver implementer");
                } else {
                    /// @solidity memory-safe-assembly
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        }
    }

    /// @inheritdoc IERC7943MultiToken
    /// @dev Can only be called by accounts holding the `FORCE_TRANSFER_ROLE`.
    function forcedTransfer(address from, address to, uint256 tokenId, uint256 amount) public onlyRole(FORCE_TRANSFER_ROLE) returns(bool result) {
        require(_isWhitelisted(to), ERC7943CannotTransact(to));

        // Reimplementing _safeTransferFrom to avoid the check on _update
        if (to == address(0)) {
            revert TransferToZeroAddress();
        }
        if (from == address(0)) {
            revert TransferToZeroAddress();
        }

        _excessFrozenUpdate(from, tokenId, amount);

        // Update balances directly without emitting standard Transfer events
        uint256[] memory ids = new uint256[](1);
        uint256[] memory values = new uint256[](1);
        ids[0] = tokenId;
        values[0] = amount;
        _updateBalancesWithoutEvent(from, to, ids, values);
        
        if (to != address(0)) {
            address operator = _msgSender();
            if (_hasContractCode(to)) {
                _checkOnERC1155Received(operator, from, to, tokenId, amount, "");
            }
        }

        // Encrypt sensitive event data with action, timestamp, and nonce
        // Reuse ids and values arrays from above
        bytes memory plaintext = abi.encode(
            from,
            to,
            ids,
            values,
            "forcedTransfer",
            block.timestamp,
            _eventNonce
        );
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this)) // Bind to contract address
        );
        emit EncryptedForcedTransfer(encrypted);

        result = true;
    }

    /// @notice Updates frozen token amount when a forced transfer or burn exceeds the unfrozen balance.
    /// @dev This function reduces the frozen token amount to ensure consistency when tokens are forcibly
    /// moved or burned beyond the unfrozen balance. Emits an encrypted {EncryptedFrozen} event when frozen amount is reduced.
    /// @param account The address whose frozen tokens may need adjustment.
    /// @param tokenId The ID of the token being transferred or burned.
    /// @param amount The amount being forcibly transferred or burned.
    function _excessFrozenUpdate(address account, uint256 tokenId, uint256 amount) internal {
        uint256 unfrozenBalance = _unfrozenBalance(account, tokenId);
        uint256 accountBalance = balanceOf(account, tokenId);
        if(amount > unfrozenBalance && amount <= accountBalance) {
            _frozenTokens[account][tokenId] -= amount - unfrozenBalance;

            // Encrypt sensitive event data
            bytes memory plaintext = abi.encode(account, tokenId, _frozenTokens[account][tokenId], _eventNonce);
            bytes32 nonce = bytes32(_eventNonce++);
            bytes memory encrypted = Sapphire.encrypt(
                _encryptionKey,
                nonce,
                plaintext,
                abi.encode(address(this)) // Bind to contract address
            );
            emit EncryptedFrozen(encrypted);
        }
    }

    /// @notice Calculates the unfrozen token balance for an account.
    /// @dev Returns the amount of tokens that are available for transfer, which is the total balance
    /// minus the frozen amount. If frozen tokens exceed the balance, returns 0 to prevent underflow.
    /// This is a helper function used throughout the contract for transfer validation.
    /// @param account The address to calculate unfrozen balance for
    /// @param tokenId The ID of the token to check
    /// @return unfrozenBalance The amount of tokens available for transfer.
    function _unfrozenBalance(address account, uint256 tokenId) internal view returns(uint256 unfrozenBalance) {
        uint256 accountBalance = balanceOf(account, tokenId);
        unfrozenBalance = accountBalance < _frozenTokens[account][tokenId] ? 0 : accountBalance - _frozenTokens[account][tokenId];
    }

    /// @notice Internal helper to update balances without emitting Transfer events.
    /// @dev Uses Solady's storage slot pattern to update balances directly for privacy.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param ids The array of token IDs.
    /// @param values The array of amounts being transferred.
    function _updateBalancesWithoutEvent(address from, address to, uint256[] memory ids, uint256[] memory values) internal {
        /// @solidity memory-safe-assembly
        assembly {
            // Solady ERC1155 storage pattern:
            // Balance slot = keccak256(0x00, 0x40) where:
            // - 0x20 contains _ERC1155_MASTER_SLOT_SEED (0x9a31110384e0b0c9)
            // - 0x14 contains owner address (20 bytes)
            // - 0x00 contains token id
            
            let masterSlotSeed := 0x9a31110384e0b0c9
            mstore(0x20, masterSlotSeed)
            
            // Loop through all ids and values
            let idsLength := mload(ids)
            for { let i := 0 } lt(i, idsLength) { i := add(i, 1) } {
                let id := mload(add(ids, add(0x20, mul(i, 0x20))))
                let amount := mload(add(values, add(0x20, mul(i, 0x20))))
                
                if iszero(iszero(from)) {
                    // Decrease balance of `from`
                    mstore(0x14, from)
                    mstore(0x00, id)
                    let fromBalanceSlot := keccak256(0x00, 0x40)
                    let fromBalance := sload(fromBalanceSlot)
                    if gt(amount, fromBalance) {
                        mstore(0x00, 0xf4d678b8) // `InsufficientBalance()`
                        revert(0x1c, 0x04)
                    }
                    sstore(fromBalanceSlot, sub(fromBalance, amount))
                }
                
                if iszero(iszero(to)) {
                    // Increase balance of `to`
                    mstore(0x14, to)
                    mstore(0x00, id)
                    let toBalanceSlot := keccak256(0x00, 0x40)
                    let toBalanceBefore := sload(toBalanceSlot)
                    let toBalanceAfter := add(toBalanceBefore, amount)
                    if lt(toBalanceAfter, toBalanceBefore) {
                        mstore(0x00, 0x01336cea) // `AccountBalanceOverflow()`
                        revert(0x1c, 0x04)
                    }
                    sstore(toBalanceSlot, toBalanceAfter)
                }
            }
        }
    }

    /// @notice Hook that is called before any token transfer, including minting and burning.
    /// @dev Overrides the ERC-1155 `_update` hook. Enforces transfer restrictions based on {canTransfer} and {canTransact} logic.
    /// Updates balances directly without emitting standard Transfer events (for privacy).
    /// Emits encrypted events using Sapphire precompiles for additional privacy.
    /// Reverts with {ERC7943CannotTransact} | {ERC7943InsufficientUnfrozenBalance} | {InsufficientBalance} 
    /// if any `canTransfer`/`canTransact` or other check fails.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param ids The array of ids.
    /// @param values The array of amounts being transferred.
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal virtual {
        if (ids.length != values.length) {
            revert ArrayLengthsMismatch();
        }

        if (from != address(0) && to != address(0)) { // Transfer
            for (uint256 i = 0; i < ids.length; ++i) {
                uint256 id = ids[i];
                uint256 value = values[i];
                uint256 fromBalance = balanceOf(from, id);
                
                if (value > fromBalance) {
                    revert InsufficientBalance();
                }
                uint256 unfrozenBalance = _unfrozenBalance(from, id);
                require(value <= unfrozenBalance, ERC7943InsufficientUnfrozenBalance(from, id, value, unfrozenBalance));
                require(_isWhitelisted(from), ERC7943CannotTransact(from));
                require(_isWhitelisted(to), ERC7943CannotTransact(to));
            }
        } else if (from == address(0) && to != address(0)) { // Mint
            require(_isWhitelisted(to), ERC7943CannotTransact(to));
        } else if (to == address(0)) { // Burn
            for (uint256 j = 0; j < ids.length; ++j) {
                _excessFrozenUpdate(from, ids[j], values[j]);
            }
        }

        // Update balances directly without emitting standard Transfer events
        _updateBalancesWithoutEvent(from, to, ids, values);

        // Determine action type
        string memory action;
        if (from == address(0) && to != address(0)) {
            action = "mint";
        } else if (to == address(0)) {
            action = "burn";
        } else {
            action = "transfer";
        }

        // Emit encrypted transfer event for privacy (using Sapphire precompile)
        bytes memory plaintext = abi.encode(
            from,
            to,
            ids,
            values,
            action,
            block.timestamp,
            _eventNonce
        );
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this)) // Bind to contract address
        );
        emit EncryptedTransfer(encrypted);

        // Pad gas to prevent side-channel leakage from conditional branches
        // Estimate worst-case gas: ~200k for batch transfer with all checks and encryption
        Sapphire.padGas(250000);
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IERC7943MultiToken} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC1155, IERC165) returns (bool) {
        return interfaceId == type(IERC7943MultiToken).interfaceId ||
               super.supportsInterface(interfaceId);
    }
}

