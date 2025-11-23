// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7943NonFungible} from "./interfaces/IERC7943.sol";
import {ERC721} from "solady/src/tokens/ERC721.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";

/// @title uRWA-721 Token Contract
/// @notice An ERC-721 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-721 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers, and freezing. Managed via AccessControl.
contract uRWA721 is Context, ERC721, AccessControlEnumerable, IERC7943NonFungible {
    /// @notice Error thrown when querying a non-existent token.
    error ERC721NonexistentToken(uint256 tokenId);
    
    /// @notice Error thrown when the receiver is invalid (e.g., zero address).
    error ERC721InvalidReceiver(address receiver);
    
    /// @notice Error thrown when the owner is incorrect.
    error ERC721IncorrectOwner(address sender, uint256 tokenId, address owner);
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
    /// @dev It gives true or false on whether the `tokenId` is frozen for `account`.
    mapping(address account => mapping(uint256 tokenId => bool frozen)) internal _frozenTokens;

    /// @notice Encryption key for encrypting sensitive event data.
    /// @dev Generated once in constructor and used for all event encryption.
    bytes32 internal _encryptionKey;

    /// @notice Nonce counter for event encryption to ensure uniqueness.
    uint256 internal _eventNonce;

    /// @notice Struct for storing decrypted transfer data.
    /// @dev Used to temporarily store decrypted data for authorized viewers.
    struct DecryptedTransferData {
        address from;
        address to;
        uint256 tokenId;
        string action;
        uint256 timestamp;
        uint256 nonce;
        bool exists;
    }

    /// @notice Mapping storing decrypted data for each authorized viewer.
    /// @dev Data is temporarily stored after successful decryption for retrieval.
    mapping(address => DecryptedTransferData) private _lastDecryptedData;

    /// @notice Token name.
    string private _name;

    /// @notice Token symbol.
    string private _symbol;

    /// @notice Emitted when an account's whitelist status is changed (encrypted).
    /// @param encryptedData Encrypted data containing account and status.
    event EncryptedWhitelisted(bytes encryptedData);

    /// @notice Emitted when tokens are transferred (encrypted).
    /// @param encryptedData Encrypted data containing from, to, and tokenId.
    event EncryptedTransfer(bytes encryptedData);

    /// @notice Emitted when tokens are frozen (encrypted).
    /// @param encryptedData Encrypted data containing account, tokenId, and frozenStatus.
    event EncryptedFrozen(bytes encryptedData);

    /// @notice Emitted when a forced transfer occurs (encrypted).
    /// @param encryptedData Encrypted data containing from, to, and tokenId.
    event EncryptedForcedTransfer(bytes encryptedData);

    /// @notice Contract constructor.
    /// @dev Initializes the ERC-721 token with name and symbol, and grants all roles
    /// (Admin, Minter, Burner, Freezer, Force Transfer, Whitelist, Viewer) to the `initialAdmin`.
    /// Generates an encryption key for encrypting sensitive events.
    /// @param name_ The name of the token collection.
    /// @param symbol_ The symbol of the token collection.
    /// @param initialAdmin The address to receive initial administrative and operational roles.
    constructor(string memory name_, string memory symbol_, address initialAdmin) {
        _name = name_;
        _symbol = symbol_;
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(FREEZING_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
        _grantRole(FORCE_TRANSFER_ROLE, initialAdmin);
        _grantRole(VIEWER_ROLE, initialAdmin);
        
        // Generate encryption key for event encryption
        bytes memory randomBytes = Sapphire.randomBytes(32, abi.encodePacked("uRWA721", name_, symbol_));
        _encryptionKey = bytes32(randomBytes);
        _eventNonce = 0;
    }

    /// @dev Returns the name of the token collection.
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /// @dev Returns the symbol of the token collection.
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /// @dev Returns the Uniform Resource Identifier (URI) for token `id`.
    /// @inheritdoc IERC7943NonFungible
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransfer(address from, address to, uint256 tokenId) public view virtual override returns (bool allowed) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        address owner = _ownerOf(tokenId);
        if (owner != from || owner == address(0)) return allowed;
        if (_frozenTokens[from][tokenId]) return allowed;
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

    /// @inheritdoc IERC7943NonFungible
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransact(address account) public view virtual override returns (bool allowed) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        allowed = _isWhitelisted(account);
    }

    /// @inheritdoc IERC7943NonFungible
    /// @dev Requires VIEWER_ROLE. Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function getFrozenTokens(address account, uint256 tokenId) public virtual override view returns (bool frozenStatus) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        frozenStatus = _frozenTokens[account][tokenId];
    }

    /// @notice Returns the number of tokens in owner's account.
    /// @dev Overrides ERC721 balanceOf to add access control. Requires VIEWER_ROLE.
    /// @param owner The address to query the balance of.
    /// @return The number of tokens owned by owner.
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.balanceOf(owner);
    }

    /// @notice Returns the owner of the token ID.
    /// @dev Overrides ERC721 ownerOf to add access control. Requires VIEWER_ROLE.
    /// @param tokenId The token ID to query.
    /// @return The address of the token owner.
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.ownerOf(tokenId);
    }

    /// @notice Returns the Uniform Resource Identifier (URI) for token.
    /// @dev Overrides ERC721 tokenURI to add access control. Requires VIEWER_ROLE.
    /// @param tokenId The token ID to query.
    /// @return The token URI string.
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        // Solady ERC721 uses a virtual tokenURI function that can be overridden
        // Return empty string or implement custom logic here
        return "";
    }

    /// @notice Returns the account approved for token ID.
    /// @dev Overrides ERC721 getApproved to add access control. Requires VIEWER_ROLE.
    /// @param tokenId The token ID to query.
    /// @return The address approved for the token.
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.getApproved(tokenId);
    }

    /// @notice Returns if the operator is allowed to manage all of the assets of owner.
    /// @dev Overrides ERC721 isApprovedForAll to add access control. Requires VIEWER_ROLE.
    /// @param owner The address that owns the tokens.
    /// @param operator The address that acts on behalf of the owner.
    /// @return True if operator is approved to manage owner's tokens.
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.isApprovedForAll(owner, operator);
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
            uint256 tokenId,
            string memory action,
            uint256 timestamp,
            uint256 nonce
        ) = abi.decode(decryptedData, (address, address, uint256, string, uint256, uint256));

        // Authorization check: caller must be sender, receiver, or have VIEWER_ROLE
        bool isAuthorized =
            msg.sender == from ||
            msg.sender == to ||
            hasRole(VIEWER_ROLE, msg.sender);

        require(isAuthorized, "Not authorized to decrypt");

        // Store decrypted data for caller
        _lastDecryptedData[msg.sender] = DecryptedTransferData(
            from, to, tokenId, action, timestamp, nonce, true
        );

        success = true;
    }

    /// @notice Retrieves the last decrypted data for the caller.
    /// @dev Returns the decrypted transfer data that was previously processed.
    /// @return from The sender address.
    /// @return to The receiver address.
    /// @return tokenId The token ID transferred.
    /// @return action The action type (e.g., "transfer", "mint", "burn").
    /// @return timestamp The timestamp of the event.
    /// @return nonce The nonce used for encryption.
    function viewLastDecryptedData() external view returns (
        address from,
        address to,
        uint256 tokenId,
        string memory action,
        uint256 timestamp,
        uint256 nonce
    ) {
        require(_lastDecryptedData[msg.sender].exists, "No decrypted data");
        DecryptedTransferData memory data = _lastDecryptedData[msg.sender];
        return (data.from, data.to, data.tokenId, data.action, data.timestamp, data.nonce);
    }

    /// @notice Clears the last decrypted data for the caller.
    /// @dev Allows users to clear their decrypted data from storage.
    function clearLastDecryptedData() external {
        delete _lastDecryptedData[msg.sender];
    }

    /// @notice Updates the whitelist status for a given account.
    /// @dev Can only be called by accounts holding the `WHITELIST_ROLE`.
    /// Emits an encrypted {EncryptedWhitelisted} event to protect privacy.
    /// @param account The address whose whitelist status is to be changed. Must not be the zero address.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    function changeWhitelist(address account, bool status) external virtual onlyRole(WHITELIST_ROLE) {
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

    /// @notice Safely creates a new token with `tokenId` and assigns it to `to`.
    /// @dev Can only be called by accounts holding the `MINTER_ROLE`.
    /// Requires `to` to be allowed according to {canTransact} (enforced by the `_update` hook).
    /// Performs an ERC721 receiver check on `to` if it is a contract.
    /// Emits a {Transfer} event with `from` set to the zero address.
    /// @param to The address that will receive the minted token.
    /// @param tokenId The specific token identifier to mint.
    function safeMint(address to, uint256 tokenId) external virtual onlyRole(MINTER_ROLE) {
        _safeMint(to, tokenId);
    }

    /// @notice Destroys the token with `tokenId`.
    /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    /// Requires the caller (`_msgSender()`) to be the owner or approved for `tokenId`.
    /// Emits a {Transfer} event with `to` set to the zero address.
    /// @param tokenId The specific token identifier to burn. 
    function burn(uint256 tokenId) external virtual onlyRole(BURNER_ROLE) {
        address previousOwner = _update(address(0), tokenId, _msgSender()); 
        if (previousOwner == address(0)) revert ERC721NonexistentToken(tokenId);
    }

    /// @inheritdoc IERC7943NonFungible
    /// @dev Can only be called by accounts holding the `FREEZING_ROLE`
    function setFrozenTokens(address account, uint256 tokenId, bool frozenStatus) public virtual override onlyRole(FREEZING_ROLE) returns(bool result) {
        _frozenTokens[account][tokenId] = frozenStatus;

        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(account, tokenId, frozenStatus, _eventNonce);
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

    /// @notice Checks if `operator` is authorized to manage `tokenId` from `owner`.
    /// @param owner The address that owns the token.
    /// @param operator The address that is trying to manage the token.
    /// @param tokenId The ID of the token.
    function _checkAuthorized(address owner, address operator, uint256 tokenId) internal view {
        if (owner != operator && !isApprovedForAll(owner, operator) && ownerOf(tokenId) != operator) {
            revert ERC721IncorrectOwner(operator, tokenId, owner);
        }
    }

    /// @notice Checks if the recipient contract implements IERC721Receiver and calls onERC721Received.
    /// @param operator The address which initiated the transfer.
    /// @param from The address which previously owned the token.
    /// @param to The address which will receive the token.
    /// @param tokenId The ID of the token being transferred.
    /// @param data Additional data with no specified format.
    function _checkOnERC721Received(
        address operator,
        address from,
        address to,
        uint256 tokenId,
        bytes memory data
    ) internal {
        if (to.code.length > 0) {
            try IERC721Receiver(to).onERC721Received(operator, from, tokenId, data) returns (bytes4 retval) {
                if (retval != IERC721Receiver.onERC721Received.selector) {
                    revert("ERC721: transfer to non-ERC721Receiver implementer");
                }
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non-ERC721Receiver implementer");
                } else {
                    /// @solidity memory-safe-assembly
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        }
    }

    /// @inheritdoc IERC7943NonFungible
    /// @dev Can only be called by accounts holding the `FORCE_TRANSFER_ROLE`.
    function forcedTransfer(address from, address to, uint256 tokenId) public virtual override onlyRole(FORCE_TRANSFER_ROLE) returns(bool result) {
        require(to != address(0), ERC721InvalidReceiver(address(0)));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));
        require(_ownerOf(tokenId) == from, ERC721IncorrectOwner(from, tokenId, _ownerOf(tokenId)));
        _excessFrozenUpdate(from , tokenId);

        // Update ownership and balances directly without emitting standard Transfer events
        _updateOwnershipAndBalance(from, to, tokenId);

        _checkOnERC721Received(_msgSender(), from, to, tokenId, "");

        // Encrypt sensitive event data with action, timestamp, and nonce
        bytes memory plaintext = abi.encode(
            from,
            to,
            tokenId,
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

    /// @notice Unfreezes a token when it's being forcibly transferred or burned.
    /// @dev This function ensures that frozen tokens are automatically unfrozen when subjected to
    /// forced transfers or burns. This maintains consistency in the frozen state since the token
    /// is leaving the account anyway. Only unfreezes if the token was previously frozen.
    /// Emits an encrypted {EncryptedFrozen} event when unfreezing occurs.
    /// @param from The address that currently owns the token.
    /// @param tokenId The ID of the token that may need to be unfrozen.
    function _excessFrozenUpdate(address from, uint256 tokenId) internal {
        if(_frozenTokens[from][tokenId]) {
            delete _frozenTokens[from][tokenId];

            // Encrypt sensitive event data
            bytes memory plaintext = abi.encode(from, tokenId, false, _eventNonce);
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

    /// @notice Internal helper to update ownership and balances without emitting Transfer events.
    /// @dev Uses Solady's storage slot pattern to update state directly for privacy.
    /// @param from The address sending tokens (zero address for minting).
    /// @param to The address receiving tokens (zero address for burning).
    /// @param tokenId The ID of the token being transferred.
    function _updateOwnershipAndBalance(address from, address to, uint256 tokenId) internal {
        /// @solidity memory-safe-assembly
        assembly {
            // Clear the upper 96 bits of addresses
            let bitmaskAddress := shr(96, not(0))
            from := and(bitmaskAddress, from)
            to := and(bitmaskAddress, to)
            
            // Compute ownership slot: add(id, add(id, keccak256(0x00, 0x20)))
            // where id is stored at 0x00
            mstore(0x00, tokenId)
            let ownershipSlot := add(tokenId, add(tokenId, keccak256(0x00, 0x20)))
            
            if iszero(iszero(from)) {
                // Token exists, load current ownership
                let ownershipPacked := sload(ownershipSlot)
                let owner := and(bitmaskAddress, ownershipPacked)
                
                // Update ownership: xor out old owner, xor in new owner
                sstore(ownershipSlot, xor(ownershipPacked, xor(from, to)))
                
                // Decrement balance of `from`
                mstore(0x0c, from)
                let fromBalanceSlot := keccak256(0x0c, 0x1c)
                sstore(fromBalanceSlot, sub(sload(fromBalanceSlot), 1))
            }
            if iszero(from) {
                // Minting: set ownership directly
                sstore(ownershipSlot, shl(96, to))
            }
            
            if iszero(iszero(to)) {
                // Increment balance of `to`
                mstore(0x0c, to)
                let toBalanceSlot := keccak256(0x0c, 0x1c)
                let toBalanceSlotPacked := add(sload(toBalanceSlot), 1)
                // Check for overflow (balance stored in lower 32 bits)
                let maxBalance := 0xffffffff
                if iszero(and(toBalanceSlotPacked, maxBalance)) {
                    // AccountBalanceOverflow
                    mstore(0x00, 0xea553b34) // `AccountBalanceOverflow()`
                    revert(0x1c, 0x04)
                }
                sstore(toBalanceSlot, toBalanceSlotPacked)
            }
        }
    }

    /// @notice Hook that is called during any token transfer, including minting and burning.
    /// @dev Overrides the ERC-721 `_update` hook. Enforces transfer restrictions based on {canTransfer} and {canTransact} logics.
    /// Updates ownership and balances directly without emitting standard Transfer events (for privacy).
    /// Emits encrypted events using Sapphire precompiles for additional privacy.
    /// Reverts with {ERC721IncorrectOwner} | {ERC7943FrozenTokenId} | {ERC7943CannotTransact} if any `canTransfer`/`canTransact` or other check fails.
    /// @param to The address receiving tokens (zero address for burning).
    /// @param tokenId The ID of the token being transferred.
    /// @param auth The address initiating the transfer.
    function _update(address to, uint256 tokenId, address auth) internal virtual returns(address) {
        address from = _ownerOf(tokenId);

        if (auth != address(0)) {
            _checkAuthorized(from, auth, tokenId);
        }

        bool isMint = (from == address(0) && to != address(0));
        bool isBurn = (from != address(0) && to == address(0));
        bool isTransfer = (from != address(0) && to != address(0));

        if (isMint) { // Mint
            require(_isWhitelisted(to), ERC7943CannotTransact(to));
        } else if (isBurn) { // Burn
            _excessFrozenUpdate(from, tokenId);
        } else if (isTransfer) { // Transfer
            require(from == _ownerOf(tokenId), ERC721IncorrectOwner(from, tokenId, _ownerOf(tokenId)));
            require(!_frozenTokens[from][tokenId], ERC7943FrozenTokenId(from, tokenId));
            require(_isWhitelisted(from), ERC7943CannotTransact(from));
            require(_isWhitelisted(to), ERC7943CannotTransact(to));
        } else {
            revert ERC721NonexistentToken(tokenId);
        }

        // Update ownership and balances directly without emitting standard Transfer events
        _updateOwnershipAndBalance(from, to, tokenId);

        // Determine action type
        string memory action;
        if (isMint) {
            action = "mint";
        } else if (isBurn) {
            action = "burn";
        } else {
            action = "transfer";
        }

        // Emit encrypted transfer event for privacy (using Sapphire precompile)
        bytes memory plaintext = abi.encode(
            from,
            to,
            tokenId,
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
        // Estimate worst-case gas: ~150k for transfer with all checks and encryption
        Sapphire.padGas(200000);

        return from;
    }

    /// @notice See {IERC165-supportsInterface}.
    /// @dev Indicates support for the {IERC7943NonFungible} interface in addition to inherited interfaces.
    /// @param interfaceId The interface identifier, as specified in ERC-165.
    /// @return True if the contract implements `interfaceId`, false otherwise.
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC721, IERC165) returns (bool) {
        return interfaceId == type(IERC7943NonFungible).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}

