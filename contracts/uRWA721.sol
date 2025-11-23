// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7943NonFungible} from "./interfaces/IERC7943.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC721Utils} from "@openzeppelin/contracts/token/ERC721/utils/ERC721Utils.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";

/// @title uRWA-721 Token Contract
/// @notice An ERC-721 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-721 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers, and freezing. Managed via AccessControl.
contract uRWA721 is Context, ERC721, AccessControlEnumerable, IERC7943NonFungible {
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
    /// @param name The name of the token collection.
    /// @param symbol The symbol of the token collection.
    /// @param initialAdmin The address to receive initial administrative and operational roles.
    constructor(string memory name, string memory symbol, address initialAdmin) ERC721(name, symbol) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        _grantRole(MINTER_ROLE, initialAdmin);
        _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(FREEZING_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
        _grantRole(FORCE_TRANSFER_ROLE, initialAdmin);
        _grantRole(VIEWER_ROLE, initialAdmin);
        
        // Generate encryption key for event encryption
        bytes memory randomBytes = Sapphire.randomBytes(32, abi.encodePacked("uRWA721", name, symbol));
        _encryptionKey = bytes32(randomBytes);
        _eventNonce = 0;
    }

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

    /// @inheritdoc IERC7943NonFungible
    /// @dev Requires VIEWER_ROLE or authenticated call (msg.sender != address(0)).
    /// Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransact(address account) public view virtual override returns (bool allowed) {
        require(hasRole(VIEWER_ROLE, msg.sender) || msg.sender != address(0), "Access denied");
        allowed = _whitelist[account] ? true : false;
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
        return super.tokenURI(tokenId);
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

    /// @notice Updates the whitelist status for a given account.
    /// @dev Can only be called by accounts holding the `WHITELIST_ROLE`.
    /// Emits an encrypted {EncryptedWhitelisted} event to protect privacy.
    /// @param account The address whose whitelist status is to be changed. Must not be the zero address.
    /// @param status The new whitelist status (true = whitelisted, false = not whitelisted).
    function changeWhitelist(address account, bool status) external virtual onlyRole(WHITELIST_ROLE) {
        _whitelist[account] = status;
        
        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(account, status, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
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
        bytes memory plaintext = abi.encode(account, tokenId, frozenStatus, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedFrozen(encrypted);
        
        result = true;
    }

    /// @inheritdoc IERC7943NonFungible
    /// @dev Can only be called by accounts holding the `FORCE_TRANSFER_ROLE`.
    function forcedTransfer(address from, address to, uint256 tokenId) public virtual override onlyRole(FORCE_TRANSFER_ROLE) returns(bool result) {
        require(to != address(0), ERC721InvalidReceiver(address(0)));
        require(canTransact(to), ERC7943CannotTransact(to));
        require(ownerOf(tokenId) == from, ERC721IncorrectOwner(from, tokenId, ownerOf(tokenId)));
        _excessFrozenUpdate(from , tokenId);
        super._update(to, tokenId, address(0)); // Skip _update override
        ERC721Utils.checkOnERC721Received(_msgSender(), from, to, tokenId, "");
        
        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(from, to, tokenId, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
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
            bytes memory plaintext = abi.encode(from, tokenId, false, _eventNonce++);
            bytes32 nonce = bytes32(_eventNonce);
            bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
            emit EncryptedFrozen(encrypted);
        }
    }

    /// @notice Hook that is called during any token transfer, including minting and burning.
    /// @dev Overrides the ERC-721 `_update` hook. Enforces transfer restrictions based on {canTransfer} and {canTransact} logics.
    /// Emits encrypted events in addition to the standard Transfer event to protect privacy.
    /// Note: The standard Transfer event is still emitted by super._update() for compatibility.
    /// Reverts with {ERC721IncorrectOwner} | {ERC7943FrozenTokenId} | {ERC7943CannotTransact} if any `canTransfer`/`canTransact` or other check fails.
    /// @param to The address receiving tokens (zero address for burning).
    /// @param tokenId The ID of the token being transferred.
    /// @param auth The address initiating the transfer.
    function _update(address to, uint256 tokenId, address auth) internal virtual override returns(address) {
        address from = _ownerOf(tokenId);

        if (auth != address(0)) {
            _checkAuthorized(from, auth, tokenId);
        }

        bool isMint = (from == address(0) && to != address(0));
        bool isBurn = (from != address(0) && to == address(0));
        bool isTransfer = (from != address(0) && to != address(0));

        if (isMint) { // Mint
            require(canTransact(to), ERC7943CannotTransact(to));
        } else if (isBurn) { // Burn
            _excessFrozenUpdate(from, tokenId);
        } else if (isTransfer) { // Transfer
            require(from == _ownerOf(tokenId), ERC721IncorrectOwner(from, tokenId, _ownerOf(tokenId)));
            require(!_frozenTokens[from][tokenId], ERC7943FrozenTokenId(from, tokenId));
            require(canTransact(from), ERC7943CannotTransact(from));
            require(canTransact(to), ERC7943CannotTransact(to));
        } else {
            revert ERC721NonexistentToken(tokenId);
        }

        address previousOwner = super._update(to, tokenId, auth);
        
        // Emit encrypted transfer event for privacy
        bytes memory plaintext = abi.encode(from, to, tokenId, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedTransfer(encrypted);
        
        // Pad gas to prevent side-channel leakage from conditional branches
        // Estimate worst-case gas: ~150k for transfer with all checks and encryption
        Sapphire.padGas(200000);
        
        return previousOwner;
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

