// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC7943Fungible} from "./interfaces/IERC7943.sol";
import {Context} from "@openzeppelin/contracts/utils/Context.sol";
import {ERC20} from "./base/ERC20.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {AccessControlEnumerable} from "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import {Sapphire} from "@oasisprotocol/sapphire-contracts/contracts/Sapphire.sol";
import {SiweAuth} from "@oasisprotocol/sapphire-contracts/contracts/auth/SiweAuth.sol";
import {CalldataEncryption} from "./CalldataEncryption.sol";

/// @title uRWA-20 Token Contract
/// @notice An ERC-20 token implementation adhering to the IERC-7943 interface for Real World Assets.
/// @dev Combines standard ERC-20 functionality with RWA-specific features like whitelisting,
/// controlled minting/burning, asset forced transfers, and freezing. Managed via AccessControl.
contract uRWA20 is Context, ERC20, AccessControlEnumerable, IERC7943Fungible, SiweAuth {
    /// @notice Role identifiers.
    // bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    // bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant FREEZING_ROLE = keccak256("FREEZING_ROLE");
    bytes32 public constant WHITELIST_ROLE = keccak256("WHITELIST_ROLE");
    bytes32 public constant FORCE_TRANSFER_ROLE = keccak256("FORCE_TRANSFER_ROLE");
    bytes32 public constant VIEWER_ROLE = keccak256("VIEWER_ROLE");
    // bytes32 public constant MAIN_AUDITOR_ROLE = keccak256("MAIN_AUDITOR_ROLE");

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

    /// @notice Struct for storing decrypted transfer data.
    /// @dev Used to temporarily store decrypted data for authorized viewers.
    struct DecryptedTransferData {
        address from;
        address to;
        uint256 amount;
        string action;
        uint256 timestamp;
        uint256 nonce;
        bool exists;
    }

    /// @notice Mapping storing decrypted data for each authorized viewer.
    /// @dev Data is temporarily stored after successful decryption for retrieval.
    mapping(address => DecryptedTransferData) private _lastDecryptedData;

    // /// @notice Struct for auditor permissions.
    // /// @dev Manages time-limited and scope-limited audit access.
    // struct AuditorPermission {
    //     uint256 expiryTime;
    //     bool hasFullAccess;
    //     bool isActive;
    //     mapping(address => bool) authorizedAddresses;
    // }

    // /// @notice Mapping storing auditor permissions.
    // /// @dev Main auditor has unrestricted access without needing this mapping.
    // mapping(address => AuditorPermission) public auditorPermissions;

    /// @notice Token name.
    string private _name;

    /// @notice Token symbol.
    string private _symbol;

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

    /// @notice Emitted when an approval occurs (encrypted).
    /// @param encryptedData Encrypted data containing owner, spender, and amount.
    event EncryptedApproval(bytes encryptedData);

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
    /// @param name_ The name of the token.
    /// @param symbol_ The symbol of the token.
    /// @param initialAdmin The address to receive initial administrative and operational roles.
    /// @param domain The domain for SIWE authentication.
    constructor(
        string memory name_,
        string memory symbol_,
        address initialAdmin,
        string memory domain
    ) SiweAuth(domain) {
        _name = name_;
        _symbol = symbol_;
        _grantRole(DEFAULT_ADMIN_ROLE, initialAdmin);
        // _grantRole(MINTER_ROLE, initialAdmin);
        // _grantRole(BURNER_ROLE, initialAdmin);
        _grantRole(FREEZING_ROLE, initialAdmin);
        _grantRole(WHITELIST_ROLE, initialAdmin);
        _grantRole(FORCE_TRANSFER_ROLE, initialAdmin);
        _grantRole(VIEWER_ROLE, initialAdmin);
        // _grantRole(MAIN_AUDITOR_ROLE, initialAdmin);

        // Generate encryption key for event encryption
        bytes memory randomBytes = Sapphire.randomBytes(32, abi.encodePacked("uRWA20", name_, symbol_));
        _encryptionKey = bytes32(randomBytes);
        _eventNonce = 0;
    }

    /// @dev Returns the name of the token.
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /// @dev Returns the symbol of the token.
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /// @notice Internal helper to get authenticated caller address.
    /// @dev Checks msg.sender first (for transactions), then validates SIWE token (for view calls).
    /// @param token Optional SIWE session token for authenticated view calls.
    /// @return caller The authenticated caller address.
    function _getAuthenticatedCaller(bytes memory token) internal view returns (address caller) {
        if (msg.sender != address(0)) {
            return msg.sender;
        }
        return authMsgSender(token);
    }

    /// @inheritdoc IERC7943Fungible
    /// @dev Allows users to check their own transfer permissions, or requires VIEWER_ROLE for others.
    /// Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransfer(address from, address to, uint256 amount, bytes memory token) public virtual override view returns (bool allowed) {
        address caller = _getAuthenticatedCaller(token);
        // Allow users to check their own transfer permissions, or require VIEWER_ROLE for others
        require(caller == from || hasRole(VIEWER_ROLE, caller), "Access denied");
        uint256 fromBalance = super.balanceOf(from);
        if (fromBalance < _frozenTokens[from]) return allowed;
        if (amount > fromBalance - _frozenTokens[from]) return allowed;
        // When caller is checking their own transfer, check whitelists directly
        // Otherwise caller has VIEWER_ROLE and can use canTransact
        bool fromCanTransact = (caller == from) ? _isWhitelisted(from) : canTransact(from, token);
        bool toCanTransact = (caller == from) ? _isWhitelisted(to) : canTransact(to, token);
        if (!fromCanTransact || !toCanTransact) return allowed;
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
    /// @dev Allows users to check their own whitelist status, or requires VIEWER_ROLE for others.
    /// Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function canTransact(address account, bytes memory token) public virtual override view returns (bool allowed) {
        address caller = _getAuthenticatedCaller(token);
        // Allow users to check their own whitelist status, or require VIEWER_ROLE for others
        require(caller == account || hasRole(VIEWER_ROLE, caller), "Access denied");
        allowed = _isWhitelisted(account);
    }

    /// @inheritdoc IERC7943Fungible
    /// @dev Allows users to check their own frozen tokens, or requires VIEWER_ROLE for others.
    /// Unauthenticated view calls (msg.sender == address(0)) are rejected to protect privacy.
    function getFrozenTokens(address account, bytes memory token) public virtual override view returns (uint256 amount) {
        address caller = _getAuthenticatedCaller(token);
        // Allow users to check their own frozen tokens, or require VIEWER_ROLE for others
        require(caller == account || hasRole(VIEWER_ROLE, caller), "Access denied");
        amount = _frozenTokens[account];
    }

    /// @notice Returns the balance of the account (standard ERC20 override).
    /// @dev Overrides standard ERC20 balanceOf to protect privacy.
    /// For transactions: requires VIEWER_ROLE via msg.sender.
    /// For view calls: returns 0 to prevent information leakage (use balanceOf(address, bytes) with SIWE token instead).
    /// @param account The address to query the balance of.
    /// @return The balance of the account (0 for unauthenticated view calls).
    function balanceOf(address account) public view virtual override returns (uint256) {
        // For view calls (msg.sender == address(0)), return 0 to protect privacy
        // Standard ERC20 functions cannot accept SIWE token parameter
        if (msg.sender == address(0)) {
            return 0;
        }
        // For transaction calls, require VIEWER_ROLE
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.balanceOf(account);
    }

    /// @notice Returns the balance of the account.
    /// @dev Allows users to read their own balance, or requires VIEWER_ROLE for other accounts.
    /// SIWE authentication via token parameter is required for view calls.
    /// @param account The address to query the balance of.
    /// @param token SIWE session token for authenticated view calls.
    /// @return The balance of the account.
    function balanceOf(address account, bytes memory token) public view virtual returns (uint256) {
        address caller = _getAuthenticatedCaller(token);
        // Allow users to read their own balance, or require VIEWER_ROLE for others
        require(caller == account || hasRole(VIEWER_ROLE, caller), "Access denied");
        return super.balanceOf(account);
    }

    /// @notice Returns the total supply of tokens (standard ERC20 override).
    /// @dev Overrides standard ERC20 totalSupply to protect privacy.
    /// For transactions: requires VIEWER_ROLE via msg.sender.
    /// For view calls: returns 0 to prevent information leakage (use totalSupply(bytes) with SIWE token instead).
    /// @return The total supply of tokens (0 for unauthenticated view calls).
    function totalSupply() public view virtual override returns (uint256) {
        // For view calls (msg.sender == address(0)), return 0 to protect privacy
        // Standard ERC20 functions cannot accept SIWE token parameter
        if (msg.sender == address(0)) {
            return 0;
        }
        // For transaction calls, require VIEWER_ROLE
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.totalSupply();
    }

    /// @notice Returns the total supply of tokens.
    /// @dev Requires VIEWER_ROLE and SIWE authentication via token parameter.
    /// @param token SIWE session token for authenticated view calls.
    /// @return The total supply of tokens.
    function totalSupply(bytes memory token) public view virtual returns (uint256) {
        address caller = _getAuthenticatedCaller(token);
        require(hasRole(VIEWER_ROLE, caller), "Access denied");
        return super.totalSupply();
    }

    /// @notice Returns the amount of tokens that an owner allowed to a spender (standard ERC20 override).
    /// @dev Overrides standard ERC20 allowance to protect privacy.
    /// For transactions: requires VIEWER_ROLE via msg.sender.
    /// For view calls: returns 0 to prevent information leakage (use allowance(address, address, bytes) with SIWE token instead).
    /// @param owner The address which owns the funds.
    /// @param spender The address which will spend the funds.
    /// @return The amount of tokens still available for the spender (0 for unauthenticated view calls).
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        // For view calls (msg.sender == address(0)), return 0 to protect privacy
        // Standard ERC20 functions cannot accept SIWE token parameter
        if (msg.sender == address(0)) {
            return 0;
        }
        // For transaction calls, require VIEWER_ROLE
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.allowance(owner, spender);
    }

    /// @notice Returns the amount of tokens that an owner allowed to a spender.
    /// @dev Allows owners to read their own allowances, or requires VIEWER_ROLE for others.
    /// SIWE authentication via token parameter is required for view calls.
    /// @param owner The address which owns the funds.
    /// @param spender The address which will spend the funds.
    /// @param token SIWE session token for authenticated view calls.
    /// @return The amount of tokens still available for the spender.
    function allowance(address owner, address spender, bytes memory token) public view virtual returns (uint256) {
        address caller = _getAuthenticatedCaller(token);
        // Allow owners to read their own allowances, or require VIEWER_ROLE for others
        require(caller == owner || hasRole(VIEWER_ROLE, caller), "Access denied");
        return super.allowance(owner, spender);
    }

    /// @notice Returns the current nonce for an owner address (for EIP-2612 permit).
    /// @dev Overrides standard ERC20 nonces to protect privacy.
    /// For view calls: returns 0 to prevent information leakage.
    /// For transactions: requires VIEWER_ROLE.
    /// @param owner The address to query the nonce for.
    /// @return The current nonce (0 for unauthenticated view calls).
    function nonces(address owner) public view virtual override returns (uint256) {
        // For view calls (msg.sender == address(0)), return 0 to protect privacy
        if (msg.sender == address(0)) {
            return 0;
        }
        // For transaction calls, require VIEWER_ROLE
        require(hasRole(VIEWER_ROLE, msg.sender), "Access denied");
        return super.nonces(owner);
    }

    /// @notice Sets `amount` as the allowance of `spender` over the caller's tokens (standard ERC20 override).
    /// @dev Overrides standard ERC20 approve to enforce whitelist checks and suppress Approval events.
    /// Requires both owner and spender to be whitelisted for RWA compliance.
    /// Does NOT emit standard Approval events for privacy, emits EncryptedApproval instead.
    /// @param spender The address that will be approved to spend tokens.
    /// @param amount The amount of tokens to approve.
    /// @return True if the operation succeeded.
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        address owner = _msgSender();
        require(_isWhitelisted(owner), ERC7943CannotTransact(owner));
        require(_isWhitelisted(spender), ERC7943CannotTransact(spender));
        
        // Update allowance directly without emitting Approval event
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, spender)
            mstore(0x0c, or(shl(96, owner), _ALLOWANCE_SLOT_SEED))
            sstore(keccak256(0x0c, 0x34), amount)
        }

        // Encrypt sensitive event data with action, timestamp, and nonce
        bytes memory plaintext = abi.encode(
            owner,
            spender,
            amount,
            "approve",
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
        emit EncryptedApproval(encrypted);
        
        return true;
    }

    /// @notice Sets `amount` as the allowance of `spender` over the `owner`'s tokens via signature (EIP-2612 permit override).
    /// @dev Overrides standard ERC20 permit to enforce whitelist checks and suppress Approval events.
    /// Requires both owner and spender to be whitelisted for RWA compliance.
    /// Does NOT emit standard Approval events for privacy, emits EncryptedApproval instead.
    /// @param owner The address that owns the tokens.
    /// @param spender The address that will be approved to spend tokens.
    /// @param value The amount of tokens to approve.
    /// @param deadline The timestamp after which the permit is no longer valid.
    /// @param v The recovery byte of the signature.
    /// @param r Half of the ECDSA signature pair.
    /// @param s Half of the ECDSA signature pair.
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual override {
        require(_isWhitelisted(owner), ERC7943CannotTransact(owner));
        require(_isWhitelisted(spender), ERC7943CannotTransact(spender));
        
        // Call super.permit which validates signature and updates allowance
        // It no longer emits Approval event (we modified the base ERC20)
        super.permit(owner, spender, value, deadline, v, r, s);

        // Encrypt sensitive event data and emit encrypted approval event
        bytes memory plaintext = abi.encode(
            owner,
            spender,
            value,
            "permit",
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
        emit EncryptedApproval(encrypted);
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
                let isMint := iszero(from)
                let isBurn := iszero(to)
                if isMint {
                    // Minting: increase total supply
                    let totalSupplyBefore := sload(_TOTAL_SUPPLY_SLOT)
                    let totalSupplyAfter := add(totalSupplyBefore, amount)
                    sstore(_TOTAL_SUPPLY_SLOT, totalSupplyAfter)
                }
                if isBurn {
                    // Burning: decrease total supply
                    sstore(_TOTAL_SUPPLY_SLOT, sub(sload(_TOTAL_SUPPLY_SLOT), amount))
                }
            }
        }
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
            uint256 amount,
            string memory action,
            uint256 timestamp,
            uint256 nonce
        ) = abi.decode(decryptedData, (address, address, uint256, string, uint256, uint256));

        // Authorization check: caller must be sender, receiver, or have VIEWER_ROLE
        bool isAuthorized =
            msg.sender == from ||
            msg.sender == to ||
            hasRole(VIEWER_ROLE, msg.sender);
            // || checkAuditorPermission(msg.sender, from) ||
            // checkAuditorPermission(msg.sender, to);

        require(isAuthorized, "Not authorized to decrypt");

        // Store decrypted data for caller
        _lastDecryptedData[msg.sender] = DecryptedTransferData(
            from, to, amount, action, timestamp, nonce, true
        );

        success = true;
    }

    /// @notice Retrieves the last decrypted data for the caller.
    /// @dev Returns the decrypted transfer data that was previously processed.
    /// @return from The sender address.
    /// @return to The receiver address.
    /// @return amount The amount transferred.
    /// @return action The action type (e.g., "transfer", "mint", "burn").
    /// @return timestamp The timestamp of the event.
    /// @return nonce The nonce used for encryption.
    function viewLastDecryptedData(bytes memory token) external view returns (
        address from,
        address to,
        uint256 amount,
        string memory action,
        uint256 timestamp,
        uint256 nonce
    ) {
        address caller = _getAuthenticatedCaller(token);
        require(_lastDecryptedData[caller].exists, "No decrypted data");
        DecryptedTransferData memory data = _lastDecryptedData[caller];
        return (data.from, data.to, data.amount, data.action, data.timestamp, data.nonce);
    }

    /// @notice Clears the last decrypted data for the caller.
    /// @dev Allows users to clear their decrypted data from storage.
    function clearLastDecryptedData() external {
        delete _lastDecryptedData[msg.sender];
    }

    // /// @notice Grants auditor permission with time and scope limits.
    // /// @dev Can only be called by MAIN_AUDITOR_ROLE. Enables controlled audit access.
    // /// @param auditor The address to grant auditor permissions to.
    // /// @param duration The duration in seconds for which the permission is valid (max 30 days).
    // /// @param fullAccess True for full access, false for address-specific access.
    // /// @param authorizedAddresses Array of addresses the auditor can audit (ignored if fullAccess is true).
    // function grantAuditorPermission(
    //     address auditor,
    //     uint256 duration,
    //     bool fullAccess,
    //     address[] calldata authorizedAddresses
    // ) external onlyRole(MAIN_AUDITOR_ROLE) {
    //     require(auditor != address(0), "Invalid auditor address");
    //     require(duration > 0 && duration <= 30 days, "Invalid duration");

    //     AuditorPermission storage perm = auditorPermissions[auditor];
    //     perm.expiryTime = block.timestamp + duration;
    //     perm.hasFullAccess = fullAccess;
    //     perm.isActive = true;

    //     if (!fullAccess) {
    //         for (uint i = 0; i < authorizedAddresses.length; i++) {
    //             perm.authorizedAddresses[authorizedAddresses[i]] = true;
    //         }
    //     }
    // }

    // /// @notice Revokes auditor permission.
    // /// @dev Can only be called by MAIN_AUDITOR_ROLE.
    // /// @param auditor The address whose auditor permissions to revoke.
    // function revokeAuditorPermission(address auditor) external onlyRole(MAIN_AUDITOR_ROLE) {
    //     auditorPermissions[auditor].isActive = false;
    // }

    // /// @notice Checks if an auditor has permission to access data for a specific address.
    // /// @dev Main auditor always has access. Other auditors checked based on permission settings.
    // /// @param auditor The auditor address to check.
    // /// @param targetAddress The address being audited.
    // /// @return hasPermission True if the auditor has permission, false otherwise.
    // function checkAuditorPermission(address auditor, address targetAddress)
    //     public view returns (bool hasPermission) {
    //     // Main auditor always has full access
    //     if (hasRole(MAIN_AUDITOR_ROLE, auditor)) {
    //         return true;
    //     }

    //     AuditorPermission storage perm = auditorPermissions[auditor];

    //     // Check if permission is active and not expired
    //     if (!perm.isActive || block.timestamp > perm.expiryTime) {
    //         return false;
    //     }

    //     // Full access auditors can access all addresses
    //     if (perm.hasFullAccess) {
    //         return true;
    //     }

    //     // Otherwise, check if this specific address is authorized
    //     return perm.authorizedAddresses[targetAddress];
    // }

    /// @notice Updates the whitelist status for a given account.
    /// @dev Can only be called by accounts holding the `WHITELIST_ROLE`.
    /// Emits an encrypted {EncryptedWhitelisted} event to protect privacy.
    /// @param account The address whose whitelist status is to be changed.
    /// @param status The new whitelist status (true or false).
    function changeWhitelist(address account, bool status) external onlyRole(WHITELIST_ROLE) {
        _whitelist[account] = status;

        // Encrypt sensitive event data with action, timestamp, and nonce
        // Note: This is not DecryptedTransferData - it's whitelist data with different structure
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

    // /// @notice Creates `amount` new tokens and assigns them to `to`.
    // /// @dev Can only be called by accounts holding the `MINTER_ROLE`.
    // /// Requires `to` to be allowed according to {canTransact}.
    // /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    // /// @param to The address that will receive the minted tokens.
    // /// @param amount The amount of tokens to mint.
    // function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
    //     _mint(to, amount);
    // }

    // /// @notice Destroys `amount` tokens from the caller's account.
    // /// @dev Can only be called by accounts holding the `BURNER_ROLE`.
    // /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    // /// @param amount The amount of tokens to burn.
    // function burn(uint256 amount) external onlyRole(BURNER_ROLE) {
    //     _burn(_msgSender(), amount);
    // }

    // /// @dev Overrides Solady's _mint to update balances without emitting Transfer events.
    // /// @param to The address that will receive the minted tokens.
    // /// @param amount The amount of tokens to mint.
    // function _mint(address to, uint256 amount) internal virtual override {
    //     require(_isWhitelisted(to), ERC7943CannotTransact(to));

    //     // Update balances directly without emitting Transfer event
    //     _updateBalanceWithoutEvent(address(0), to, amount);

    //     // Emit only encrypted event with action, timestamp, and nonce
    //     bytes memory plaintext = abi.encode(
    //         address(0),
    //         to,
    //         amount,
    //         "mint",
    //         block.timestamp,
    //         _eventNonce
    //     );
    //     bytes32 nonce = bytes32(_eventNonce++);
    //     bytes memory encrypted = Sapphire.encrypt(
    //         _encryptionKey,
    //         nonce,
    //         plaintext,
    //         abi.encode(address(this)) // Bind to contract address
    //     );
    //     emit EncryptedTransfer(encrypted);

    //     Sapphire.padGas(200000);
    // }

    /// @dev Hook called before token transfer (Solady pattern).
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {}

    /// @dev Hook called after token transfer (Solady pattern).
    function _afterTokenTransfer(address from, address to, uint256 amount) internal virtual override {}

    // /// @dev Overrides Solady's _burn to update balances without emitting Transfer events.
    // /// @param from The address from which tokens are burned.
    // /// @param amount The amount of tokens to burn.
    // function _burn(address from, uint256 amount) internal virtual override {
    //     _excessFrozenUpdate(from, amount);

    //     // Update balances directly without emitting Transfer event
    //     _updateBalanceWithoutEvent(from, address(0), amount);

    //     // Emit only encrypted event with action, timestamp, and nonce
    //     bytes memory plaintext = abi.encode(
    //         from,
    //         address(0),
    //         amount,
    //         "burn",
    //         block.timestamp,
    //         _eventNonce
    //     );
    //     bytes32 nonce = bytes32(_eventNonce++);
    //     bytes memory encrypted = Sapphire.encrypt(
    //         _encryptionKey,
    //         nonce,
    //         plaintext,
    //         abi.encode(address(this)) // Bind to contract address
    //     );
    //     emit EncryptedTransfer(encrypted);

    //     Sapphire.padGas(200000);
    // }

    /// @inheritdoc IERC7943Fungible
    /// @dev Can only be called by accounts holding the `FREEZING_ROLE`
    function setFrozenTokens(address account, uint256 amount) public virtual override onlyRole(FREEZING_ROLE) returns(bool result) {
        _frozenTokens[account] = amount;

        // Encrypt sensitive event data
        bytes memory plaintext = abi.encode(account, amount, _eventNonce);
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

    /// @inheritdoc IERC7943Fungible
    /// @dev Can only be called by accounts holding the `FORCE_TRANSFER_ROLE`.
    function forcedTransfer(address from, address to, uint256 amount) public virtual override onlyRole(FORCE_TRANSFER_ROLE) returns(bool result) {
        require(from != address(0) && to != address(0), NotZeroAddress());
        require(_isWhitelisted(to), ERC7943CannotTransact(to));
        uint256 fromBalance = super.balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        _excessFrozenUpdate(from, amount);

        // Update balances directly without emitting Transfer event
        _updateBalanceWithoutEvent(from, to, amount);

        // Encrypt sensitive event data with action, timestamp, and nonce
        bytes memory plaintext = abi.encode(
            from,
            to,
            amount,
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
        uint256 accountBalance = super.balanceOf(account);
        if(amount > unfrozenBalance && amount <= accountBalance) {
            _frozenTokens[account] -= amount - unfrozenBalance;

            // Encrypt sensitive event data
            bytes memory plaintext = abi.encode(account, _frozenTokens[account], _eventNonce);
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
    /// @param account The address to calculate unfrozen balance for.
    /// @return unfrozenBalance The amount of tokens available for transfer.
    function _unfrozenBalance(address account) internal view returns(uint256 unfrozenBalance) {
        uint256 accountBalance = super.balanceOf(account);
        unfrozenBalance = accountBalance < _frozenTokens[account] ? 0 : accountBalance - _frozenTokens[account];
    }

    /// @dev Internal transfer function that enforces transfer restrictions.
    /// @param from The address sending tokens.
    /// @param to The address receiving tokens.
    /// @param amount The amount being transferred.
    function _transfer(address from, address to, uint256 amount) internal virtual override {
        uint256 fromBalance = super.balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        uint256 unfrozenFromBalance = _unfrozenBalance(from);
        require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));
        require(_isWhitelisted(from), ERC7943CannotTransact(from));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));

        // Update balances directly without emitting standard Transfer events
        _updateBalanceWithoutEvent(from, to, amount);
        
        // Emit encrypted transfer event for privacy (using Sapphire precompile)
        bytes memory plaintext = abi.encode(from, to, amount, _eventNonce++);
        bytes32 nonce = bytes32(_eventNonce);
        bytes memory encrypted = Sapphire.encrypt(_encryptionKey, nonce, plaintext, "");
        emit EncryptedTransfer(encrypted);
        
        // Pad gas to prevent side-channel leakage from conditional branches
        Sapphire.padGas(200000);
    }

    /// @dev Overrides Solady's transfer to enforce whitelist and frozen token checks.
    /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        address from = _msgSender();
        require(_isWhitelisted(from), ERC7943CannotTransact(from));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));

        uint256 fromBalance = super.balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        uint256 unfrozenFromBalance = _unfrozenBalance(from);
        require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));

        // Update balances directly without emitting Transfer event
        _updateBalanceWithoutEvent(from, to, amount);

        // Emit only encrypted event with action, timestamp, and nonce
        bytes memory plaintext = abi.encode(
            from,
            to,
            amount,
            "transfer",
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

        Sapphire.padGas(200000);
        return true;
    }

    /// @dev Overrides Solady's transferFrom to enforce whitelist and frozen token checks.
    /// Does NOT emit standard Transfer events (only encrypted events for privacy).
    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        require(_isWhitelisted(from), ERC7943CannotTransact(from));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));

        uint256 fromBalance = super.balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        uint256 unfrozenFromBalance = _unfrozenBalance(from);
        require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));

        // Check and update allowance
        address spender = _msgSender();
        uint256 currentAllowance = super.allowance(from, spender);
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

        // Emit only encrypted event with action, timestamp, and nonce
        bytes memory plaintext = abi.encode(
            from,
            to,
            amount,
            "transferFrom",
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

    /// @notice Helper function to create encrypted calldata for transactions.
    /// @dev This function is called client-side to encrypt transaction parameters.
    /// The encrypted data is then sent to executeEncrypted().
    /// @param selector The function selector (first 4 bytes of keccak256 of function signature).
    /// @param params ABI-encoded parameters for the function.
    /// @return Encrypted calldata that can be passed to executeEncrypted().
    function makeEncryptedTransaction(
        bytes4 selector,
        bytes memory params
    ) external view returns (bytes memory) {
        return CalldataEncryption.encryptCallData(
            abi.encode(selector, params)
        );
    }

    /// @notice Executes a transaction with encrypted calldata.
    /// @dev Decrypts the calldata and routes to appropriate internal functions.
    /// The encrypted data is wrapped in a CBOR envelope which needs to be unwrapped.
    /// This is the main entry point for all encrypted write operations.
    /// @param encryptedData The encrypted calldata containing function selector and parameters.
    function executeEncrypted(bytes memory encryptedData) external payable {
        // Decode the CBOR envelope and extract the body
        // The plaintext has structure: {body: <encoded bytes>}
        bytes memory decodedData = _decodeCBOREnvelope(encryptedData);

        // Now decode the selector and params from the unwrapped data
        (bytes4 selector, bytes memory params) = abi.decode(decodedData, (bytes4, bytes));

        // Route to appropriate internal function based on selector
        if (selector == this.transfer.selector) {
            (address to, uint256 amount) = abi.decode(params, (address, uint256));
            _executeTransfer(_msgSender(), to, amount);
        } else if (selector == this.transferFrom.selector) {
            (address from, address to, uint256 amount) = abi.decode(params, (address, address, uint256));
            _executeTransferFrom(from, to, amount);
        } else if (selector == this.approve.selector) {
            (address spender, uint256 amount) = abi.decode(params, (address, uint256));
            _executeApprove(_msgSender(), spender, amount);
        // } else if (selector == this.mint.selector) {
        //     (address to, uint256 amount) = abi.decode(params, (address, uint256));
        //     _executeMint(to, amount);
        // } else if (selector == this.burn.selector) {
        //     (uint256 amount) = abi.decode(params, (uint256));
        //     _executeBurn(_msgSender(), amount);
        } else if (selector == this.changeWhitelist.selector) {
            (address account, bool status) = abi.decode(params, (address, bool));
            _executeChangeWhitelist(account, status);
        } else if (selector == this.setFrozenTokens.selector) {
            (address account, uint256 amount) = abi.decode(params, (address, uint256));
            _executeSetFrozenTokens(account, amount);
        } else if (selector == this.forcedTransfer.selector) {
            (address from, address to, uint256 amount) = abi.decode(params, (address, address, uint256));
            _executeForcedTransfer(from, to, amount);
        } else if (selector == bytes4(keccak256("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)"))) {
            (address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) =
                abi.decode(params, (address, address, uint256, uint256, uint8, bytes32, bytes32));
            _executePermit(owner, spender, value, deadline, v, r, s);
        } else {
            revert("Invalid function selector");
        }
    }

    /// @notice Decodes the CBOR envelope wrapping the encrypted calldata.
    /// @dev The plaintext structure is: map(1) with key "body" containing the encoded data.
    /// This function extracts the body field from the CBOR map.
    /// @param cborData The CBOR-encoded plaintext containing the body field.
    /// @return The decoded bytes from the body field.
    function _decodeCBOREnvelope(bytes memory cborData) internal pure returns (bytes memory) {
        // CBOR structure: hex"a1" (map with 1 entry) + key + value
        // Key: hex"64" "body" (text string of length 4)
        // Value: CBOR-encoded bytes

        uint256 offset = 0;

        // Check for map(1) marker
        require(cborData[offset] == 0xa1, "Invalid CBOR map header");
        offset++;

        // Check for text string of length 4 marker
        require(cborData[offset] == 0x64, "Invalid CBOR text marker");
        offset++;

        // Check for "body" key
        require(
            cborData[offset] == 0x62 &&
            cborData[offset + 1] == 0x6f &&
            cborData[offset + 2] == 0x64 &&
            cborData[offset + 3] == 0x79,
            "Invalid body key"
        );
        offset += 4;

        // Now parse the CBOR-encoded bytes value
        // The value is a byte string: marker + length + data
        uint8 marker = uint8(cborData[offset]);
        offset++;

        uint256 length;
        if (marker >= 0x40 && marker <= 0x57) {
            // Byte string with inline length (0-23 bytes)
            length = marker - 0x40;
        } else if (marker == 0x58) {
            // Byte string with 1-byte length
            length = uint8(cborData[offset]);
            offset++;
        } else if (marker == 0x59) {
            // Byte string with 2-byte length
            length = (uint256(uint8(cborData[offset])) << 8) | uint256(uint8(cborData[offset + 1]));
            offset += 2;
        } else {
            revert("Invalid CBOR byte string marker");
        }

        // Extract the actual data
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = cborData[offset + i];
        }

        return result;
    }

    /// @notice Internal function to execute transfer with encrypted calldata.
    function _executeTransfer(address from, address to, uint256 amount) internal returns (bool) {
        require(_isWhitelisted(from), ERC7943CannotTransact(from));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));

        uint256 fromBalance = super.balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        uint256 unfrozenFromBalance = _unfrozenBalance(from);
        require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));

        _updateBalanceWithoutEvent(from, to, amount);

        bytes memory plaintext = abi.encode(
            from,
            to,
            amount,
            "transfer",
            block.timestamp,
            _eventNonce
        );
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this))
        );
        emit EncryptedTransfer(encrypted);

        Sapphire.padGas(200000);
        return true;
    }

    /// @notice Internal function to execute transferFrom with encrypted calldata.
    function _executeTransferFrom(address from, address to, uint256 amount) internal returns (bool) {
        require(_isWhitelisted(from), ERC7943CannotTransact(from));
        require(_isWhitelisted(to), ERC7943CannotTransact(to));

        uint256 fromBalance = super.balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        uint256 unfrozenFromBalance = _unfrozenBalance(from);
        require(amount <= unfrozenFromBalance, ERC7943InsufficientUnfrozenBalance(from, amount, unfrozenFromBalance));

        address spender = _msgSender();
        uint256 currentAllowance = super.allowance(from, spender);
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

        _updateBalanceWithoutEvent(from, to, amount);

        bytes memory plaintext = abi.encode(
            from,
            to,
            amount,
            "transferFrom",
            block.timestamp,
            _eventNonce
        );
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this))
        );
        emit EncryptedTransfer(encrypted);

        Sapphire.padGas(200000);
        return true;
    }

    /// @notice Internal function to execute approve with encrypted calldata.
    function _executeApprove(address owner, address spender, uint256 amount) internal returns (bool) {
        require(_isWhitelisted(owner), ERC7943CannotTransact(owner));
        require(_isWhitelisted(spender), ERC7943CannotTransact(spender));

        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, spender)
            mstore(0x0c, or(shl(96, owner), _ALLOWANCE_SLOT_SEED))
            sstore(keccak256(0x0c, 0x34), amount)
        }

        bytes memory plaintext = abi.encode(
            owner,
            spender,
            amount,
            "approve",
            block.timestamp,
            _eventNonce
        );
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this))
        );
        emit EncryptedApproval(encrypted);

        return true;
    }

    /// @notice Internal function to execute permit with encrypted calldata.
    function _executePermit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        require(_isWhitelisted(owner), ERC7943CannotTransact(owner));
        require(_isWhitelisted(spender), ERC7943CannotTransact(spender));

        super.permit(owner, spender, value, deadline, v, r, s);

        bytes memory plaintext = abi.encode(
            owner,
            spender,
            value,
            "permit",
            block.timestamp,
            _eventNonce
        );
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this))
        );
        emit EncryptedApproval(encrypted);
    }

    // /// @notice Internal function to execute mint with encrypted calldata.
    // function _executeMint(address to, uint256 amount) internal {
    //     require(hasRole(MINTER_ROLE, _msgSender()), "AccessControl: account missing role");
    //     _mint(to, amount);
    // }

    // /// @notice Internal function to execute burn with encrypted calldata.
    // function _executeBurn(address from, uint256 amount) internal {
    //     require(hasRole(BURNER_ROLE, _msgSender()), "AccessControl: account missing role");
    //     _burn(from, amount);
    // }

    /// @notice Internal function to execute changeWhitelist with encrypted calldata.
    function _executeChangeWhitelist(address account, bool status) internal {
        require(hasRole(WHITELIST_ROLE, _msgSender()), "AccessControl: account missing role");
        _whitelist[account] = status;

        bytes memory plaintext = abi.encode(account, status, _eventNonce);
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this))
        );
        emit EncryptedWhitelisted(encrypted);
    }

    /// @notice Internal function to execute setFrozenTokens with encrypted calldata.
    function _executeSetFrozenTokens(address account, uint256 amount) internal returns(bool result) {
        require(hasRole(FREEZING_ROLE, _msgSender()), "AccessControl: account missing role");
        _frozenTokens[account] = amount;

        bytes memory plaintext = abi.encode(account, amount, _eventNonce);
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this))
        );
        emit EncryptedFrozen(encrypted);

        result = true;
    }

    /// @notice Internal function to execute forcedTransfer with encrypted calldata.
    function _executeForcedTransfer(address from, address to, uint256 amount) internal returns(bool result) {
        require(hasRole(FORCE_TRANSFER_ROLE, _msgSender()), "AccessControl: account missing role");
        require(from != address(0) && to != address(0), NotZeroAddress());
        require(_isWhitelisted(to), ERC7943CannotTransact(to));
        uint256 fromBalance = super.balanceOf(from);
        require(fromBalance >= amount, InsufficientBalance());
        _excessFrozenUpdate(from, amount);

        _updateBalanceWithoutEvent(from, to, amount);

        bytes memory plaintext = abi.encode(
            from,
            to,
            amount,
            "forcedTransfer",
            block.timestamp,
            _eventNonce
        );
        bytes32 nonce = bytes32(_eventNonce++);
        bytes memory encrypted = Sapphire.encrypt(
            _encryptionKey,
            nonce,
            plaintext,
            abi.encode(address(this))
        );
        emit EncryptedForcedTransfer(encrypted);

        Sapphire.padGas(200000);
        result = true;
    }
}

