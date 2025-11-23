# ERC-7943 on Sapphire

This project implements ERC-7943 (uRWA - Universal Real-World Asset) standards on the Oasis Sapphire network, providing confidential token implementations for ERC-20, ERC-721, and ERC-1155 with whitelisting, freezing, and forced transfer capabilities.

## Overview

This repository contains Solidity contracts implementing ERC-7943 standards on Sapphire's confidential computing environment. The implementation includes:

- **uRWA20**: ERC-7943 compliant ERC-20 token with whitelist and freeze functionality
- **uRWA721**: ERC-7943 compliant ERC-721 token with whitelist and freeze functionality
- **uRWA1155**: ERC-7943 compliant ERC-1155 token with whitelist and freeze functionality

All contracts are designed to work with Sapphire's privacy features, including encrypted calldata and state, while maintaining compatibility with the ERC-7943 standard.

**Technical Details:**
- Solidity version: `^0.8.28`
- Built with Hardhat and OpenZeppelin Contracts v5.4.0
- Uses TypeScript for tests and deployment scripts

## Encryption & Confidential Computing Features

This implementation includes comprehensive encryption features leveraging Sapphire's confidential computing capabilities:

### Encrypted Events

All sensitive on-chain events are encrypted to protect transaction privacy:

- **EncryptedTransfer**: Encrypted transfer events containing sender, receiver, amount, action type, timestamp, and nonce
- **EncryptedWhitelisted**: Encrypted whitelist status changes
- **EncryptedFrozen**: Encrypted token freezing/unfreezing events
- **EncryptedForcedTransfer**: Encrypted forced transfer events
- **EncryptedApproval**: Encrypted approval events (uRWA20 only)

Standard Transfer events are eliminated to prevent information leakage. All sensitive data is encrypted using Sapphire's `encrypt()` function with contract-specific encryption keys.

### Event Decryption Mechanism

Authorized parties can decrypt events using the `processDecryption()` function:

- **Authorization**: Decryption is restricted to:
  - Transaction sender and receiver
  - Accounts with `VIEWER_ROLE`
  - Authorized auditors (see Auditor Permissions below)
- **Data Storage**: Decrypted data is temporarily stored and can be retrieved via `viewLastDecryptedData()`
- **Enhanced Format**: Encrypted events include:
  - Action type ("transfer", "mint", "burn", "forcedTransfer")
  - Block timestamp
  - Unique nonce for replay attack prevention
  - Contract address binding for additional security

### Auditor Permission System (uRWA20)

Comprehensive auditor permission system for compliance and regulatory requirements:

- **Time-Limited Access**: Auditor permissions can be granted for durations from 1 hour to 30 days
- **Full Access Mode**: Auditors can be granted full access to decrypt all transactions
- **Address-Specific Access**: Auditors can be restricted to decrypt transactions involving specific addresses
- **Main Auditor Role**: `MAIN_AUDITOR_ROLE` provides unrestricted audit access
- **Revocable Permissions**: Permissions can be revoked at any time by the main auditor

This enables compliance with regulatory audit requirements (SEC, FinCEN, etc.), controlled data disclosure for court orders, and temporary access for external auditors.

### View Function Access Control

All view functions that access private contract state require authorization:

- **VIEWER_ROLE**: Required for viewing balances, frozen amounts, whitelist status, and other sensitive data
- **Self-Read Permissions**: Users can read their own data without `VIEWER_ROLE`
- **SIWE Authentication**: View functions support SIWE (Sign-In With Ethereum) authentication for secure access

### Encryption Implementation Details

- **Encryption Key**: Contract-specific encryption key generated during deployment
- **Nonce Counter**: Incrementing nonce ensures uniqueness of encrypted events
- **Contract Binding**: Additional data parameter binds encryption to contract address, preventing replay attacks
- **Gas Padding**: Uses `Sapphire.padGas()` to prevent gas-based side-channel attacks

For comprehensive analysis of encryption features, privacy considerations, and implementation details, see [`SAPPHIRE_ENCRYPTION.md`](./SAPPHIRE_ENCRYPTION.md).

## Testing

Tests are run against a local Sapphire node (Hardhat network `sapphire-localnet`). The test suite validates:

- Whitelist functionality (`canTransact`)
- Token freezing (`setFrozenTokens`)
- Forced transfers
- Role-based access control
- Interface support (`supportsInterface`)
- Mint/burn operations
- **Encryption and decryption** (encrypted events, sender/receiver decryption, unauthorized access prevention)
- **Auditor permissions** (time-limited access, full access, address-specific access, permission revocation)
- **View function access control** (VIEWER_ROLE requirements, self-read permissions)

Run tests with:

```shell
pnpm test
REPORT_GAS=true pnpm test
```

For detailed test results and failure analysis, see [`TESTS.md`](./TESTS.md).

## Privacy Considerations

This implementation addresses privacy concerns through comprehensive encryption:

- **Encrypted Events**: All sensitive events (transfers, whitelist changes, freezes, forced transfers) are encrypted using Sapphire's encryption functions. Standard Transfer events are eliminated to prevent information leakage.
- **Encrypted Calldata and State**: Leverages Sapphire's built-in encryption for calldata and contract state
- **Access Control**: View functions require `VIEWER_ROLE` or self-read permissions, preventing unauthorized access to private data
- **Gas Padding**: Uses `Sapphire.padGas()` to prevent gas-based side-channel attacks
- **Contract Binding**: Encryption includes contract address as additional data to prevent replay attacks

**Note**: While events are encrypted, access patterns and gas usage can still leak information. Best practices include using constant-size storage layouts, predictable access patterns, and gas padding for branches that depend on private data.

For comprehensive analysis of encryption features, privacy gaps, and implementation status, see [`SAPPHIRE_ENCRYPTION.md`](./SAPPHIRE_ENCRYPTION.md).

## Development

### Prerequisites

- Node.js and pnpm installed
- A local Sapphire node running (for local testing)

### Installation

```shell
# Install dependencies
pnpm install
```

### Environment Setup

For deploying to testnet or mainnet, create a `.env` file in the project root:

```shell
# Private key for deployment (required for testnet/mainnet)
PRIVATE_KEY=your_private_key_here

# Optional: Override localnet URL (defaults to http://localhost:8545)
LOCALNET_URL=http://localhost:8545

# uRWA20 Deployment Parameters
TOKEN_NAME=Real World Asset Token
TOKEN_SYMBOL=RWA
INITIAL_ADMIN=                    # Leave empty to use deployer's address
SIWE_DOMAIN=localhost             # For testnet/mainnet, use your actual domain
```

**Note**: The `.env` file is gitignored. Never commit private keys to version control.

### Localnet Setup

To run tests locally, start a Sapphire localnet node:

```shell
docker run -it --rm -p8544-8548:8544-8548 --platform linux/x86_64 ghcr.io/oasisprotocol/sapphire-localnet
```

The localnet uses the standard Hardhat test mnemonic and runs on `http://localhost:8545` by default.

**macOS Startup Issue on Apple Silicon**

On Apple Silicon Macs running macOS 26 (Tahoe) or later, the sapphire-localnet Docker image may hang on startup with peer authentication errors (e.g., chacha20poly1305: message authentication failed).

This is due to a bug in Rosetta 2's x86_64 emulation. The workaround is to disable Rosetta in Docker Desktop settings, which makes Docker use QEMU instead.

Go to Settings > Virtual Machine Options and disable "Use Rosetta for x86/amd64 emulation on Apple Silicon".

### Network Configuration

The project is configured for three networks:

- **sapphire-localnet** (chainId: 0x5afd / 23293): Local development network
- **sapphire-testnet** (chainId: 0x5aff): Oasis Sapphire testnet
- **sapphire** (chainId: 0x5afe): Oasis Sapphire mainnet

Network URLs and chain IDs are configured in `hardhat.config.ts`.

### Deployments

**Testnet Deployment:**

The contracts are currently deployed on the Oasis Sapphire testnet:

- **Contract Address**: [`0x5c5FC7995b0Ca3471dea4e5E1b8E1562f2adF4d3`](https://explorer.oasis.io/testnet/sapphire/address/0x5c5FC7995b0Ca3471dea4e5E1b8E1562f2adF4d3)

View the deployment on the [Oasis Sapphire Testnet Explorer](https://explorer.oasis.io/testnet/sapphire/address/0x5c5FC7995b0Ca3471dea4e5E1b8E1562f2adF4d3).

### Contract Structure

```
contracts/
├── interfaces/
│   └── IERC7943.sol          # ERC-7943 interface definitions
├── uRWA20.sol                 # ERC-20 implementation with ERC-7943
├── uRWA721.sol                # ERC-721 implementation with ERC-7943
└── uRWA1155.sol               # ERC-1155 implementation with ERC-7943
```

All contracts use OpenZeppelin's `AccessControlEnumerable` for role-based access control with the following roles:
- `MINTER_ROLE`: Can mint new tokens
- `BURNER_ROLE`: Can burn tokens
- `FREEZING_ROLE`: Can freeze/unfreeze tokens
- `WHITELIST_ROLE`: Can manage whitelist
- `FORCE_TRANSFER_ROLE`: Can perform forced transfers
- `VIEWER_ROLE`: Can view private contract state (balances, frozen amounts, etc.) and decrypt events
- `MAIN_AUDITOR_ROLE`: Can grant/revoke auditor permissions (uRWA20 only)

### Common Tasks

```shell
# Run tests
pnpm test

# Run tests with gas reporting
REPORT_GAS=true pnpm test

# Deploy uRWA20 contract (localnet)
pnpm deploy:urwa20:localnet

# Deploy uRWA20 contract (testnet)
pnpm deploy:urwa20:testnet

# Deploy uRWA20 contract (mainnet)
pnpm deploy:urwa20:mainnet

# Compile contracts
pnpm compile

# Get help
pnpm hardhat help
```

### Contract Verification

After deploying contracts to testnet or mainnet, you can verify them on Sourcify. The project is configured to use Sourcify for verification (Etherscan is disabled).

**Prerequisites:**
- Contract must be deployed without encryption (encrypted deployments cannot be verified)
- `hardhat.config.ts` is already configured with Sourcify enabled

**Verification Command:**

```shell
pnpm hardhat verify --network sapphire-testnet <CONTRACT_ADDRESS> "arg1" "arg2" "arg3" "arg4"
```

**Example for uRWA20:**

```shell
pnpm hardhat verify --network sapphire-testnet 0x7442E3dE5f4210Fa2f74e358ba30F9ee6b9f2bd3 \
  "Battery Included GmbH" \
  "BAT" \
  "0xb391EB20b1975160594b74A66f8E4128Ba887c0A" \
  "localhost"
```

The constructor arguments for uRWA20 are:
1. `TOKEN_NAME` - The token name (string)
2. `TOKEN_SYMBOL` - The token symbol (string)
3. `INITIAL_ADMIN` - The initial admin address (address)
4. `SIWE_DOMAIN` - The SIWE authentication domain (string)

**Note**: Replace the contract address and arguments with your actual deployment values. The initial admin address will be your deployer's address if left empty in `.env`.

For more details, see the [Oasis verification documentation](https://docs.oasis.io/build/tools/verification).

## Specification

The full ERC-7943 specification is available in [`EIP-7943.md`](./EIP-7943.md) in this repository.

## Reference Documentation

- [EIP-7943 Specification](https://eips.ethereum.org/EIPS/eip-7943)
- [Local EIP-7943 Specification](./EIP-7943.md)
- [Oasis Sapphire Documentation](https://docs.oasis.io/dapp/sapphire/)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/)
