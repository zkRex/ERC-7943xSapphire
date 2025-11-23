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

## Testing

Tests are run against a local Sapphire node (Hardhat network `sapphire-localnet`). The test suite validates:

- Whitelist functionality (`canTransact`)
- Token freezing (`setFrozenTokens`)
- Forced transfers
- Role-based access control
- Interface support (`supportsInterface`)
- Mint/burn operations

Run tests with:

```shell
pnpm test
REPORT_GAS=true pnpm test
```

## Privacy Considerations

On Sapphire:
- **Events/logs are plaintext**: Avoid emitting sensitive data (KYC status, identities, exact freeze amounts) unless intentionally encrypted or redacted
- **Calldata and state are encrypted**: However, access patterns and gas usage can still leak information
- **Best practices**: Use constant-size storage layouts, predictable access patterns, and consider `Sapphire.padGas` for branches that depend on private data

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
- `VIEWER_ROLE`: Can view private contract state (balances, frozen amounts, etc.)

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
