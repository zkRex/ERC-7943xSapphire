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
```

**Note**: The `.env` file is gitignored. Never commit private keys to version control.

### Localnet Setup

To run tests locally, start a Sapphire localnet node:

```shell
docker run -it -p8544-8548:8544-8548 ghcr.io/oasisprotocol/sapphire-localnet
```

The localnet uses the standard Hardhat test mnemonic and runs on `http://localhost:8545` by default.

**Note for Apple Silicon users**: If you encounter difficulties running the Docker image on Apple Silicon (M1/M2/M3), it's recommended to run the localnet on a remote server and use SSH port forwarding:

```shell
# On your local machine, forward ports to the remote server
ssh -L 8545:localhost:8545 -L 8546:localhost:8546 -L 8547:localhost:8547 -L 8548:localhost:8548 user@remote-server

# On the remote server, run the Docker container
docker run -it -p8544-8548:8544-8548 ghcr.io/oasisprotocol/sapphire-localnet
```

Then configure your `LOCALNET_URL` environment variable or use the default `http://localhost:8545` which will be forwarded to the remote server.

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

### Common Tasks

```shell
# Run tests
pnpm test

# Run tests with gas reporting
REPORT_GAS=true pnpm test

# Deploy contracts (localnet)
pnpm deploy:localnet

# Deploy contracts (testnet)
pnpm deploy:testnet

# Deploy contracts (mainnet)
pnpm deploy:mainnet

# Compile contracts
pnpm compile

# Get help
pnpm hardhat help
```

## Specification

The full ERC-7943 specification is available in [`EIP-7943.md`](./EIP-7943.md) in this repository.

## Reference Documentation

- [EIP-7943 Specification](https://eips.ethereum.org/EIPS/eip-7943)
- [Local EIP-7943 Specification](./EIP-7943.md)
- [Oasis Sapphire Documentation](https://docs.oasis.io/dapp/sapphire/)
- [OpenZeppelin Contracts](https://docs.openzeppelin.com/contracts/)
