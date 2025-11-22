# ERC-7943 on Sapphire

This project implements ERC-7943 (uRWA - Universal Real-World Asset) standards on the Oasis Sapphire network, providing confidential token implementations for ERC-20, ERC-721, and ERC-1155 with whitelisting, freezing, and forced transfer capabilities.

## Overview

This repository contains Solidity contracts implementing ERC-7943 standards on Sapphire's confidential computing environment. The implementation includes:

- **uRWA20**: ERC-7943 compliant ERC-20 token with whitelist and freeze functionality
- **uRWA721**: ERC-7943 compliant ERC-721 token with whitelist and freeze functionality
- **uRWA1155**: ERC-7943 compliant ERC-1155 token with whitelist and freeze functionality

All contracts are designed to work with Sapphire's privacy features, including encrypted calldata and state, while maintaining compatibility with the ERC-7943 standard.

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
npx hardhat test
REPORT_GAS=true npx hardhat test
```

## Privacy Considerations

On Sapphire:
- **Events/logs are plaintext**: Avoid emitting sensitive data (KYC status, identities, exact freeze amounts) unless intentionally encrypted or redacted
- **Calldata and state are encrypted**: However, access patterns and gas usage can still leak information
- **Best practices**: Use constant-size storage layouts, predictable access patterns, and consider `Sapphire.padGas` for branches that depend on private data

## Development

### Prerequisites

- A local Sapphire node running
- Node.js and pnpm installed

### Common Tasks

```shell
# Run tests
npx hardhat test

# Run tests with gas reporting
REPORT_GAS=true npx hardhat test

# Deploy contracts
npx hardhat ignition deploy ./ignition/modules/Lock.ts

# Get help
npx hardhat help
```

## Reference Documentation

- [EIP-7943 Specification](https://eips.ethereum.org/EIPS/eip-7943)
- [Oasis Sapphire Documentation](https://docs.oasis.io/dapp/sapphire/)
