# Hackathon Demo

This demo showcases the ERC-7943 encrypted calldata functionality integrated with Oasis Sapphire confidential EVM.

## What This Demo Shows

The demo demonstrates how sensitive token operations can be performed with encrypted calldata using the ERC-7943 standard on Sapphire testnet:

1. Encrypted whitelisting of addresses
2. Encrypted token minting
3. Encrypted token transfers
4. Encrypted approvals
5. Encrypted transferFrom operations

All transaction parameters (addresses, amounts) are encrypted end-to-end, providing confidentiality for sensitive RWA operations.

## Running the Demo

```bash
# From project root
pnpm tsx demo/demo.ts
```

## What Happens

The demo uses 4 wallets configured in `.env`:
- Admin wallet: Manages whitelist and minting
- User 1: Receives minted tokens
- User 2: Receives transfer from User 1
- User 3: Receives tokens via transferFrom

Each operation demonstrates encrypted calldata in action, showing balances and transaction confirmations.

## Architecture

- Uses deployed contracts on Sapphire testnet
- Leverages Sapphire's confidential compute for encryption
- Implements ERC-7943 encrypted calldata pattern
- All sensitive parameters encrypted before execution
