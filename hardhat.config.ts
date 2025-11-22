import type { HardhatUserConfig } from "hardhat/config";
import "@oasisprotocol/sapphire-hardhat";
import "@nomicfoundation/hardhat-toolbox-viem";
import "./tasks";
import * as dotenv from "dotenv";

dotenv.config();

// Accounts for mainnet/testnet (from environment variable)
const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

// Test accounts for localnet (standard Hardhat test mnemonic)
// These match the accounts provided by sapphire-localnet
const localnetAccounts = [
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // Account 0
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", // Account 1
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", // Account 2
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", // Account 3
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a", // Account 4
];

const config: HardhatUserConfig = {
  solidity: "0.8.28",
  networks: {
    sapphire: {
      url: "https://sapphire.oasis.io",
      chainId: 0x5afe,
      accounts,
    },
    "sapphire-testnet": {
      url: "https://testnet.sapphire.oasis.io",
      accounts,
      chainId: 0x5aff,
    },
    "sapphire-localnet": {
      // docker run -it -p8544-8548:8544-8548 ghcr.io/oasisprotocol/sapphire-localnet
      url: "http://localhost:8545",
      chainId: 0x5afd,
      accounts: localnetAccounts,
    },
  },
};

export default config;
