import type { HardhatUserConfig } from "hardhat/config";
import "@oasisprotocol/sapphire-hardhat";
import "@nomicfoundation/hardhat-toolbox-viem";
import "./tasks";
import * as dotenv from "dotenv";
import { defineChain } from "viem";

dotenv.config();

// Accounts for mainnet/testnet (from environment variables)
const accounts = process.env.PRIVATE_KEY
  ? [
      process.env.PRIVATE_KEY,
      process.env.PRIVATE_KEY_2,
      process.env.PRIVATE_KEY_3,
      process.env.PRIVATE_KEY_4
    ].filter(Boolean) as string[]
  : [];

// Mnemonic for localnet (standard Hardhat test mnemonic)
// This matches the mnemonic used by sapphire-localnet
const localnetMnemonic = "test test test test test test test test test test test junk";

// Localnet URL - can be overridden with LOCALNET_URL env var
// Defaults to http://localhost:8545 if not set
const localnetUrl = process.env.LOCALNET_URL || "http://localhost:8545";

// Define custom chain for Sapphire localnet (chainId: 0x5afd = 23293)
const sapphireLocalnetChain = defineChain({
  id: 0x5afd,
  name: "Sapphire Localnet",
  nativeCurrency: {
    decimals: 18,
    name: "TEST",
    symbol: "TEST",
  },
  rpcUrls: {
    default: {
      http: [localnetUrl],
    },
  },
});

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1,
      },
      viaIR: true, // Enable IR-based code generation for better optimization
    },
  },
  etherscan: {
    enabled: false,
  },
  sourcify: {
    enabled: true,
  },
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
      // URL can be overridden with LOCALNET_URL environment variable
      url: localnetUrl,
      chainId: 0x5afd,
      accounts: {
        mnemonic: localnetMnemonic,
      },
    },
  },
};

// Export the custom chain for use in tasks
export { sapphireLocalnetChain };

export default config;
