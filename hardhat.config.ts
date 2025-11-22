import type { HardhatUserConfig } from "hardhat/config";
import "@oasisprotocol/sapphire-hardhat";
import "@nomicfoundation/hardhat-toolbox-viem";
import "./tasks";
import * as dotenv from "dotenv";
import { defineChain } from "viem";

dotenv.config();

// Accounts for mainnet/testnet (from environment variable)
const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

// Mnemonic for localnet (standard Hardhat test mnemonic)
// This matches the mnemonic used by sapphire-localnet
const localnetMnemonic = "test test test test test test test test test test test junk";

// Localnet URL - defaults to http://51.83.238.236:8545, can be overridden with LOCALNET_URL env var
const localnetUrl = process.env.LOCALNET_URL || "http://51.83.238.236:8545";

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
