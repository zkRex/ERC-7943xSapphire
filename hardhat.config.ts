import type { HardhatUserConfig } from "hardhat/config";
import "@oasisprotocol/sapphire-hardhat";
import "@nomicfoundation/hardhat-toolbox-viem";
import "./tasks";
import * as dotenv from "dotenv";

dotenv.config();

// Accounts for mainnet/testnet (from environment variable)
const accounts = process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [];

// Mnemonic for localnet (standard Hardhat test mnemonic)
// This matches the mnemonic used by sapphire-localnet
const localnetMnemonic = "test test test test test test test test test test test junk";

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
      accounts: {
        mnemonic: localnetMnemonic,
      },
    },
  },
};

export default config;
