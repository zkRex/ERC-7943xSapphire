import hre from "hardhat";
import { createPublicClient, http, formatEther, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import * as dotenv from "dotenv";

dotenv.config();

async function main() {
  // Get private key from environment
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error("PRIVATE_KEY environment variable is required");
  }

  // Get network from command line args or default to testnet
  const networkName = process.argv[2] || "sapphire-testnet";
  const network = hre.config.networks[networkName] as any;
  
  if (!network) {
    throw new Error(`Network ${networkName} not found in hardhat.config.ts`);
  }

  const networkUrl = network.url as string;
  const networkChainId = network.chainId as number;

  // Create chain definition for viem
  const chain = defineChain({
    id: networkChainId,
    name: networkName,
    nativeCurrency: {
      decimals: 18,
      name: "ROSE",
      symbol: "ROSE",
    },
    rpcUrls: {
      default: {
        http: [networkUrl],
      },
    },
  });

  // Create account from private key
  const account = privateKeyToAccount(privateKey as `0x${string}`);

  // Create public client
  const publicClient = createPublicClient({
    chain,
    transport: http(),
  });

  console.log(`\nChecking balance on ${networkName}...`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Deployer address: ${account.address}\n`);

  // Check balance
  const balance = await publicClient.getBalance({ address: account.address });
  const balanceInRose = formatEther(balance);
  
  console.log(`Balance: ${balanceInRose} ROSE`);
  console.log(`Balance (wei): ${balance.toString()}\n`);

  // Estimate if balance is sufficient for deployment
  // A typical contract deployment on Sapphire might cost around 0.01-0.1 ROSE
  // We'll check if balance is at least 0.01 ROSE
  const minRequiredBalance = BigInt("10000000000000000"); // 0.01 ROSE
  const recommendedBalance = BigInt("100000000000000000"); // 0.1 ROSE
  
  if (balance < minRequiredBalance) {
    console.log("⚠️  WARNING: Balance is very low. Deployment may fail!");
    console.log(`   Minimum recommended: ${formatEther(minRequiredBalance)} ROSE`);
  } else if (balance < recommendedBalance) {
    console.log("⚠️  Balance is low but should be sufficient for deployment.");
    console.log(`   Recommended: ${formatEther(recommendedBalance)} ROSE`);
  } else {
    console.log("✓ Balance looks sufficient for deployment.");
  }

  console.log("\nTo get testnet ROSE, visit:");
  console.log("https://faucet.testnet.oasis.dev/");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

