import hre from "hardhat";
import { createWalletClient, createPublicClient, http, parseEther, formatEther, defineChain } from "viem";
import { privateKeyToAccount, generatePrivateKey } from "viem/accounts";
import * as dotenv from "dotenv";

// Load environment variables
dotenv.config();

async function main() {
  // Use testnet
  const networkName = "sapphire-testnet";
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
      name: "TEST",
      symbol: "TEST",
    },
    rpcUrls: {
      default: {
        http: [networkUrl],
      },
    },
  });

  // Get deployer private key from environment
  const deployerPrivateKey = process.env.PRIVATE_KEY;
  if (!deployerPrivateKey) {
    throw new Error("PRIVATE_KEY environment variable is required");
  }

  // Generate a new private key
  const newPrivateKey = generatePrivateKey();
  const newAccount = privateKeyToAccount(newPrivateKey);
  const newAddress = newAccount.address;

  console.log("\n=== Generated New Account ===");
  console.log(`Private Key: ${newPrivateKey}`);
  console.log(`Address: ${newAddress}`);

  // Get amount from environment or default to 1 ETH
  const ethAmountStr = process.env.ETH_AMOUNT || "1";
  const ethAmount = parseEther(ethAmountStr);

  // Create deployer account
  const deployerAccount = privateKeyToAccount(deployerPrivateKey as `0x${string}`);

  console.log(`\n=== Funding Information ===`);
  console.log(`Using network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Deployer address: ${deployerAccount.address}`);
  console.log(`Amount to send: ${formatEther(ethAmount)} ETH`);

  // Create clients
  const publicClient = createPublicClient({
    chain,
    transport: http(),
  });

  const walletClient = createWalletClient({
    account: deployerAccount,
    chain,
    transport: http(),
  });

  // Check deployer balance
  const deployerBalance = await publicClient.getBalance({ address: deployerAccount.address });
  console.log(`\nDeployer balance: ${formatEther(deployerBalance)} ETH`);

  const totalNeeded = ethAmount + parseEther("0.01"); // Transfer + gas
  if (deployerBalance < totalNeeded) {
    throw new Error(`Insufficient balance. Need ${formatEther(totalNeeded)} ETH, have ${formatEther(deployerBalance)} ETH`);
  }

  // Send ETH to new address
  console.log(`\n=== Sending ${formatEther(ethAmount)} ETH to ${newAddress} ===`);
  try {
    const txHash = await walletClient.sendTransaction({
      to: newAddress,
      value: ethAmount,
    });
    console.log(`Transaction hash: ${txHash}`);
    
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
    console.log(`Transaction confirmed in block ${receipt.blockNumber}`);
    
    const newBalance = await publicClient.getBalance({ address: newAddress });
    console.log(`New account balance: ${formatEther(newBalance)} ETH`);
  } catch (error: any) {
    console.error(`Error sending ETH: ${error.message}`);
    throw error;
  }

  console.log("\n=== Summary ===");
  console.log(`New Private Key: ${newPrivateKey}`);
  console.log(`New Address: ${newAddress}`);
  console.log(`Amount sent: ${formatEther(ethAmount)} ETH`);
  console.log("\nDone! Save the private key securely.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

