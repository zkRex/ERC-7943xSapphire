import hre from "hardhat";
import { createWalletClient, createPublicClient, http, parseEther, formatEther, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
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

  // Get private key from environment
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error("PRIVATE_KEY environment variable is required");
  }

  // Get addresses from environment (PRIVATE_KEY_1_ADDRESS and PRIVATE_KEY_2_ADDRESS)
  const address1 = process.env.PRIVATE_KEY_1_ADDRESS as `0x${string}`;
  const address2 = process.env.PRIVATE_KEY_2_ADDRESS as `0x${string}`;
  
  if (!address1 || !address2) {
    throw new Error("PRIVATE_KEY_1_ADDRESS and PRIVATE_KEY_2_ADDRESS environment variables are required");
  }

  // Get amount from environment or default to 1 ETH
  const ethAmountStr = process.env.ETH_AMOUNT || "1";
  const ethAmount = parseEther(ethAmountStr);

  // Create account from private key
  const account = privateKeyToAccount(privateKey as `0x${string}`);

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Sender address: ${account.address}`);
  console.log(`Amount per address: ${formatEther(ethAmount)} ETH`);

  // Create clients
  const publicClient = createPublicClient({
    chain,
    transport: http(),
  });

  const walletClient = createWalletClient({
    account,
    chain,
    transport: http(),
  });

  // Check sender balance
  const senderBalance = await publicClient.getBalance({ address: account.address });
  console.log(`\nSender balance: ${formatEther(senderBalance)} ETH`);

  const totalNeeded = ethAmount * 2n + parseEther("0.01"); // 2 transfers + gas
  if (senderBalance < totalNeeded) {
    throw new Error(`Insufficient balance. Need ${formatEther(totalNeeded)} ETH, have ${formatEther(senderBalance)} ETH`);
  }

  // Send to address 1
  console.log(`\nSending ${formatEther(ethAmount)} ETH to ${address1}...`);
  try {
    const txHash1 = await walletClient.sendTransaction({
      to: address1,
      value: ethAmount,
    });
    console.log(`Transaction hash: ${txHash1}`);
    
    const receipt1 = await publicClient.waitForTransactionReceipt({ hash: txHash1 });
    console.log(`Transaction confirmed in block ${receipt1.blockNumber}`);
    
    const balance1 = await publicClient.getBalance({ address: address1 });
    console.log(`New balance: ${formatEther(balance1)} ETH`);
  } catch (error: any) {
    console.error(`Error sending to address 1: ${error.message}`);
    throw error;
  }

  // Send to address 2
  console.log(`\nSending ${formatEther(ethAmount)} ETH to ${address2}...`);
  try {
    const txHash2 = await walletClient.sendTransaction({
      to: address2,
      value: ethAmount,
    });
    console.log(`Transaction hash: ${txHash2}`);
    
    const receipt2 = await publicClient.waitForTransactionReceipt({ hash: txHash2 });
    console.log(`Transaction confirmed in block ${receipt2.blockNumber}`);
    
    const balance2 = await publicClient.getBalance({ address: address2 });
    console.log(`New balance: ${formatEther(balance2)} ETH`);
  } catch (error: any) {
    console.error(`Error sending to address 2: ${error.message}`);
    throw error;
  }

  console.log("\nDone! Both addresses have been funded.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

