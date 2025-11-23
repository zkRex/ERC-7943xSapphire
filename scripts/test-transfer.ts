import hre from "hardhat";
import { createWalletClient, createPublicClient, http, parseEther, formatEther, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import * as dotenv from "dotenv";
import * as path from "path";

// Load environment variables from root .env
dotenv.config();
// Also try to load from scripts/.env if it exists
dotenv.config({ path: path.join(__dirname, ".env") });

async function main() {
  // Get network from environment or default to sapphire-testnet
  const networkName = process.env.NETWORK || "sapphire-testnet";
  const network = hre.config.networks[networkName] as any;
  
  if (!network) {
    throw new Error(`Network ${networkName} not found in hardhat.config.ts. Available networks: ${Object.keys(hre.config.networks).join(", ")}`);
  }

  const networkUrl = network.url as string;
  const networkChainId = network.chainId as number;

  // Create chain definition for viem
  const chain = defineChain({
    id: networkChainId,
    name: networkName,
    nativeCurrency: {
      decimals: 18,
      name: networkName.includes("testnet") || networkName.includes("localnet") ? "TEST" : "ROSE",
      symbol: networkName.includes("testnet") || networkName.includes("localnet") ? "TEST" : "ROSE",
    },
    rpcUrls: {
      default: {
        http: [networkUrl],
      },
    },
  });

  // Get token address from environment
  const tokenAddress = process.env.TOKEN_ADDRESS as `0x${string}`;
  if (!tokenAddress) {
    throw new Error("TOKEN_ADDRESS environment variable is required");
  }

  // Get the address that should be able to transact
  const senderAddress = process.env.TARGET_ADDRESS as `0x${string}`;
  if (!senderAddress) {
    throw new Error("TARGET_ADDRESS environment variable is required (this is the address that should transact)");
  }

  // Get recipient address (default to deployer for testing)
  const recipientAddress = process.env.RECIPIENT_ADDRESS as `0x${string}`;
  if (!recipientAddress) {
    // Use deployer as recipient for testing
    const privateKey = process.env.PRIVATE_KEY;
    if (!privateKey) {
      throw new Error("Either RECIPIENT_ADDRESS or PRIVATE_KEY environment variable is required");
    }
    const deployerAccount = privateKeyToAccount(privateKey as `0x${string}`);
    const deployerAddress = deployerAccount.address;
    console.log(`No RECIPIENT_ADDRESS provided, using deployer address: ${deployerAddress}`);
  }

  // Use PRIVATE_KEY for the sender (the address that should transact)
  // Note: This assumes TARGET_ADDRESS corresponds to a private key in env
  // For testing, we'll use a different approach - we need the private key for the sender
  const senderPrivateKey = process.env.SENDER_PRIVATE_KEY || process.env.PRIVATE_KEY;
  if (!senderPrivateKey) {
    throw new Error("SENDER_PRIVATE_KEY or PRIVATE_KEY environment variable is required for the sender account");
  }

  const senderAccount = privateKeyToAccount(senderPrivateKey as `0x${string}`);
  
  // Verify the sender account matches TARGET_ADDRESS
  if (senderAccount.address.toLowerCase() !== senderAddress.toLowerCase()) {
    console.log(`⚠️  Warning: Sender account address (${senderAccount.address}) does not match TARGET_ADDRESS (${senderAddress})`);
    console.log(`   Using sender account: ${senderAccount.address}`);
  }

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Token contract: ${tokenAddress}`);
  console.log(`Sender address: ${senderAccount.address}`);
  console.log(`Recipient address: ${recipientAddress || "deployer"}\n`);

  // Create clients
  const publicClient = createPublicClient({
    chain,
    transport: http(),
  });

  const senderWalletClient = createWalletClient({
    account: senderAccount,
    chain,
    transport: http(),
  });

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");

  // Check sender balance
  try {
    const balance = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "balanceOf",
      args: [senderAccount.address, "0x"],
    });
    console.log(`Sender token balance: ${formatEther(balance as bigint)} tokens`);
  } catch (error: any) {
    console.log(`Could not read sender balance (may require SIWE): ${error.message}`);
  }

  // Ensure recipient is whitelisted (use deployer account for this)
  const deployerPrivateKey = process.env.PRIVATE_KEY;
  if (!deployerPrivateKey) {
    throw new Error("PRIVATE_KEY environment variable is required for whitelisting recipient");
  }
  const deployerAccount = privateKeyToAccount(deployerPrivateKey as `0x${string}`);
  const deployerWalletClient = createWalletClient({
    account: deployerAccount,
    chain,
    transport: http(),
  });

  const finalRecipientAddress = recipientAddress || deployerAccount.address;

  // Whitelist recipient if needed (using deployer account)
  console.log(`Ensuring recipient ${finalRecipientAddress} is whitelisted...`);
  try {
    const whitelistTxHash = await deployerWalletClient.writeContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "changeWhitelist",
      args: [finalRecipientAddress, true],
    });
    console.log(`Whitelist transaction hash: ${whitelistTxHash}`);
    const whitelistReceipt = await publicClient.waitForTransactionReceipt({ hash: whitelistTxHash });
    console.log(`Recipient whitelisted in block ${whitelistReceipt.blockNumber}`);
  } catch (error: any) {
    console.log(`Note: Could not whitelist recipient (may already be whitelisted): ${error.message}`);
  }

  // Try to perform a transfer
  const transferAmount = parseEther("1"); // Transfer 1 token for testing
  console.log(`\nAttempting to transfer ${formatEther(transferAmount)} tokens from ${senderAccount.address} to ${finalRecipientAddress}...`);
  
  try {
    const transferTxHash = await senderWalletClient.writeContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "transfer",
      args: [finalRecipientAddress, transferAmount],
    });
    console.log(`Transfer transaction hash: ${transferTxHash}`);
    const transferReceipt = await publicClient.waitForTransactionReceipt({ hash: transferTxHash });
    console.log(`✓ Transfer successful! Confirmed in block ${transferReceipt.blockNumber}`);
  } catch (error: any) {
    console.error(`✗ Transfer failed: ${error.message}`);
    throw error;
  }

  console.log("\nDone! The address can successfully transact.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


