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

  // Get private key from environment
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error("PRIVATE_KEY environment variable is required");
  }

  // Get target address from environment
  const targetAddress = process.env.TARGET_ADDRESS as `0x${string}`;
  if (!targetAddress) {
    throw new Error("TARGET_ADDRESS environment variable is required");
  }

  // Get token address from environment
  const tokenAddress = process.env.TOKEN_ADDRESS as `0x${string}`;
  if (!tokenAddress) {
    throw new Error("TOKEN_ADDRESS environment variable is required");
  }

  // Get amounts from environment
  const ethAmountStr = process.env.ETH_AMOUNT || "1";
  const tokenAmountStr = process.env.TOKEN_AMOUNT || "1000";
  const ethAmount = parseEther(ethAmountStr);
  const tokenAmount = parseEther(tokenAmountStr);

  // Create account from private key
  const account = privateKeyToAccount(privateKey as `0x${string}`);

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Sender address: ${account.address}`);
  console.log(`Target address: ${targetAddress}`);
  console.log(`Token contract: ${tokenAddress}`);

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

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");
  
  // Use PRIVATE_KEY (deployer account) for whitelisting and minting
  // This account should have DEFAULT_ADMIN_ROLE and WHITELIST_ROLE
  const deployerPrivateKey = process.env.PRIVATE_KEY;
  if (!deployerPrivateKey) {
    throw new Error("PRIVATE_KEY environment variable is required for whitelisting and minting");
  }
  const adminAccount = privateKeyToAccount(deployerPrivateKey as `0x${string}`);
  const adminWalletClient = createWalletClient({
    account: adminAccount,
    chain,
    transport: http(),
  });

  // Step 1: Add target address to whitelist
  console.log(`\nStep 1: Adding ${targetAddress} to whitelist...`);
  try {
    const whitelistHash = await adminWalletClient.writeContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "changeWhitelist",
      args: [targetAddress, true],
    });
    console.log(`Whitelist transaction hash: ${whitelistHash}`);
    const whitelistReceipt = await publicClient.waitForTransactionReceipt({ hash: whitelistHash });
    console.log(`Whitelist transaction confirmed in block ${whitelistReceipt.blockNumber}`);
  } catch (error: any) {
    console.error(`Error whitelisting: ${error.message}`);
    throw error;
  }

  // Step 2: Send 1 ETH
  console.log(`\nStep 2: Sending ${formatEther(ethAmount)} ETH...`);
  try {
    const ethTxHash = await walletClient.sendTransaction({
      to: targetAddress,
      value: ethAmount,
    });
    console.log(`ETH transaction hash: ${ethTxHash}`);
    
    const ethReceipt = await publicClient.waitForTransactionReceipt({ hash: ethTxHash });
    console.log(`ETH transaction confirmed in block ${ethReceipt.blockNumber}`);
  } catch (error: any) {
    console.error(`Error sending ETH: ${error.message}`);
    throw error;
  }

  // Step 3: Check if sender has enough tokens, mint if needed
  let senderTokenBalance = 0n;
  try {
    const balance = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "balanceOf",
      args: [account.address],
    });
    senderTokenBalance = typeof balance === "bigint" ? balance : BigInt(String(balance));
    console.log(`\nSender token balance: ${formatEther(senderTokenBalance)} tokens`);
  } catch (error) {
    console.log(`Could not read sender token balance (may require SIWE), proceeding to mint...`);
  }

  // Whitelist sender if needed
  try {
    const whitelistSenderHash = await adminWalletClient.writeContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "changeWhitelist",
      args: [account.address, true],
    });
    await publicClient.waitForTransactionReceipt({ hash: whitelistSenderHash });
    console.log(`Sender whitelisted`);
  } catch (error: any) {
    console.log(`Note: Could not whitelist sender (may already be whitelisted): ${error.message}`);
  }

  // Mint tokens to sender if they don't have enough
  if (senderTokenBalance < tokenAmount) {
    const mintExtraStr = process.env.MINT_EXTRA || "10";
    const mintAmount = tokenAmount + parseEther(mintExtraStr); // Mint extra for gas
    console.log(`\nMinting ${formatEther(mintAmount)} tokens to sender...`);
    try {
      const mintTxHash = await adminWalletClient.writeContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "mint",
        args: [account.address, mintAmount],
      });
      console.log(`Mint transaction hash: ${mintTxHash}`);
      const mintReceipt = await publicClient.waitForTransactionReceipt({ hash: mintTxHash });
      console.log(`Mint transaction confirmed in block ${mintReceipt.blockNumber}`);
    } catch (error: any) {
      console.error(`Error minting tokens: ${error.message}`);
      throw error;
    }
  }
  
  // Step 4: Send tokens
  console.log(`\nStep 3: Sending ${formatEther(tokenAmount)} tokens...`);
  try {
    const tokenTxHash = await walletClient.writeContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "transfer",
      args: [targetAddress, tokenAmount],
    });
    console.log(`Token transaction hash: ${tokenTxHash}`);
    
    const tokenReceipt = await publicClient.waitForTransactionReceipt({ hash: tokenTxHash });
    console.log(`Token transaction confirmed in block ${tokenReceipt.blockNumber}`);
  } catch (error: any) {
    console.error(`Error sending tokens: ${error.message}`);
    throw error;
  }

  // Verify balances
  console.log(`\nVerifying balances...`);
  const targetEthBalance = await publicClient.getBalance({ address: targetAddress });
  console.log(`Target ETH balance: ${formatEther(targetEthBalance)} ETH`);

  // Try to read token balance (may require SIWE on Sapphire, so we'll catch errors)
  try {
    const targetTokenBalance = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "balanceOf",
      args: [targetAddress],
    });
    const balance = typeof targetTokenBalance === "bigint" ? targetTokenBalance : BigInt(String(targetTokenBalance));
    console.log(`Target token balance: ${formatEther(balance)} tokens`);
  } catch (error) {
    console.log(`Note: Could not read token balance (may require SIWE authentication)`);
  }

  console.log("\nDone!");
  console.log(`\nSummary:`);
  console.log(`  - Added ${targetAddress} to whitelist`);
  console.log(`  - Sent ${formatEther(ethAmount)} ETH to ${targetAddress}`);
  console.log(`  - Sent ${formatEther(tokenAmount)} tokens to ${targetAddress}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

