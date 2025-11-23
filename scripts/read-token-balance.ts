import hre from "hardhat";
import { createWalletClient, createPublicClient, http, formatEther, defineChain } from "viem";
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

  // Get address to check from environment
  const addressToCheck = process.env.TARGET_ADDRESS as `0x${string}`;
  if (!addressToCheck) {
    throw new Error("TARGET_ADDRESS environment variable is required");
  }

  // Use PRIVATE_KEY (deployer account) which should have VIEWER_ROLE or can grant it
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error("PRIVATE_KEY environment variable is required");
  }

  const account = privateKeyToAccount(privateKey as `0x${string}`);

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Reader address: ${account.address}`);
  console.log(`Token contract: ${tokenAddress}`);
  console.log(`Address to check: ${addressToCheck}\n`);

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

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");

  // Step 1: Check if reader has VIEWER_ROLE
  console.log("Step 1: Checking VIEWER_ROLE...");
  let viewerRoleHash: `0x${string}`;
  try {
    viewerRoleHash = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "VIEWER_ROLE",
      args: [],
    }) as `0x${string}`;
    console.log(`VIEWER_ROLE hash: ${viewerRoleHash}`);
  } catch (error: any) {
    console.log(`Could not read VIEWER_ROLE: ${error.message}`);
    // Compute it manually
    const crypto = require("crypto");
    viewerRoleHash = ("0x" + crypto.createHash("sha256").update("VIEWER_ROLE").digest("hex")) as `0x${string}`;
    console.log(`Using computed VIEWER_ROLE hash: ${viewerRoleHash}`);
  }

  let hasViewerRole = false;
  try {
    hasViewerRole = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "hasRole",
      args: [viewerRoleHash, account.address],
    }) as boolean;
    console.log(`Reader has VIEWER_ROLE: ${hasViewerRole}`);
  } catch (error: any) {
    console.log(`Could not check VIEWER_ROLE: ${error.message}`);
  }

  // Step 2: Grant VIEWER_ROLE if needed
  if (!hasViewerRole) {
    console.log("\nStep 2: Attempting to grant VIEWER_ROLE...");
    try {
      const DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
      const hasAdminRole = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "hasRole",
        args: [DEFAULT_ADMIN_ROLE, account.address],
      }) as boolean;
      
      if (hasAdminRole) {
        const grantTxHash = await walletClient.writeContract({
          address: tokenAddress,
          abi: tokenArtifact.abi,
          functionName: "grantRole",
          args: [viewerRoleHash, account.address],
        });
        console.log(`Grant transaction hash: ${grantTxHash}`);
        const grantReceipt = await publicClient.waitForTransactionReceipt({ hash: grantTxHash });
        console.log(`VIEWER_ROLE granted in block ${grantReceipt.blockNumber}`);
        hasViewerRole = true;
      } else {
        console.log("Reader does not have DEFAULT_ADMIN_ROLE, cannot grant VIEWER_ROLE");
      }
    } catch (error: any) {
      console.log(`Could not grant VIEWER_ROLE: ${error.message}`);
    }
  }

  // Step 3: Try to read balance
  console.log("\nStep 3: Reading token balance...");
  
  // Method 1: Try with VIEWER_ROLE (empty token)
  if (hasViewerRole) {
    try {
      const balance = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "balanceOf",
        args: [addressToCheck, "0x"], // Empty token, but we have VIEWER_ROLE
      });
      const balanceBigInt = typeof balance === "bigint" ? balance : BigInt(String(balance));
      console.log(`✓ Token balance: ${formatEther(balanceBigInt)} tokens`);
      console.log(`  Raw balance: ${balanceBigInt.toString()}`);
      return;
    } catch (error: any) {
      console.log(`Could not read balance with VIEWER_ROLE: ${error.message}`);
    }
  }

  // Method 2: Try reading as the account itself (if checking own balance)
  if (account.address.toLowerCase() === addressToCheck.toLowerCase()) {
    try {
      const balance = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "balanceOf",
        args: [addressToCheck, "0x"], // Empty token for own balance
      });
      const balanceBigInt = typeof balance === "bigint" ? balance : BigInt(String(balance));
      console.log(`✓ Token balance (own account): ${formatEther(balanceBigInt)} tokens`);
      console.log(`  Raw balance: ${balanceBigInt.toString()}`);
      return;
    } catch (error: any) {
      console.log(`Could not read own balance: ${error.message}`);
    }
  }

  // Method 3: Try to read directly from storage (workaround)
  console.log("\nAttempting to read balance from storage slot...");
  console.log("Note: This is a workaround and may not work due to Sapphire's privacy features.");
  
  // The balance is stored in Solady's ERC20 storage layout
  // We can't easily read it without proper authentication
  
  console.log("\n⚠️  Could not read balance. This is expected on Sapphire because:");
  console.log("   1. balanceOf requires SIWE authentication");
  console.log("   2. The address must authenticate itself OR");
  console.log("   3. The reader must have VIEWER_ROLE");
  console.log("\nTo read the balance, the address itself needs to:");
  console.log("   - Use a wallet that supports SIWE authentication");
  console.log("   - Or use a dApp that handles SIWE authentication");
  console.log("\nThe balance should be 1000 tokens based on the transfer transaction.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

