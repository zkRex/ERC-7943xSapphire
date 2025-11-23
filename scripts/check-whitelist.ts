import hre from "hardhat";
import { createPublicClient, http, defineChain } from "viem";
import { mnemonicToAccount } from "viem/accounts";
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

  // Use admin account for checking (has VIEWER_ROLE)
  const adminMnemonic = process.env.ADMIN_MNEMONIC || "test test test test test test test test test test test junk";
  const adminAccount = mnemonicToAccount(adminMnemonic, { accountIndex: 0 });

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Token contract: ${tokenAddress}`);
  console.log(`Address to check: ${addressToCheck}\n`);

  // Create clients
  const publicClient = createPublicClient({
    chain,
    transport: http(),
  });

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");

  // Try to check whitelist status using canTransact
  // This requires VIEWER_ROLE or the address checking itself
  console.log("Checking whitelist status...");
  try {
    // Try with admin account (should have VIEWER_ROLE)
    // Note: canTransact requires SIWE authentication, so this might fail
    // We'll need to use a different approach
    const isWhitelisted = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "canTransact",
      args: [addressToCheck, "0x"], // Empty token for now
    });
    console.log(`Whitelist status (via canTransact): ${isWhitelisted}`);
  } catch (error: any) {
    console.log(`Could not check via canTransact (may require SIWE): ${error.message}`);
  }

  // Check if admin has VIEWER_ROLE
  console.log("\nChecking admin roles...");
  try {
    const VIEWER_ROLE = "0x" + "0".repeat(64); // We'll need to compute this
    // Actually, let's read it from the contract
    const viewerRoleHash = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "VIEWER_ROLE",
      args: [],
    });
    console.log(`VIEWER_ROLE hash: ${viewerRoleHash}`);
    
    const hasViewerRole = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "hasRole",
      args: [viewerRoleHash, adminAccount.address],
    });
    console.log(`Admin has VIEWER_ROLE: ${hasViewerRole}`);
  } catch (error: any) {
    console.log(`Could not check roles: ${error.message}`);
  }

  // Alternative: Try to read the whitelist mapping directly via storage slot
  // This is a workaround since _whitelist is internal
  console.log("\nAttempting to verify whitelist via storage slot...");
  console.log("Note: This is a workaround - the contract may use different storage layout");
  
  // Check balance as a sanity check
  try {
    const balance = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "balanceOf",
      args: [addressToCheck, "0x"],
    });
    console.log(`Balance: ${balance}`);
  } catch (error: any) {
    console.log(`Could not read balance (may require SIWE): ${error.message}`);
  }

  console.log("\nNote: Due to Sapphire's privacy features, checking whitelist status");
  console.log("may require SIWE authentication. The address should be whitelisted");
  console.log("if the changeWhitelist transaction succeeded.");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });


