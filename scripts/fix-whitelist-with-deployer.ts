import hre from "hardhat";
import { createWalletClient, createPublicClient, http, defineChain } from "viem";
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

  // Get address to whitelist from environment
  const targetAddress = process.env.TARGET_ADDRESS as `0x${string}`;
  if (!targetAddress) {
    throw new Error("TARGET_ADDRESS environment variable is required");
  }

  // Use PRIVATE_KEY from environment (this should be the deployer/admin)
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error("PRIVATE_KEY environment variable is required. This should be the account that deployed the contract.");
  }

  const deployerAccount = privateKeyToAccount(privateKey as `0x${string}`);

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Deployer address: ${deployerAccount.address}`);
  console.log(`Token contract: ${tokenAddress}`);
  console.log(`Target address: ${targetAddress}\n`);

  // Create clients
  const publicClient = createPublicClient({
    chain,
    transport: http(),
  });

  const deployerWalletClient = createWalletClient({
    account: deployerAccount,
    chain,
    transport: http(),
  });

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");

  // Step 1: Check if deployer has DEFAULT_ADMIN_ROLE
  console.log("Step 1: Checking deployer roles...");
  const DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
  
  let deployerHasAdminRole = false;
  try {
    deployerHasAdminRole = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "hasRole",
      args: [DEFAULT_ADMIN_ROLE, deployerAccount.address],
    }) as boolean;
    console.log(`Deployer has DEFAULT_ADMIN_ROLE: ${deployerHasAdminRole}`);
  } catch (error: any) {
    console.log(`Could not check DEFAULT_ADMIN_ROLE: ${error.message}`);
  }

  // Step 2: Get WHITELIST_ROLE hash
  let whitelistRoleHash: `0x${string}`;
  try {
    whitelistRoleHash = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "WHITELIST_ROLE",
      args: [],
    }) as `0x${string}`;
    console.log(`WHITELIST_ROLE hash: ${whitelistRoleHash}`);
  } catch (error: any) {
    console.log(`Could not read WHITELIST_ROLE from contract: ${error.message}`);
    // Compute it manually
    const crypto = require("crypto");
    whitelistRoleHash = ("0x" + crypto.createHash("sha256").update("WHITELIST_ROLE").digest("hex")) as `0x${string}`;
    console.log(`Using computed WHITELIST_ROLE hash: ${whitelistRoleHash}`);
  }

  // Step 3: Check if deployer has WHITELIST_ROLE
  let deployerHasWhitelistRole = false;
  try {
    deployerHasWhitelistRole = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "hasRole",
      args: [whitelistRoleHash, deployerAccount.address],
    }) as boolean;
    console.log(`Deployer has WHITELIST_ROLE: ${deployerHasWhitelistRole}`);
  } catch (error: any) {
    console.log(`Could not check WHITELIST_ROLE: ${error.message}`);
  }

  // Step 4: Grant WHITELIST_ROLE to deployer if needed
  if (!deployerHasWhitelistRole && deployerHasAdminRole) {
    console.log("\nStep 4: Granting WHITELIST_ROLE to deployer...");
    try {
      const grantTxHash = await deployerWalletClient.writeContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "grantRole",
        args: [whitelistRoleHash, deployerAccount.address],
      });
      console.log(`Grant transaction hash: ${grantTxHash}`);
      const grantReceipt = await publicClient.waitForTransactionReceipt({ hash: grantTxHash });
      console.log(`Grant transaction confirmed in block ${grantReceipt.blockNumber}`);
      deployerHasWhitelistRole = true;
    } catch (error: any) {
      console.error(`Error granting WHITELIST_ROLE: ${error.message}`);
      throw error;
    }
  }

  // Step 5: Add target address to whitelist
  if (deployerHasWhitelistRole) {
    console.log("\nStep 5: Adding target address to whitelist...");
    try {
      const whitelistTxHash = await deployerWalletClient.writeContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "changeWhitelist",
        args: [targetAddress, true],
      });
      console.log(`Whitelist transaction hash: ${whitelistTxHash}`);
      const whitelistReceipt = await publicClient.waitForTransactionReceipt({ hash: whitelistTxHash });
      console.log(`Whitelist transaction confirmed in block ${whitelistReceipt.blockNumber}`);
      console.log(`✓ Successfully added ${targetAddress} to whitelist`);
    } catch (error: any) {
      console.error(`Error adding to whitelist: ${error.message}`);
      throw error;
    }
  } else {
    console.log("\n⚠️  Cannot add to whitelist: Deployer does not have WHITELIST_ROLE");
    if (!deployerHasAdminRole) {
      console.log("⚠️  Deployer also does not have DEFAULT_ADMIN_ROLE");
      console.log("Please ensure the PRIVATE_KEY corresponds to the contract deployer/admin.");
    }
  }

  console.log("\nDone!");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });



