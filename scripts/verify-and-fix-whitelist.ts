import hre from "hardhat";
import { createWalletClient, createPublicClient, http, parseEther, formatEther, defineChain } from "viem";
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

  // Get address to whitelist from environment
  const targetAddress = process.env.TARGET_ADDRESS as `0x${string}`;
  if (!targetAddress) {
    throw new Error("TARGET_ADDRESS environment variable is required");
  }

  // Use admin account (account 0 from mnemonic)
  const adminMnemonic = process.env.ADMIN_MNEMONIC || "test test test test test test test test test test test junk";
  const adminAccount = mnemonicToAccount(adminMnemonic, { accountIndex: 0 });

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);
  console.log(`Admin address: ${adminAccount.address}`);
  console.log(`Token contract: ${tokenAddress}`);
  console.log(`Target address: ${targetAddress}\n`);

  // Create clients
  const publicClient = createPublicClient({
    chain,
    transport: http(),
  });

  const adminWalletClient = createWalletClient({
    account: adminAccount,
    chain,
    transport: http(),
  });

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");

  // Step 1: Check if admin has WHITELIST_ROLE
  console.log("Step 1: Checking admin roles...");
  const WHITELIST_ROLE = "0x" + Buffer.from(
    require("crypto").createHash("sha256").update("WHITELIST_ROLE").digest()
  ).toString("hex");
  
  // Actually, let's read it from the contract
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
    whitelistRoleHash = "0x" + require("crypto").createHash("sha256").update("WHITELIST_ROLE").digest("hex");
    console.log(`Using computed WHITELIST_ROLE hash: ${whitelistRoleHash}`);
  }

  // Check if admin has WHITELIST_ROLE
  let adminHasWhitelistRole = false;
  try {
    adminHasWhitelistRole = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "hasRole",
      args: [whitelistRoleHash, adminAccount.address],
    }) as boolean;
    console.log(`Admin has WHITELIST_ROLE: ${adminHasWhitelistRole}`);
  } catch (error: any) {
    console.log(`Could not check WHITELIST_ROLE: ${error.message}`);
  }

  // Step 2: Grant WHITELIST_ROLE to admin if needed
  if (!adminHasWhitelistRole) {
    console.log("\nStep 2: Granting WHITELIST_ROLE to admin...");
    try {
      // First check if admin has DEFAULT_ADMIN_ROLE (can grant roles)
      const DEFAULT_ADMIN_ROLE = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
      const adminHasAdminRole = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "hasRole",
        args: [DEFAULT_ADMIN_ROLE, adminAccount.address],
      }) as boolean;
      
      if (adminHasAdminRole) {
        console.log("Admin has DEFAULT_ADMIN_ROLE, granting WHITELIST_ROLE...");
        const grantTxHash = await adminWalletClient.writeContract({
          address: tokenAddress,
          abi: tokenArtifact.abi,
          functionName: "grantRole",
          args: [whitelistRoleHash, adminAccount.address],
        });
        console.log(`Grant transaction hash: ${grantTxHash}`);
        const grantReceipt = await publicClient.waitForTransactionReceipt({ hash: grantTxHash });
        console.log(`Grant transaction confirmed in block ${grantReceipt.blockNumber}`);
        adminHasWhitelistRole = true;
      } else {
        console.log("Admin does not have DEFAULT_ADMIN_ROLE. Cannot grant WHITELIST_ROLE.");
        console.log("Please ensure the admin account has the necessary permissions.");
      }
    } catch (error: any) {
      console.error(`Error granting WHITELIST_ROLE: ${error.message}`);
    }
  }

  // Step 3: Add target address to whitelist (if admin has WHITELIST_ROLE)
  if (adminHasWhitelistRole) {
    console.log("\nStep 3: Adding target address to whitelist...");
    try {
      const whitelistTxHash = await adminWalletClient.writeContract({
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
    console.log("\n⚠️  Cannot add to whitelist: Admin does not have WHITELIST_ROLE");
    console.log("Please grant WHITELIST_ROLE to the admin account first.");
  }

  console.log("\nDone!");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });



