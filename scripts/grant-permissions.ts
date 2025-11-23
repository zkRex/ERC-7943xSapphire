import hre from "hardhat";
import { createWalletClient, createPublicClient, http } from "viem";
import { mnemonicToAccount } from "viem/accounts";
import { sapphireLocalnetChain } from "../hardhat.config";

// Role names - we'll read the actual hashes from the contract
const ROLE_NAMES = [
  "DEFAULT_ADMIN_ROLE",
  "MINTER_ROLE",
  "BURNER_ROLE",
  "FREEZING_ROLE",
  "WHITELIST_ROLE",
  "FORCE_TRANSFER_ROLE",
  "VIEWER_ROLE",
  "MAIN_AUDITOR_ROLE",
] as const;

async function main() {
  // Target address to grant permissions to
  const targetAddress = "0xB4AB6388B6b5eC3Ec4076A2515B398b019229813" as `0x${string}`;
  
  // Token contract address
  const tokenAddress = "0x7969c5eD335650692Bc04293B07F5BF2e7A673C0" as `0x${string}`;

  // Use account 0 (deployer/admin) which has DEFAULT_ADMIN_ROLE
  const defaultMnemonic = "test test test test test test test test test test test junk";
  const adminAccount = mnemonicToAccount(defaultMnemonic, { accountIndex: 0 });

  // Create clients
  const publicClient = createPublicClient({
    chain: sapphireLocalnetChain,
    transport: http(),
  });

  const adminWalletClient = createWalletClient({
    account: adminAccount,
    chain: sapphireLocalnetChain,
    transport: http(),
  });

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");

  console.log(`Admin address: ${adminAccount.address}`);
  console.log(`Target address: ${targetAddress}`);
  console.log(`Token contract: ${tokenAddress}\n`);

  // Read role hashes from contract
  console.log("Reading role hashes from contract...");
  const roleHashes: Record<string, `0x${string}`> = {};
  
  // DEFAULT_ADMIN_ROLE is always 0x00...00
  roleHashes["DEFAULT_ADMIN_ROLE"] = "0x0000000000000000000000000000000000000000000000000000000000000000" as `0x${string}`;
  
  // Read other roles from contract
  for (const roleName of ROLE_NAMES) {
    if (roleName === "DEFAULT_ADMIN_ROLE") continue;
    try {
      const roleHash = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: `${roleName}`,
      }) as `0x${string}`;
      roleHashes[roleName] = roleHash;
    } catch (error) {
      console.log(`  Warning: Could not read ${roleName} (may require SIWE)`);
    }
  }
  console.log("");

  // Check current roles
  console.log("Checking current roles...");
  const currentRoles: string[] = [];
  for (const [roleName, roleHash] of Object.entries(roleHashes)) {
    try {
      const hasRole = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "hasRole",
        args: [roleHash, targetAddress],
      });
      if (hasRole) {
        currentRoles.push(roleName);
        console.log(`  ✓ ${roleName}`);
      }
    } catch (error) {
      // May fail due to SIWE, but that's okay
    }
  }
  if (currentRoles.length === 0) {
    console.log("  No roles currently assigned\n");
  } else {
    console.log("");
  }

  // Grant roles - you can modify this array to grant specific roles
  // For now, granting common useful roles (excluding DEFAULT_ADMIN_ROLE for security)
  const rolesToGrant = [
    "MINTER_ROLE",
    "BURNER_ROLE",
    "WHITELIST_ROLE",
    "VIEWER_ROLE",
    // Uncomment to grant additional roles:
    // "FREEZING_ROLE",
    // "FORCE_TRANSFER_ROLE",
    // "MAIN_AUDITOR_ROLE",
  ];

  console.log(`Granting ${rolesToGrant.length} role(s) to ${targetAddress}...\n`);

  for (const roleName of rolesToGrant) {
    const roleHash = roleHashes[roleName];
    if (!roleHash) {
      console.log(`  ⚠️  ${roleName} - hash not available, skipping`);
      continue;
    }

    // Check if already has role
    let alreadyHasRole = false;
    try {
      alreadyHasRole = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "hasRole",
        args: [roleHash, targetAddress],
      }) as boolean;
    } catch (error) {
      // Continue anyway if read fails
    }

    if (alreadyHasRole) {
      console.log(`  ⏭️  ${roleName} - already granted, skipping`);
      continue;
    }

    console.log(`  Granting ${roleName}...`);
    try {
      const grantTxHash = await adminWalletClient.writeContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "grantRole",
        args: [roleHash, targetAddress],
      });
      console.log(`    Transaction hash: ${grantTxHash}`);
      
      const receipt = await publicClient.waitForTransactionReceipt({ hash: grantTxHash });
      console.log(`    ✓ Confirmed in block ${receipt.blockNumber}`);
    } catch (error: any) {
      console.log(`    ✗ Failed: ${error.message}`);
    }
    console.log("");
  }

  // Verify final roles
  console.log("Verifying granted roles...");
  const finalRoles: string[] = [];
  for (const [roleName, roleHash] of Object.entries(roleHashes)) {
    try {
      const hasRole = await publicClient.readContract({
        address: tokenAddress,
        abi: tokenArtifact.abi,
        functionName: "hasRole",
        args: [roleHash, targetAddress],
      });
      if (hasRole) {
        finalRoles.push(roleName);
        console.log(`  ✓ ${roleName}`);
      }
    } catch (error) {
      // May fail due to SIWE, but that's okay
    }
  }
  if (finalRoles.length === 0) {
    console.log("  No roles found (may require SIWE authentication to read)");
  }

  console.log("\nDone!");
  console.log("\nAvailable roles:");
  console.log("  - DEFAULT_ADMIN_ROLE: Full administrative control");
  console.log("  - MINTER_ROLE: Can mint new tokens");
  console.log("  - BURNER_ROLE: Can burn tokens");
  console.log("  - FREEZING_ROLE: Can freeze/unfreeze tokens");
  console.log("  - WHITELIST_ROLE: Can manage whitelist");
  console.log("  - FORCE_TRANSFER_ROLE: Can force transfer tokens");
  console.log("  - VIEWER_ROLE: Can view decrypted transfer data");
  console.log("  - MAIN_AUDITOR_ROLE: Can grant auditor permissions");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

