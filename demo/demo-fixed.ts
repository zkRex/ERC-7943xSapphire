// @ts-nocheck
import hre from "hardhat";
import { parseEther, formatEther, getContract } from "viem";
import * as dotenv from "dotenv";
import { join } from "path";

dotenv.config({ path: join(__dirname, ".env") });

const CONTRACT_ADDRESS = process.env.Contract_uRWA20 as `0x${string}`;

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForTx(hash: `0x${string}`, client: any) {
  console.log(`  ⏳ Waiting for tx: ${hash.slice(0, 10)}...`);
  const receipt = await client.waitForTransactionReceipt({ hash });
  await sleep(2000);

  // Check if transaction succeeded
  if (receipt.status !== 'success') {
    console.error(`   ❌ Transaction failed!`);
    throw new Error(`Transaction ${hash} reverted`);
  }
  return receipt;
}

async function main() {
  console.log("\n🎬 ERC-7943 x Sapphire - Hackathon Demo\n");
  console.log("=".repeat(60));

  // Get contract ABI
  const uRWA20Artifact = await hre.artifacts.readArtifact("uRWA20");

  // Use hardhat's viem clients which are automatically wrapped by sapphire-hardhat
  const publicClient = await hre.viem.getPublicClient();
  const [admin, user1, user2, user3] = await hre.viem.getWalletClients();

  // Create contract instances for each wallet
  const adminContract = getContract({
    address: CONTRACT_ADDRESS,
    abi: uRWA20Artifact.abi,
    client: { public: publicClient, wallet: admin }
  });

  const user1Contract = getContract({
    address: CONTRACT_ADDRESS,
    abi: uRWA20Artifact.abi,
    client: { public: publicClient, wallet: user1 }
  });

  const user2Contract = getContract({
    address: CONTRACT_ADDRESS,
    abi: uRWA20Artifact.abi,
    client: { public: publicClient, wallet: user2 }
  });

  const user3Contract = getContract({
    address: CONTRACT_ADDRESS,
    abi: uRWA20Artifact.abi,
    client: { public: publicClient, wallet: user3 }
  });

  console.log("\n📋 Contract Information:");
  console.log(`   uRWA20 Token: ${CONTRACT_ADDRESS}`);

  console.log("\n👥 Wallets:");
  console.log(`   Admin:  ${admin.account.address}`);
  console.log(`   User 1: ${user1.account.address}`);
  console.log(`   User 2: ${user2.account.address}`);
  console.log(`   User 3: ${user3.account.address}`);

  console.log("\n" + "=".repeat(60));
  console.log("\n🔐 DEMONSTRATION: Encrypted Calldata Transactions\n");

  try {
    // Step 1: Whitelist User 1 - sapphire-hardhat automatically encrypts the calldata
    console.log("1️⃣  Whitelisting User 1 (Encrypted by sapphire-hardhat)");
    const whitelistHash = await adminContract.write.changeWhitelist([
      user1.account.address,
      true
    ]);
    await waitForTx(whitelistHash, publicClient);
    console.log("   ✅ User 1 whitelisted successfully\n");

    // Step 2: Mint tokens to User 1
    console.log("2️⃣  Minting 1000 tokens to User 1 (Encrypted)");
    const mintAmount = parseEther("1000");
    const mintHash = await adminContract.write.mint([
      user1.account.address,
      mintAmount
    ]);
    await waitForTx(mintHash, publicClient);

    console.log(`   ✅ Minted successfully`);
    console.log(`      ℹ️  Balances are CONFIDENTIAL and encrypted on-chain\n`);

    // Step 3: Whitelist User 2
    console.log("3️⃣  Whitelisting User 2 (Encrypted)");
    const whitelistHash2 = await adminContract.write.changeWhitelist([
      user2.account.address,
      true
    ]);
    await waitForTx(whitelistHash2, publicClient);
    console.log("   ✅ User 2 whitelisted successfully\n");

    // Step 4: Transfer from User 1 to User 2
    console.log("4️⃣  User 1 transfers 250 tokens to User 2 (Encrypted)");
    const transferAmount = parseEther("250");
    const transferHash = await user1Contract.write.transfer([
      user2.account.address,
      transferAmount
    ]);
    await waitForTx(transferHash, publicClient);

    console.log(`   ✅ Transfer successful!`);
    console.log(`      ℹ️  Balances are CONFIDENTIAL and encrypted on-chain\n`);

    // Step 5: Approve and TransferFrom
    console.log("5️⃣  User 2 approves User 1 to spend 100 tokens (Encrypted)");
    const approveAmount = parseEther("100");
    const approveHash = await user2Contract.write.approve([
      user1.account.address,
      approveAmount
    ]);
    await waitForTx(approveHash, publicClient);
    console.log("   ✅ Approval successful\n");

    console.log("6️⃣  User 1 transfers 100 tokens from User 2 to themselves (Encrypted)");
    const transferFromHash = await user1Contract.write.transferFrom([
      user2.account.address,
      user1.account.address,
      approveAmount
    ]);
    await waitForTx(transferFromHash, publicClient);

    console.log(`   ✅ TransferFrom successful!`);
    console.log(`      ℹ️  Balances are CONFIDENTIAL and encrypted on-chain\n`);

    // Step 7: Whitelist and interact with User 3
    console.log("7️⃣  Whitelisting User 3 (Encrypted)");
    const whitelistHash3 = await adminContract.write.changeWhitelist([
      user3.account.address,
      true
    ]);
    await waitForTx(whitelistHash3, publicClient);
    console.log("   ✅ User 3 whitelisted successfully\n");

    console.log("8️⃣  User 1 transfers 50 tokens to User 3 (Encrypted)");
    const transferToUser3 = parseEther("50");
    const transferHash3 = await user1Contract.write.transfer([
      user3.account.address,
      transferToUser3
    ]);
    await waitForTx(transferHash3, publicClient);
    console.log(`   ✅ Transfer to User 3 successful!`);
    console.log(`      ℹ️  Balances are CONFIDENTIAL and encrypted on-chain\n`);

    console.log("\n" + "=".repeat(60));
    console.log("\n✨ Demo Complete!\n");
    console.log("Key Features Demonstrated:");
    console.log("  🔐 Encrypted whitelisting (via sapphire-hardhat)");
    console.log("  🔐 Encrypted minting");
    console.log("  🔐 Encrypted transfers");
    console.log("  🔐 Encrypted approvals");
    console.log("  🔐 Encrypted transferFrom\n");
    console.log("Privacy Features:");
    console.log("  ✅ All transaction calldata is encrypted on-chain");
    console.log("  ✅ Token balances are CONFIDENTIAL (encrypted state)");
    console.log("  ✅ Transfer amounts and recipients are hidden from observers");
    console.log("  ✅ Only authorized parties can view private data\n");
    console.log("All transactions used Sapphire's automatic calldata encryption!");
    console.log("=".repeat(60) + "\n");
  } catch (error) {
    console.error("\n❌ Demo failed:", error);
    throw error;
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Error:", error);
    process.exit(1);
  });
