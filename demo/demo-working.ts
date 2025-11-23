// @ts-nocheck
import hre from "hardhat";
import { parseEther, keccak256, encodePacked, encodeAbiParameters, formatEther } from "viem";
import * as dotenv from "dotenv";
import { join } from "path";

dotenv.config({ path: join(__dirname, ".env") });

const TOKEN_ABI = [
  {
    inputs: [{ internalType: "bytes", name: "encryptedData", type: "bytes" }],
    name: "executeEncrypted",
    outputs: [{ internalType: "bytes", name: "", type: "bytes" }],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      { internalType: "bytes4", name: "selector", type: "bytes4" },
      { internalType: "bytes", name: "params", type: "bytes" },
    ],
    name: "makeEncryptedTransaction",
    outputs: [{ internalType: "bytes", name: "", type: "bytes" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [{ internalType: "address", name: "account", type: "address" }],
    name: "balanceOf",
    outputs: [{ internalType: "uint256", name: "", type: "uint256" }],
    stateMutability: "view",
    type: "function",
  },
] as const;

const CONTRACT_ADDRESS = process.env.Contract_uRWA20 as `0x${string}`;

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForTx(hash: `0x${string}`, client: any) {
  console.log(`  Waiting for tx: ${hash.slice(0, 10)}...`);
  await client.waitForTransactionReceipt({ hash });
  await sleep(2000);
}

async function main() {
  console.log("\nERC-7943 x Sapphire - Demo (Fixed)\n");
  console.log("=".repeat(60));

  // Use hardhat's viem clients which are automatically wrapped by sapphire-hardhat
  const publicClient = await hre.viem.getPublicClient();
  const [admin, user1, user2] = await hre.viem.getWalletClients();

  console.log("\nContract Information:");
  console.log(`   uRWA20 Token: ${CONTRACT_ADDRESS}`);

  console.log("\nWallets:");
  console.log(`   Admin:  ${admin.account.address}`);
  console.log(`   User 1: ${user1.account.address}`);
  console.log(`   User 2: ${user2.account.address}`);

  console.log("\n" + "=".repeat(60));
  console.log("\nDEMONSTRATION: Encrypted Calldata Transactions\n");

  // Step 1: Whitelist User 1 using encrypted calldata
  console.log("1. Whitelisting User 1 (Encrypted)");
  const whitelistSelector = keccak256(encodePacked(["string"], ["changeWhitelist(address,bool)"])).slice(0, 10);
  const whitelistParams = encodeAbiParameters(
    [{ type: "address" }, { type: "bool" }],
    [user1.account.address, true]
  );

  const encryptedWhitelist = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [whitelistSelector, whitelistParams],
  });

  const whitelistHash = await admin.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedWhitelist],
  });

  await waitForTx(whitelistHash, publicClient);
  console.log("   OK: User 1 whitelisted successfully\n");

  // Step 2: Whitelist User 2
  console.log("2. Whitelisting User 2 (Encrypted)");
  const whitelistParams2 = encodeAbiParameters(
    [{ type: "address" }, { type: "bool" }],
    [user2.account.address, true]
  );

  const encryptedWhitelist2 = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [whitelistSelector, whitelistParams2],
  });

  const whitelistHash2 = await admin.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedWhitelist2],
  });

  await waitForTx(whitelistHash2, publicClient);
  console.log("   OK: User 2 whitelisted successfully\n");

  // Step 3: Transfer from User 1 to User 2 using encrypted calldata
  console.log("3. User 1 transfers 250 tokens to User 2 (Encrypted)");
  const transferAmount = parseEther("250");
  const transferSelector = keccak256(encodePacked(["string"], ["transfer(address,uint256)"])).slice(0, 10);
  const transferParams = encodeAbiParameters(
    [{ type: "address" }, { type: "uint256" }],
    [user2.account.address, transferAmount]
  );

  const encryptedTransfer = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [transferSelector, transferParams],
  });

  const transferHash = await user1.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedTransfer],
  });

  await waitForTx(transferHash, publicClient);
  console.log(`   OK: Transfer successful\n`);

  // Step 4: Approve and TransferFrom using encrypted calldata
  console.log("4. User 2 approves User 1 to spend 100 tokens (Encrypted)");

  const approveAmount = parseEther("100");
  const approveSelector = keccak256(encodePacked(["string"], ["approve(address,uint256)"])).slice(0, 10);
  const approveParams = encodeAbiParameters(
    [{ type: "address" }, { type: "uint256" }],
    [user1.account.address, approveAmount]
  );

  const encryptedApprove = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [approveSelector, approveParams],
  });

  const approveHash = await user2.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedApprove],
  });

  await waitForTx(approveHash, publicClient);
  console.log("   OK: Approval successful\n");

  console.log("5. User 1 transfers 100 tokens from User 2 to themselves (Encrypted)");
  const transferFromSelector = keccak256(encodePacked(["string"], ["transferFrom(address,address,uint256)"])).slice(0, 10);
  const transferFromParams = encodeAbiParameters(
    [{ type: "address" }, { type: "address" }, { type: "uint256" }],
    [user2.account.address, user1.account.address, approveAmount]
  );

  const encryptedTransferFrom = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [transferFromSelector, transferFromParams],
  });

  const transferFromHash = await user1.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedTransferFrom],
  });

  await waitForTx(transferFromHash, publicClient);
  console.log(`   OK: TransferFrom successful\n`);

  console.log("\n" + "=".repeat(60));
  console.log("\nDemo Complete!\n");
  console.log("Key Features Demonstrated:");
  console.log("  - Encrypted whitelisting");
  console.log("  - Encrypted transfers");
  console.log("  - Encrypted approvals");
  console.log("  - Encrypted transferFrom\n");
  console.log("All transactions used ERC-7943 encrypted calldata on Sapphire!");
  console.log("=".repeat(60) + "\n");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\nError:", error);
    process.exit(1);
  });
