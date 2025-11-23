import { createWalletClient, createPublicClient, http, parseEther, keccak256, encodePacked, encodeAbiParameters, formatEther, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import * as dotenv from "dotenv";
import { join } from "path";

const sapphireTestnet = defineChain({
  id: 0x5aff,
  name: "Sapphire Testnet",
  nativeCurrency: {
    decimals: 18,
    name: "TEST",
    symbol: "TEST",
  },
  rpcUrls: {
    default: {
      http: ["https://testnet.sapphire.oasis.io"],
    },
  },
});

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
  {
    inputs: [],
    name: "name",
    outputs: [{ internalType: "string", name: "", type: "string" }],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "symbol",
    outputs: [{ internalType: "string", name: "", type: "string" }],
    stateMutability: "view",
    type: "function",
  },
];

const CONTRACT_ADDRESS = process.env.Contract_uRWA20 as `0x${string}`;
const PRIVATE_KEY = process.env.PRIVATE_KEY as `0x${string}`;
const PRIVATE_KEY_2 = process.env.PRIVATE_KEY_2 as `0x${string}`;
const PRIVATE_KEY_3 = process.env.PRIVATE_KEY_3 as `0x${string}`;
const PRIVATE_KEY_4 = process.env.PRIVATE_KEY_4 as `0x${string}`;

async function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForTx(hash: `0x${string}`, client: any) {
  console.log(`  ⏳ Waiting for tx: ${hash.slice(0, 10)}...`);
  await client.waitForTransactionReceipt({ hash });
  await sleep(2000);
}

async function main() {
  console.log("\n🎬 ERC-7943 x Sapphire - Hackathon Demo\n");
  console.log("=" .repeat(60));

  const publicClient = createPublicClient({
    chain: sapphireTestnet,
    transport: http(),
  });

  const admin = createWalletClient({
    account: privateKeyToAccount(PRIVATE_KEY),
    chain: sapphireTestnet,
    transport: http(),
  });

  const user1 = createWalletClient({
    account: privateKeyToAccount(PRIVATE_KEY_2),
    chain: sapphireTestnet,
    transport: http(),
  });

  const user2 = createWalletClient({
    account: privateKeyToAccount(PRIVATE_KEY_3),
    chain: sapphireTestnet,
    transport: http(),
  });

  const user3 = createWalletClient({
    account: privateKeyToAccount(PRIVATE_KEY_4),
    chain: sapphireTestnet,
    transport: http(),
  });

  console.log("\n📋 Contract Information:");
  console.log(`   uRWA20 Token: ${CONTRACT_ADDRESS}`);

  const name = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "name",
  });

  const symbol = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "symbol",
  });

  console.log(`   Token Name: ${name}`);
  console.log(`   Token Symbol: ${symbol}`);

  console.log("\n👥 Wallets:");
  console.log(`   Admin:  ${admin.account.address}`);
  console.log(`   User 1: ${user1.account.address}`);
  console.log(`   User 2: ${user2.account.address}`);
  console.log(`   User 3: ${user3.account.address}`);

  console.log("\n" + "=" .repeat(60));
  console.log("\n🔐 DEMONSTRATION: Encrypted Calldata Transactions\n");

  // Step 1: Whitelist User 1 using encrypted calldata
  console.log("1️⃣  Whitelisting User 1 (Encrypted)");
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
  console.log("   ✅ User 1 whitelisted successfully\n");

  // Step 2: Mint tokens to User 1 using encrypted calldata
  console.log("2️⃣  Minting 1000 tokens to User 1 (Encrypted)");
  const mintAmount = parseEther("1000");
  const mintSelector = keccak256(encodePacked(["string"], ["mint(address,uint256)"])).slice(0, 10);
  const mintParams = encodeAbiParameters(
    [{ type: "address" }, { type: "uint256" }],
    [user1.account.address, mintAmount]
  );

  const encryptedMint = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [mintSelector, mintParams],
  });

  const mintHash = await admin.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedMint],
  });

  await waitForTx(mintHash, publicClient);

  const balance1 = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "balanceOf",
    args: [user1.account.address],
  });

  console.log(`   ✅ Minted successfully. User 1 balance: ${formatEther(balance1 as bigint)} tokens\n`);

  // Step 3: Whitelist User 2
  console.log("3️⃣  Whitelisting User 2 (Encrypted)");
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
  console.log("   ✅ User 2 whitelisted successfully\n");

  // Step 4: Transfer from User 1 to User 2 using encrypted calldata
  console.log("4️⃣  User 1 transfers 250 tokens to User 2 (Encrypted)");
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

  const balance1After = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "balanceOf",
    args: [user1.account.address],
  });

  const balance2After = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "balanceOf",
    args: [user2.account.address],
  });

  console.log(`   ✅ Transfer successful!`);
  console.log(`      User 1 balance: ${formatEther(balance1After as bigint)} tokens`);
  console.log(`      User 2 balance: ${formatEther(balance2After as bigint)} tokens\n`);

  // Step 5: Approve and TransferFrom using encrypted calldata
  console.log("5️⃣  User 2 approves User 3 to spend 100 tokens (Encrypted)");

  // First whitelist User 3
  const whitelistParams3 = encodeAbiParameters(
    [{ type: "address" }, { type: "bool" }],
    [user3.account.address, true]
  );

  const encryptedWhitelist3 = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [whitelistSelector, whitelistParams3],
  });

  const whitelistHash3 = await admin.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedWhitelist3],
  });

  await waitForTx(whitelistHash3, publicClient);

  const approveAmount = parseEther("100");
  const approveSelector = keccak256(encodePacked(["string"], ["approve(address,uint256)"])).slice(0, 10);
  const approveParams = encodeAbiParameters(
    [{ type: "address" }, { type: "uint256" }],
    [user3.account.address, approveAmount]
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
  console.log("   ✅ Approval successful\n");

  console.log("6️⃣  User 3 transfers 100 tokens from User 2 to themselves (Encrypted)");
  const transferFromSelector = keccak256(encodePacked(["string"], ["transferFrom(address,address,uint256)"])).slice(0, 10);
  const transferFromParams = encodeAbiParameters(
    [{ type: "address" }, { type: "address" }, { type: "uint256" }],
    [user2.account.address, user3.account.address, approveAmount]
  );

  const encryptedTransferFrom = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "makeEncryptedTransaction",
    args: [transferFromSelector, transferFromParams],
  });

  const transferFromHash = await user3.writeContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "executeEncrypted",
    args: [encryptedTransferFrom],
  });

  await waitForTx(transferFromHash, publicClient);

  const balance2Final = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "balanceOf",
    args: [user2.account.address],
  });

  const balance3Final = await publicClient.readContract({
    address: CONTRACT_ADDRESS,
    abi: TOKEN_ABI,
    functionName: "balanceOf",
    args: [user3.account.address],
  });

  console.log(`   ✅ TransferFrom successful!`);
  console.log(`      User 2 balance: ${formatEther(balance2Final as bigint)} tokens`);
  console.log(`      User 3 balance: ${formatEther(balance3Final as bigint)} tokens\n`);

  console.log("\n" + "=" .repeat(60));
  console.log("\n✨ Demo Complete!\n");
  console.log("Key Features Demonstrated:");
  console.log("  🔐 Encrypted whitelisting");
  console.log("  🔐 Encrypted minting");
  console.log("  🔐 Encrypted transfers");
  console.log("  🔐 Encrypted approvals");
  console.log("  🔐 Encrypted transferFrom\n");
  console.log("All transactions used ERC-7943 encrypted calldata on Sapphire!");
  console.log("=" .repeat(60) + "\n");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Error:", error);
    process.exit(1);
  });
