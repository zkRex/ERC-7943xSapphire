import hre from "hardhat";
import { createWalletClient, createPublicClient, http, parseEther, formatEther, defineChain } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mnemonicToAccount } from "viem/accounts";
import * as dotenv from "dotenv";
import * as path from "path";

// Load environment variables from root .env
dotenv.config();
// Also try to load from scripts/.env if it exists
dotenv.config({ path: path.join(__dirname, ".env") });

async function main() {
  // Get network from environment or default to sapphire-localnet
  const networkName = process.env.NETWORK || "sapphire-localnet";
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

  // Get values from environment
  const targetAddress = process.env.TARGET_ADDRESS as `0x${string}`;
  if (!targetAddress) {
    throw new Error("TARGET_ADDRESS environment variable is required");
  }

  const tokenAddress = process.env.TOKEN_ADDRESS as `0x${string}`;
  if (!tokenAddress) {
    throw new Error("TOKEN_ADDRESS environment variable is required");
  }

  const ethAmountStr = process.env.ETH_AMOUNT || "10";
  const tokenAmountStr = process.env.TOKEN_AMOUNT || "100";
  const ethAmount = parseEther(ethAmountStr);
  const tokenAmount = parseEther(tokenAmountStr);

  // Create account from private key
  const account = privateKeyToAccount(privateKey as `0x${string}`);

  console.log(`\nUsing network: ${networkName}`);
  console.log(`Network URL: ${networkUrl}`);
  console.log(`Chain ID: ${networkChainId}`);

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

  console.log(`Sender address: ${account.address}`);
  console.log(`Target address: ${targetAddress}`);
  console.log(`Token contract: ${tokenAddress}`);

  // Check sender balance
  const senderBalance = await publicClient.getBalance({ address: account.address });
  console.log(`\nSender balance: ${formatEther(senderBalance)} ETH`);

  // If sender has insufficient balance, fund it from a default account
  const requiredBalance = ethAmount + parseEther("0.1"); // ETH amount + gas
  if (senderBalance < requiredBalance) {
    console.log(`\nInsufficient balance. Funding sender account from default mnemonic...`);
    const funderMnemonic = process.env.FUNDER_MNEMONIC || "test test test test test test test test test test test junk";
    const funderAccount = mnemonicToAccount(funderMnemonic, { accountIndex: 0 });
    
    const funderWalletClient = createWalletClient({
      account: funderAccount,
      chain,
      transport: http(),
    });

    const fundAmountStr = process.env.FUND_AMOUNT || "20";
    const fundAmount = parseEther(fundAmountStr); // Fund amount to cover transactions
    console.log(`Funding ${formatEther(fundAmount)} ETH from ${funderAccount.address}...`);
    
    const fundTxHash = await funderWalletClient.sendTransaction({
      to: account.address,
      value: fundAmount,
    });
    console.log(`Funding transaction hash: ${fundTxHash}`);
    
    const fundReceipt = await publicClient.waitForTransactionReceipt({ hash: fundTxHash });
    console.log(`Funding transaction confirmed in block ${fundReceipt.blockNumber}`);
    
    const newBalance = await publicClient.getBalance({ address: account.address });
    console.log(`New sender balance: ${formatEther(newBalance)} ETH`);
  }

  // Send 10 ETH
  console.log(`\nSending ${formatEther(ethAmount)} ETH...`);
  const ethTxHash = await walletClient.sendTransaction({
    to: targetAddress,
    value: ethAmount,
  });
  console.log(`ETH transaction hash: ${ethTxHash}`);
  
  const ethReceipt = await publicClient.waitForTransactionReceipt({ hash: ethTxHash });
  console.log(`ETH transaction confirmed in block ${ethReceipt.blockNumber}`);

  // Get token ABI
  const tokenArtifact = await hre.artifacts.readArtifact("uRWA20");
  
  // Check if sender has tokens, if not, mint them first
  // Use account 0 (deployer/admin) which has MINTER_ROLE
  const adminMnemonic = process.env.ADMIN_MNEMONIC || "test test test test test test test test test test test junk";
  const adminAccount = mnemonicToAccount(adminMnemonic, { accountIndex: 0 });
  const adminWalletClient = createWalletClient({
    account: adminAccount,
    chain,
    transport: http(),
  });

  // Check sender token balance (may fail due to SIWE, so we'll try to mint anyway)
  let senderTokenBalance = 0n;
  try {
    const balance = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "balanceOf",
      args: [account.address],
    });
    senderTokenBalance = typeof balance === "bigint" ? balance : BigInt(balance as string);
    console.log(`\nSender token balance: ${formatEther(senderTokenBalance)} tokens`);
  } catch (error) {
    console.log(`\nCould not read sender token balance (may require SIWE), proceeding to mint...`);
  }

  // Whitelist both sender and target addresses if needed
  console.log(`\nWhitelisting sender and target addresses...`);
  const whitelistSenderHash = await adminWalletClient.writeContract({
    address: tokenAddress,
    abi: tokenArtifact.abi,
    functionName: "changeWhitelist",
    args: [account.address, true],
  });
  await publicClient.waitForTransactionReceipt({ hash: whitelistSenderHash });
  console.log(`Sender whitelisted`);

  const whitelistTargetHash = await adminWalletClient.writeContract({
    address: tokenAddress,
    abi: tokenArtifact.abi,
    functionName: "changeWhitelist",
    args: [targetAddress, true],
  });
  await publicClient.waitForTransactionReceipt({ hash: whitelistTargetHash });
  console.log(`Target whitelisted`);

  // Mint tokens to sender if they don't have enough
  if (senderTokenBalance < tokenAmount) {
    const mintExtraStr = process.env.MINT_EXTRA || "10";
    const mintAmount = tokenAmount + parseEther(mintExtraStr); // Mint extra for gas
    console.log(`\nMinting ${formatEther(mintAmount)} tokens to sender...`);
    const mintTxHash = await adminWalletClient.writeContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "mint",
      args: [account.address, mintAmount],
    });
    console.log(`Mint transaction hash: ${mintTxHash}`);
    const mintReceipt = await publicClient.waitForTransactionReceipt({ hash: mintTxHash });
    console.log(`Mint transaction confirmed in block ${mintReceipt.blockNumber}`);
  }
  
  // Send tokens
  console.log(`\nSending ${formatEther(tokenAmount)} tokens...`);
  const tokenTxHash = await walletClient.writeContract({
    address: tokenAddress,
    abi: tokenArtifact.abi,
    functionName: "transfer",
    args: [targetAddress, tokenAmount],
  });
  console.log(`Token transaction hash: ${tokenTxHash}`);
  
  const tokenReceipt = await publicClient.waitForTransactionReceipt({ hash: tokenTxHash });
  console.log(`Token transaction confirmed in block ${tokenReceipt.blockNumber}`);

  // Verify balances
  const targetEthBalance = await publicClient.getBalance({ address: targetAddress });
  console.log(`\nTarget ETH balance: ${formatEther(targetEthBalance)} ETH`);

  // Try to read token balance (may require SIWE on Sapphire, so we'll catch errors)
  try {
    const targetTokenBalance = await publicClient.readContract({
      address: tokenAddress,
      abi: tokenArtifact.abi,
      functionName: "balanceOf",
      args: [targetAddress],
    });
    const balance = typeof targetTokenBalance === "bigint" ? targetTokenBalance : BigInt(targetTokenBalance as string);
    console.log(`Target token balance: ${formatEther(balance)} tokens`);
  } catch (error) {
    console.log(`Note: Could not read token balance (may require SIWE authentication)`);
  }

  console.log("\nDone!");
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

