import hre from "hardhat";
import { createWalletClient, createPublicClient, http, parseEther, formatEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { mnemonicToAccount } from "viem/accounts";
import { sapphireLocalnetChain } from "../hardhat.config";

async function main() {
  // Get private key from environment
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    throw new Error("PRIVATE_KEY environment variable is required");
  }

  // Target address
  const targetAddress = "0xB4AB6388B6b5eC3Ec4076A2515B398b019229813" as `0x${string}`;
  
  // Token contract address
  const tokenAddress = "0x7969c5eD335650692Bc04293B07F5BF2e7A673C0" as `0x${string}`;

  // Amounts
  const ethAmount = parseEther("10"); // 10 ETH
  const tokenAmount = parseEther("100"); // 100 * 10^18 tokens

  // Create account from private key
  const account = privateKeyToAccount(privateKey as `0x${string}`);

  // Create clients
  const publicClient = createPublicClient({
    chain: sapphireLocalnetChain,
    transport: http(),
  });

  const walletClient = createWalletClient({
    account,
    chain: sapphireLocalnetChain,
    transport: http(),
  });

  console.log(`Sender address: ${account.address}`);
  console.log(`Target address: ${targetAddress}`);
  console.log(`Token contract: ${tokenAddress}`);

  // Check sender balance
  const senderBalance = await publicClient.getBalance({ address: account.address });
  console.log(`\nSender balance: ${formatEther(senderBalance)} ETH`);

  // If sender has insufficient balance, fund it from a default account
  const requiredBalance = ethAmount + parseEther("0.1"); // 10 ETH + gas
  if (senderBalance < requiredBalance) {
    console.log(`\nInsufficient balance. Funding sender account from default mnemonic...`);
    const defaultMnemonic = "test test test test test test test test test test test junk";
    const funderAccount = mnemonicToAccount(defaultMnemonic, { accountIndex: 0 });
    
    const funderWalletClient = createWalletClient({
      account: funderAccount,
      chain: sapphireLocalnetChain,
      transport: http(),
    });

    const fundAmount = parseEther("20"); // Fund with 20 ETH to cover both transactions
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
  const defaultMnemonic = "test test test test test test test test test test test junk";
  const adminAccount = mnemonicToAccount(defaultMnemonic, { accountIndex: 0 });
  const adminWalletClient = createWalletClient({
    account: adminAccount,
    chain: sapphireLocalnetChain,
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
    senderTokenBalance = BigInt(balance.toString());
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
    const mintAmount = tokenAmount + parseEther("10"); // Mint extra for gas
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
    console.log(`Target token balance: ${formatEther(BigInt(targetTokenBalance.toString()))} tokens`);
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

