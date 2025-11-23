import { PublicClient } from "viem";
import hre from "hardhat";

/**
 * Get polling configuration based on network type.
 * Local networks use faster polling and shorter timeouts since transactions
 * are nearly instant. Remote networks need longer timeouts for network latency.
 */
function getPollingConfig() {
  const isLocalNetwork = hre.network.name === "sapphire-localnet" || hre.network.name === "hardhat";
  
  if (isLocalNetwork) {
    return {
      pollingInterval: 100, // 100ms - fast polling for local networks
      timeout: 10000, // 5 seconds - more than enough for local transactions
    };
  }
  
  // Remote network configuration
  // With ~470ms network latency, polling every 2 seconds reduces
  // unnecessary network calls while still being responsive.
  return {
    pollingInterval: 2000, // 2 seconds - matches network latency
    timeout: 120000, // 2 minutes timeout for remote networks
  };
}

/**
 * Wait for a transaction receipt with optimized polling settings.
 * Uses faster polling and shorter timeout for local networks, and slower
 * polling with longer timeout for remote networks.
 * Throws an error if the transaction reverted.
 */
export async function waitForTx(
  hash: `0x${string}`,
  publicClient: PublicClient
) {
  const config = getPollingConfig();
  const receipt = await publicClient.waitForTransactionReceipt({
    hash,
    ...config,
  });
  
  // Check if transaction reverted
  if (receipt.status === 'reverted') {
    throw new Error(`Transaction ${hash} reverted`);
  }
  
  return receipt;
}

/**
 * Wait for multiple transaction receipts in parallel.
 * This is more efficient than waiting sequentially.
 */
export async function waitForTxs(
  hashes: `0x${string}`[],
  publicClient: PublicClient
) {
  return Promise.all(hashes.map((hash) => waitForTx(hash, publicClient)));
}

