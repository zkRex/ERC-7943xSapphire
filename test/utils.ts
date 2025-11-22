import { PublicClient } from "viem";

/**
 * Optimized polling configuration for remote RPC connections.
 * With ~470ms network latency, polling every 2 seconds reduces
 * unnecessary network calls while still being responsive.
 */
const OPTIMIZED_POLLING_CONFIG = {
  pollingInterval: 2000, // 2 seconds - matches network latency
  timeout: 120000, // 2 minutes timeout
};

/**
 * Wait for a transaction receipt with optimized polling settings.
 * This reduces the number of RPC calls by polling less frequently,
 * which is especially beneficial for remote connections with latency.
 * Throws an error if the transaction reverted.
 */
export async function waitForTx(
  hash: `0x${string}`,
  publicClient: PublicClient
) {
  const receipt = await publicClient.waitForTransactionReceipt({
    hash,
    ...OPTIMIZED_POLLING_CONFIG,
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

