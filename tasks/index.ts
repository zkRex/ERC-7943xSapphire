import { task } from "hardhat/config";
import { sapphireLocalnetChain } from "../hardhat.config";

task("deploy").setAction(async (_args, hre) => {
  const chain = hre.network.name === "sapphire-localnet" ? sapphireLocalnetChain : undefined;
  let config;
  if (chain) {
    const [walletClient] = await hre.viem.getWalletClients({ chain });
    const publicClient = await hre.viem.getPublicClient({ chain });
    config = { client: { public: publicClient, wallet: walletClient } };
  }
  
  const vigil = await hre.viem.deployContract("Vigil", [], config);

  console.log(`Vigil address: ${vigil.address}`);
  return vigil.address;
});

task("create-secret")
  .addParam("address", "contract address")
  .setAction(async (args, hre) => {
    const chain = hre.network.name === "sapphire-localnet" ? sapphireLocalnetChain : undefined;
    let config;
    let publicClient;
    if (chain) {
      const [walletClient] = await hre.viem.getWalletClients({ chain });
      publicClient = await hre.viem.getPublicClient({ chain });
      config = { client: { public: publicClient, wallet: walletClient } };
    } else {
      publicClient = await hre.viem.getPublicClient();
    }
    const vigil = await hre.viem.getContractAt("Vigil", args.address as `0x${string}`, config);

    const secretBytes = Buffer.from("brussels sprouts");
    const hash = await vigil.write.createSecret([
      "ingredient",
      30n /* seconds */,
      `0x${secretBytes.toString("hex")}` as `0x${string}`,
    ]);
    console.log("Storing a secret in", hash);
    await publicClient.waitForTransactionReceipt({ hash });
  });

task("check-secret")
  .addParam("address", "contract address")
  .setAction(async (args, hre) => {
    const chain = hre.network.name === "sapphire-localnet" ? sapphireLocalnetChain : undefined;
    let config;
    if (chain) {
      const [walletClient] = await hre.viem.getWalletClients({ chain });
      const publicClient = await hre.viem.getPublicClient({ chain });
      config = { client: { public: publicClient, wallet: walletClient } };
    }
    const vigil = await hre.viem.getContractAt("Vigil", args.address as `0x${string}`, config);

    try {
      console.log("Checking the secret");
      await vigil.read.revealSecret([0n]);
      console.log("Uh oh. The secret was available!");
      process.exit(1);
    } catch (e: any) {
      console.log("failed to fetch secret:", e.message);
    }
    console.log("Waiting...");

    await new Promise((resolve) => setTimeout(resolve, 30_000));
    console.log("Checking the secret again");
    const secret = await vigil.read.revealSecret([0n]);
    console.log(
      "The secret ingredient is",
      Buffer.from(secret.slice(2), "hex").toString(),
    );
  });

task("full-vigil").setAction(async (_args, hre) => {
  await hre.run("compile");

  const address = await hre.run("deploy");

  await hre.run("create-secret", { address });
  await hre.run("check-secret", { address });
});

