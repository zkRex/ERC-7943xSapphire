import { expect } from "chai";
import hre from "hardhat";
import { getAddress, keccak256, toHex } from "viem";
import { sapphireLocalnetChain } from "../hardhat.config";

const itIfSupportsEventLogs =
  hre.network.name === "sapphire-localnet" ? it.skip : it;

describe("Vigil", function () {
  let vigil: any;
  let owner: any;
  let otherAccount: any;
  let publicClient: any;

  async function deployVigilFixture() {
    // Only sapphire-localnet needs custom chain config
    const chain = hre.network.name === "sapphire-localnet" ? sapphireLocalnetChain : undefined;
    
    const [ownerWallet, otherAccountWallet] = await hre.viem.getWalletClients({ chain });
    const client = await hre.viem.getPublicClient({ chain });
    const config = { client: { public: client, wallet: ownerWallet } };
    
    const vigilContract = await hre.viem.deployContract("Vigil", [], config);

    return {
      vigil: vigilContract,
      owner: ownerWallet,
      otherAccount: otherAccountWallet,
      publicClient: client,
    };
  }

  async function getCurrentTimestamp(publicClient: any): Promise<bigint> {
    const block = await publicClient.getBlock();
    return BigInt(block.timestamp);
  }

  beforeEach(async function () {
    const fixture = await deployVigilFixture();
    vigil = fixture.vigil;
    owner = fixture.owner;
    otherAccount = fixture.otherAccount;
    publicClient = fixture.publicClient;
  });

  describe("Deployment", function () {
    it("Should deploy successfully", async function () {
      expect(vigil.address).to.be.a("string");
      expect(vigil.address).to.have.lengthOf(42);
    });
  });

  describe("createSecret", function () {
    it("Should create a secret successfully", async function () {
      const secretBytes = Buffer.from("test secret");
      const hash = await vigil.write.createSecret([
        "test-secret",
        60n,
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);

      await publicClient.waitForTransactionReceipt({ hash });

      const metas = await vigil.read.getMetas([0n, 1n]);
      expect(metas).to.have.lengthOf(1);
      expect(metas[0].name).to.equal("test-secret");
      expect(metas[0].longevity).to.equal(60n);
    });

    itIfSupportsEventLogs("Should emit SecretCreated event", async function () {
      const secretBytes = Buffer.from("test secret");
      const hash = await vigil.write.createSecret([
        "test-secret",
        60n,
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);

      const receipt = await publicClient.waitForTransactionReceipt({ hash });

      const events = await vigil.getEvents.SecretCreated({
        fromBlock: receipt.blockNumber,
        toBlock: receipt.blockNumber,
      });
      expect(events).to.have.lengthOf(1);
      expect(events[0].args.creator).to.equal(
        getAddress(owner.account.address),
      );
      // Indexed string parameters are hashed
      expect(events[0].args.name).to.equal(keccak256(toHex("test-secret")));
      expect(events[0].args.index).to.equal(0n);
    });

    it("Should update last seen timestamp when creating secret", async function () {
      const beforeTimestamp = await getCurrentTimestamp(publicClient);
      const secretBytes = Buffer.from("test secret");
      const hash = await vigil.write.createSecret([
        "test-secret",
        60n,
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);

      await publicClient.waitForTransactionReceipt({ hash });

      const lastSeen = await vigil.read.getLastSeen([
        getAddress(owner.account.address),
      ]);
      expect(lastSeen >= beforeTimestamp).to.be.true;
    });
  });

  describe("revealSecret", function () {
    it("Should revert when trying to reveal secret before expiry", async function () {
      const secretBytes = Buffer.from("test secret");
      const hash = await vigil.write.createSecret([
        "test-secret",
        60n,
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);

      await publicClient.waitForTransactionReceipt({ hash });

      await expect(vigil.read.revealSecret([0n])).to.be.rejected;
    });

    it("Should revert when trying to reveal non-existent secret", async function () {
      await expect(vigil.read.revealSecret([0n])).to.be.rejected;
    });

    it("Should reveal secret after expiry", async function () {
      const secretBytes = Buffer.from("test secret");
      const hash = await vigil.write.createSecret([
        "test-secret",
        5n, // Use 5 seconds for faster test
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);

      await publicClient.waitForTransactionReceipt({ hash });

      // Wait for the secret to expire (5 seconds + buffer)
      await new Promise((resolve) => setTimeout(resolve, 6000));

      const revealedSecret = await vigil.read.revealSecret([0n]);
      const secretString = Buffer.from(
        revealedSecret.slice(2),
        "hex",
      ).toString();
      expect(secretString).to.equal("test secret");
    });

    it("Should reveal secret after creator's last seen + longevity", async function () {
      const secretBytes = Buffer.from("test secret");
      const hash = await vigil.write.createSecret([
        "test-secret",
        5n, // Use 5 seconds for faster test
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);

      await publicClient.waitForTransactionReceipt({ hash });

      const lastSeen = await vigil.read.getLastSeen([
        getAddress(owner.account.address),
      ]);
      const expiryTime = lastSeen + 5n;

      // Wait for the secret to expire (5 seconds + buffer)
      await new Promise((resolve) => setTimeout(resolve, 6000));

      const revealedSecret = await vigil.read.revealSecret([0n]);
      const secretString = Buffer.from(
        revealedSecret.slice(2),
        "hex",
      ).toString();
      expect(secretString).to.equal("test secret");
    });
  });

  describe("getLastSeen", function () {
    it("Should return zero for address that has never been seen", async function () {
      const lastSeen = await vigil.read.getLastSeen([
        getAddress(otherAccount.account.address),
      ]);
      expect(lastSeen).to.equal(0n);
    });

    it("Should return timestamp after creating secret", async function () {
      const beforeTimestamp = await getCurrentTimestamp(publicClient);
      const secretBytes = Buffer.from("test secret");
      const hash = await vigil.write.createSecret([
        "test-secret",
        60n,
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);

      await publicClient.waitForTransactionReceipt({ hash });

      const lastSeen = await vigil.read.getLastSeen([
        getAddress(owner.account.address),
      ]);
      expect(lastSeen >= beforeTimestamp).to.be.true;
    });
  });

  describe("getMetas", function () {
    it("Should return empty array when offset is beyond length", async function () {
      const metas = await vigil.read.getMetas([10n, 5n]);
      expect(metas).to.have.lengthOf(0);
    });

    it("Should return all metas when count exceeds available", async function () {
      const secretBytes1 = Buffer.from("secret 1");
      const hash1 = await vigil.write.createSecret([
        "secret-1",
        60n,
        `0x${secretBytes1.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const secretBytes2 = Buffer.from("secret 2");
      const hash2 = await vigil.write.createSecret([
        "secret-2",
        120n,
        `0x${secretBytes2.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const metas = await vigil.read.getMetas([0n, 10n]);
      expect(metas).to.have.lengthOf(2);
      expect(metas[0].name).to.equal("secret-1");
      expect(metas[1].name).to.equal("secret-2");
    });

    it("Should return paginated metas correctly", async function () {
      const secretBytes1 = Buffer.from("secret 1");
      const hash1 = await vigil.write.createSecret([
        "secret-1",
        60n,
        `0x${secretBytes1.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const secretBytes2 = Buffer.from("secret 2");
      const hash2 = await vigil.write.createSecret([
        "secret-2",
        120n,
        `0x${secretBytes2.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const secretBytes3 = Buffer.from("secret 3");
      const hash3 = await vigil.write.createSecret([
        "secret-3",
        180n,
        `0x${secretBytes3.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash3 });

      const metas1 = await vigil.read.getMetas([0n, 2n]);
      expect(metas1).to.have.lengthOf(2);
      expect(metas1[0].name).to.equal("secret-1");
      expect(metas1[1].name).to.equal("secret-2");

      const metas2 = await vigil.read.getMetas([2n, 2n]);
      expect(metas2).to.have.lengthOf(1);
      expect(metas2[0].name).to.equal("secret-3");
    });
  });

  describe("refreshSecrets", function () {
    it("Should update last seen timestamp", async function () {
      const secretBytes = Buffer.from("test secret");
      const hash1 = await vigil.write.createSecret([
        "test-secret",
        30n,
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const lastSeen1 = await vigil.read.getLastSeen([
        getAddress(owner.account.address),
      ]);

      // Wait a bit for block time to advance
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const hash2 = await vigil.write.refreshSecrets();
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const lastSeen2 = await vigil.read.getLastSeen([
        getAddress(owner.account.address),
      ]);

      expect(lastSeen2 > lastSeen1).to.be.true;
    });

    it("Should extend expiry time when refreshing", async function () {
      const secretBytes = Buffer.from("test secret");
      const hash1 = await vigil.write.createSecret([
        "test-secret",
        10n,
        `0x${secretBytes.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const lastSeen1 = await vigil.read.getLastSeen([
        getAddress(owner.account.address),
      ]);
      const initialExpiry = lastSeen1 + 10n;

      // Wait a bit for block time to advance
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const hash2 = await vigil.write.refreshSecrets();
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const lastSeen2 = await vigil.read.getLastSeen([
        getAddress(owner.account.address),
      ]);
      const newExpiry = lastSeen2 + 10n;

      expect(newExpiry > initialExpiry).to.be.true;

      // Check that secret is not yet expired (should be rejected)
      // We check immediately after refresh, so it should still be protected
      const currentTime = await getCurrentTimestamp(publicClient);
      if (currentTime < initialExpiry) {
        await expect(vigil.read.revealSecret([0n])).to.be.rejected;
      }
    });
  });

  describe("Multiple secrets", function () {
    it("Should handle multiple secrets from different creators", async function () {
      const secretBytes1 = Buffer.from("owner secret");
      const hash1 = await vigil.write.createSecret([
        "owner-secret",
        30n,
        `0x${secretBytes1.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const config = { client: { public: publicClient, wallet: otherAccount } };

      const vigilAsOtherAccount = await hre.viem.getContractAt(
        "Vigil",
        vigil.address,
        config,
      );

      const secretBytes2 = Buffer.from("other secret");
      const hash2 = await vigilAsOtherAccount.write.createSecret([
        "other-secret",
        30n,
        `0x${secretBytes2.toString("hex")}` as `0x${string}`,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const metas = await vigil.read.getMetas([0n, 10n]);
      expect(metas).to.have.lengthOf(2);
      expect(metas[0].creator).to.equal(getAddress(owner.account.address));
      expect(metas[1].creator).to.equal(
        getAddress(otherAccount.account.address),
      );
    });
  });
});

