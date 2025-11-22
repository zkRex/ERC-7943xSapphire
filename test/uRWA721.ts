import { expect } from "chai";
import hre from "hardhat";
import { getAddress } from "viem";
import { sapphireLocalnetChain } from "../hardhat.config";
import { waitForTx, waitForTxs } from "./utils";

const itIfSupportsEventLogs =
  hre.network.name === "sapphire-localnet" ? it.skip : it;

describe("uRWA721", function () {
  let token: any;
  let owner: any;
  let otherAccount: any;
  let thirdAccount: any;
  let publicClient: any;

  async function deployTokenFixture() {
    const chain = hre.network.name === "sapphire-localnet" ? sapphireLocalnetChain : undefined;
    
    const [ownerWallet, otherAccountWallet, thirdAccountWallet] = await hre.viem.getWalletClients({ chain });
    const client = await hre.viem.getPublicClient({ chain });
    const config = { client: { public: client, wallet: ownerWallet } };
    
    const tokenContract = await hre.viem.deployContract(
      "uRWA721",
      ["Test NFT", "TNFT", ownerWallet.account.address],
      config
    );

    return {
      token: tokenContract,
      owner: ownerWallet,
      otherAccount: otherAccountWallet,
      thirdAccount: thirdAccountWallet,
      publicClient: client,
    };
  }

  beforeEach(async function () {
    const fixture = await deployTokenFixture();
    token = fixture.token;
    owner = fixture.owner;
    otherAccount = fixture.otherAccount;
    thirdAccount = fixture.thirdAccount;
    publicClient = fixture.publicClient;
  });

  describe("Deployment", function () {
    it("Should deploy successfully", async function () {
      expect(token.address).to.be.a("string");
      expect(token.address).to.have.lengthOf(42);
    });

    it("Should have correct name and symbol", async function () {
      expect(await token.read.name()).to.equal("Test NFT");
      expect(await token.read.symbol()).to.equal("TNFT");
    });
  });

  describe("canTransact", function () {
    it("Should return false for non-whitelisted account", async function () {
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.false;
    });

    it("Should return true for whitelisted account", async function () {
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash, publicClient);
      
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.true;
    });
  });

  describe("mint", function () {
    it("Should allow MINTER_ROLE to mint tokens", async function () {
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(otherAccount.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);
      
      expect(await token.read.ownerOf([1n])).to.equal(getAddress(otherAccount.account.address));
    });

    it("Should revert when minting to non-whitelisted account", async function () {
      // Ensure otherAccount is NOT whitelisted
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        false,
      ]);
      await waitForTx(hash, publicClient);
      
      // Verify account is not whitelisted
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.false;
      
      await expect(
        token.write.safeMint([
          getAddress(otherAccount.account.address),
          1n,
        ])
      ).to.be.rejected;
    });
  });

  describe("burn", function () {
    it("Should allow BURNER_ROLE to burn tokens", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(owner.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      const burnHash = await token.write.burn([1n]);
      await waitForTx(burnHash, publicClient);
      
      await expect(token.read.ownerOf([1n])).to.be.rejected;
    });
  });

  describe("setFrozenTokens", function () {
    it("Should allow FREEZING_ROLE to freeze tokens", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(otherAccount.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(otherAccount.account.address),
        1n,
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });
      
      expect(await token.read.getFrozenTokens([
        getAddress(otherAccount.account.address),
        1n,
      ])).to.be.true;
    });
  });

  describe("transfer restrictions", function () {
    it("Should allow transfer between whitelisted accounts", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash2, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(owner.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      const config = { client: { public: publicClient, wallet: owner } };
      const tokenAsOwner = await hre.viem.getContractAt("uRWA721", token.address, config);

      const transferHash = await tokenAsOwner.write.transferFrom([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: transferHash });
      
      expect(await token.read.ownerOf([1n])).to.equal(getAddress(otherAccount.account.address));
    });

    it("Should revert transfer when token is frozen", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash2, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(owner.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        1n,
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });

      // Verify token is frozen
      expect(await token.read.getFrozenTokens([
        getAddress(owner.account.address),
        1n,
      ])).to.be.true;
      
      // Verify canTransfer returns false
      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
      ])).to.be.false;

      const config = { client: { public: publicClient, wallet: owner } };
      const tokenAsOwner = await hre.viem.getContractAt("uRWA721", token.address, config);
      
      await expect(
        tokenAsOwner.write.transferFrom([
          getAddress(owner.account.address),
          getAddress(otherAccount.account.address),
          1n,
        ])
      ).to.be.rejected;
    });
  });

  describe("forcedTransfer", function () {
    it("Should allow FORCE_TRANSFER_ROLE to force transfer tokens", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash2, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(owner.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        1n,
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });

      const forceHash = await token.write.forcedTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: forceHash });
      
      expect(await token.read.ownerOf([1n])).to.equal(getAddress(otherAccount.account.address));
      // Token should be unfrozen after forced transfer
      expect(await token.read.getFrozenTokens([
        getAddress(owner.account.address),
        1n,
      ])).to.be.false;
    });
  });

  describe("canTransfer", function () {
    it("Should return true for valid transfer", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash2, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(owner.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
      ])).to.be.true;
    });

    it("Should return false when token is frozen", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash2, publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(owner.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        1n,
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });

      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
      ])).to.be.false;
    });
  });
});

