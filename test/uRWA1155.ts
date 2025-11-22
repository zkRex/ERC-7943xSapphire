import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther } from "viem";
import { sapphireLocalnetChain } from "../hardhat.config";
import { waitForTx, waitForTxs } from "./utils";

const itIfSupportsEventLogs =
  hre.network.name === "sapphire-localnet" ? it.skip : it;

describe("uRWA1155", function () {
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
      "uRWA1155",
      ["https://example.com/{id}.json", ownerWallet.account.address],
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

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);
      
      expect(await token.read.balanceOf([
        getAddress(otherAccount.account.address),
        1n,
      ])).to.equal(parseEther("100"));
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
        token.write.mint([
          getAddress(otherAccount.account.address),
          1n,
          parseEther("100"),
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

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const burnHash = await token.write.burn([1n, parseEther("50")]);
      await waitForTx(burnHash, publicClient);
      
      expect(await token.read.balanceOf([
        getAddress(owner.account.address),
        1n,
      ])).to.equal(parseEther("50"));
    });
  });

  describe("setFrozenTokens", function () {
    it("Should allow FREEZING_ROLE to freeze tokens", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(otherAccount.account.address),
        1n,
        parseEther("50"),
      ]);
      await waitForTx(freezeHash, publicClient);
      
      expect(await token.read.getFrozenTokens([
        getAddress(otherAccount.account.address),
        1n,
      ])).to.equal(parseEther("50"));
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

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const config = { client: { public: publicClient, wallet: owner } };
      const tokenAsOwner = await hre.viem.getContractAt("uRWA1155", token.address, config);

      const transferHash = await tokenAsOwner.write.safeTransferFrom([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
        parseEther("50"),
        "0x",
      ]);
      await waitForTx(transferHash, publicClient);
      
      expect(await token.read.balanceOf([
        getAddress(owner.account.address),
        1n,
      ])).to.equal(parseEther("50"));
      expect(await token.read.balanceOf([
        getAddress(otherAccount.account.address),
        1n,
      ])).to.equal(parseEther("50"));
    });

    it("Should revert transfer when amount exceeds unfrozen balance", async function () {
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

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        1n,
        parseEther("60"),
      ]);
      await waitForTx(freezeHash, publicClient);

      // Verify frozen tokens
      expect(await token.read.getFrozenTokens([
        getAddress(owner.account.address),
        1n,
      ])).to.equal(parseEther("60"));
      expect(await token.read.balanceOf([
        getAddress(owner.account.address),
        1n,
      ])).to.equal(parseEther("100"));
      
      // Verify canTransfer returns false
      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
        parseEther("50"),
      ])).to.be.false;

      const config = { client: { public: publicClient, wallet: owner } };
      const tokenAsOwner = await hre.viem.getContractAt("uRWA1155", token.address, config);
      
      // Should revert because only 40 tokens are unfrozen, but trying to transfer 50
      await expect(
        tokenAsOwner.write.safeTransferFrom([
          getAddress(owner.account.address),
          getAddress(otherAccount.account.address),
          1n,
          parseEther("50"),
          "0x",
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

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        1n,
        parseEther("60"),
      ]);
      await waitForTx(freezeHash, publicClient);

      const forceHash = await token.write.forcedTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
        parseEther("50"),
      ]);
      await waitForTx(forceHash, publicClient);
      
      expect(await token.read.balanceOf([
        getAddress(owner.account.address),
        1n,
      ])).to.equal(parseEther("50"));
      expect(await token.read.balanceOf([
        getAddress(otherAccount.account.address),
        1n,
      ])).to.equal(parseEther("50"));
      // Frozen tokens should be reduced since we transferred from frozen balance
      // Unfrozen was 40, we transferred 50, so we took 10 from frozen: 60 - 10 = 50
      expect(await token.read.getFrozenTokens([
        getAddress(owner.account.address),
        1n,
      ])).to.equal(parseEther("50"));
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

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
        parseEther("50"),
      ])).to.be.true;
    });

    it("Should return false when amount exceeds unfrozen balance", async function () {
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

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        1n,
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        1n,
        parseEther("60"),
      ]);
      await waitForTx(freezeHash, publicClient);

      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
        parseEther("50"),
      ])).to.be.false;
    });
  });
});

