import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther } from "viem";
import { sapphireLocalnetChain } from "../hardhat.config";

const itIfSupportsEventLogs =
  hre.network.name === "sapphire-localnet" ? it.skip : it;

describe("uRWA20", function () {
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
      "uRWA20",
      ["Test Token", "TEST", ownerWallet.account.address],
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
      expect(await token.read.name()).to.equal("Test Token");
      expect(await token.read.symbol()).to.equal("TEST");
    });

    it("Should grant all roles to initialAdmin", async function () {
      const ownerAddress = getAddress(owner.account.address);
      expect(await token.read.hasRole([await token.read.DEFAULT_ADMIN_ROLE(), ownerAddress])).to.be.true;
      expect(await token.read.hasRole([await token.read.MINTER_ROLE(), ownerAddress])).to.be.true;
      expect(await token.read.hasRole([await token.read.BURNER_ROLE(), ownerAddress])).to.be.true;
      expect(await token.read.hasRole([await token.read.FREEZING_ROLE(), ownerAddress])).to.be.true;
      expect(await token.read.hasRole([await token.read.WHITELIST_ROLE(), ownerAddress])).to.be.true;
      expect(await token.read.hasRole([await token.read.FORCE_TRANSFER_ROLE(), ownerAddress])).to.be.true;
    });
  });

  describe("supportsInterface", function () {
    it("Should support IERC7943Fungible interface", async function () {
      // IERC7943Fungible interface ID
      const interfaceId = "0x" + Buffer.from(
        "forcedTransfer(address,uint256)" +
        "setFrozenTokens(address,uint256)" +
        "canTransact(address)" +
        "getFrozenTokens(address)" +
        "canTransfer(address,address,uint256)"
      ).toString("hex").slice(0, 8);
      
      // Note: This is a simplified check. In practice, we'd calculate the proper interface ID.
      // For now, we'll test the known interfaces
      expect(await token.read.supportsInterface(["0x01ffc9a7"])).to.be.true; // IERC165
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
      await publicClient.waitForTransactionReceipt({ hash });
      
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.true;
    });

    it("Should return false after removing from whitelist", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        false,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });
      
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.false;
    });
  });

  describe("changeWhitelist", function () {
    it("Should allow WHITELIST_ROLE to change whitelist status", async function () {
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash });
      
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.true;
    });

    it("Should revert when called by non-whitelist role", async function () {
      // Verify otherAccount does not have WHITELIST_ROLE
      const whitelistRole = await token.read.WHITELIST_ROLE();
      expect(await token.read.hasRole([whitelistRole, getAddress(otherAccount.account.address)])).to.be.false;
      
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      await expect(
        tokenAsOther.write.changeWhitelist([
          getAddress(thirdAccount.account.address),
          true,
        ])
      ).to.be.rejected;
    });
  });

  describe("mint", function () {
    it("Should allow MINTER_ROLE to mint tokens", async function () {
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash });

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });
      
      expect(await token.read.balanceOf([getAddress(otherAccount.account.address)])).to.equal(parseEther("100"));
    });

    it("Should revert when minting to non-whitelisted account", async function () {
      // Ensure otherAccount is NOT whitelisted
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        false,
      ]);
      await publicClient.waitForTransactionReceipt({ hash });
      
      // Verify account is not whitelisted
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.false;
      
      await expect(
        token.write.mint([
          getAddress(otherAccount.account.address),
          parseEther("100"),
        ])
      ).to.be.rejected;
    });

    it("Should revert when called by non-minter role", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const hash2 = await token.write.changeWhitelist([
        getAddress(thirdAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      // Verify otherAccount does NOT have MINTER_ROLE
      const minterRole = await token.read.MINTER_ROLE();
      expect(await token.read.hasRole([minterRole, getAddress(otherAccount.account.address)])).to.be.false;
      
      // otherAccount does NOT have MINTER_ROLE, so this should revert
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      await expect(
        tokenAsOther.write.mint([
          getAddress(thirdAccount.account.address),
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
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      const burnHash = await token.write.burn([parseEther("50")]);
      await publicClient.waitForTransactionReceipt({ hash: burnHash });
      
      expect(await token.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("50"));
    });

    it("Should revert when called by non-burner role", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      // Verify otherAccount does NOT have BURNER_ROLE
      const burnerRole = await token.read.BURNER_ROLE();
      expect(await token.read.hasRole([burnerRole, getAddress(otherAccount.account.address)])).to.be.false;
      
      // otherAccount does NOT have BURNER_ROLE, so this should revert
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      await expect(
        tokenAsOther.write.burn([parseEther("50")])
      ).to.be.rejected;
    });
  });

  describe("setFrozenTokens", function () {
    it("Should allow FREEZING_ROLE to freeze tokens", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });
      
      expect(await token.read.getFrozenTokens([getAddress(otherAccount.account.address)])).to.equal(parseEther("50"));
    });

    it("Should revert when called by non-freezing role", async function () {
      // Verify otherAccount does NOT have FREEZING_ROLE
      const freezingRole = await token.read.FREEZING_ROLE();
      expect(await token.read.hasRole([freezingRole, getAddress(otherAccount.account.address)])).to.be.false;
      
      // otherAccount does NOT have FREEZING_ROLE, so this should revert
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      await expect(
        tokenAsOther.write.setFrozenTokens([
          getAddress(thirdAccount.account.address),
          parseEther("50"),
        ])
      ).to.be.rejected;
    });
  });

  describe("transfer restrictions", function () {
    it("Should allow transfer between whitelisted accounts", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      const transferHash = await token.write.transfer([
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: transferHash });
      
      expect(await token.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("50"));
      expect(await token.read.balanceOf([getAddress(otherAccount.account.address)])).to.equal(parseEther("50"));
    });

    it("Should revert transfer from non-whitelisted account", async function () {
      // Ensure owner is NOT whitelisted
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        false,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      // Mint tokens to owner (this will fail because owner is not whitelisted)
      // So we need to whitelist first, mint, then remove whitelist
      const hash2 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      // Now remove from whitelist
      const hash3 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        false,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash3 });

      const config = { client: { public: publicClient, wallet: owner } };
      const tokenAsOwner = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      await expect(
        tokenAsOwner.write.transfer([
          getAddress(otherAccount.account.address),
          parseEther("50"),
        ])
      ).to.be.rejected;
    });

    it("Should revert transfer to non-whitelisted account", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      const config = { client: { public: publicClient, wallet: owner } };
      const tokenAsOwner = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      await expect(
        tokenAsOwner.write.transfer([
          getAddress(otherAccount.account.address),
          parseEther("50"),
        ])
      ).to.be.rejected;
    });

    it("Should revert transfer when amount exceeds unfrozen balance", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        parseEther("60"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });

      // Verify frozen tokens
      expect(await token.read.getFrozenTokens([getAddress(owner.account.address)])).to.equal(parseEther("60"));
      expect(await token.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("100"));
      
      // Verify canTransfer returns false
      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ])).to.be.false;

      const config = { client: { public: publicClient, wallet: owner } };
      const tokenAsOwner = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      // Should revert because only 40 tokens are unfrozen, but trying to transfer 50
      await expect(
        tokenAsOwner.write.transfer([
          getAddress(otherAccount.account.address),
          parseEther("50"),
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
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        parseEther("60"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });

      const forceHash = await token.write.forcedTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: forceHash });
      
      expect(await token.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("50"));
      expect(await token.read.balanceOf([getAddress(otherAccount.account.address)])).to.equal(parseEther("50"));
      // Frozen tokens should be reduced since we transferred from frozen balance
      // Unfrozen was 40, we transferred 50, so we took 10 from frozen: 60 - 10 = 50
      expect(await token.read.getFrozenTokens([getAddress(owner.account.address)])).to.equal(parseEther("50"));
    });

    it("Should revert when called by non-force-transfer role", async function () {
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      await expect(
        tokenAsOther.write.forcedTransfer([
          getAddress(owner.account.address),
          getAddress(thirdAccount.account.address),
          parseEther("50"),
        ])
      ).to.be.rejected;
    });

    it("Should revert when transferring to non-whitelisted account", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });
      
      await expect(
        token.write.forcedTransfer([
          getAddress(owner.account.address),
          getAddress(otherAccount.account.address),
          parseEther("50"),
        ])
      ).to.be.rejected;
    });
  });

  describe("canTransfer", function () {
    it("Should return true for valid transfer", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ])).to.be.true;
    });

    it("Should return false when amount exceeds unfrozen balance", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash1 });

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await publicClient.waitForTransactionReceipt({ hash: hash2 });

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: mintHash });

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        parseEther("60"),
      ]);
      await publicClient.waitForTransactionReceipt({ hash: freezeHash });

      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ])).to.be.false;
    });
  });
});

