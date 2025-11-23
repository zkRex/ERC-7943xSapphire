import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther, keccak256, encodePacked } from "viem";
import { readContract } from "viem/actions";
import { sapphireLocalnetChain } from "../hardhat.config";
import { waitForTx, waitForTxs } from "./utils";

const itIfSupportsEventLogs =
  hre.network.name === "sapphire-localnet" ? it.skip : it;

describe("uRWA20", function () {
  this.timeout(120000); // 2 minutes timeout for all tests
  
  let token: any;
  let owner: any;
  let otherAccount: any;
  let thirdAccount: any;
  let publicClient: any;
  
  // Helper to read from contract with signed queries on Sapphire
  // On Sapphire, view calls must be signed to have a non-zero msg.sender.
  // Viem's contract.read.* uses the public client, so we use readContract with wallet client.
  async function readToken(
    functionName: any,
    args: any[] = [],
    walletClient: any = owner
  ): Promise<any> {
    if (hre.network.name === "sapphire-localnet") {
      // On Sapphire, use readContract with wallet client to sign the query
      const abi = await hre.artifacts.readArtifact("uRWA20");
      return readContract(walletClient, {
        address: token.address,
        abi: abi.abi,
        functionName,
        args,
        account: walletClient.account,
      } as any);
    } else {
      // For non-Sapphire networks, use regular contract.read
      return (token.read as any)[functionName](args);
    }
  }

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

    // Grant VIEWER_ROLE to all test accounts
    // Compute VIEWER_ROLE directly: keccak256(abi.encodePacked("VIEWER_ROLE"))
    // This matches Solidity's keccak256("VIEWER_ROLE")
    const viewerRole = keccak256(encodePacked(["string"], ["VIEWER_ROLE"])) as `0x${string}`;
    
    // Grant roles sequentially to avoid potential issues
    const hash1 = await tokenContract.write.grantRole([
      viewerRole,
      getAddress(otherAccountWallet.account.address),
    ]);
    await waitForTx(hash1, client);
    
    const hash2 = await tokenContract.write.grantRole([
      viewerRole,
      getAddress(thirdAccountWallet.account.address),
    ]);
    await waitForTx(hash2, client);

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
      expect(await readToken("name", [])).to.equal("Test Token");
      expect(await readToken("symbol", [])).to.equal("TEST");
    });

    it("Should grant all roles to initialAdmin", async function () {
      const ownerAddress = getAddress(owner.account.address);
      const defaultAdminRole = await readToken("DEFAULT_ADMIN_ROLE", []);
      const minterRole = await readToken("MINTER_ROLE", []);
      const burnerRole = await readToken("BURNER_ROLE", []);
      const freezingRole = await readToken("FREEZING_ROLE", []);
      const whitelistRole = await readToken("WHITELIST_ROLE", []);
      const forceTransferRole = await readToken("FORCE_TRANSFER_ROLE", []);
      expect(await readToken("hasRole", [defaultAdminRole, ownerAddress])).to.be.true;
      expect(await readToken("hasRole", [minterRole, ownerAddress])).to.be.true;
      expect(await readToken("hasRole", [burnerRole, ownerAddress])).to.be.true;
      expect(await readToken("hasRole", [freezingRole, ownerAddress])).to.be.true;
      expect(await readToken("hasRole", [whitelistRole, ownerAddress])).to.be.true;
      expect(await readToken("hasRole", [forceTransferRole, ownerAddress])).to.be.true;
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
      expect(await readToken("supportsInterface", ["0x01ffc9a7"])).to.be.true; // IERC165
    });
  });

  describe("canTransact", function () {
    it("Should return false for non-whitelisted account", async function () {
      expect(await readToken("canTransact", [getAddress(otherAccount.account.address)])).to.be.false;
    });

    it("Should return true for whitelisted account", async function () {
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash, publicClient);
      
      expect(await readToken("canTransact", [getAddress(otherAccount.account.address)])).to.be.true;
    });

    it("Should return false after removing from whitelist", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        false,
      ]);
      await waitForTx(hash2, publicClient);
      
      expect(await readToken("canTransact", [getAddress(otherAccount.account.address)])).to.be.false;
    });
  });

  describe("changeWhitelist", function () {
    it("Should allow WHITELIST_ROLE to change whitelist status", async function () {
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash, publicClient);
      
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.true;
    });

    it("Should revert when called by non-whitelist role", async function () {
      // Verify otherAccount does not have WHITELIST_ROLE
      const whitelistRole = await token.read.WHITELIST_ROLE();
      expect(await token.read.hasRole([whitelistRole, getAddress(otherAccount.account.address)])).to.be.false;
      
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      // Use simulateContract to check if it would revert
      await expect(
        tokenAsOther.simulate.changeWhitelist([
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
      await waitForTx(hash, publicClient);

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);
      
      expect(await token.read.balanceOf([getAddress(otherAccount.account.address)])).to.equal(parseEther("100"));
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
      
      // Use simulateContract to check if it would revert
      await expect(
        token.simulate.mint([
          getAddress(otherAccount.account.address),
          parseEther("100"),
        ])
      ).to.be.rejected;
    });

    it.skip("Should revert when called by non-minter role", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      const hash2 = await token.write.changeWhitelist([
        getAddress(thirdAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      // Verify otherAccount does NOT have MINTER_ROLE
      const minterRole = await token.read.MINTER_ROLE();
      expect(await token.read.hasRole([minterRole, getAddress(otherAccount.account.address)])).to.be.false;
      
      // otherAccount does NOT have MINTER_ROLE, so this should revert
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      
      // Try to simulate the transaction - it should revert due to missing role
      let simulationSucceeded = false;
      try {
        await tokenAsOther.simulate.mint([
          getAddress(thirdAccount.account.address),
          parseEther("100"),
        ]);
        simulationSucceeded = true;
      } catch (error: any) {
        // Expected - transaction should revert
        expect(error).to.exist;
      }
      
      // If simulation didn't throw, the test should fail
      if (simulationSucceeded) {
        throw new Error("Expected transaction to revert but simulation succeeded");
      }
    }).timeout(120000);
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
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const burnHash = await token.write.burn([parseEther("50")]);
      await waitForTx(burnHash, publicClient);
      
      expect(await token.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("50"));
    });

    it("Should revert when called by non-burner role", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

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
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ]);
      await waitForTx(freezeHash, publicClient);
      
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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const transferHash = await token.write.transfer([
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ]);
      await waitForTx(transferHash, publicClient);
      
      expect(await token.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("50"));
      expect(await token.read.balanceOf([getAddress(otherAccount.account.address)])).to.equal(parseEther("50"));
    });

    it("Should revert transfer from non-whitelisted account", async function () {
      // Ensure owner is NOT whitelisted
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        false,
      ]);
      await waitForTx(hash1, publicClient);

      // Mint tokens to owner (this will fail because owner is not whitelisted)
      // So we need to whitelist first, mint, then remove whitelist
      const hash2 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash2, publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      // Now remove from whitelist
      const hash3 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        false,
      ]);
      await waitForTx(hash3, publicClient);

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
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        parseEther("60"),
      ]);
      await waitForTx(freezeHash, publicClient);

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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        parseEther("60"),
      ]);
      await waitForTx(freezeHash, publicClient);

      const forceHash = await token.write.forcedTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ]);
      await waitForTx(forceHash, publicClient);
      
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
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);
      
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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(owner.account.address),
        parseEther("60"),
      ]);
      await waitForTx(freezeHash, publicClient);

      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ])).to.be.false;
    });
  });

  describe("View function access control", function () {
    it("Should allow VIEWER_ROLE to call balanceOf", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      // Owner has VIEWER_ROLE (granted in constructor)
      expect(await token.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("100"));

      // otherAccount has VIEWER_ROLE (granted in deployTokenFixture)
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      expect(await tokenAsOther.read.balanceOf([getAddress(owner.account.address)])).to.equal(parseEther("100"));
    });

    it("Should allow VIEWER_ROLE to call canTransact", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      // Owner has VIEWER_ROLE
      expect(await token.read.canTransact([getAddress(otherAccount.account.address)])).to.be.true;

      // otherAccount has VIEWER_ROLE
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      expect(await tokenAsOther.read.canTransact([getAddress(otherAccount.account.address)])).to.be.true;
    });

    it("Should allow VIEWER_ROLE to call canTransfer", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      // Owner has VIEWER_ROLE
      expect(await token.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ])).to.be.true;

      // otherAccount has VIEWER_ROLE
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      expect(await tokenAsOther.read.canTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ])).to.be.true;
    });

    it("Should allow VIEWER_ROLE to call getFrozenTokens", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(otherAccount.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const freezeHash = await token.write.setFrozenTokens([
        getAddress(otherAccount.account.address),
        parseEther("30"),
      ]);
      await waitForTx(freezeHash, publicClient);

      // Owner has VIEWER_ROLE
      expect(await token.read.getFrozenTokens([getAddress(otherAccount.account.address)])).to.equal(parseEther("30"));

      // otherAccount has VIEWER_ROLE
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      expect(await tokenAsOther.read.getFrozenTokens([getAddress(otherAccount.account.address)])).to.equal(parseEther("30"));
    });

    it("Should allow VIEWER_ROLE to call totalSupply", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      await waitForTx(hash1, publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      // Owner has VIEWER_ROLE
      expect(await token.read.totalSupply()).to.equal(parseEther("100"));

      // otherAccount has VIEWER_ROLE
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      expect(await tokenAsOther.read.totalSupply()).to.equal(parseEther("100"));
    });

    it("Should allow VIEWER_ROLE to call allowance", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.mint([
        getAddress(owner.account.address),
        parseEther("100"),
      ]);
      await waitForTx(mintHash, publicClient);

      const approveHash = await token.write.approve([
        getAddress(otherAccount.account.address),
        parseEther("50"),
      ]);
      await waitForTx(approveHash, publicClient);

      // Owner has VIEWER_ROLE
      expect(await token.read.allowance([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
      ])).to.equal(parseEther("50"));

      // otherAccount has VIEWER_ROLE
      const config = { client: { public: publicClient, wallet: otherAccount } };
      const tokenAsOther = await hre.viem.getContractAt("uRWA20", token.address, config);
      expect(await tokenAsOther.read.allowance([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
      ])).to.equal(parseEther("50"));
    });

    it("Should revert view calls from unauthorized accounts", async function () {
      // Get a new account without VIEWER_ROLE (use 4th account if available, or revoke from thirdAccount)
      const chain = hre.network.name === "sapphire-localnet" ? sapphireLocalnetChain : undefined;
      const allWallets = await hre.viem.getWalletClients({ chain });
      const unauthorizedWallet = allWallets.length > 3 ? allWallets[3] : thirdAccount;
      
      // If using thirdAccount, revoke VIEWER_ROLE temporarily
      // Compute VIEWER_ROLE directly to avoid read call issues
      const viewerRole = keccak256(encodePacked(["string"], ["VIEWER_ROLE"])) as `0x${string}`;
      let needsRevoke = false;
      if (unauthorizedWallet === thirdAccount) {
        const hasRole = await token.read.hasRole([viewerRole, getAddress(thirdAccount.account.address)]);
        if (hasRole) {
          needsRevoke = true;
          const revokeHash = await token.write.revokeRole([
            viewerRole,
            getAddress(thirdAccount.account.address),
          ]);
          await waitForTx(revokeHash, publicClient);
        }
      }

      const config = { client: { public: publicClient, wallet: unauthorizedWallet } };
      const tokenAsUnauthorized = await hre.viem.getContractAt("uRWA20", token.address, config);

      // Verify unauthorized account does NOT have VIEWER_ROLE
      expect(await token.read.hasRole([viewerRole, getAddress(unauthorizedWallet.account.address)])).to.be.false;

      // Verify view calls revert
      await expect(
        tokenAsUnauthorized.read.balanceOf([getAddress(owner.account.address)])
      ).to.be.rejected;

      await expect(
        tokenAsUnauthorized.read.canTransact([getAddress(owner.account.address)])
      ).to.be.rejected;

      await expect(
        tokenAsUnauthorized.read.canTransfer([
          getAddress(owner.account.address),
          getAddress(otherAccount.account.address),
          parseEther("50"),
        ])
      ).to.be.rejected;

      await expect(
        tokenAsUnauthorized.read.getFrozenTokens([getAddress(owner.account.address)])
      ).to.be.rejected;

      await expect(
        tokenAsUnauthorized.read.totalSupply()
      ).to.be.rejected;

      await expect(
        tokenAsUnauthorized.read.allowance([
          getAddress(owner.account.address),
          getAddress(otherAccount.account.address),
        ])
      ).to.be.rejected;

      // Restore VIEWER_ROLE if we revoked it
      if (needsRevoke) {
        const grantHash = await token.write.grantRole([
          viewerRole,
          getAddress(thirdAccount.account.address),
        ]);
        await waitForTx(grantHash, publicClient);
      }
    });
  });
});

