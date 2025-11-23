import { expect } from "chai";
import hre from "hardhat";
import { getAddress, keccak256, encodePacked } from "viem";
import { simulateContract } from "viem/actions";
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

  // Helper to read from contract with signed queries on Sapphire
  // On Sapphire, view calls must be signed to have a non-zero msg.sender.
  // readContract doesn't sign calls, so we use simulateContract instead which signs the call.
  // This ensures msg.sender is set correctly for VIEWER_ROLE checks.
  async function readToken(
    functionName: any,
    args: any[] = [],
    walletClient: any = owner
  ): Promise<any> {
    if (hre.network.name === "sapphire-localnet") {
      // On Sapphire, use simulateContract to sign the query (required for VIEWER_ROLE checks)
      const abi = await hre.artifacts.readArtifact("uRWA721");
      const result = await simulateContract(walletClient, {
        address: token.address,
        abi: abi.abi,
        functionName,
        args,
        account: walletClient.account,
      } as any);
      return result.result;
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
      "uRWA721",
      ["Test NFT", "TNFT", ownerWallet.account.address],
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
      expect(await readToken("name", [])).to.equal("Test NFT");
      expect(await readToken("symbol", [])).to.equal("TNFT");
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
      
      expect(await readToken("ownerOf", [1n])).to.equal(getAddress(otherAccount.account.address));
    });

    it("Should revert when minting to non-whitelisted account", async function () {
      // Ensure otherAccount is NOT whitelisted
      const hash = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        false,
      ]);
      await waitForTx(hash, publicClient);
      
      // Verify account is not whitelisted
      expect(await readToken("canTransact", [getAddress(otherAccount.account.address)])).to.be.false;
      
      // Use simulateContract to check if it would revert
      await expect(
        token.simulate.safeMint([
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
      
      await expect(readToken("ownerOf", [1n])).to.be.rejected;
    });
  }).timeout(60000);

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
      await waitForTx(freezeHash, publicClient);
      
      expect(await readToken("getFrozenTokens", [
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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

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
      await waitForTx(transferHash, publicClient);
      
      expect(await readToken("ownerOf", [1n])).to.equal(getAddress(otherAccount.account.address));
    });

    it("Should revert transfer when token is frozen", async function () {
      const hash1 = await token.write.changeWhitelist([
        getAddress(owner.account.address),
        true,
      ]);
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

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
      await waitForTx(freezeHash, publicClient);

      // Verify token is frozen
      expect(await readToken("getFrozenTokens", [
        getAddress(owner.account.address),
        1n,
      ])).to.be.true;
      
      // Verify canTransfer returns false
      expect(await readToken("canTransfer", [
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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

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
      await waitForTx(freezeHash, publicClient);

      const forceHash = await token.write.forcedTransfer([
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
      ]);
      await waitForTx(forceHash, publicClient);
      
      expect(await readToken("ownerOf", [1n])).to.equal(getAddress(otherAccount.account.address));
      // Token should be unfrozen after forced transfer
      expect(await readToken("getFrozenTokens", [
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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

      const mintHash = await token.write.safeMint([
        getAddress(owner.account.address),
        1n,
      ]);
      await waitForTx(mintHash, publicClient);

      expect(await readToken("canTransfer", [
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
      const hash2 = await token.write.changeWhitelist([
        getAddress(otherAccount.account.address),
        true,
      ]);
      await waitForTxs([hash1, hash2], publicClient);

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
      await waitForTx(freezeHash, publicClient);

      expect(await readToken("canTransfer", [
        getAddress(owner.account.address),
        getAddress(otherAccount.account.address),
        1n,
      ])).to.be.false;
    });
  });
});

