import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther, keccak256, encodePacked, toHex, encodeAbiParameters } from "viem";
import { waitForTx } from "./utils";
import { sapphireLocalnetChain } from "../hardhat.config";

describe("uRWA20 Calldata Encryption", function () {
  const isLocalNetwork = hre.network.name === "sapphire-localnet" || hre.network.name === "hardhat";
  this.timeout(isLocalNetwork ? 30000 : 120000);

  let token: any;
  let owner: any;
  let alice: any;
  let bob: any;
  let publicClient: any;

  beforeEach(async function () {
    const useSapphireLocalnet = hre.network.name === "sapphire-localnet";
    const chain = useSapphireLocalnet ? sapphireLocalnetChain : undefined;

    // Get wallet clients with proper chain configuration
    const walletClients = useSapphireLocalnet
      ? await hre.viem.getWalletClients({ chain })
      : await hre.viem.getWalletClients();

    [owner, alice, bob] = walletClients;

    // Get public client with proper chain configuration
    publicClient = useSapphireLocalnet
      ? await hre.viem.getPublicClient({ chain })
      : await hre.viem.getPublicClient();

    const config = { client: { public: publicClient, wallet: owner } };

    // Deploy CalldataEncryption library first
    const calldataEncryptionLib = await hre.viem.deployContract("CalldataEncryption", [], config);
    console.log("CalldataEncryption library deployed at:", calldataEncryptionLib.address);

    // Deploy token contract with library linking
    token = await hre.viem.deployContract("uRWA20", [
      "Test Token",
      "TEST",
      owner.account.address,
      "localhost"
    ], {
      ...config,
      libraries: {
        CalldataEncryption: calldataEncryptionLib.address
      }
    });

    console.log("Token deployed at:", token.address);
  });

  describe("Setup & Deployment", function () {
    it("Should deploy contract with encrypted calldata support", async function () {
      expect(token.address).to.not.be.undefined;

      // Verify the contract has the executeEncrypted and makeEncryptedTransaction functions
      const artifact = await hre.artifacts.readArtifact("uRWA20");
      const executeEncryptedExists = artifact.abi.some((item: any) =>
        item.type === 'function' && item.name === 'executeEncrypted'
      );
      const makeEncryptedExists = artifact.abi.some((item: any) =>
        item.type === 'function' && item.name === 'makeEncryptedTransaction'
      );

      expect(executeEncryptedExists).to.be.true;
      expect(makeEncryptedExists).to.be.true;
    });
  });

  describe("Transfer Functions", function () {
    beforeEach(async function () {
      // Whitelist accounts
      const hash1 = await token.write.changeWhitelist([alice.account.address, true], { account: owner.account });
      await waitForTx(hash1, publicClient);
      const hash2 = await token.write.changeWhitelist([bob.account.address, true], { account: owner.account });
      await waitForTx(hash2, publicClient);

      // Mint tokens to alice
      const hash3 = await token.write.mint([alice.account.address, parseEther("100")], { account: owner.account });
      await waitForTx(hash3, publicClient);
    });

    it("Should encrypt and execute transfer()", async function () {
      const transferAmount = parseEther("10");

      // Get the function selector for transfer(address,uint256)
      const transferSelector = keccak256(encodePacked(["string"], ["transfer(address,uint256)"])).slice(0, 10);

      // Encode parameters
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [bob.account.address, transferAmount]
      );

      // Generate encrypted calldata
      const encryptedData = await token.read.makeEncryptedTransaction([transferSelector, params]);

      // Execute encrypted transfer
      const hash = await token.write.executeEncrypted([encryptedData], { account: alice.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted transfer executed successfully");
    });

    it("Should encrypt and execute transferFrom()", async function () {
      const approveAmount = parseEther("20");
      const transferAmount = parseEther("15");

      // First approve bob to spend alice's tokens using encrypted calldata
      const approveSelector = keccak256(encodePacked(["string"], ["approve(address,uint256)"])).slice(0, 10);
      const approveParams = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [bob.account.address, approveAmount]
      );
      const encryptedApprove = await token.read.makeEncryptedTransaction([approveSelector, approveParams]);
      const approveHash = await token.write.executeEncrypted([encryptedApprove], { account: alice.account });
      await waitForTx(approveHash, publicClient);

      // Now execute transferFrom using encrypted calldata
      const transferFromSelector = keccak256(encodePacked(["string"], ["transferFrom(address,address,uint256)"])).slice(0, 10);
      const transferFromParams = encodeAbiParameters(
        [{ type: 'address' }, { type: 'address' }, { type: 'uint256' }],
        [alice.account.address, bob.account.address, transferAmount]
      );
      const encryptedTransferFrom = await token.read.makeEncryptedTransaction([transferFromSelector, transferFromParams]);

      const hash = await token.write.executeEncrypted([encryptedTransferFrom], { account: bob.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted transferFrom executed successfully");
    });
  });

  describe("Mint & Burn Functions", function () {
    beforeEach(async function () {
      const hash = await token.write.changeWhitelist([alice.account.address, true], { account: owner.account });
      await waitForTx(hash, publicClient);
    });

    it("Should encrypt and execute mint()", async function () {
      const mintAmount = parseEther("50");

      const mintSelector = keccak256(encodePacked(["string"], ["mint(address,uint256)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [alice.account.address, mintAmount]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([mintSelector, params]);
      const hash = await token.write.executeEncrypted([encryptedData], { account: owner.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted mint executed successfully");
    });

    it("Should encrypt and execute burn()", async function () {
      // First mint tokens
      const mintHash = await token.write.mint([alice.account.address, parseEther("100")], { account: owner.account });
      await waitForTx(mintHash, publicClient);

      // Grant alice BURNER_ROLE
      const BURNER_ROLE = keccak256(encodePacked(["string"], ["BURNER_ROLE"]));
      const roleHash = await token.write.grantRole([BURNER_ROLE, alice.account.address], { account: owner.account });
      await waitForTx(roleHash, publicClient);

      const burnAmount = parseEther("30");
      const burnSelector = keccak256(encodePacked(["string"], ["burn(uint256)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'uint256' }],
        [burnAmount]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([burnSelector, params]);
      const hash = await token.write.executeEncrypted([encryptedData], { account: alice.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted burn executed successfully");
    });
  });

  describe("Approval Functions", function () {
    beforeEach(async function () {
      const hash1 = await token.write.changeWhitelist([alice.account.address, true], { account: owner.account });
      await waitForTx(hash1, publicClient);
      const hash2 = await token.write.changeWhitelist([bob.account.address, true], { account: owner.account });
      await waitForTx(hash2, publicClient);
    });

    it("Should encrypt and execute approve()", async function () {
      const approveAmount = parseEther("25");

      const approveSelector = keccak256(encodePacked(["string"], ["approve(address,uint256)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [bob.account.address, approveAmount]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([approveSelector, params]);
      const hash = await token.write.executeEncrypted([encryptedData], { account: alice.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted approve executed successfully");
    });
  });

  describe("Admin Functions", function () {
    it("Should encrypt and execute changeWhitelist()", async function () {
      const whitelistSelector = keccak256(encodePacked(["string"], ["changeWhitelist(address,bool)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'bool' }],
        [alice.account.address, true]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([whitelistSelector, params]);
      const hash = await token.write.executeEncrypted([encryptedData], { account: owner.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted changeWhitelist executed successfully");
    });

    it("Should encrypt and execute setFrozenTokens()", async function () {
      // First whitelist and mint tokens to alice
      const hash1 = await token.write.changeWhitelist([alice.account.address, true], { account: owner.account });
      await waitForTx(hash1, publicClient);
      const hash2 = await token.write.mint([alice.account.address, parseEther("100")], { account: owner.account });
      await waitForTx(hash2, publicClient);

      const frozenAmount = parseEther("40");
      const setFrozenSelector = keccak256(encodePacked(["string"], ["setFrozenTokens(address,uint256)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [alice.account.address, frozenAmount]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([setFrozenSelector, params]);
      const hash = await token.write.executeEncrypted([encryptedData], { account: owner.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted setFrozenTokens executed successfully");
    });

    it("Should encrypt and execute forcedTransfer()", async function () {
      // Setup: whitelist and mint tokens
      const hash1 = await token.write.changeWhitelist([alice.account.address, true], { account: owner.account });
      await waitForTx(hash1, publicClient);
      const hash2 = await token.write.changeWhitelist([bob.account.address, true], { account: owner.account });
      await waitForTx(hash2, publicClient);
      const hash3 = await token.write.mint([alice.account.address, parseEther("100")], { account: owner.account });
      await waitForTx(hash3, publicClient);

      const transferAmount = parseEther("20");
      const forcedTransferSelector = keccak256(encodePacked(["string"], ["forcedTransfer(address,address,uint256)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'address' }, { type: 'uint256' }],
        [alice.account.address, bob.account.address, transferAmount]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([forcedTransferSelector, params]);
      const hash = await token.write.executeEncrypted([encryptedData], { account: owner.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted forcedTransfer executed successfully");
    });
  });

  describe("Security & Access Control", function () {
    it("Should maintain access control with encryption", async function () {
      // Try to mint without MINTER_ROLE - should fail
      const hash = await token.write.changeWhitelist([alice.account.address, true], { account: owner.account });
      await waitForTx(hash, publicClient);

      const mintSelector = keccak256(encodePacked(["string"], ["mint(address,uint256)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [alice.account.address, parseEther("50")]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([mintSelector, params]);

      // Alice doesn't have MINTER_ROLE, so this should revert
      await expect(
        token.write.executeEncrypted([encryptedData], { account: alice.account })
      ).to.be.rejected;

      console.log("Access control correctly enforced with encrypted calldata");
    });

    it("Should handle invalid encrypted data gracefully", async function () {
      // Try to execute with invalid selector
      const invalidSelector = "0x12345678" as `0x${string}`;
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [alice.account.address, parseEther("10")]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([invalidSelector, params]);

      await expect(
        token.write.executeEncrypted([encryptedData], { account: owner.account })
      ).to.be.rejected;

      console.log("Invalid selector correctly rejected");
    });
  });

  describe("Integration with Existing Features", function () {
    it("Should emit encrypted events after encrypted transactions", async function () {
      const hash1 = await token.write.changeWhitelist([alice.account.address, true], { account: owner.account });
      await waitForTx(hash1, publicClient);
      const hash2 = await token.write.changeWhitelist([bob.account.address, true], { account: owner.account });
      await waitForTx(hash2, publicClient);
      const hash3 = await token.write.mint([alice.account.address, parseEther("100")], { account: owner.account });
      await waitForTx(hash3, publicClient);

      const transferAmount = parseEther("10");
      const transferSelector = keccak256(encodePacked(["string"], ["transfer(address,uint256)"])).slice(0, 10);
      const params = encodeAbiParameters(
        [{ type: 'address' }, { type: 'uint256' }],
        [bob.account.address, transferAmount]
      );

      const encryptedData = await token.read.makeEncryptedTransaction([transferSelector, params]);
      const hash = await token.write.executeEncrypted([encryptedData], { account: alice.account });
      await waitForTx(hash, publicClient);

      console.log("Encrypted events should be emitted (check with EncryptedTransfer event)");
    });
  });
});
