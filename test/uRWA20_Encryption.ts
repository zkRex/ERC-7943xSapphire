import { expect } from "chai";
import hre from "hardhat";
import { getAddress, parseEther, keccak256, encodePacked, decodeEventLog, hexToSignature, Hex } from "viem";
import { readContract } from "viem/actions";
import { sapphireLocalnetChain } from "../hardhat.config";
import { waitForTx } from "./utils";
import { SiweMessage } from "siwe";

describe("uRWA20 Encryption & Auditing", function () {
    const isLocalNetwork = hre.network.name === "sapphire-localnet" || hre.network.name === "hardhat";
    this.timeout(isLocalNetwork ? 30000 : 120000);

    let token: any;
    let owner: any;
    let user1: any;
    let user2: any;
    let auditor: any;
    let publicClient: any;

    const sessionTokens = new Map<string, string>();

    async function loginAndGetToken(
        tokenContract: any,
        walletClient: any,
        chainId: number
    ): Promise<string> {
        const address = getAddress(walletClient.account.address);

        if (sessionTokens.has(address)) {
            return sessionTokens.get(address)!;
        }

        const domain = await tokenContract.read.domain();

        const siweMsg = new SiweMessage({
            domain,
            address,
            uri: `http://${domain}`,
            version: "1",
            chainId,
            statement: "Sign in to access uRWA20 token",
            issuedAt: new Date().toISOString(),
        });

        const message = siweMsg.prepareMessage();

        const signatureHex = await walletClient.signMessage({
            message
        }) as Hex;

        const sig = hexToSignature(signatureHex);

        const token = await tokenContract.read.login([message, sig]);

        sessionTokens.set(address, token);

        return token;
    }

    async function readDecryptedData(walletClient: any) {
        if (hre.network.name === "sapphire-localnet") {
            const sessionToken = await loginAndGetToken(token, walletClient, sapphireLocalnetChain.id);
            const abi = await hre.artifacts.readArtifact("uRWA20");
            return readContract(walletClient, {
                address: token.address,
                abi: abi.abi,
                functionName: "viewLastDecryptedData",
                args: [sessionToken],
                account: walletClient.account
            } as any);
        } else {
            const config = { client: { public: publicClient, wallet: walletClient } };
            const tokenAsWallet = await hre.viem.getContractAt("uRWA20", token.address, config);
            return tokenAsWallet.read.viewLastDecryptedData(["0x"]);
        }
    }

    async function deployTokenFixture() {
        const useSapphireLocalnet = hre.network.name === "sapphire-localnet";
        const chain = useSapphireLocalnet ? sapphireLocalnetChain : undefined;

        const walletClients = useSapphireLocalnet
            ? await hre.viem.getWalletClients({ chain })
            : await hre.viem.getWalletClients();

        // We need at least 4 accounts: owner, user1, user2, auditor
        const [ownerWallet, user1Wallet, user2Wallet, auditorWallet] = walletClients;

        // Ensure accounts are distinct
        expect(getAddress(auditorWallet.account.address)).to.not.equal(getAddress(ownerWallet.account.address));
        expect(getAddress(auditorWallet.account.address)).to.not.equal(getAddress(user1Wallet.account.address));
        expect(getAddress(auditorWallet.account.address)).to.not.equal(getAddress(user2Wallet.account.address));

        const client = useSapphireLocalnet
            ? await hre.viem.getPublicClient({ chain })
            : await hre.viem.getPublicClient();

        const config = { client: { public: client, wallet: ownerWallet } };

        const tokenContract = await hre.viem.deployContract(
            "uRWA20",
            [
                "Test Token",
                "TEST",
                ownerWallet.account.address,
                "localhost:3000"
            ],
            config
        );

        // Whitelist users for transfers
        const whitelistRole = await tokenContract.read.WHITELIST_ROLE();

        // Whitelist user1
        let hash = await tokenContract.write.changeWhitelist([
            getAddress(user1Wallet.account.address),
            true,
        ]);
        await waitForTx(hash, client);

        // Whitelist user2
        hash = await tokenContract.write.changeWhitelist([
            getAddress(user2Wallet.account.address),
            true,
        ]);
        await waitForTx(hash, client);

        // Mint tokens to user1
        hash = await tokenContract.write.mint([
            getAddress(user1Wallet.account.address),
            parseEther("100"),
        ]);
        await waitForTx(hash, client);

        return {
            token: tokenContract,
            owner: ownerWallet,
            user1: user1Wallet,
            user2: user2Wallet,
            auditor: auditorWallet,
            publicClient: client,
        };
    }

    beforeEach(async function () {
        const fixture = await deployTokenFixture();
        token = fixture.token;
        owner = fixture.owner;
        user1 = fixture.user1;
        user2 = fixture.user2;
        auditor = fixture.auditor;
        publicClient = fixture.publicClient;

        sessionTokens.clear();
    });

    describe("Encrypted Events & Decryption", function () {
        it("Should emit EncryptedTransfer and allow sender to decrypt", async function () {
            // User1 transfers to User2
            const config = { client: { public: publicClient, wallet: user1 } };
            const tokenAsUser1 = await hre.viem.getContractAt("uRWA20", token.address, config);

            const hash = await tokenAsUser1.write.transfer([
                getAddress(user2.account.address),
                parseEther("10"),
            ]);
            const receipt = await waitForTx(hash, publicClient);

            // Find EncryptedTransfer event
            // Event signature: event EncryptedTransfer(bytes encryptedData)
            const encryptedTransferTopic = keccak256(encodePacked(["string"], ["EncryptedTransfer(bytes)"]));

            const log = receipt.logs.find((l: any) => l.topics[0] === encryptedTransferTopic);
            expect(log).to.not.be.undefined;

            // Decode the log to get encryptedData
            const abi = await hre.artifacts.readArtifact("uRWA20");
            const decodedLog = decodeEventLog({
                abi: abi.abi,
                data: log.data,
                topics: log.topics,
            });
            const encryptedData = (decodedLog.args as any).encryptedData;

            // User1 (sender) should be able to decrypt
            const decryptHash = await tokenAsUser1.write.processDecryption([encryptedData]);
            await waitForTx(decryptHash, publicClient);

            // Check decrypted data
            const data = await readDecryptedData(user1);
            expect(getAddress(data[0])).to.equal(getAddress(user1.account.address)); // from
            expect(getAddress(data[1])).to.equal(getAddress(user2.account.address)); // to
            expect(data[2]).to.equal(parseEther("10")); // amount
            expect(data[3]).to.equal("transfer"); // action
        });

        it("Should allow receiver to decrypt", async function () {
            // User1 transfers to User2
            const config1 = { client: { public: publicClient, wallet: user1 } };
            const tokenAsUser1 = await hre.viem.getContractAt("uRWA20", token.address, config1);

            const hash = await tokenAsUser1.write.transfer([
                getAddress(user2.account.address),
                parseEther("10"),
            ]);
            const receipt = await waitForTx(hash, publicClient);

            // Get encrypted data
            const abi = await hre.artifacts.readArtifact("uRWA20");
            const encryptedTransferTopic = keccak256(encodePacked(["string"], ["EncryptedTransfer(bytes)"]));
            const log = receipt.logs.find((l: any) => l.topics[0] === encryptedTransferTopic);
            const decodedLog = decodeEventLog({
                abi: abi.abi,
                data: log.data,
                topics: log.topics,
            });
            const encryptedData = (decodedLog.args as any).encryptedData;

            // User2 (receiver) should be able to decrypt
            const config2 = { client: { public: publicClient, wallet: user2 } };
            const tokenAsUser2 = await hre.viem.getContractAt("uRWA20", token.address, config2);

            const decryptHash = await tokenAsUser2.write.processDecryption([encryptedData]);
            await waitForTx(decryptHash, publicClient);

            const data = await readDecryptedData(user2);
            expect(getAddress(data[0])).to.equal(getAddress(user1.account.address));
            expect(getAddress(data[1])).to.equal(getAddress(user2.account.address));
            expect(data[2]).to.equal(parseEther("10"));
        });

        it("Should NOT allow unauthorized user to decrypt", async function () {
            // User1 transfers to User2
            const config1 = { client: { public: publicClient, wallet: user1 } };
            const tokenAsUser1 = await hre.viem.getContractAt("uRWA20", token.address, config1);

            const hash = await tokenAsUser1.write.transfer([
                getAddress(user2.account.address),
                parseEther("10"),
            ]);
            const receipt = await waitForTx(hash, publicClient);

            // Get encrypted data
            const abi = await hre.artifacts.readArtifact("uRWA20");
            const encryptedTransferTopic = keccak256(encodePacked(["string"], ["EncryptedTransfer(bytes)"]));
            const log = receipt.logs.find((l: any) => l.topics[0] === encryptedTransferTopic);
            const decodedLog = decodeEventLog({
                abi: abi.abi,
                data: log.data,
                topics: log.topics,
            });
            const encryptedData = (decodedLog.args as any).encryptedData;

            // Auditor (initially unauthorized) should NOT be able to decrypt
            const configAuditor = { client: { public: publicClient, wallet: auditor } };
            const tokenAsAuditor = await hre.viem.getContractAt("uRWA20", token.address, configAuditor);

            // Verify auditor has no roles/permissions
            const viewerRole = await token.read.VIEWER_ROLE();
            expect(await token.read.hasRole([viewerRole, getAddress(auditor.account.address)])).to.be.false;

            const mainAuditorRole = await token.read.MAIN_AUDITOR_ROLE();
            expect(await token.read.hasRole([mainAuditorRole, getAddress(auditor.account.address)])).to.be.false;

            expect(await token.read.checkAuditorPermission([getAddress(auditor.account.address), getAddress(user1.account.address)])).to.be.false;

            // Should revert
            await expect(
                auditor.writeContractSync({
                    address: token.address,
                    abi: abi.abi,
                    functionName: 'processDecryption',
                    args: [encryptedData],
                    throwOnReceiptRevert: true
                })
            ).to.be.rejected;
        });
    });

    describe("Auditor Permissions", function () {
        it("Should allow authorized auditor to decrypt specific address data", async function () {
            // User1 transfers to User2
            const config1 = { client: { public: publicClient, wallet: user1 } };
            const tokenAsUser1 = await hre.viem.getContractAt("uRWA20", token.address, config1);

            const hash = await tokenAsUser1.write.transfer([
                getAddress(user2.account.address),
                parseEther("10"),
            ]);
            const receipt = await waitForTx(hash, publicClient);

            // Get encrypted data
            const abi = await hre.artifacts.readArtifact("uRWA20");
            const encryptedTransferTopic = keccak256(encodePacked(["string"], ["EncryptedTransfer(bytes)"]));
            const log = receipt.logs.find((l: any) => l.topics[0] === encryptedTransferTopic);
            const decodedLog = decodeEventLog({
                abi: abi.abi,
                data: log.data,
                topics: log.topics,
            });
            const encryptedData = (decodedLog.args as any).encryptedData;

            // Grant auditor permission for User1
            // grantAuditorPermission(auditor, duration, fullAccess, [addresses])
            const grantHash = await token.write.grantAuditorPermission([
                getAddress(auditor.account.address),
                3600n, // 1 hour
                false, // no full access
                [getAddress(user1.account.address)], // only User1
            ]);
            await waitForTx(grantHash, publicClient);

            // Auditor should now be able to decrypt
            const configAuditor = { client: { public: publicClient, wallet: auditor } };
            const tokenAsAuditor = await hre.viem.getContractAt("uRWA20", token.address, configAuditor);

            const decryptHash = await tokenAsAuditor.write.processDecryption([encryptedData]);
            await waitForTx(decryptHash, publicClient);

            const data = await readDecryptedData(auditor);
            expect(getAddress(data[0])).to.equal(getAddress(user1.account.address));
        });

        it("Should allow full access auditor to decrypt any data", async function () {
            // User1 transfers to User2
            const config1 = { client: { public: publicClient, wallet: user1 } };
            const tokenAsUser1 = await hre.viem.getContractAt("uRWA20", token.address, config1);

            const hash = await tokenAsUser1.write.transfer([
                getAddress(user2.account.address),
                parseEther("10"),
            ]);
            const receipt = await waitForTx(hash, publicClient);

            // Get encrypted data
            const abi = await hre.artifacts.readArtifact("uRWA20");
            const encryptedTransferTopic = keccak256(encodePacked(["string"], ["EncryptedTransfer(bytes)"]));
            const log = receipt.logs.find((l: any) => l.topics[0] === encryptedTransferTopic);
            const decodedLog = decodeEventLog({
                abi: abi.abi,
                data: log.data,
                topics: log.topics,
            });
            const encryptedData = (decodedLog.args as any).encryptedData;

            // Grant full access auditor permission
            const grantHash = await token.write.grantAuditorPermission([
                getAddress(auditor.account.address),
                3600n, // 1 hour
                true, // full access
                [], // empty list
            ]);
            await waitForTx(grantHash, publicClient);

            // Auditor should be able to decrypt
            const configAuditor = { client: { public: publicClient, wallet: auditor } };
            const tokenAsAuditor = await hre.viem.getContractAt("uRWA20", token.address, configAuditor);

            const decryptHash = await tokenAsAuditor.write.processDecryption([encryptedData]);
            await waitForTx(decryptHash, publicClient);

            const data = await readDecryptedData(auditor);
            expect(getAddress(data[0])).to.equal(getAddress(user1.account.address));
        });

        it("Should revoke auditor permission", async function () {
            // Grant full access first
            const grantHash = await token.write.grantAuditorPermission([
                getAddress(auditor.account.address),
                3600n,
                true,
                [],
            ]);
            await waitForTx(grantHash, publicClient);

            // Revoke permission
            const revokeHash = await token.write.revokeAuditorPermission([
                getAddress(auditor.account.address),
            ]);
            await waitForTx(revokeHash, publicClient);

            // Create a transfer
            const config1 = { client: { public: publicClient, wallet: user1 } };
            const tokenAsUser1 = await hre.viem.getContractAt("uRWA20", token.address, config1);
            const hash = await tokenAsUser1.write.transfer([
                getAddress(user2.account.address),
                parseEther("10"),
            ]);
            const receipt = await waitForTx(hash, publicClient);

            // Get encrypted data
            const abi = await hre.artifacts.readArtifact("uRWA20");
            const encryptedTransferTopic = keccak256(encodePacked(["string"], ["EncryptedTransfer(bytes)"]));
            const log = receipt.logs.find((l: any) => l.topics[0] === encryptedTransferTopic);
            const decodedLog = decodeEventLog({
                abi: abi.abi,
                data: log.data,
                topics: log.topics,
            });
            const encryptedData = (decodedLog.args as any).encryptedData;

            // Auditor should NOT be able to decrypt anymore
            const configAuditor = { client: { public: publicClient, wallet: auditor } };
            const tokenAsAuditor = await hre.viem.getContractAt("uRWA20", token.address, configAuditor);

            await expect(
                auditor.writeContractSync({
                    address: token.address,
                    abi: abi.abi,
                    functionName: 'processDecryption',
                    args: [encryptedData],
                    throwOnReceiptRevert: true
                })
            ).to.be.rejected;
        });
    });
});
