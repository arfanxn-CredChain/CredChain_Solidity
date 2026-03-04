import { expect } from "chai";
import { ethers } from "hardhat";

describe("CredChain", function () {
    let config: any;
    let authority: any;
    let registry: any;
    let superAdmin: any;
    let admin: any;
    let issuer: any;
    let holder: any;
    let relayer: any;
    let extraUser: any;

    beforeEach(async function () {
        [superAdmin, admin, issuer, holder, relayer, extraUser] = await ethers.getSigners();

        const ConfigFactory = await ethers.getContractFactory("CredentialConfig");
        config = await ConfigFactory.deploy();
        await config.waitForDeployment();
        const configContract = await config.getAddress();

        const AuthorityFactory = await ethers.getContractFactory("CredentialAuthority");
        authority = await AuthorityFactory.deploy();
        const authorityContract = await authority.getAddress();

        const RegistryFactory = await ethers.getContractFactory("CredentialRegistry");
        registry = await RegistryFactory.deploy();
        await registry.waitForDeployment();
        const registryContract = await registry.getAddress();

        // Initialize Config
        await config.initialize(authorityContract, registryContract);

        // Initialize everything else
        await authority.initialize(superAdmin.address, configContract);
        await registry.initialize(configContract);
    });

    describe("Initialization", function () {
        it("Should not allow re-initialization", async function () {
            await expect(authority.initialize(superAdmin.address, await config.getAddress())).to.be.revertedWithCustomError(authority, "InvalidInitialization");
            await expect(registry.initialize(await config.getAddress())).to.be.revertedWithCustomError(registry, "InvalidInitialization");
        });

        it("Should set the superAdmin role properly", async function () {
            expect(await authority.userToRole(superAdmin.address)).to.equal(4); // SuperAdmin
            expect(await authority.isAdminOrHigher(superAdmin.address)).to.be.true;
        });
    });

    describe("Role Hierarchy & Signatures", function () {
        it("Should batch update role via valid signature (SuperAdmin -> Admin)", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, admin.address, 3, nonce]
            );
            const digest = ethers.keccak256(packed);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.batchUpdateUserRoleWithSignature(superAdmin.address, [admin.address], [3], nonce, signature)
            ).to.emit(authority, "UserRoleUpdated").withArgs(admin.address, 0, 3, superAdmin.address);

            expect(await authority.userToRole(admin.address)).to.equal(3);
        });

        it("Should revert batch update on invalid signature", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, admin.address, 3, nonce]
            );
            const digest = ethers.keccak256(packed);
            const signature = await extraUser.signMessage(ethers.getBytes(digest));

            await expect(
                authority.batchUpdateUserRoleWithSignature(superAdmin.address, [admin.address], [3], nonce, signature)
            ).to.be.revertedWithCustomError(authority, "InvalidSignatureForbidden");
        });

        it("Should prevent Replay attacks on batch update", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, admin.address, 3, nonce]
            );
            const digest = ethers.keccak256(packed);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature(superAdmin.address, [admin.address], [3], nonce, signature);

            await expect(
                authority.batchUpdateUserRoleWithSignature(superAdmin.address, [admin.address], [3], nonce, signature)
            ).to.be.revertedWithCustomError(authority, "InvalidNonceForbidden");
        });

        it("Should transfer SuperAdmin to a new address", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint256"],
                [superAdmin.address, extraUser.address, nonce]
            );
            const digest = ethers.keccak256(packed);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.transferSuperAdminWithSignature(superAdmin.address, extraUser.address, nonce, signature)
            ).to.emit(authority, "SuperAdminTransferred").withArgs(superAdmin.address, extraUser.address);

            expect(await authority.isSuperAdmin(extraUser.address)).to.be.true;
            expect(await authority.isAdminOrHigher(extraUser.address)).to.be.true;
            expect(await authority.isIssuerOrHigher(extraUser.address)).to.be.true;
        });
    });

    describe("Credential Registry functionality", function () {
        beforeEach(async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, issuer.address, 2, nonce] // Issuer
            );
            const signature = await superAdmin.signMessage(ethers.getBytes(ethers.keccak256(packed)));
            await authority.batchUpdateUserRoleWithSignature(superAdmin.address, [issuer.address], [2], nonce, signature);
        });

        it("Should batch issue credentials successfully & enforce soulbound", async function () {
            const hashes = ["h1", "h2"];
            const holders = [holder.address, extraUser.address];
            const uris = ["u1", "u2"];
            const nonce = await registry.userToNonce(issuer.address);

            const packed = ethers.solidityPacked(
                ["address", "string", "string", "address", "address", "string", "string", "uint256"],
                [
                    issuer.address,
                    hashes[0], hashes[1],
                    holders[0], holders[1],
                    uris[0], uris[1],
                    nonce
                ]
            );
            const signature = await issuer.signMessage(ethers.getBytes(ethers.keccak256(packed)));

            await expect(
                registry.batchIssueCredentialsWithSignature(issuer.address, hashes, holders, uris, nonce, signature)
            ).to.emit(registry, "CredentialIssued");

            const tokenId = ethers.keccak256(ethers.toUtf8Bytes(hashes[0]));
            const idStr = BigInt(tokenId).toString();

            await expect(
                registry.connect(holder).transferFrom(holder.address, admin.address, idStr)
            ).to.be.revertedWithCustomError(registry, "CredentialTransferForbidden");

            // Grant Holder role to holder.address
            const superAdminNonce = await authority.userToNonce(superAdmin.address);
            const saPacked = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, holder.address, 1, superAdminNonce] // Role 1 = Holder
            );
            const saSignature = await superAdmin.signMessage(ethers.getBytes(ethers.keccak256(saPacked)));
            await authority.batchUpdateUserRoleWithSignature(superAdmin.address, [holder.address], [1], superAdminNonce, saSignature);

            expect(await authority.isHolder(holder.address)).to.be.true;
        });

        it("Should batch revoke credentials successfully", async function () {
            const hashes = ["hashToRevoke1", "hashToRevoke2"];
            const holders = [holder.address, extraUser.address];
            const uris = ["u1", "u2"];

            let nonce = await registry.userToNonce(issuer.address);
            let packed = ethers.solidityPacked(
                ["address", "string", "string", "address", "address", "string", "string", "uint256"],
                [issuer.address, hashes[0], hashes[1], holders[0], holders[1], uris[0], uris[1], nonce]
            );
            let signature = await issuer.signMessage(ethers.getBytes(ethers.keccak256(packed)));

            await registry.batchIssueCredentialsWithSignature(issuer.address, hashes, holders, uris, nonce, signature);

            const tId1 = BigInt(ethers.keccak256(ethers.toUtf8Bytes(hashes[0]))).toString();
            const tId2 = BigInt(ethers.keccak256(ethers.toUtf8Bytes(hashes[1]))).toString();

            nonce = await registry.userToNonce(issuer.address);
            packed = ethers.solidityPacked(
                ["address", "uint256", "uint256", "uint256"],
                [issuer.address, tId1, tId2, nonce]
            );
            signature = await issuer.signMessage(ethers.getBytes(ethers.keccak256(packed)));

            await expect(
                registry.batchRevokeCredentialsWithSignature(issuer.address, [tId1, tId2], nonce, signature)
            ).to.emit(registry, "CredentialRevoked");

            const cred = await registry.findCredential(tId1);
            expect(cred.revokedAt).to.be.greaterThan(0);
        });

        it("Should paginate users correctly", async function () {
            const result = await authority.paginateUsers(0, 10);
            expect(result.length).to.equal(2); // SuperAdmin + Issuer (added in beforeEach)

            // Delete user test implicitly via updating to None
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, issuer.address, 0, nonce] // Set Issuer to None
            );
            const signature = await superAdmin.signMessage(ethers.getBytes(ethers.keccak256(packed)));
            await authority.batchUpdateUserRoleWithSignature(superAdmin.address, [issuer.address], [0], nonce, signature);

            const updatedResult = await authority.paginateUsers(0, 10);
            expect(updatedResult.length).to.equal(1); // Issuer deleted from enumerated array
            expect(updatedResult[0]).to.equal(superAdmin.address);
        });

        it("Should properly verify isHolderOfCredentialIds and paginations", async function () {
            const hashes = ["h3", "h4", "h5"];
            const holders = [holder.address, holder.address, extraUser.address];
            const uris = ["u3", "u4", "u5"];
            const nonce = await registry.userToNonce(issuer.address);
            const packed = ethers.solidityPacked(
                ["address", "string", "string", "string", "address", "address", "address", "string", "string", "string", "uint256"],
                [
                    issuer.address,
                    hashes[0], hashes[1], hashes[2],
                    holders[0], holders[1], holders[2],
                    uris[0], uris[1], uris[2],
                    nonce
                ]
            );
            const signature = await issuer.signMessage(ethers.getBytes(ethers.keccak256(packed)));
            await registry.batchIssueCredentialsWithSignature(issuer.address, hashes, holders, uris, nonce, signature);

            const tId1 = BigInt(ethers.keccak256(ethers.toUtf8Bytes(hashes[0]))).toString();
            const tId2 = BigInt(ethers.keccak256(ethers.toUtf8Bytes(hashes[1]))).toString();
            const tId3 = BigInt(ethers.keccak256(ethers.toUtf8Bytes(hashes[2]))).toString();

            // isHolderOfCredentialIds
            expect(await registry.isHolderOfCredentialIds(holder.address, [tId1, tId2])).to.be.true;
            expect(await registry.isHolderOfCredentialIds(holder.address, [tId1, tId3])).to.be.false;

            // paginateCredentialsByIds
            const credsByIds = await registry.paginateCredentialsByIds([tId1, tId2]);
            expect(credsByIds.length).to.equal(2);
            expect(credsByIds[0].hash).to.equal(hashes[0]);

            // paginateCredentialsByHolder
            const holderCreds = await registry.paginateCredentialsByHolder(holder.address, 0, 10);
            expect(holderCreds.length).to.equal(2);

            // paginateCredentials
            const allCreds = await registry.paginateCredentials(0, 10);
            expect(allCreds.length).to.equal(3);
        });
    });

    describe("Relayer Gas Sponsoring (Meta-transactions)", function () {
        it("Should allow a relayer to sponsor gas for batchUpdateUserRoleWithSignature", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, holder.address, 3, nonce]
            );
            const digest = ethers.keccak256(packed);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            const signerBalBefore = await ethers.provider.getBalance(superAdmin.address);
            const relayerBalBefore = await ethers.provider.getBalance(relayer.address);

            // Relayer executes the transaction
            await expect(
                authority.connect(relayer).batchUpdateUserRoleWithSignature(
                    superAdmin.address, [holder.address], [3], nonce, signature
                )
            ).to.emit(authority, "UserRoleUpdated").withArgs(holder.address, 0, 3, superAdmin.address);

            const signerBalAfter = await ethers.provider.getBalance(superAdmin.address);
            const relayerBalAfter = await ethers.provider.getBalance(relayer.address);

            expect(signerBalAfter).to.equal(signerBalBefore);
            expect(relayerBalAfter).to.be.lessThan(relayerBalBefore);

            expect(await authority.userToRole(holder.address)).to.equal(3);
        });

        it("Should allow a relayer to sponsor gas for transferSuperAdminWithSignature", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const packed = ethers.solidityPacked(
                ["address", "address", "uint256"],
                [superAdmin.address, holder.address, nonce]
            );
            const digest = ethers.keccak256(packed);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            const signerBalBefore = await ethers.provider.getBalance(superAdmin.address);
            const relayerBalBefore = await ethers.provider.getBalance(relayer.address);

            // Relayer executes the transaction
            await expect(
                authority.connect(relayer).transferSuperAdminWithSignature(
                    superAdmin.address, holder.address, nonce, signature
                )
            ).to.emit(authority, "SuperAdminTransferred").withArgs(superAdmin.address, holder.address);

            const signerBalAfter = await ethers.provider.getBalance(superAdmin.address);
            const relayerBalAfter = await ethers.provider.getBalance(relayer.address);

            expect(signerBalAfter).to.equal(signerBalBefore);
            expect(relayerBalAfter).to.be.lessThan(relayerBalBefore);

            // Revert the SuperAdmin back to superAdmin.address for remaining tests, via a relayer call
            const reversionNonce = await authority.userToNonce(holder.address);
            const reversionPacked = ethers.solidityPacked(
                ["address", "address", "uint256"],
                [holder.address, superAdmin.address, reversionNonce]
            );
            const reversionDigest = ethers.keccak256(reversionPacked);
            const reversionSignature = await holder.signMessage(ethers.getBytes(reversionDigest));

            await authority.connect(relayer).transferSuperAdminWithSignature(
                holder.address, superAdmin.address, reversionNonce, reversionSignature
            );
        });

        it("Should allow a relayer to sponsor gas for batchIssueCredentialsWithSignature", async function () {
            // Give extraUser Issuer role first
            const adminNonce = await authority.userToNonce(superAdmin.address);
            const rolePacked = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, extraUser.address, 2, adminNonce]
            );
            const roleSig = await superAdmin.signMessage(ethers.getBytes(ethers.keccak256(rolePacked)));
            await authority.batchUpdateUserRoleWithSignature(superAdmin.address, [extraUser.address], [2], adminNonce, roleSig);

            const hashes = ["relayerHash1"];
            const holders = [holder.address];
            const uris = ["relayerUri1"];
            const nonce = await registry.userToNonce(extraUser.address);

            const packed = ethers.solidityPacked(
                ["address", "string", "address", "string", "uint256"],
                [extraUser.address, hashes[0], holders[0], uris[0], nonce]
            );
            const signature = await extraUser.signMessage(ethers.getBytes(ethers.keccak256(packed)));

            const signerBalBefore = await ethers.provider.getBalance(extraUser.address);
            const relayerBalBefore = await ethers.provider.getBalance(relayer.address);

            // Relayer executes the transaction on behalf of the issuer (extraUser)
            await expect(
                registry.connect(relayer).batchIssueCredentialsWithSignature(
                    extraUser.address, hashes, holders, uris, nonce, signature
                )
            ).to.emit(registry, "CredentialIssued");

            const signerBalAfter = await ethers.provider.getBalance(extraUser.address);
            const relayerBalAfter = await ethers.provider.getBalance(relayer.address);

            expect(signerBalAfter).to.equal(signerBalBefore);
            expect(relayerBalAfter).to.be.lessThan(relayerBalBefore);
        });

        it("Should allow a relayer to sponsor gas for batchRevokeCredentialsWithSignature", async function () {
            // Give extraUser Issuer role first
            const adminNonce = await authority.userToNonce(superAdmin.address);
            const rolePacked = ethers.solidityPacked(
                ["address", "address", "uint8", "uint256"],
                [superAdmin.address, extraUser.address, 2, adminNonce]
            );
            const roleSig = await superAdmin.signMessage(ethers.getBytes(ethers.keccak256(rolePacked)));
            await authority.batchUpdateUserRoleWithSignature(superAdmin.address, [extraUser.address], [2], adminNonce, roleSig);

            const hashes = ["relayerHashToRevoke"];
            const holders = [holder.address];
            const uris = ["revokableUri"];

            // Issuer (extraUser) issues one using regular execution
            let nonce = await registry.userToNonce(extraUser.address);
            let packed = ethers.solidityPacked(
                ["address", "string", "address", "string", "uint256"],
                [extraUser.address, hashes[0], holders[0], uris[0], nonce]
            );
            let signature = await extraUser.signMessage(ethers.getBytes(ethers.keccak256(packed)));
            await registry.batchIssueCredentialsWithSignature(extraUser.address, hashes, holders, uris, nonce, signature);

            const tId = BigInt(ethers.keccak256(ethers.toUtf8Bytes(hashes[0]))).toString();

            // Revoke the credential via a relayer
            nonce = await registry.userToNonce(extraUser.address);
            packed = ethers.solidityPacked(
                ["address", "uint256", "uint256"],
                [extraUser.address, tId, nonce]
            );
            signature = await extraUser.signMessage(ethers.getBytes(ethers.keccak256(packed)));

            const signerBalBefore = await ethers.provider.getBalance(extraUser.address);
            const relayerBalBefore = await ethers.provider.getBalance(relayer.address);

            // Relayer executes the transaction on behalf of the issuer (extraUser)
            await expect(
                registry.connect(relayer).batchRevokeCredentialsWithSignature(
                    extraUser.address, [tId], nonce, signature
                )
            ).to.emit(registry, "CredentialRevoked");

            const signerBalAfter = await ethers.provider.getBalance(extraUser.address);
            const relayerBalAfter = await ethers.provider.getBalance(relayer.address);

            expect(signerBalAfter).to.equal(signerBalBefore);
            expect(relayerBalAfter).to.be.lessThan(relayerBalBefore);
        });
    });
});
