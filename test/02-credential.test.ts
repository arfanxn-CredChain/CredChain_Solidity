import { expect } from "chai";
import { ethers } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

describe("CredentialConfig", function () {
    let config: any;
    let authority: any;
    let registry: any;
    let deployer: HardhatEthersSigner;
    let otherUser: HardhatEthersSigner;

    beforeEach(async function () {
        [deployer, otherUser] = await ethers.getSigners();

        const ConfigFactory = await ethers.getContractFactory("CredentialConfig");
        config = await ConfigFactory.deploy();
        await config.waitForDeployment();

        const AuthorityFactory = await ethers.getContractFactory("CredentialAuthority");
        authority = await AuthorityFactory.deploy();
        await authority.waitForDeployment();

        const RegistryFactory = await ethers.getContractFactory("CredentialRegistry");
        registry = await RegistryFactory.deploy();
        await registry.waitForDeployment();
    });

    describe("Initialization", function () {
        it("Should initialize with valid addresses", async function () {
            const authorityContract = await authority.getAddress();
            const registryContract = await registry.getAddress();

            await config.initialize(authorityContract, registryContract);

            expect(await config.authority()).to.equal(authorityContract);
            expect(await config.registry()).to.equal(registryContract);
        });

        it("Should prevent double initialization", async function () {
            const authorityContract = await authority.getAddress();
            const registryContract = await registry.getAddress();

            await config.initialize(authorityContract, registryContract);

            await expect(
                config.initialize(authorityContract, registryContract)
            ).to.be.revertedWithCustomError(config, "InvalidInitialization");
        });

        it("Should prevent non-deployer from initializing", async function () {
            const authorityContract = await authority.getAddress();
            const registryContract = await registry.getAddress();

            await expect(
                config.connect(otherUser).initialize(authorityContract, registryContract)
            ).to.be.revertedWithCustomError(config, "NotDeployerError");
        });

        it("Should revert on zero address for authority", async function () {
            const registryContract = await registry.getAddress();

            await expect(
                config.initialize(ethers.ZeroAddress, registryContract)
            ).to.be.revertedWithCustomError(config, "InvalidAddressError");
        });

        it("Should revert on zero address for registry", async function () {
            const authorityContract = await authority.getAddress();

            await expect(
                config.initialize(authorityContract, ethers.ZeroAddress)
            ).to.be.revertedWithCustomError(config, "InvalidAddressError");
        });
    });

    describe("Getters", function () {
        it("Should return authority address", async function () {
            const authorityContract = await authority.getAddress();
            const registryContract = await registry.getAddress();

            await config.initialize(authorityContract, registryContract);

            const result = await config.authority();
            expect(result).to.equal(authorityContract);
        });

        it("Should return registry address", async function () {
            const authorityContract = await authority.getAddress();
            const registryContract = await registry.getAddress();

            await config.initialize(authorityContract, registryContract);

            const result = await config.registry();
            expect(result).to.equal(registryContract);
        });
    });
});

describe("CredentialAuthority", function () {
    let config: any;
    let authority: any;
    let registry: any;
    let superAdmin: HardhatEthersSigner;
    let admin: HardhatEthersSigner;
    let issuer: HardhatEthersSigner;
    let holder: HardhatEthersSigner;
    let extraUser: HardhatEthersSigner;
    let relayer: HardhatEthersSigner;

    beforeEach(async function () {
        [superAdmin, admin, issuer, holder, extraUser, relayer] = await ethers.getSigners();

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

        // Initialize Authority
        await authority.initialize(superAdmin.address, configContract);

        // Initialize Registry
        await registry.initialize(configContract);
    });

    function packUserRoles(signer: string, userRoles: { addr: string; role: number }[], nonce: number): string {
        let packed = ethers.solidityPacked(
            ["address", "uint256"],
            [signer, nonce]
        );
        for (const ur of userRoles) {
            packed = ethers.solidityPacked(
                ["bytes", "address", "uint8"],
                [packed, ur.addr, ur.role]
            );
        }
        return ethers.keccak256(packed);
    }

    function packTransferSuperAdmin(signer: string, newSuperAdmin: string, nonce: number): string {
        return ethers.keccak256(
            ethers.solidityPacked(
                ["address", "address", "uint256"],
                [signer, newSuperAdmin, nonce]
            )
        );
    }

    describe("Initialization", function () {
        it("Should initialize with valid addresses", async function () {
            const configContract = await config.getAddress();
            const AuthorityFactory = await ethers.getContractFactory("CredentialAuthority");
            const newAuthority = await AuthorityFactory.deploy();
            await newAuthority.waitForDeployment();

            await newAuthority.initialize(superAdmin.address, configContract);

            expect(await newAuthority.userToRole(superAdmin.address)).to.equal(4); // SuperAdmin
        });

        it("Should prevent double initialization", async function () {
            const configContract = await config.getAddress();

            await expect(
                authority.initialize(superAdmin.address, configContract)
            ).to.be.revertedWithCustomError(authority, "InvalidInitialization");
        });

        it("Should revert on zero address for superAdmin", async function () {
            const configContract = await config.getAddress();
            const AuthorityFactory = await ethers.getContractFactory("CredentialAuthority");
            const newAuthority = await AuthorityFactory.deploy();
            await newAuthority.waitForDeployment();

            await expect(
                newAuthority.initialize(ethers.ZeroAddress, configContract)
            ).to.be.revertedWithCustomError(newAuthority, "InvalidAddressError");
        });

        it("Should revert on zero address for config", async function () {
            const AuthorityFactory = await ethers.getContractFactory("CredentialAuthority");
            const newAuthority = await AuthorityFactory.deploy();
            await newAuthority.waitForDeployment();

            await expect(
                newAuthority.initialize(superAdmin.address, ethers.ZeroAddress)
            ).to.be.revertedWithCustomError(newAuthority, "InvalidAddressError");
        });
    });

    describe("hasRoleOrAbove", function () {
        it("Should return true for SuperAdmin with minimum Admin role", async function () {
            expect(await authority.hasRoleOrAbove(superAdmin.address, 3)).to.be.true;
        });

        it("Should return true for Admin with minimum Issuer role", async function () {
            // Grant Admin role to admin
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: admin.address, role: 3 }],
                nonce: nonce,
                signature: signature
            });

            expect(await authority.hasRoleOrAbove(admin.address, 2)).to.be.true;
        });

        it("Should return false for Holder when minimum role is Issuer", async function () {
            // Grant Holder role
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: holder.address, role: 1 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: holder.address, role: 1 }],
                nonce: nonce,
                signature: signature
            });

            expect(await authority.hasRoleOrAbove(holder.address, 2)).to.be.false;
        });

        it("Should return false for zero address", async function () {
            expect(await authority.hasRoleOrAbove(ethers.ZeroAddress, 1)).to.be.false;
        });

        it("Should return true for exact role match", async function () {
            expect(await authority.hasRoleOrAbove(superAdmin.address, 4)).to.be.true;
        });

        it("Should return false for role above minimum", async function () {
            // Grant Holder role
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: holder.address, role: 1 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: holder.address, role: 1 }],
                nonce: nonce,
                signature: signature
            });

            expect(await authority.hasRoleOrAbove(holder.address, 0)).to.be.true;
        });
    });

    describe("batchUpdateUserRoleWithSignature", function () {
        it("Should batch update role with valid signature", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.batchUpdateUserRoleWithSignature({
                    signer: superAdmin.address,
                    userRoles: [{ addr: admin.address, role: 3 }],
                    nonce: nonce,
                    signature: signature
                })
            ).to.emit(authority, "UserRoleUpdated").withArgs(admin.address, 0, 3, superAdmin.address);

            expect(await authority.userToRole(admin.address)).to.equal(3);
        });

        it("Should batch update role via relayer", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: holder.address, role: 2 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.connect(relayer).batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: holder.address, role: 2 }],
                nonce: nonce,
                signature: signature
            });

            expect(await authority.userToRole(holder.address)).to.equal(2);
        });

        it("Should revert on invalid signature", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            const signature = await extraUser.signMessage(ethers.getBytes(digest));

            await expect(
                authority.batchUpdateUserRoleWithSignature({
                    signer: superAdmin.address,
                    userRoles: [{ addr: admin.address, role: 3 }],
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "InvalidSignatureError");
        });

        it("Should prevent replay attack with invalid nonce", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: admin.address, role: 3 }],
                nonce: nonce,
                signature: signature
            });

            await expect(
                authority.batchUpdateUserRoleWithSignature({
                    signer: superAdmin.address,
                    userRoles: [{ addr: admin.address, role: 3 }],
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "InvalidNonceError");
        });

        it("Should revert on zero address target", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: ethers.ZeroAddress, role: 1 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.batchUpdateUserRoleWithSignature({
                    signer: superAdmin.address,
                    userRoles: [{ addr: ethers.ZeroAddress, role: 1 }],
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "InvalidAddressError");
        });

        it("Should revert when trying to set SuperAdmin role", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: extraUser.address, role: 4 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.batchUpdateUserRoleWithSignature({
                    signer: superAdmin.address,
                    userRoles: [{ addr: extraUser.address, role: 4 }],
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "SuperAdminRoleNotUpdatableError");
        });

        it("Should prevent Admin from updating another Admin", async function () {
            // First, grant Admin role to admin
            let nonce = await authority.userToNonce(superAdmin.address);
            let digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            let signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: admin.address, role: 3 }],
                nonce: nonce,
                signature: signature
            });

            // Also grant Admin role to extraUser so they are a peer Admin
            nonce = await authority.userToNonce(superAdmin.address);
            const peerDigest = packUserRoles(superAdmin.address, [{ addr: extraUser.address, role: 3 }], nonce);
            const peerSignature = await superAdmin.signMessage(ethers.getBytes(peerDigest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: extraUser.address, role: 3 }],
                nonce: nonce,
                signature: peerSignature
            });

            // Now admin tries to grant Admin role to extraUser (peer admin update)
            nonce = await authority.userToNonce(admin.address);
            digest = packUserRoles(admin.address, [{ addr: extraUser.address, role: 3 }], nonce);
            signature = await admin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.connect(admin).batchUpdateUserRoleWithSignature({
                    signer: admin.address,
                    userRoles: [{ addr: extraUser.address, role: 3 }],
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "AdminUpdatePeerAdminRoleError");
        });

        it("Should prevent non-Admin from updating roles", async function () {
            // Grant Holder role to holder
            let nonce = await authority.userToNonce(superAdmin.address);
            let digest = packUserRoles(superAdmin.address, [{ addr: holder.address, role: 1 }], nonce);
            let signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: holder.address, role: 1 }],
                nonce: nonce,
                signature: signature
            });

            // Holder tries to grant Issuer role
            nonce = await authority.userToNonce(holder.address);
            digest = packUserRoles(holder.address, [{ addr: extraUser.address, role: 2 }], nonce);
            signature = await holder.signMessage(ethers.getBytes(digest));

            await expect(
                authority.connect(holder).batchUpdateUserRoleWithSignature({
                    signer: holder.address,
                    userRoles: [{ addr: extraUser.address, role: 2 }],
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "RoleBelowAdminError");
        });

        it("Should revert when batch size exceeds MAX_BATCH_ROLE", async function () {
            const roles: { addr: string; role: number }[] = [];
            for (let i = 0; i < 101; i++) {
                roles.push({ addr: ethers.Wallet.createRandom().address, role: 1 });
            }

            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, roles, nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.batchUpdateUserRoleWithSignature({
                    signer: superAdmin.address,
                    userRoles: roles,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "MaxBatchExceededError");
        });

        it("Should emit UserRoleUpdated event", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: issuer.address, role: 2 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            const tx = authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: issuer.address, role: 2 }],
                nonce: nonce,
                signature: signature
            });

            await expect(tx).to.emit(authority, "UserRoleUpdated");
        });
    });

    describe("transferSuperAdminWithSignature", function () {
        it("Should transfer SuperAdmin with struct params", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packTransferSuperAdmin(superAdmin.address, extraUser.address, nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.transferSuperAdminWithSignature({
                    signer: superAdmin.address,
                    newSuperAdmin: extraUser.address,
                    nonce: nonce,
                    signature: signature
                })
            ).to.emit(authority, "SuperAdminTransferred").withArgs(superAdmin.address, extraUser.address);

            expect(await authority.userToRole(extraUser.address)).to.equal(4);
            expect(await authority.userToRole(superAdmin.address)).to.equal(3);
        });

        it("Should revert on zero address newSuperAdmin", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packTransferSuperAdmin(superAdmin.address, ethers.ZeroAddress, nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.transferSuperAdminWithSignature({
                    signer: superAdmin.address,
                    newSuperAdmin: ethers.ZeroAddress,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "InvalidAddressError");
        });

        it("Should revert when transferring to self", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packTransferSuperAdmin(superAdmin.address, superAdmin.address, nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await expect(
                authority.transferSuperAdminWithSignature({
                    signer: superAdmin.address,
                    newSuperAdmin: superAdmin.address,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(authority, "TransferSuperAdminToSelfError");
        });

        it("Should revert when signer is not SuperAdmin", async function () {
            // First grant Admin role to admin
            let nonce = await authority.userToNonce(superAdmin.address);
            let digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            let signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: admin.address, role: 3 }],
                nonce: nonce,
                signature: signature
            });

            // Admin tries to transfer SuperAdmin
            nonce = await authority.userToNonce(admin.address);
            const transferDigest = packTransferSuperAdmin(admin.address, extraUser.address, nonce);
            const transferSignature = await admin.signMessage(ethers.getBytes(transferDigest));

            await expect(
                authority.connect(admin).transferSuperAdminWithSignature({
                    signer: admin.address,
                    newSuperAdmin: extraUser.address,
                    nonce: nonce,
                    signature: transferSignature
                })
            ).to.be.revertedWithCustomError(authority, "RoleNotSuperAdminError");
        });
    });

    describe("paginateUsers", function () {
        it("Should return paginated users", async function () {
            const result = await authority.paginateUsers(0, 10);
            expect(result.length).to.equal(1);
            expect(result[0]).to.equal(superAdmin.address);
        });

        it("Should return empty array when offset exceeds length", async function () {
            const result = await authority.paginateUsers(100, 10);
            expect(result.length).to.equal(0);
        });
    });

    describe("User management", function () {
        it("Should track new users in paginated list", async function () {
            const nonce = await authority.userToNonce(superAdmin.address);
            const digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            const signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: admin.address, role: 3 }],
                nonce: nonce,
                signature: signature
            });

            const result = await authority.paginateUsers(0, 10);
            expect(result.length).to.equal(2);
        });

        it("Should remove users from list when role set to None", async function () {
            // Grant Admin role first
            let nonce = await authority.userToNonce(superAdmin.address);
            let digest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 3 }], nonce);
            let signature = await superAdmin.signMessage(ethers.getBytes(digest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: admin.address, role: 3 }],
                nonce: nonce,
                signature: signature
            });

            // Revoke role
            nonce = await authority.userToNonce(superAdmin.address);
            const revokeDigest = packUserRoles(superAdmin.address, [{ addr: admin.address, role: 0 }], nonce);
            const revokeSignature = await superAdmin.signMessage(ethers.getBytes(revokeDigest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: admin.address, role: 0 }],
                nonce: nonce,
                signature: revokeSignature
            });

            const result = await authority.paginateUsers(0, 10);
            expect(result.length).to.equal(1);
        });
    });
});

describe("CredentialRegistry", function () {
    let config: any;
    let authority: any;
    let registry: any;
    let superAdmin: HardhatEthersSigner;
    let admin: HardhatEthersSigner;
    let issuer: HardhatEthersSigner;
    let holder: HardhatEthersSigner;
    let extraUser: HardhatEthersSigner;
    let relayer: HardhatEthersSigner;

    beforeEach(async function () {
        [superAdmin, admin, issuer, holder, extraUser, relayer] = await ethers.getSigners();

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

        // Initialize Authority
        await authority.initialize(superAdmin.address, configContract);

        // Initialize Registry
        await registry.initialize(configContract);

        // Grant Issuer role to issuer
        const nonce = await authority.userToNonce(superAdmin.address);
        let packed = ethers.solidityPacked(
            ["address", "uint256"],
            [superAdmin.address, nonce]
        );
        packed = ethers.solidityPacked(
            ["bytes", "address", "uint8"],
            [packed, issuer.address, 2]
        );
        const digest = ethers.keccak256(packed);
        const signature = await superAdmin.signMessage(ethers.getBytes(digest));

        await authority.batchUpdateUserRoleWithSignature({
            signer: superAdmin.address,
            userRoles: [{ addr: issuer.address, role: 2 }],
            nonce: nonce,
            signature: signature
        });
    });

    function computeCredentialId(issuer: string, nonce: number, holder: string, hash: string): bigint {
        return BigInt(ethers.solidityPackedKeccak256(
            ["address", "uint256", "address", "string"],
            [issuer, nonce, holder, hash]
        ));
    }

    function packIssueCredentials(issuer: string, credentials: { holder: string; hash: string; uri: string }[], nonce: number): string {
        let packed = ethers.solidityPacked(
            ["address", "uint256"],
            [issuer, nonce]
        );
        for (const cred of credentials) {
            packed = ethers.solidityPacked(
                ["bytes", "address", "string", "string"],
                [packed, cred.holder, cred.hash, cred.uri]
            );
        }
        return ethers.keccak256(packed);
    }

    function packRevokeCredentials(revoker: string, credentialIds: bigint[], nonce: number): string {
        let packed = ethers.solidityPacked(
            ["address", "uint256"],
            [revoker, nonce]
        );
        for (const id of credentialIds) {
            packed = ethers.solidityPacked(
                ["bytes", "uint256"],
                [packed, id]
            );
        }
        return ethers.keccak256(packed);
    }

    describe("Initialization", function () {
        it("Should initialize with valid config address", async function () {
            expect(await registry.config()).to.equal(await config.getAddress());
        });

        it("Should prevent double initialization", async function () {
            await expect(
                registry.initialize(await config.getAddress())
            ).to.be.revertedWithCustomError(registry, "InvalidInitialization");
        });

it("Should revert on zero address config", async function () {
            const RegistryFactory = await ethers.getContractFactory("CredentialRegistry");
            const newRegistry = await RegistryFactory.deploy();
            await newRegistry.waitForDeployment();

            await expect(
                newRegistry.initialize(ethers.ZeroAddress)
            ).to.be.revertedWithCustomError(newRegistry, "InvalidAddressError");
        });
    });

    describe("batchIssueCredentialsWithSignature", function () {
        it("Should batch issue with struct params", async function () {
            const credentials = [
                { holder: holder.address, hash: "hash1", uri: "uri1" },
                { holder: extraUser.address, hash: "hash2", uri: "uri2" }
            ];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credentials,
                    nonce: nonce,
                    signature: signature
                })
            ).to.emit(registry, "CredentialIssued");

            const credId1 = computeCredentialId(issuer.address, nonce, holder.address, "hash1");
            const cred = await registry.findCredential(credId1);
            expect(cred.holder).to.equal(holder.address);
        });

        it("Should batch issue via relayer", async function () {
            const credentials = [{ holder: holder.address, hash: "relayerHash", uri: "relayerUri" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.connect(relayer).batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credentials,
                nonce: nonce,
                signature: signature
            });

            const credId = computeCredentialId(issuer.address, nonce, holder.address, "relayerHash");
            const cred = await registry.findCredential(credId);
            expect(cred.holder).to.equal(holder.address);
        });

        it("Should revert on invalid signature", async function () {
            const credentials = [{ holder: holder.address, hash: "hash1", uri: "uri1" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await extraUser.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credentials,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(registry, "InvalidSignatureError");
        });

        it("Should prevent replay attack", async function () {
            const credentials = [{ holder: holder.address, hash: "hashReplay", uri: "uriReplay" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credentials,
                nonce: nonce,
                signature: signature
            });

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credentials,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(registry, "InvalidNonceError");
        });

        it("Should revert on duplicate credential (same holder, same hash, active)", async function () {
            const credentials = [{ holder: holder.address, hash: "duplicateHash", uri: "uri1" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address, credentials: credentials, nonce: nonce, signature: signature
            });

            const credId1 = computeCredentialId(issuer.address, nonce, holder.address, "duplicateHash");
            expect((await registry.findCredential(credId1)).holder).to.equal(holder.address);

            const nonce2 = await registry.userToNonce(issuer.address);
            const digest2 = packIssueCredentials(issuer.address, credentials, nonce2);
            const signature2 = await issuer.signMessage(ethers.getBytes(digest2));

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address, credentials: credentials, nonce: nonce2, signature: signature2
                })
            ).to.be.revertedWithCustomError(registry, "IssuedCredentialError");
        });

        it("Should revert on zero address holder", async function () {
            const credentials = [{ holder: ethers.ZeroAddress, hash: "hash1", uri: "uri1" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credentials,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(registry, "InvalidAddressError");
        });

        it("Should revert when batch size exceeds MAX_BATCH_CREDENTIAL", async function () {
            const credentials: { holder: string; hash: string; uri: string }[] = [];
            for (let i = 0; i < 101; i++) {
                credentials.push({
                    holder: ethers.Wallet.createRandom().address,
                    hash: `hash${i}`,
                    uri: `uri${i}`
                });
            }
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credentials,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(registry, "MaxBatchExceededError");
        });

        it("Should emit CredentialIssued event", async function () {
            const credentials = [{ holder: holder.address, hash: "eventHash", uri: "eventUri" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credentials,
                    nonce: nonce,
                    signature: signature
                })
            ).to.emit(registry, "CredentialIssued");
        });

        it("Should allow re-issuing same hash for same holder after revoke", async function () {
            const credentials = [{ holder: holder.address, hash: "reissueHash", uri: "uri1" }];
            let nonce = await registry.userToNonce(issuer.address);
            let digest = packIssueCredentials(issuer.address, credentials, nonce);
            let signature = await issuer.signMessage(ethers.getBytes(digest));
            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address, credentials: credentials, nonce: nonce, signature: signature
            });

            const credId = computeCredentialId(issuer.address, nonce, holder.address, "reissueHash");

            nonce = await registry.userToNonce(issuer.address);
            const revokeDigest = packRevokeCredentials(issuer.address, [credId], nonce);
            const revokeSignature = await issuer.signMessage(ethers.getBytes(revokeDigest));
            await registry.batchRevokeCredentialsWithSignature({
                revoker: issuer.address, credentialIds: [credId], nonce: nonce, signature: revokeSignature
            });

            nonce = await registry.userToNonce(issuer.address);
            digest = packIssueCredentials(issuer.address, credentials, nonce);
            signature = await issuer.signMessage(ethers.getBytes(digest));
            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address, credentials: credentials, nonce: nonce, signature: signature
                })
            ).to.emit(registry, "CredentialIssued");
        });

        it("Should revert when issuing same file hash to a different holder", async function () {
            const hash = "0x" + "ab".repeat(32);
            const uri = "ipfs://test";

            const credsA = [{ holder: holder.address, hash, uri }];
            const nonceA = await registry.userToNonce(issuer.address);
            const digestA = packIssueCredentials(issuer.address, credsA, nonceA);
            const sigA = await issuer.signMessage(ethers.getBytes(digestA));
            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credsA,
                nonce: nonceA,
                signature: sigA,
            });

            const credsB = [{ holder: extraUser.address, hash, uri }];
            const nonceB = await registry.userToNonce(issuer.address);
            const digestB = packIssueCredentials(issuer.address, credsB, nonceB);
            const sigB = await issuer.signMessage(ethers.getBytes(digestB));
            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credsB,
                    nonce: nonceB,
                    signature: sigB,
                })
            ).to.be.revertedWithCustomError(registry, "IssuedCredentialError");
        });

        it("Should allow reissuing a revoked hash to a different holder", async function () {
            const hash = "0x" + "cd".repeat(32);
            const uri = "ipfs://test";

            const credsA = [{ holder: holder.address, hash, uri }];
            let nonce = await registry.userToNonce(issuer.address);
            const issueDigestA = packIssueCredentials(issuer.address, credsA, nonce);
            let sig = await issuer.signMessage(ethers.getBytes(issueDigestA));
            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credsA,
                nonce,
                signature: sig,
            });
            const tokenId = computeCredentialId(issuer.address, nonce, holder.address, hash);

            nonce = await registry.userToNonce(issuer.address);
            const revokeDigest = packRevokeCredentials(issuer.address, [tokenId], nonce);
            sig = await issuer.signMessage(ethers.getBytes(revokeDigest));
            await registry.batchRevokeCredentialsWithSignature({
                revoker: issuer.address,
                credentialIds: [tokenId],
                nonce,
                signature: sig,
            });

            const credsB = [{ holder: extraUser.address, hash, uri }];
            nonce = await registry.userToNonce(issuer.address);
            const issueDigestB = packIssueCredentials(issuer.address, credsB, nonce);
            sig = await issuer.signMessage(ethers.getBytes(issueDigestB));
            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credsB,
                    nonce,
                    signature: sig,
                })
            ).to.not.be.reverted;
        });
    });

    describe("batchRevokeCredentialsWithSignature", function () {
        let issuedCredentialId: bigint;

        beforeEach(async function () {
            // Issue a credential first
            const credentials = [{ holder: holder.address, hash: "revokeHash", uri: "revokeUri" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credentials,
                nonce: nonce,
                signature: signature
            });

            issuedCredentialId = computeCredentialId(issuer.address, nonce, holder.address, "revokeHash");
        });

        it("Should batch revoke with struct params", async function () {
            const credentialIds = [issuedCredentialId];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packRevokeCredentials(issuer.address, credentialIds, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchRevokeCredentialsWithSignature({
                    revoker: issuer.address,
                    credentialIds: credentialIds,
                    nonce: nonce,
                    signature: signature
                })
            ).to.emit(registry, "CredentialRevoked");

            const cred = await registry.findCredential(issuedCredentialId);
            expect(cred.revokedAt).to.be.greaterThan(0);
        });

        it("Should revert when credential not found", async function () {
            const nonexistentId = BigInt(ethers.keccak256(ethers.toUtf8Bytes("nonexistent")));
            const credentialIds = [nonexistentId];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packRevokeCredentials(issuer.address, credentialIds, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchRevokeCredentialsWithSignature({
                    revoker: issuer.address,
                    credentialIds: credentialIds,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(registry, "CredentialNotFoundError");
        });

        it("Should revert when credential already revoked", async function () {
            const credentialIds = [issuedCredentialId];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packRevokeCredentials(issuer.address, credentialIds, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            // First revoke
            await registry.batchRevokeCredentialsWithSignature({
                revoker: issuer.address,
                credentialIds: credentialIds,
                nonce: nonce,
                signature: signature
            });

            // Second revoke should fail
            const nonce2 = await registry.userToNonce(issuer.address);
            const digest2 = packRevokeCredentials(issuer.address, credentialIds, nonce2);
            const signature2 = await issuer.signMessage(ethers.getBytes(digest2));

            await expect(
                registry.batchRevokeCredentialsWithSignature({
                    revoker: issuer.address,
                    credentialIds: credentialIds,
                    nonce: nonce2,
                    signature: signature2
                })
            ).to.be.revertedWithCustomError(registry, "RevokeRevokedCredentialError");
        });

        it("Should prevent non-Issuer from revoking", async function () {
            // First grant Holder role to holder
            const nonce = await authority.userToNonce(superAdmin.address);
            let packed = ethers.solidityPacked(
                ["address", "uint256"],
                [superAdmin.address, nonce]
            );
            packed = ethers.solidityPacked(
                ["bytes", "address", "uint8"],
                [packed, holder.address, 1]
            );
            const roleDigest = ethers.keccak256(packed);
            const roleSignature = await superAdmin.signMessage(ethers.getBytes(roleDigest));

            await authority.batchUpdateUserRoleWithSignature({
                signer: superAdmin.address,
                userRoles: [{ addr: holder.address, role: 1 }],
                nonce: nonce,
                signature: roleSignature
            });

            // Holder tries to revoke
            const credentialIds = [issuedCredentialId];
            const nonce2 = await registry.userToNonce(holder.address);
            const digest = packRevokeCredentials(holder.address, credentialIds, nonce2);
            const signature = await holder.signMessage(ethers.getBytes(digest));

            await expect(
                registry.connect(holder).batchRevokeCredentialsWithSignature({
                    revoker: holder.address,
                    credentialIds: credentialIds,
                    nonce: nonce2,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(registry, "RoleBelowIssuerError");
        });
    });

    describe("Soulbound behavior", function () {
        it("Should prevent transfer of credentials", async function () {
            const credentials = [{ holder: holder.address, hash: "soulboundHash", uri: "soulboundUri" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credentials,
                nonce: nonce,
                signature: signature
            });

            const credId = computeCredentialId(issuer.address, nonce, holder.address, "soulboundHash");

            await expect(
                registry.connect(holder).transferFrom(holder.address, admin.address, credId)
            ).to.be.revertedWithCustomError(registry, "CredentialTransferError");
        });

        it("Should prevent safeTransferFrom of credentials", async function () {
            const credentials = [{ holder: holder.address, hash: "safeTransferHash", uri: "safeTransferUri" }];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credentials,
                nonce: nonce,
                signature: signature
            });

            const credId = computeCredentialId(issuer.address, nonce, holder.address, "safeTransferHash");

            await expect(
                registry["safeTransferFrom(address,address,uint256)"](holder.address, admin.address, credId)
            ).to.be.revertedWithCustomError(registry, "CredentialTransferError");
        });
    });

    describe("Query functions", function () {
        let credentialId1: bigint;
        let credentialId2: bigint;

        beforeEach(async function () {
            const credentials = [
                { holder: holder.address, hash: "queryHash1", uri: "queryUri1" },
                { holder: holder.address, hash: "queryHash2", uri: "queryUri2" }
            ];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credentials,
                nonce: nonce,
                signature: signature
            });

            credentialId1 = computeCredentialId(issuer.address, nonce, holder.address, "queryHash1");
            credentialId2 = computeCredentialId(issuer.address, nonce, holder.address, "queryHash2");
        });

        it("Should find credential by ID", async function () {
            const cred = await registry.findCredential(credentialId1);
            expect(cred.holder).to.equal(holder.address);
            expect(cred.hash).to.equal("queryHash1");
        });

        it("Should revert when credential not found", async function () {
            const nonexistentId = BigInt(ethers.keccak256(ethers.toUtf8Bytes("nonexistent")));

            await expect(
                registry.findCredential(nonexistentId)
            ).to.be.revertedWithCustomError(registry, "CredentialNotFoundError");
        });

        it("Should get credentials by IDs", async function () {
            const creds = await registry.getCredentialsByIds([credentialId1, credentialId2]);
            expect(creds.length).to.equal(2);
            expect(creds[0].hash).to.equal("queryHash1");
            expect(creds[1].hash).to.equal("queryHash2");
        });

        it("Should paginate credentials", async function () {
            const creds = await registry.paginateCredentials(0, 10);
            expect(creds.length).to.be.greaterThanOrEqual(2);
        });

        it("Should paginate credentials by holder", async function () {
            const creds = await registry.paginateCredentialsByHolder(holder.address, 0, 10);
            expect(creds.length).to.equal(2);
        });

        it("Should verify isHolderOfCredentialIds", async function () {
            const isHolder = await registry.isHolderOfCredentialIds(holder.address, [credentialId1, credentialId2]);
            expect(isHolder).to.be.true;

            const isNotHolder = await registry.isHolderOfCredentialIds(extraUser.address, [credentialId1]);
            expect(isNotHolder).to.be.false;
        });

        describe("getCredentialHashStatuses", function () {
            it("Should return None for unknown hash", async function () {
                const fileHash = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
                const statuses = await registry.getCredentialHashStatuses([fileHash]);
                expect(statuses.length).to.equal(1);
                expect(statuses[0].hash).to.equal(fileHash);
                expect(statuses[0].status).to.equal(0);
            });

            it("Should return Issued for active hash after issue", async function () {
                const hash = "0x" + "ef".repeat(32);
                const uri = "ipfs://test";
                const creds = [{ holder: holder.address, hash, uri }];
                const nonce = await registry.userToNonce(issuer.address);
                const issueDigest = packIssueCredentials(issuer.address, creds, nonce);
                const sig = await issuer.signMessage(ethers.getBytes(issueDigest));
                await registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: creds,
                    nonce,
                    signature: sig,
                });
                const fileHashBytes = ethers.keccak256(ethers.toUtf8Bytes(hash));
                const statuses = await registry.getCredentialHashStatuses([fileHashBytes]);
                expect(statuses[0].status).to.equal(1);
            });

            it("Should return Revoked for revoked hash", async function () {
                const hash = "0x" + "ff".repeat(32);
                const uri = "ipfs://test";
                const creds = [{ holder: holder.address, hash, uri }];
                let nonce = await registry.userToNonce(issuer.address);
                const issueDigest = packIssueCredentials(issuer.address, creds, nonce);
                let sig = await issuer.signMessage(ethers.getBytes(issueDigest));
                await registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: creds,
                    nonce,
                    signature: sig,
                });
                const tokenId = computeCredentialId(issuer.address, nonce, holder.address, hash);
                nonce = await registry.userToNonce(issuer.address);
                const revokeDigest = packRevokeCredentials(issuer.address, [tokenId], nonce);
                sig = await issuer.signMessage(ethers.getBytes(revokeDigest));
                await registry.batchRevokeCredentialsWithSignature({
                    revoker: issuer.address,
                    credentialIds: [tokenId],
                    nonce,
                    signature: sig,
                });
                const fileHashBytes = ethers.keccak256(ethers.toUtf8Bytes(hash));
                const statuses = await registry.getCredentialHashStatuses([fileHashBytes]);
                expect(statuses[0].status).to.equal(2);
            });

            it("Should handle empty array", async function () {
                const statuses = await registry.getCredentialHashStatuses([]);
                expect(statuses.length).to.equal(0);
            });
        });
    });

    describe("MAX_BATCH_CREDENTIAL enforcement", function () {
        it("Should revert when issue batch exceeds limit", async function () {
            const credentials: { holder: string; hash: string; uri: string }[] = [];
            for (let i = 0; i < 101; i++) {
                credentials.push({
                    holder: holder.address,
                    hash: `maxBatchHash${i}`,
                    uri: `maxBatchUri${i}`
                });
            }
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await expect(
                registry.batchIssueCredentialsWithSignature({
                    issuer: issuer.address,
                    credentials: credentials,
                    nonce: nonce,
                    signature: signature
                })
            ).to.be.revertedWithCustomError(registry, "MaxBatchExceededError");
        });

        it("Should revert when revoke batch exceeds limit", async function () {
            // Issue 2 credentials first
            const credentials = [
                { holder: holder.address, hash: "revokeMax1", uri: "uri1" },
                { holder: holder.address, hash: "revokeMax2", uri: "uri2" }
            ];
            const nonce = await registry.userToNonce(issuer.address);
            const digest = packIssueCredentials(issuer.address, credentials, nonce);
            const signature = await issuer.signMessage(ethers.getBytes(digest));

            await registry.batchIssueCredentialsWithSignature({
                issuer: issuer.address,
                credentials: credentials,
                nonce: nonce,
                signature: signature
            });

            const credentialIds: bigint[] = [];
            for (let i = 0; i < 101; i++) {
                credentialIds.push(BigInt(i));
            }

            const nonce2 = await registry.userToNonce(issuer.address);
            const revokeDigest = packRevokeCredentials(issuer.address, credentialIds, nonce2);
            const revokeSignature = await issuer.signMessage(ethers.getBytes(revokeDigest));

            await expect(
                registry.batchRevokeCredentialsWithSignature({
                    revoker: issuer.address,
                    credentialIds: credentialIds,
                    nonce: nonce2,
                    signature: revokeSignature
                })
            ).to.be.revertedWithCustomError(registry, "MaxBatchExceededError");
        });
    });
});