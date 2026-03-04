import { ethers } from "hardhat";

async function main() {
    const [deployer] = await ethers.getSigners();
    const superAdminAddress = process.env.SUPER_ADMIN_WALLET || deployer.address;

    console.log("Deploying contracts with the account:", deployer.address);
    console.log("SuperAdmin account:", superAdminAddress);

    // Deploy Config
    const ConfigFactory = await ethers.getContractFactory("CredentialConfig");
    const config = await ConfigFactory.deploy();
    await config.waitForDeployment();
    const configContract = await config.getAddress();
    console.log(`CredentialConfig deployed to: ${configContract}`);

    // Deploy Authority
    const AuthorityFactory = await ethers.getContractFactory("CredentialAuthority");
    const authority = await AuthorityFactory.deploy();
    await authority.waitForDeployment();
    const authorityContract = await authority.getAddress();
    console.log(`CredentialAuthority deployed to: ${authorityContract}`);

    // Deploy Registry
    const RegistryFactory = await ethers.getContractFactory("CredentialRegistry");
    const registry = await RegistryFactory.deploy();
    await registry.waitForDeployment();
    const registryContract = await registry.getAddress();
    console.log(`CredentialRegistry deployed to: ${registryContract}`);

    // Initialize Config
    await config.initialize(authorityContract, registryContract);
    console.log(`CredentialConfig initialized with Authority & Registry.`);

    // Initialize Authority
    await authority.initialize(superAdminAddress, configContract);
    console.log(`CredentialAuthority initialized with SuperAdmin: ${superAdminAddress} and Config: ${configContract}`);

    // Initialize Registry with Config
    await registry.initialize(configContract);
    console.log(`CredentialRegistry initialized with Config: ${configContract}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
