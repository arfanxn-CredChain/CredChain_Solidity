import { ethers } from "hardhat";
import hre from "hardhat";
import * as fs from "fs";
import * as path from "path";

/**
 * @file Credential Contract Deployment Script
 * @notice Deploys and initializes the three-contract CredChain system in the correct order.
 * @dev The deployment follows a strict sequence to prevent circular dependencies:
 *   1. Deploy all contracts (uninitialized state)
 *   2. Initialize Config with Authority and Registry addresses
 *   3. Initialize Authority with SuperAdmin and Config addresses
 *   4. Initialize Registry with Config address
 * 
 * @required INITIAL_SUPER_ADMIN_WALLET_ADDRESS - Must be set in environment variables
 */

async function main() {
    // Get the deployer account (first signer from Hardhat config or private key)
    // This account will deploy all contracts and become the "deployer" stored in each contract
    const [deployer] = await ethers.getSigners();

    // Get SuperAdmin address from environment variable
    // This address will receive the SuperAdmin role during Authority initialization
    // CRITICAL: This variable MUST be set - there is no fallback to prevent accidental deployment
    const superAdminAddress = process.env.INITIAL_SUPER_ADMIN_WALLET_ADDRESS;

    // Validate that INITIAL_SUPER_ADMIN_WALLET_ADDRESS is set
    // This is a safety check to prevent deploying without a designated SuperAdmin
    if (!superAdminAddress) {
        throw new Error(
            "INITIAL_SUPER_ADMIN_WALLET_ADDRESS environment variable is required. " +
            "Please set it in your .env file or export it before running this script. " +
            "Example: INITIAL_SUPER_ADMIN_WALLET_ADDRESS=0x123...abc"
        );
    }

    // Log deployment information
    console.log("Deploying contracts with the account:", deployer.address);
    console.log("Initial SuperAdmin account:", superAdminAddress);

    // ============================================================
    // STEP 1: Deploy all three contracts (uninitialized state)
    // ============================================================

    // Deploy CredentialConfig contract
    // This contract acts as the service locator storing Authority and Registry addresses
    const ConfigFactory = await ethers.getContractFactory("CredentialConfig");
    const config = await ConfigFactory.deploy();
    await config.waitForDeployment();
    const configContract = await config.getAddress();
    console.log(`CredentialConfig deployed to: ${configContract}`);

    // Deploy CredentialAuthority contract
    // This contract manages role assignments and signature verification
    const AuthorityFactory = await ethers.getContractFactory("CredentialAuthority");
    const authority = await AuthorityFactory.deploy();
    await authority.waitForDeployment();
    const authorityContract = await authority.getAddress();
    console.log(`CredentialAuthority deployed to: ${authorityContract}`);

    // Deploy CredentialRegistry contract
    // This contract manages soulbound ERC-721 credential NFTs
    const RegistryFactory = await ethers.getContractFactory("CredentialRegistry");
    const registry = await RegistryFactory.deploy();
    await registry.waitForDeployment();
    const registryContract = await registry.getAddress();
    console.log(`CredentialRegistry deployed to: ${registryContract}`);

    // ============================================================
    // STEP 2: Initialize contracts in dependency order
    // ============================================================

    // Initialize CredentialConfig first
    // Config needs Authority and Registry addresses to serve as the source of truth
    await config.initialize(authorityContract, registryContract);
    console.log(`CredentialConfig initialized with Authority & Registry.`);

    // Initialize CredentialAuthority second
    // Authority needs Config address to query Registry, and SuperAdmin address for initial role
    await authority.initialize(superAdminAddress, configContract);
    console.log(`CredentialAuthority initialized with SuperAdmin: ${superAdminAddress} and Config: ${configContract}`);

    // Initialize CredentialRegistry last
    // Registry only needs Config address to query Authority for role checks
    await registry.initialize(configContract);
    console.log(`CredentialRegistry initialized with Config: ${configContract}`);

    // ============================================================
    // DEPLOYMENT COMPLETE
    // All three contracts are now deployed and initialized
    // Save the contract addresses for backend configuration
    // ============================================================

    const network = process.env.HARDHAT_NETWORK || hre.network.name;
    const deployment = {
        network,
        credentialConfig: await config.getAddress(),
        credentialAuthority: await authority.getAddress(),
        credentialRegistry: await registry.getAddress(),
        timestamp: new Date().toISOString(),
    };

    const deploymentsDir = path.join(__dirname, "..", "deployments");
    if (!fs.existsSync(deploymentsDir)) {
        fs.mkdirSync(deploymentsDir, { recursive: true });
    }

    const outputPath = path.join(deploymentsDir, `${network}.json`);
    fs.writeFileSync(outputPath, JSON.stringify(deployment, null, 2));
    console.log(`Deployment artifact saved to ${outputPath}`);
}

// Execute the deployment script
// If any error occurs, log it and exit with error code
main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
