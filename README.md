# CredChain — Smart Contracts

Solidity contracts for the CredChain decentralized credential platform.

## Stack

Solidity 0.8.24 · Hardhat 2.28 · OpenZeppelin 5.6.1 · TypeScript · Chai + Mocha (69 tests)

## Contracts

| Contract | Purpose |
|---|---|
| `CredentialBase` | Abstract base: shared errors, deployer protection |
| `CredentialConfig` | Service locator for authority + registry addresses |
| `CredentialAuthority` | Role management (5 tiers), ECDSA signature verification |
| `CredentialRegistry` | Soulbound ERC-721 credential NFTs (issue, revoke, verify) |

### Role Hierarchy

`None(0) → Holder(1) → Issuer(2) → Admin(3) → SuperAdmin(4)`

Mirrored across all CredChain components (Go, React, Python consume this schema).

## Quick Start

```bash
cp .env.example .env
# Set PRIVATE_KEY, RPC URLs, INITIAL_SUPER_ADMIN_WALLET_ADDRESS
npm install
npx hardhat compile
npx hardhat test
```

## Deploy

```bash
# Amoy testnet (recommended)
npx hardhat run scripts/deploy.ts --network amoy

# Polygon mainnet
npx hardhat run scripts/deploy.ts --network polygon

# Local development
npx hardhat node &
npx hardhat run scripts/deploy.ts --network localhost
```

Mumbai is deprecated (retired April 2024). Use Amoy instead.

## Key Commands

| Command | Purpose |
|---|---|
| `npx hardhat compile` | Compile contracts |
| `npx hardhat test` | Run 69 tests |
| `npx hardhat coverage` | Generate coverage report |
| `npx hardhat node` | Start local Ethereum node |

## Related Docs

- [AGENTS.md](AGENTS.md) — Full contract specs, deployment details, architecture
