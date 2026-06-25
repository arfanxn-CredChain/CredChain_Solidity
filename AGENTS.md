# CredChain Solidity - Agent Instructions

Smart contracts for the CredChain decentralized credential platform. Four contracts implement a role-based authority + soulbound ERC-721 credential registry, wired together through a service-locator config contract. Hardhat 2.28 + Solidity 0.8.24 + OpenZeppelin 5.6.1.

This file is the authoritative reference for AI assistants and engineers working in `CredChain_Solidity/`.

## Repo Position

Sibling to `CredChain_Golang/` (backend API), `CredChain_React/` (frontend), and `CredChain_Python/` (AI service).

- **Consumers:** the Go backend consumes contracts via `abigen`-generated bindings located at `CredChain_Golang/infrastructure/chain/contracts/{authority.go,registry.go}`. Those bindings are generated artifacts — **never hand-edit**. Go-side `chain.AuthorityBinding` / `chain.RegistryBinding` interfaces are satisfied structurally by the abigen output, which keeps the backend testable without a live RPC.
- **Deploy targets:** Polygon mainnet + Mumbai testnet (configured in `hardhat.config.ts`).
- **Initial role bootstrap:** the SuperAdmin wallet address must be supplied at deploy time. The Go backend's `init-super-admin` CLI then verifies on-chain that the wallet actually holds the SuperAdmin role before allowing database initialization.

## Critical Commands

```bash
npx hardhat compile                                   # compile contracts → artifacts/ + typechain-types/
npx hardhat test                                      # run all tests (62 tests, chai/mocha)
npx hardhat test test/02-credential.test.ts           # run a single test file
npx hardhat coverage                                  # solidity-coverage report → coverage/ + coverage.json
npx hardhat run scripts/deploy.ts --network polygon   # deploy to Polygon mainnet
npx hardhat run scripts/deploy.ts --network mumbai    # deploy to Mumbai testnet
npx hardhat clean                                     # remove artifacts/ + cache/
```

No CI pipeline is configured. No lint script exists in `package.json`. Tests must pass before any push (see Deployment section).

## Environment Setup

Copy `.env.example` → `.env` and fill in:

```bash
PRIVATE_KEY=<deployer_private_key>                            # 64-char hex, no 0x prefix
POLYGON_RPC_URL=https://polygon-rpc.com/
MUMBAI_RPC_URL=https://rpc-mumbai.maticvigil.com/
INITIAL_SUPER_ADMIN_WALLET_ADDRESS=0x...                      # REQUIRED at deploy time
```

`.env` is gitignored. `deploy.ts` throws immediately if `INITIAL_SUPER_ADMIN_WALLET_ADDRESS` is unset — there is no fallback, by design. Tests run on the in-process Hardhat network and do not require any env vars.

## Project Architecture

```
CredChain_Solidity/
  contracts/
    CredentialBase.sol           # abstract base: shared errors + deployer protection
    CredentialConfig.sol         # service locator: authority + registry addresses
    CredentialAuthority.sol      # role management + ECDSA signature verification
    CredentialRegistry.sol       # soulbound ERC-721 credential NFTs
  scripts/
    deploy.ts                    # deploys + initializes all 3 contracts in order
  test/
    01-deploy.test.ts            # 2 tests: deployment env-var validation
    02-credential.test.ts        # 60 tests: contract behavior across all 4 contracts
  artifacts/                     # compiled contract artifacts (gitignored)
  cache/                         # hardhat compilation cache (gitignored)
  typechain-types/               # generated TypeScript bindings (gitignored)
  coverage/                      # solidity-coverage HTML report (gitignored)
  coverage.json                  # coverage summary
  hardhat.config.ts              # solc 0.8.24, viaIR, cancun, optimizer 200 runs
  tsconfig.json
  package.json
  .env / .env.example            # .env gitignored
```

All four contracts inherit from `CredentialBase`. `Config` is the only contract holding addresses; `Authority` and `Registry` reach each other through `Config`.

## Key Patterns & Conventions

### Contract Inheritance & Initializable Pattern

All four contracts inherit from `CredentialBase`, which itself extends OpenZeppelin's `Initializable`. State setup happens in `initialize(...)` functions guarded by the `initializer` modifier — **not in constructors**. Constructors only set the `deployer` immutable. This pattern keeps the contracts upgrade-ready (even though no upgrade proxy is currently deployed) and ensures every contract can be wired post-deploy without circular-dependency problems.

`_requireDeployer()` (defined in `CredentialBase`) gates every `initialize` function so only the original deployer can wire the system.

### Error Naming (`*Error` suffix)

Every custom error ends with `Error`. Shared errors live in `CredentialBase`:

- `InvalidAddressError`, `InvalidSignatureError`, `InvalidNonceError`
- `NotDeployerError`, `RoleBelowAdminError`, `RoleBelowIssuerError`, `RoleNotSuperAdminError`
- `MaxBatchExceededError`

Contract-specific errors are declared in the contract that owns them:

- `CredentialAuthority`: `SuperAdminRoleNotUpdatableError`, `AdminUpdatePeerAdminRoleError`, `TransferSuperAdminToSelfError`, `SameRoleUpdateError`
- `CredentialRegistry`: `CredentialTransferError`, `IssuedCredentialError`, `RevokeRevokedCredentialError`, `CredentialNotFoundError`

Always raise the most specific error available; do not use generic `require` strings.

### Calldata Struct Params for Signature Functions

All signature-verified entry points take a single calldata struct rather than positional args. This keeps signatures stable as new fields are added and matches the encoding the Go backend uses to sign messages:

- `BatchUpdateUserRoleWithSignatureParams { signer, userRoles[], nonce, signature }`
- `TransferSuperAdminWithSignatureParams { signer, newSuperAdmin, nonce, signature }`
- `BatchIssueCredentialsWithSignatureParams { issuer, credentials[], nonce, signature }`
- `BatchRevokeCredentialsWithSignatureParams { revoker, credentialIds[], nonce, signature }`

When adding a new signature-protected function, follow the same pattern.

### Role Hierarchy & `hasRoleOrAbove`

`None(0) → Holder(1) → Issuer(2) → Admin(3) → SuperAdmin(4)`

`hasRoleOrAbove(address user, Role minimumRole)` is the **only** role check method. Convenience helpers (`isAdmin`, `isIssuer`, etc.) have been removed — call `hasRoleOrAbove` with the exact minimum required.

Role-update hierarchy rules (enforced in `_enforceUserRoleUpdateHierarchy`):
- Signer below Admin → reverts `RoleBelowAdminError`
- Admin attempting to update another Admin/SuperAdmin → reverts `AdminUpdatePeerAdminRoleError`
- Admin attempting to promote to Admin/SuperAdmin → reverts `RoleBelowAdminError`
- Any attempt to assign `SuperAdmin` via `batchUpdateUserRoleWithSignature` → reverts `SuperAdminRoleNotUpdatableError` (SuperAdmin is only transferred via the dedicated `transferSuperAdminWithSignature` flow)
- Updating a user to their existing role → reverts `SameRoleUpdateError`

### Separate Authority/Registry Nonces

`CredentialAuthority.userToNonce` and `CredentialRegistry.userToNonce` are **independent mappings**. A user signing role updates and a user signing credential issuances may have different nonces. The Go backend reads each via the appropriate binding (`AuthorityBinding.UserToNonce` vs `RegistryBinding.UserToNonce`) — never assume they are synchronized.

Replay protection: every signature includes the current `userToNonce[signer]`; the contract checks `nonce == userToNonce[signer]` before accepting and increments after a successful operation.

### Soulbound Enforcement (`_update` override)

`CredentialRegistry._update(to, tokenId, auth)` overrides the OpenZeppelin ERC-721 hook. If `from != address(0)` (i.e., the transition is anything other than a mint), it reverts with `CredentialTransferError`. This blocks all transfers AND burns. Credentials can only be issued (`_mint`) and revoked (logical revoke via `revokedAt` timestamp; the NFT remains owned by the holder).

There is no `burn`, `transferFrom`, `safeTransferFrom`, or `approve` path that escapes this — the override applies to every state-changing token operation.

### Deploy Order & `scripts/deploy.ts`

Strict deploy + initialize order to avoid circular dependencies:

1. Deploy `CredentialConfig` (uninitialized)
2. Deploy `CredentialAuthority` (uninitialized)
3. Deploy `CredentialRegistry` (uninitialized)
4. `config.initialize(authorityAddr, registryAddr)`
5. `authority.initialize(superAdminAddr, configAddr)` — emits initial `UserRoleUpdated` for SuperAdmin
6. `registry.initialize(configAddr)` — calls `__ERC721_init("CredChain Credential", "CCC")`

`deploy.ts` enforces `INITIAL_SUPER_ADMIN_WALLET_ADDRESS` is set, then runs steps 1–6 sequentially. Log each address — they must be propagated into the Go backend's `.env` (`AUTHORITY_CONTRACT`, `REGISTRY_CONTRACT`).

### Solidity Compiler Settings

Pinned in `hardhat.config.ts`:

| Setting | Value | Reason |
|---|---|---|
| `version` | `0.8.24` | matches OpenZeppelin 5.6.1 requirements |
| `viaIR` | `true` | needed for stack-too-deep on signature-struct functions |
| `evmVersion` | `cancun` | enables transient storage + latest opcodes |
| `optimizer.enabled` | `true` | |
| `optimizer.runs` | `200` | balances deploy cost vs runtime cost |

Do not change these without re-running the full test suite and re-generating abigen bindings on the Go side.

### Contract-by-Contract Reference

#### `CredentialBase` (abstract)

- Shared errors (see Error Naming above)
- `address internal immutable deployer` set in constructor
- `_requireDeployer()` modifier gate
- No state beyond `deployer`; no public functions

#### `CredentialConfig`

- State: `address public authority`, `address public registry`
- `initialize(address _authority, address _registry)` — deployer-only, one-time
- Read by both `Authority` and `Registry` as a service locator

#### `CredentialAuthority`

- Enum `Role { None, Holder, Issuer, Admin, SuperAdmin }`
- State: `userToRole`, `userToNonce`, `config`, `users[]`, `userToIndex` (1-based for existence check)
- Constants: `MAX_BATCH_ROLE = 100`
- Events: `UserRoleUpdated(user, oldRole, newRole, updatedBy)`, `SuperAdminTransferred(old, new)`
- Methods:
  - `initialize(superAdminUser, _config)`
  - `hasRoleOrAbove(user, minimumRole) → bool`
  - `batchUpdateUserRoleWithSignature(params)` — bounded by `MAX_BATCH_ROLE`, increments signer nonce
  - `transferSuperAdminWithSignature(params)` — downgrades old SuperAdmin to Admin, promotes new
  - `paginateUsers(offset, limit) → address[]`
- Internal: `_updateUserRole`, `_enforceUserRoleUpdateHierarchy`, `_verifyBatchUpdateUserRoleSignature`, `_verifyTransferSuperAdminSignature`

#### `CredentialRegistry`

- Extends `ERC721Upgradeable` + `CredentialBase`. Name `"CredChain Credential"`, symbol `"CCC"`.
- Structs: `Credential { id, holder, hash, issuer, revoker, issuedAt, revokedAt, uri }`, `CredentialHashStatus { hash, status }`
- Enum: `CredentialStatus { None, Issued, Revoked }`
- State: `config` (typed `CredentialConfig`), `credentialIdToCredential`, `holderToCredentialIds`, `userToNonce`, `credentials[]`, `credentialHashToStatus`
- Constants: `MAX_BATCH_CREDENTIAL = 100`
- Events: `CredentialIssued(id, holder, issuer)`, `CredentialRevoked(id, revoker)`
- Token ID: `uint256(keccak256(abi.encodePacked(issuer, nonce, holder, hash)))`
- Duplicate check: global via `credentialHashToStatus` (blocked if Issued for any holder, allowed if Revoked)
- Methods:
  - `initialize(_config)`
  - `batchIssueCredentialsWithSignature(params)` — gated by `onlyRoleOrAbove(issuer, Issuer)`; sets `credentialHashToStatus[hash]=Issued`
  - `batchRevokeCredentialsWithSignature(params)` — gated by `onlyRoleOrAbove(revoker, Issuer)`; sets `credentialHashToStatus[hash]=Revoked`
  - `paginateCredentials(offset, limit) → Credential[]`
  - `paginateCredentialsByHolder(holder, offset, limit) → Credential[]`
  - `getCredentialsByIds(ids[]) → Credential[]`
  - `findCredential(id) → Credential`
  - `isHolderOfCredentialIds(holder, ids[]) → bool`
  - `getCredentialHashStatuses(hashes[]) → CredentialHashStatus[]`
- Soulbound: `_update` override reverts on any non-mint transition

## Configuration / Env Vars

| Var | Required | Purpose |
|---|---|---|
| `PRIVATE_KEY` | only for `--network polygon`/`mumbai` | deployer + tx signer |
| `POLYGON_RPC_URL` | only for `--network polygon` | RPC endpoint |
| `MUMBAI_RPC_URL` | only for `--network mumbai` | RPC endpoint |
| `INITIAL_SUPER_ADMIN_WALLET_ADDRESS` | **only for `scripts/deploy.ts`** | the wallet that receives `Role.SuperAdmin` during initialization. Hard-fail if missing. |

No env vars are needed for `npx hardhat test` (runs in-process).

## Testing

- **Framework:** Chai 4.5 + Mocha + Hardhat Network (in-process EVM)
- **Files:**
  - `test/01-deploy.test.ts` — 2 tests, validates deployment env-var requirements
  - `test/02-credential.test.ts` — 67 tests, full behavioral coverage of all 4 contracts
- **Coverage:** `coverage.json` is committed; regenerate with `npx hardhat coverage`
- **Style:** white-box, in-repo, asserts against revert errors by name (e.g. `.to.be.revertedWithCustomError(contract, "InvalidNonceError")`)
- **No integration tests against real RPC** — Hardhat in-process is the only target

When adding a new contract feature, add tests in `02-credential.test.ts` covering: success path, every custom revert error, replay protection (nonce reuse), and role-hierarchy violations.

## Tech Stack

| Layer | Tool | Version |
|---|---|---|
| Language | Solidity | 0.8.24 |
| Build / test runner | Hardhat | ^2.28.6 |
| Toolbox | @nomicfoundation/hardhat-toolbox | ^6.1.2 |
| Tracing | hardhat-tracer | ^3.4.0 |
| Contracts library | @openzeppelin/contracts | ^5.6.1 |
| Upgradeable library | @openzeppelin/contracts-upgradeable | ^5.6.1 |
| Assertions | chai | ^4.5.0 |
| Test framework | mocha | (via toolbox) |
| Env loader | dotenv | ^17.3.1 |
| TypeScript | typescript | ^5.9.3 |
| TS runner | ts-node | ^10.9.2 |

## Cross-Repo Integration

- **`../CredChain_Golang/AGENTS.md`** — backend that consumes these contracts. Abigen bindings live at `CredChain_Golang/infrastructure/chain/contracts/`. Hand-written code uses `chain.AuthorityBinding` / `chain.RegistryBinding` interfaces, satisfied structurally by the abigen output.
- **`../CredChain_React/AGENTS.md`** — frontend; never talks to contracts directly, always via the Go API.
- **`../CredChain_Python/AGENTS.md`** — AI service; never talks to contracts.

When a contract's external interface changes (new function, changed signature, new event), the workflow is:

1. Change + test on this repo
2. Re-run `abigen` against the new ABI on the Go side (manual step)
3. Update Go-side `AuthorityBinding` / `RegistryBinding` interfaces in `chain/bindings.go` to mirror the abigen pointer methods
4. Update Go consumer code (`chain/authority_service.go`, feature services) and tests
5. Bump documentation in both AGENTS.md files

Response/error codes on the Go side use a 6-digit `AABBCC` format with categories `10` (system), `20` (auth), `30` (user), `40` (credential), `50` (AI service). Contract revert errors propagate up as `CodeUser*BlockchainSyncFailed` / `CodeCredential*BlockchainSyncFailed` codes — see `CredChain_Golang/domain/codes.go`.

## Deployment

**Push to master branch only when build succeeds. Do not create feature branches, bugfix branches, or any other branch types — commit directly to master.**

Before pushing, run the repo's canonical verification command and confirm it passes:

- `CredChain_Golang`: `go test ./... && go vet ./... && gofmt -l .` (last must produce zero output)
- `CredChain_Solidity`: `npx hardhat compile && npx hardhat test`
- `CredChain_Python`: `make lint && make typecheck && make test`
- `CredChain_React`: `npm run lint && npm run build && npm run test && npm run check-locales`

## Local Dev Chain Persistence

Hardhat's `npx hardhat node` has no state persistence — all chain state is lost on restart.
Use Anvil (Foundry) in Docker Compose for a persisted local chain:

```bash
# Start persisted chain
cd CredChain_Golang && docker compose up -d anvil

# Deploy (first time only — contracts survive restarts)
INITIAL_SUPER_ADMIN_WALLET_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  npx hardhat run scripts/deploy.ts --network localhost

# Run tests (still uses in-process Hardhat — unchanged)
npx hardhat test
```

State is saved to `CredChain_Golang/docker/anvil/data/state.json` via bind mount.
On graceful shutdown (docker stop → SIGTERM), Anvil writes the full chain state to this file and auto-loads it on next start.

**Post-deploy setup** (run once — Go runs locally, infrastructure in Docker):

```bash
# Start infrastructure
cd CredChain_Golang && docker compose up -d anvil postgres mongo

# Update .env with contract addresses from deploy output

# One-time setup (local Go)
make migrate-up
make init-super-admin
make seed
make seed-chain

# Start backend
make serve
```

Contracts and chain state survive `docker compose down` and PC reboots.
Only the database setup needs to be done once per fresh state deletion.

**Hardhat accounts (mnemonic):**

| Index | Address | Role |
|---|---|---|
| 0 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` | Relayer |
| 1 | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` | SuperAdmin |
| 2 | `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC` | Admin |
| 3–15 | (derived via BIP44) | Issuers/Holders |

## See Also

- `hardhat.config.ts` — compiler + network configuration
- `scripts/deploy.ts` — canonical deployment flow
- `coverage.json` — last recorded test coverage
- `../AGENTS.md` (workspace root, uncommitted) — multi-repo reference
- `../CredChain_Golang/AGENTS.md` — backend consumer of these contracts
