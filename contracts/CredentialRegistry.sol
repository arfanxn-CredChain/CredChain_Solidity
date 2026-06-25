// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./CredentialBase.sol";
import "./CredentialConfig.sol";
import "./CredentialAuthority.sol";

/// @title Credential Registry
/// @notice Manages Soulbound Credentials issuance and revocation using offline signatures.
/// @dev Credentials are ERC-721 tokens that cannot be transferred or burned (soulbound).
/// @dev Inherits from CredentialBase for common error definitions.
contract CredentialRegistry is CredentialBase, ERC721Upgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice The CredentialConfig contract address.
    /// @return The address of the config contract
    CredentialConfig public config;

    enum CredentialStatus { None, Issued, Revoked }

    struct CredentialHashStatus {
        bytes32 hash;
        CredentialStatus status;
    }

    mapping(bytes32 => CredentialStatus) public credentialHashToStatus;

    /// @notice Struct representing a credential's complete information.
    struct Credential {
        uint256 id;
        address holder;
        string hash;
        address issuer;
        address revoker;
        uint256 issuedAt;
        uint256 revokedAt;
        string uri;
    }

    /// @notice Maps credential ID to its full credential data.
    mapping(uint256 => Credential) public credentialIdToCredential;

    /// @notice Maps holder address to array of credential IDs they hold.
    mapping(address => uint256[]) public holderToCredentialIds;

    /// @notice Maps user address to their current nonce for signature replay protection.
    mapping(address => uint256) public userToNonce;

    /// @notice Array of all credential IDs ever issued.
    /// @dev Used for pagination across all credentials.
    uint256[] public credentials;

    /// @notice Maximum number of credentials that can be issued/revoked in a single batch.
    uint256 public constant MAX_BATCH_CREDENTIAL = 100;

    /// @notice Emitted when a credential is issued to a holder.
    /// @param id The credential (token) ID
    /// @param holder The address receiving the credential
    /// @param issuer The address that issued the credential
    event CredentialIssued(
        uint256 indexed id,
        address indexed holder,
        address indexed issuer
    );

    /// @notice Emitted when a credential is revoked.
    /// @param id The credential (token) ID
    /// @param revoker The address that revoked the credential
    event CredentialRevoked(uint256 indexed id, address indexed revoker);

    // ============ REGISTRY-SPECIFIC ERRORS ============

    /// @notice Emitted when attempting to transfer a soulbound credential.
    /// @dev Soulbound credentials cannot be transferred.
    error CredentialTransferError();

    /// @notice Emitted when attempting to issue a credential with a file hash that is already actively issued.
    error IssuedCredentialError();

    /// @notice Emitted when attempting to revoke a credential that is already revoked.
    error RevokeRevokedCredentialError();

    /// @notice Emitted when a credential is not found (does not exist).
    error CredentialNotFoundError();

    /// @notice Sets the deployer address.
    constructor() {
        deployer = msg.sender;
    }

    /// @notice Initializes the registry with the CredentialConfig contract.
    /// @dev Can only be called by the deployer once during deployment.
    /// @param _config The address of the CredentialConfig contract
    function initialize(address _config) external initializer {
        _requireDeployer();
        if (_config == address(0)) revert InvalidAddressError();

        __ERC721_init("CredChain Credential", "CCC");
        config = CredentialConfig(_config);
    }

    /// @notice Gets the CredentialAuthority contract instance.
    /// @return The CredentialAuthority contract
    function _getAuthority() internal view returns (CredentialAuthority) {
        return CredentialAuthority(config.authority());
    }

    /// @notice Modifier to check if the caller has at least the specified role.
    /// @param signer The address to check
    /// @param minimumRole The minimum required role
    modifier onlyRoleOrAbove(
        address signer,
        CredentialAuthority.Role minimumRole
    ) {
        if (!_getAuthority().hasRoleOrAbove(signer, minimumRole))
            revert RoleBelowIssuerError();
        _;
    }

    /// @notice Struct for defining a credential issuance.
    struct CredentialIssuance {
        address holder;
        string hash;
        string uri;
    }

    /// @notice Struct containing parameters for batch credential issuance with signature.
    struct BatchIssueCredentialsWithSignatureParams {
        address issuer;
        CredentialIssuance[] credentials;
        uint256 nonce;
        bytes signature;
    }

    /// @notice Batch issues credentials using an offline signature.
    /// @param params Struct containing issuer, credentials[], nonce, and signature
    /// @dev Verifies signature, checks for duplicates, and mints each credential.
    function batchIssueCredentialsWithSignature(
        BatchIssueCredentialsWithSignatureParams calldata params
    ) external onlyRoleOrAbove(params.issuer, CredentialAuthority.Role.Issuer) {
        if (params.credentials.length > MAX_BATCH_CREDENTIAL)
            revert MaxBatchExceededError();

        _verifyBatchIssueCredentialsSignature(
            params.issuer,
            params.credentials,
            params.nonce,
            params.signature
        );

        for (uint256 i = 0; i < params.credentials.length; i++) {
            if (params.credentials[i].holder == address(0))
                revert InvalidAddressError();

            uint256 id = uint256(
                keccak256(
                    abi.encodePacked(
                        params.issuer,
                        params.nonce,
                        params.credentials[i].holder,
                        params.credentials[i].hash
                    )
                )
            );
            bytes32 fileHashBytes = keccak256(abi.encodePacked(params.credentials[i].hash));
            if (credentialHashToStatus[fileHashBytes] == CredentialStatus.Issued)
                revert IssuedCredentialError();

            _issueCredential(
                id,
                params.credentials[i].holder,
                params.credentials[i].hash,
                params.credentials[i].uri,
                params.issuer
            );
        }

        userToNonce[params.issuer]++;
    }

    /// @notice Struct containing parameters for batch credential revocation with signature.
    struct BatchRevokeCredentialsWithSignatureParams {
        address revoker;
        uint256[] credentialIds;
        uint256 nonce;
        bytes signature;
    }

    /// @notice Batch revokes credentials using an offline signature.
    /// @param params Struct containing revoker, credentialIds[], nonce, and signature
    function batchRevokeCredentialsWithSignature(
        BatchRevokeCredentialsWithSignatureParams calldata params
    )
        external
        onlyRoleOrAbove(params.revoker, CredentialAuthority.Role.Issuer)
    {
        if (params.credentialIds.length > MAX_BATCH_CREDENTIAL)
            revert MaxBatchExceededError();

        _verifyBatchRevokeCredentialsSignature(
            params.revoker,
            params.credentialIds,
            params.nonce,
            params.signature
        );

        for (uint256 i = 0; i < params.credentialIds.length; i++) {
            if (_ownerOf(params.credentialIds[i]) == address(0))
                revert CredentialNotFoundError();
            _revokeCredential(params.credentialIds[i], params.revoker);
        }

        userToNonce[params.revoker]++;
    }

    /// @notice Returns a paginated list of all credentials.
    /// @param offset The starting index in the credentials array
    /// @param limit The maximum number of credentials to return
    /// @return Array of Credential structs
    function paginateCredentials(
        uint256 offset,
        uint256 limit
    ) external view returns (Credential[] memory) {
        uint256 total = credentials.length;
        if (offset >= total) return new Credential[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        Credential[] memory result = new Credential[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = credentialIdToCredential[credentials[i]];
        }
        return result;
    }

    /// @notice Returns a paginated list of credentials for a specific holder.
    /// @param holder The address of the credential holder
    /// @param offset The starting index
    /// @param limit The maximum number to return
    /// @return Array of Credential structs
    function paginateCredentialsByHolder(
        address holder,
        uint256 offset,
        uint256 limit
    ) external view returns (Credential[] memory) {
        uint256[] storage userCreds = holderToCredentialIds[holder];
        uint256 total = userCreds.length;
        if (offset >= total) return new Credential[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        Credential[] memory result = new Credential[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = credentialIdToCredential[userCreds[i]];
        }
        return result;
    }

    /// @notice Returns credentials by their exact IDs.
    /// @param ids Array of credential IDs to retrieve
    /// @return Array of Credential structs
    function getCredentialsByIds(
        uint256[] calldata ids
    ) external view returns (Credential[] memory) {
        Credential[] memory result = new Credential[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            if (_ownerOf(ids[i]) == address(0))
                revert CredentialNotFoundError();
            result[i] = credentialIdToCredential[ids[i]];
        }
        return result;
    }

    /// @notice Returns the full credential data for a specific ID.
    /// @param id The credential (token) ID
    /// @return The Credential struct
    function findCredential(
        uint256 id
    ) external view returns (Credential memory) {
        if (_ownerOf(id) == address(0)) revert CredentialNotFoundError();
        return credentialIdToCredential[id];
    }

    /// @notice Checks if a holder owns all specified credential IDs.
    /// @param holder The address to check
    /// @param credentialIds Array of credential IDs to verify
    /// @return true if holder owns all credentials, false otherwise
    function isHolderOfCredentialIds(
        address holder,
        uint256[] calldata credentialIds
    ) external view returns (bool) {
        for (uint256 i = 0; i < credentialIds.length; i++) {
            if (_ownerOf(credentialIds[i]) != holder) {
                return false;
            }
        }
        return true;
    }

    /// @notice Returns credential statuses for the given file hashes.
    /// @param hashes Array of file hashes to query
    /// @return Array of CredentialHashStatus (hash + status)
    function getCredentialHashStatuses(
        bytes32[] calldata hashes
    ) external view returns (CredentialHashStatus[] memory) {
        CredentialHashStatus[] memory statuses = new CredentialHashStatus[](hashes.length);
        for (uint256 i = 0; i < hashes.length; i++) {
            statuses[i] = CredentialHashStatus(
                hashes[i],
                credentialHashToStatus[hashes[i]]
            );
        }
        return statuses;
    }

    /// @notice Internal function to issue a credential (mint NFT and store data).
    /// @param id The token ID
    /// @param holder The credential holder
    /// @param hashStr The document hash
    /// @param uriStr The metadata URI
    /// @param issuer The issuing address
    function _issueCredential(
        uint256 id,
        address holder,
        string memory hashStr,
        string memory uriStr,
        address issuer
    ) internal {
        _mint(holder, id);

        credentialIdToCredential[id] = Credential({
            id: id,
            holder: holder,
            hash: hashStr,
            issuer: issuer,
            revoker: address(0),
            issuedAt: block.timestamp,
            revokedAt: 0,
            uri: uriStr
        });

        credentials.push(id);
        holderToCredentialIds[holder].push(id);

        emit CredentialIssued(id, holder, issuer);

        bytes32 fileHashBytes = keccak256(abi.encodePacked(hashStr));
        credentialHashToStatus[fileHashBytes] = CredentialStatus.Issued;
    }

    /// @notice Internal function to revoke a credential.
    /// @param id The credential (token) ID
    /// @param revoker The address performing the revocation
    function _revokeCredential(uint256 id, address revoker) internal {
        Credential storage cred = credentialIdToCredential[id];
        if (cred.revokedAt != 0) revert RevokeRevokedCredentialError();

        cred.revokedAt = block.timestamp;
        cred.revoker = revoker;

        emit CredentialRevoked(id, revoker);

        bytes32 fileHashBytes = keccak256(abi.encodePacked(cred.hash));
        credentialHashToStatus[fileHashBytes] = CredentialStatus.Revoked;
    }

    /// @notice Overrides ERC721's _update to enforce soulbound (non-transferable) behavior.
    /// @param to The destination address
    /// @param tokenId The token ID
    /// @param auth The authorized address
    /// @return The from address
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        address from = _ownerOf(tokenId);
        if (from != address(0)) {
            revert CredentialTransferError();
        }
        return super._update(to, tokenId, auth);
    }

    /// @notice Internal function to verify batch issuance signature.
    /// @param issuer The address that signed the message
    /// @param issuances Array of credential issuances
    /// @param nonce The current nonce of the issuer
    /// @param signature The ECDSA signature
    function _verifyBatchIssueCredentialsSignature(
        address issuer,
        CredentialIssuance[] calldata issuances,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userToNonce[issuer]) revert InvalidNonceError();

        bytes memory packedData = abi.encodePacked(issuer, nonce);
        for (uint256 i = 0; i < issuances.length; i++) {
            packedData = abi.encodePacked(
                packedData,
                issuances[i].holder,
                issuances[i].hash,
                issuances[i].uri
            );
        }

        bytes32 digest = keccak256(packedData).toEthSignedMessageHash();
        if (digest.recover(signature) != issuer) revert InvalidSignatureError();
    }

    /// @notice Internal function to verify batch revocation signature.
    /// @param revoker The address that signed the message
    /// @param ids Array of credential IDs to revoke
    /// @param nonce The current nonce of the revoker
    /// @param signature The ECDSA signature
    function _verifyBatchRevokeCredentialsSignature(
        address revoker,
        uint256[] calldata ids,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userToNonce[revoker]) revert InvalidNonceError();

        bytes memory packedData = abi.encodePacked(revoker, nonce);
        for (uint256 i = 0; i < ids.length; i++) {
            packedData = abi.encodePacked(packedData, ids[i]);
        }

        bytes32 digest = keccak256(packedData).toEthSignedMessageHash();
        if (digest.recover(signature) != revoker)
            revert InvalidSignatureError();
    }
}
