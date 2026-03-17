// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./CredentialAuthority.sol";
import "./CredentialConfig.sol";

/// @title Credential Registry
/// @notice Manages Soulbound Credentials issuance and revocation using offline signatures.
contract CredentialRegistry is Initializable, ERC721Upgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    CredentialConfig public config;

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

    mapping(uint256 => Credential) public credentialIdToCredential;
    mapping(address => uint256[]) public holderToCredentialIds;
    mapping(address => uint256) public userToNonce;
    uint256[] public credentials;

    event CredentialIssued(
        uint256 indexed id,
        address indexed holder,
        address indexed issuer
    );
    event CredentialRevoked(uint256 indexed id, address indexed revoker);

    error ConfigZeroAddressForbidden();
    error HolderZeroAddressForbidden();
    error BatchIssueCredentialsLengthMismatchForbidden();
    error IssueIssuedCredentialForbidden();
    error RevokeRevokedCredentialForbidden();
    error CredentialNotFound();
    error CredentialTransferForbidden();
    error InvalidSignatureForbidden();
    error InvalidNonceForbidden();
    error IssuerRoleRequiredForbidden();
    error OnlyDeployerForbidden();

    address private immutable deployer;

    constructor() {
        deployer = msg.sender;
    }

    /// @notice Initializes the registry with the configuration contract
    /// @param _config Address of the CredentialConfig
    function initialize(address _config) external initializer {
        if (msg.sender != deployer) revert OnlyDeployerForbidden();
        if (_config == address(0)) revert ConfigZeroAddressForbidden();
        __ERC721_init("CredChain Credential", "CCC");
        config = CredentialConfig(_config);
    }

    /// @notice Internal helper to query Authority contract
    /// @return CredentialAuthority The authority instance
    function _getAuthority() internal view returns (CredentialAuthority) {
        return CredentialAuthority(config.authority());
    }

    /// @notice Modifier enforcing the caller is an Issuer or higher
    /// @param signer The address to verify
    modifier onlyIssuerOrHigher(address signer) {
        if (!_getAuthority().isIssuerOrHigher(signer))
            revert IssuerRoleRequiredForbidden();
        _;
    }

    /// @notice Checks if a user holds an array of credentials
    /// @param holder The address to verify
    /// @param credentialIds The array of credential IDs to check
    /// @return bool True if user holds all the credentials
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

    /// @notice Batch issues multiple credentials safely via signature
    /// @param issuer The address authorizing the issuance
    /// @param hashes The array of credential hashes
    /// @param holders The array of receiving holders
    /// @param uris The array of metadata URIs
    /// @param nonce The distinct nonce
    /// @param signature The ECDSA signature
    function batchIssueCredentialsWithSignature(
        address issuer,
        string[] calldata hashes,
        address[] calldata holders,
        string[] calldata uris,
        uint256 nonce,
        bytes calldata signature
    ) external onlyIssuerOrHigher(issuer) {
        if (hashes.length != holders.length || hashes.length != uris.length)
            revert BatchIssueCredentialsLengthMismatchForbidden();

        _verifyBatchIssueCredentialsSignature(
            issuer,
            hashes,
            holders,
            uris,
            nonce,
            signature
        );

        for (uint256 i = 0; i < hashes.length; i++) {
            if (holders[i] == address(0)) revert HolderZeroAddressForbidden();

            uint256 id = uint256(keccak256(abi.encodePacked(hashes[i])));
            if (_ownerOf(id) != address(0))
                revert IssueIssuedCredentialForbidden();

            _issueCredential(id, holders[i], hashes[i], uris[i], issuer);
        }

        userToNonce[issuer]++;
    }

    /// @notice Batch revokes multiple credentials via signature
    /// @param revoker The address authorizing revocation
    /// @param ids The array of token IDs to revoke
    /// @param nonce The distinct nonce
    /// @param signature The ECDSA signature
    function batchRevokeCredentialsWithSignature(
        address revoker,
        uint256[] calldata ids,
        uint256 nonce,
        bytes calldata signature
    ) external onlyIssuerOrHigher(revoker) {
        _verifyBatchRevokeCredentialsSignature(revoker, ids, nonce, signature);

        for (uint256 i = 0; i < ids.length; i++) {
            if (_ownerOf(ids[i]) == address(0)) revert CredentialNotFound();
            _revokeCredential(ids[i], revoker);
        }

        userToNonce[revoker]++;
    }

    /// @notice Retrieve paginated credentials universally
    /// @param offset The starting position
    /// @param limit Maximum amount to return
    /// @return Credential[] Array of credentials
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

    /// @notice Retrieve paginated credentials bounded to a specific holder
    /// @param holder Address of the holder
    /// @param offset Starting index
    /// @param limit Maximum return size
    /// @return Credential[] Array of user's credentials
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

    /// @notice Retrieve credentials by an exact list of IDs
    /// @param ids Array of Token IDs
    /// @return Credential[] Array of credentials
    function paginateCredentialsByIds(
        uint256[] calldata ids
    ) external view returns (Credential[] memory) {
        Credential[] memory result = new Credential[](ids.length);
        for (uint256 i = 0; i < ids.length; i++) {
            if (_ownerOf(ids[i]) == address(0)) revert CredentialNotFound();
            result[i] = credentialIdToCredential[ids[i]];
        }
        return result;
    }

    /// @notice Queries metadata of a single credential
    /// @param id Token ID
    /// @return Credential Full credential block
    function findCredential(
        uint256 id
    ) external view returns (Credential memory) {
        if (_ownerOf(id) == address(0)) revert CredentialNotFound();
        return credentialIdToCredential[id];
    }

    /// @notice Internal method to issue securely
    /// @param id Generated Token ID
    /// @param holder Receiver
    /// @param hashStr Raw document hash
    /// @param uriStr Metadata URI
    /// @param issuer Minting issuer
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
    }

    /// @notice Internal method to revoke a credential safely
    /// @param id Token ID to revoke
    /// @param revoker The authorizing caller
    function _revokeCredential(uint256 id, address revoker) internal {
        Credential storage cred = credentialIdToCredential[id];
        if (cred.revokedAt != 0) revert RevokeRevokedCredentialForbidden();

        cred.revokedAt = block.timestamp;
        cred.revoker = revoker;

        emit CredentialRevoked(id, revoker);
    }

    /// @notice Overrides base update to strictly enforce soulbound and unburnable behavior
    /// @param to Destination address
    /// @param tokenId The NFT identifier
    /// @param auth Authenticated user for transfer
    function _update(
        address to,
        uint256 tokenId,
        address auth
    ) internal virtual override returns (address) {
        address from = _ownerOf(tokenId);
        // Only allow minting (from == 0). Disallow regular transfers and burning (unburnable).
        if (from != address(0)) {
            revert CredentialTransferForbidden();
        }
        return super._update(to, tokenId, auth);
    }

    /// @notice Internal method verifying batch issue signature structurally
    /// @param issuer Authorized sender
    /// @param hashes Credentials hashes array
    /// @param holders Receiving holders array
    /// @param uris Metadata links array
    /// @param nonce The distinct nonce
    /// @param signature Signature bytes
    function _verifyBatchIssueCredentialsSignature(
        address issuer,
        string[] calldata hashes,
        address[] calldata holders,
        string[] calldata uris,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userToNonce[issuer]) revert InvalidNonceForbidden();

        bytes memory packedData = abi.encodePacked(issuer);
        for (uint256 i = 0; i < hashes.length; i++)
            packedData = abi.encodePacked(packedData, hashes[i]);
        for (uint256 i = 0; i < holders.length; i++)
            packedData = abi.encodePacked(packedData, holders[i]);
        for (uint256 i = 0; i < uris.length; i++)
            packedData = abi.encodePacked(packedData, uris[i]);
        packedData = abi.encodePacked(packedData, nonce);

        bytes32 digest = keccak256(packedData).toEthSignedMessageHash();
        if (digest.recover(signature) != issuer)
            revert InvalidSignatureForbidden();
    }

    /// @notice Internal method verifying batch revoke signature structurally
    /// @param revoker Authorized revocation agent
    /// @param ids Token IDs to revoke
    /// @param nonce Distinct nonce
    /// @param signature Signature bytes
    function _verifyBatchRevokeCredentialsSignature(
        address revoker,
        uint256[] calldata ids,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userToNonce[revoker]) revert InvalidNonceForbidden();

        bytes memory packedData = abi.encodePacked(revoker);
        for (uint256 i = 0; i < ids.length; i++)
            packedData = abi.encodePacked(packedData, ids[i]);
        packedData = abi.encodePacked(packedData, nonce);

        bytes32 digest = keccak256(packedData).toEthSignedMessageHash();
        if (digest.recover(signature) != revoker)
            revert InvalidSignatureForbidden();
    }
}
