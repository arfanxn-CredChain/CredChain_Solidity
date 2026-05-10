// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./CredentialBase.sol";

/// @title Credential Authority
/// @notice Manages roles and permissions for the CredChain system.
/// @dev Inherits from CredentialBase for common error definitions.
/// @dev Users can be assigned roles: None(0), Holder(1), Issuer(2), Admin(3), SuperAdmin(4).
contract CredentialAuthority is CredentialBase {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice Role levels in the system.
    /// @dev None(0) < Holder(1) < Issuer(2) < Admin(3) < SuperAdmin(4)
    enum Role {
        None,
        Holder,
        Issuer,
        Admin,
        SuperAdmin
    }

    /// @notice Maps user address to their assigned role.
    mapping(address => Role) public userToRole;

    /// @notice Maps user address to their current nonce for signature replay protection.
    mapping(address => uint256) public userToNonce;

    /// @notice The CredentialConfig contract address.
    address public config;

    /// @notice Array of all user addresses that have ever been assigned a non-None role.
    /// @dev Used for pagination and enumeration.
    address[] public users;

    /// @notice Maps user address to their index in the users array (index + 1).
    /// @dev Storing index + 1 allows checking existence (0 = not in array).
    mapping(address => uint256) public userToIndex;

    /// @notice Maximum number of users that can be updated in a single batch operation.
    uint256 public constant MAX_BATCH_ROLE = 100;

    /// @notice Emitted when a user's role is updated.
    /// @param user The address whose role was updated
    /// @param oldRole The previous role
    /// @param newRole The new role
    /// @param updatedBy The address that triggered the update
    event UserRoleUpdated(
        address indexed user,
        Role oldRole,
        Role newRole,
        address indexed updatedBy
    );

    /// @notice Emitted when SuperAdmin role is transferred from one address to another.
    /// @param oldSuperAdmin The previous SuperAdmin address
    /// @param newSuperAdmin The new SuperAdmin address
    event SuperAdminTransferred(
        address indexed oldSuperAdmin,
        address indexed newSuperAdmin
    );

    // ============ AUTHORITY-SPECIFIC ERRORS ============

    /// @notice Emitted when attempting to assign SuperAdmin role via batch update.
    /// @dev SuperAdmin role can only be transferred via transferSuperAdminWithSignature.
    error SuperAdminRoleNotUpdatableError();

    /// @notice Emitted when an Admin attempts to update another Admin's role.
    error AdminUpdatePeerAdminRoleError();

    /// @notice Emitted when attempting to transfer SuperAdmin to the same address.
    error TransferSuperAdminToSelfError();

    /// @notice Emitted when trying to update a user's role to the same role they already have.
    error SameRoleUpdateError();

    /// @notice Sets the deployer address.
    constructor() {
        deployer = msg.sender;
    }

    /// @notice Initializes the contract with a super admin and config contract.
    /// @dev Can only be called by the deployer once during deployment.
    /// @param superAdminUser The address to assign the SuperAdmin role
    /// @param _config The address of the CredentialConfig contract
    function initialize(
        address superAdminUser,
        address _config
    ) external initializer {
        _requireDeployer();

        if (superAdminUser == address(0)) revert InvalidAddressError();
        if (_config == address(0)) revert InvalidAddressError();

        config = _config;
        userToRole[superAdminUser] = Role.SuperAdmin;

        users.push(superAdminUser);
        userToIndex[superAdminUser] = users.length;

        emit UserRoleUpdated(
            superAdminUser,
            Role.None,
            Role.SuperAdmin,
            msg.sender
        );
    }

    /// @notice Checks if a user has a role greater than or equal to the minimum required role.
    /// @param user The address to check
    /// @param minimumRole The minimum role required
    /// @return true if user has role >= minimumRole, false otherwise
    function hasRoleOrAbove(address user, Role minimumRole) public view returns (bool) {
        return userToRole[user] >= minimumRole;
    }

    /// @notice Struct for defining a user's role update.
    /// @dev Used in batch role update operations.
    struct UserRoleUpdation {
        address addr;
        Role role;
    }

    /// @notice Struct containing parameters for batch user role update with signature.
    struct BatchUpdateUserRoleWithSignatureParams {
        address signer;
        UserRoleUpdation[] userRoles;
        uint256 nonce;
        bytes signature;
    }

    /// @notice Batch updates user roles using an offline signature.
    /// @param params Struct containing signer, userRoles[], nonce, and signature
    /// @dev Verifies signature, enforces role hierarchy, and updates each user's role.
    function batchUpdateUserRoleWithSignature(
        BatchUpdateUserRoleWithSignatureParams calldata params
    ) external {
        if (params.userRoles.length > MAX_BATCH_ROLE) revert MaxBatchExceededError();

        _verifyBatchUpdateUserRoleSignature(
            params.signer,
            params.userRoles,
            params.nonce,
            params.signature
        );

        for (uint256 i = 0; i < params.userRoles.length; i++) {
            if (params.userRoles[i].addr == address(0)) revert InvalidAddressError();
            if (params.userRoles[i].role == Role.SuperAdmin) revert SuperAdminRoleNotUpdatableError();

            _enforceUserRoleUpdateHierarchy(params.signer, params.userRoles[i].addr, params.userRoles[i].role);
            _updateUserRole(params.userRoles[i].addr, params.userRoles[i].role, params.signer);
        }

        userToNonce[params.signer]++;
    }

    /// @notice Struct containing parameters for SuperAdmin transfer with signature.
    struct TransferSuperAdminWithSignatureParams {
        address signer;
        address newSuperAdmin;
        uint256 nonce;
        bytes signature;
    }

    /// @notice Transfers SuperAdmin role from current SuperAdmin to a new address.
    /// @param params Struct containing signer, newSuperAdmin, nonce, and signature
    /// @dev The old SuperAdmin is downgraded to Admin, new address becomes SuperAdmin.
    function transferSuperAdminWithSignature(
        TransferSuperAdminWithSignatureParams calldata params
    ) external {
        if (params.newSuperAdmin == address(0)) revert InvalidAddressError();
        if (params.signer == params.newSuperAdmin) revert TransferSuperAdminToSelfError();

        _verifyTransferSuperAdminSignature(
            params.signer,
            params.newSuperAdmin,
            params.nonce,
            params.signature
        );

        _updateUserRole(params.signer, Role.Admin, params.signer);
        _updateUserRole(params.newSuperAdmin, Role.SuperAdmin, params.signer);

        userToNonce[params.signer]++;
        emit SuperAdminTransferred(params.signer, params.newSuperAdmin);
    }

    /// @notice Returns a paginated list of user addresses with assigned roles.
    /// @param offset The starting index in the users array
    /// @param limit The maximum number of users to return
    /// @return Array of user addresses within the specified range
    function paginateUsers(uint256 offset, uint256 limit) external view returns (address[] memory) {
        uint256 total = users.length;
        if (offset >= total) return new address[](0);

        uint256 end = offset + limit;
        if (end > total) end = total;

        address[] memory result = new address[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            result[i - offset] = users[i];
        }
        return result;
    }

    /// @notice Internal function to update a user's role and manage the users array.
    /// @param targetUser The user whose role is being updated
    /// @param newRole The new role to assign
    /// @param updatedBy The address triggering the update
    function _updateUserRole(
        address targetUser,
        Role newRole,
        address updatedBy
    ) internal {
        Role oldRole = userToRole[targetUser];
        if (oldRole == newRole) revert SameRoleUpdateError();

        if (oldRole == Role.None && newRole != Role.None) {
            users.push(targetUser);
            userToIndex[targetUser] = users.length;
        } else if (newRole == Role.None && oldRole != Role.None) {
            uint256 indexToPop = userToIndex[targetUser] - 1;
            address lastUser = users[users.length - 1];

            users[indexToPop] = lastUser;
            userToIndex[lastUser] = indexToPop + 1;

            users.pop();
            delete userToIndex[targetUser];
        }

        userToRole[targetUser] = newRole;
        emit UserRoleUpdated(targetUser, oldRole, newRole, updatedBy);
    }

    /// @notice Internal function to enforce role hierarchy during role updates.
    /// @param signer The address attempting the update
    /// @param targetUser The user whose role is being updated
    /// @param newRole The role being assigned
    function _enforceUserRoleUpdateHierarchy(
        address signer,
        address targetUser,
        Role newRole
    ) internal view {
        Role signerRole = userToRole[signer];
        Role targetCurrentRole = userToRole[targetUser];

        if (signerRole < Role.Admin) revert RoleBelowAdminError();

        if (signerRole == Role.Admin) {
            if (targetCurrentRole >= Role.Admin) revert AdminUpdatePeerAdminRoleError();
            if (newRole >= Role.Admin) revert RoleBelowAdminError();
        }
    }

    /// @notice Internal function to verify batch role update signature.
    /// @param signer The address that signed the message
    /// @param userRoles Array of user role updates
    /// @param nonce The current nonce of the signer
    /// @param signature The ECDSA signature
    function _verifyBatchUpdateUserRoleSignature(
        address signer,
        UserRoleUpdation[] calldata userRoles,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userToNonce[signer]) revert InvalidNonceError();

        bytes memory packedData = abi.encodePacked(signer, nonce);
        for (uint256 i = 0; i < userRoles.length; i++) {
            packedData = abi.encodePacked(packedData, userRoles[i].addr, uint8(userRoles[i].role));
        }

        bytes32 digest = keccak256(packedData).toEthSignedMessageHash();
        if (digest.recover(signature) != signer) revert InvalidSignatureError();
    }

    /// @notice Internal function to verify SuperAdmin transfer signature.
    /// @param signer The current SuperAdmin signing the message
    /// @param newSuperAdmin The new SuperAdmin address
    /// @param nonce The current nonce of the signer
    /// @param signature The ECDSA signature
    function _verifyTransferSuperAdminSignature(
        address signer,
        address newSuperAdmin,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (userToRole[signer] != Role.SuperAdmin) revert RoleNotSuperAdminError();
        if (nonce != userToNonce[signer]) revert InvalidNonceError();

        bytes32 digest = keccak256(
            abi.encodePacked(signer, newSuperAdmin, nonce)
        ).toEthSignedMessageHash();

        if (digest.recover(signature) != signer) revert InvalidSignatureError();
    }
}