// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./CredentialConfig.sol";
import "./CredentialRegistry.sol";

/// @title Credential Authority
/// @notice Manages roles and permissions for the CredChain system.
contract CredentialAuthority is Initializable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    enum Role {
        None, // 0
        Holder, // 1
        Issuer, // 2
        Admin, // 3
        SuperAdmin // 4
    }

    mapping(address => Role) public userToRole;
    mapping(address => uint256) public userToNonce;

    CredentialConfig public config;

    // For enumeration:
    address[] public users;
    // userToIndex stores (index + 1) to allow checking for existence
    mapping(address => uint256) public userToIndex;

    event UserRoleUpdated(
        address indexed user,
        Role oldRole,
        Role newRole,
        address indexed updatedBy
    );
    event SuperAdminTransferred(
        address indexed oldSuperAdmin,
        address indexed newSuperAdmin
    );

    // Specific Errors
    error SuperAdminZeroAddressForbidden();
    error TargetUserZeroAddressForbidden();
    error SuperAdminRoleUpdateForbidden();
    error AdminUpdatePeerAdminRoleForbidden();
    error TransferSuperAdminToSelfForbidden();
    error SameRoleUpdateForbidden();
    error InvalidSignatureForbidden();
    error InvalidNonceForbidden();
    error SignerRoleAdminRequiredForbidden();
    error SuperAdminRoleForbidden();
    error BatchUpdateUserRoleLengthMismatchForbidden();

    // No constructor to disable initializers, since proxy upgrades aren't used.

    /// @notice Initializes the contract with a super admin and config
    /// @param superAdminUser The address of the initial super admin
    /// @param _config Address of CredentialConfig
    function initialize(
        address superAdminUser,
        address _config
    ) external initializer {
        if (superAdminUser == address(0))
            revert SuperAdminZeroAddressForbidden();

        config = CredentialConfig(_config);
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

    /// @notice Checks if the user is a SuperAdmin
    /// @param user The address to check
    /// @return bool True if SuperAdmin
    function isSuperAdmin(address user) public view returns (bool) {
        return userToRole[user] == Role.SuperAdmin;
    }

    /// @notice Checks if a user is the active holder of a credential dynamically
    /// @param user The address to verify
    /// @return bool True if user holds the credential and it is active
    function isHolder(address user) public view returns (bool) {
        return userToRole[user] == Role.Holder;
    }

    /// @notice Checks if the user is at least an Issuer
    /// @param user The address to check
    /// @return bool True if Issuer, Admin, or SuperAdmin
    function isIssuerOrHigher(address user) public view returns (bool) {
        return userToRole[user] >= Role.Issuer;
    }

    /// @notice Checks if the user is at least an Admin
    /// @param user The address to check
    /// @return bool True if Admin or SuperAdmin
    function isAdminOrHigher(address user) public view returns (bool) {
        return userToRole[user] >= Role.Admin;
    }

    /// @notice Batch updates roles using offline signatures
    /// @param signer The address authorizing the update
    /// @param targetUsers The array of users to update
    /// @param newRoles The array of new roles corresponding to users
    /// @param nonce The distinct nonce for replay protection
    /// @param signature The ECDSA signature
    function batchUpdateUserRoleWithSignature(
        address signer,
        address[] calldata targetUsers,
        Role[] calldata newRoles,
        uint256 nonce,
        bytes calldata signature
    ) external {
        if (targetUsers.length != newRoles.length)
            revert BatchUpdateUserRoleLengthMismatchForbidden();

        _verifyBatchUpdateUserRoleSignature(
            signer,
            targetUsers,
            newRoles,
            nonce,
            signature
        );

        for (uint256 i = 0; i < targetUsers.length; i++) {
            if (targetUsers[i] == address(0))
                revert TargetUserZeroAddressForbidden();
            if (newRoles[i] == Role.SuperAdmin)
                revert SuperAdminRoleUpdateForbidden();

            _enforceUserRoleUpdateHierarchy(
                signer,
                targetUsers[i],
                newRoles[i]
            );
            _updateUserRole(targetUsers[i], newRoles[i], signer);
        }

        userToNonce[signer]++;
    }

    /// @notice Transfers SuperAdmin role using signature
    /// @param signer The current SuperAdmin
    /// @param newSuperAdmin The address to become the new SuperAdmin
    /// @param nonce The distinct nonce
    /// @param signature The ECDSA signature
    function transferSuperAdminWithSignature(
        address signer,
        address newSuperAdmin,
        uint256 nonce,
        bytes calldata signature
    ) external {
        if (newSuperAdmin == address(0))
            revert TargetUserZeroAddressForbidden();
        if (signer == newSuperAdmin) revert TransferSuperAdminToSelfForbidden();

        _verifyTransferSuperAdminSignature(
            signer,
            newSuperAdmin,
            nonce,
            signature
        );

        if (!isSuperAdmin(signer)) revert SuperAdminRoleForbidden();

        // Update state
        _updateUserRole(signer, Role.Admin, signer); // Downgrade old SuperAdmin to Admin
        _updateUserRole(newSuperAdmin, Role.SuperAdmin, signer); // Upgrade new SuperAdmin

        userToNonce[signer]++;
        emit SuperAdminTransferred(signer, newSuperAdmin);
    }

    /// @notice Paginates all users that have an active role
    /// @param offset The starting index
    /// @param limit The maximum number of users to return
    /// @return address[] Array of user addresses
    function paginateUsers(
        uint256 offset,
        uint256 limit
    ) external view returns (address[] memory) {
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

    /// @notice Internal function to execute role updates and manage user array
    /// @param targetUser The user to update
    /// @param newRole The new role
    /// @param updatedBy The address making the update
    function _updateUserRole(
        address targetUser,
        Role newRole,
        address updatedBy
    ) internal {
        Role oldRole = userToRole[targetUser];
        if (oldRole == newRole) revert SameRoleUpdateForbidden();

        // Manage array for enumeration
        if (oldRole == Role.None && newRole != Role.None) {
            users.push(targetUser);
            userToIndex[targetUser] = users.length;
        } else if (newRole == Role.None && oldRole != Role.None) {
            // Delete user by swapping with last element
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

    /// @notice Internal function to enforce access control hierarchy
    /// @param signer The address attempting the update
    /// @param targetUser The target user
    /// @param newRole The rank being assigned
    function _enforceUserRoleUpdateHierarchy(
        address signer,
        address targetUser,
        Role newRole
    ) internal view {
        Role signerRole = userToRole[signer];
        Role targetCurrentRole = userToRole[targetUser];

        if (signerRole < Role.Admin) revert SignerRoleAdminRequiredForbidden();

        if (signerRole == Role.Admin) {
            if (targetCurrentRole >= Role.Admin)
                revert AdminUpdatePeerAdminRoleForbidden();
            if (newRole >= Role.Admin)
                revert SignerRoleAdminRequiredForbidden();
        }
    }

    /// @notice Internal function to verify batch role update signature
    /// @param signer The authorizing signer
    /// @param targetUsers Users to update
    /// @param newRoles New roles to assign
    /// @param nonce The distinct nonce
    /// @param signature The ECDSA signature
    function _verifyBatchUpdateUserRoleSignature(
        address signer,
        address[] calldata targetUsers,
        Role[] calldata newRoles,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userToNonce[signer]) revert InvalidNonceForbidden();

        bytes memory packedData = abi.encodePacked(signer);
        for (uint256 i = 0; i < targetUsers.length; i++) {
            packedData = abi.encodePacked(packedData, targetUsers[i]);
        }
        for (uint256 i = 0; i < newRoles.length; i++) {
            packedData = abi.encodePacked(packedData, uint8(newRoles[i]));
        }
        packedData = abi.encodePacked(packedData, nonce);

        bytes32 digest = keccak256(packedData).toEthSignedMessageHash();
        if (digest.recover(signature) != signer)
            revert InvalidSignatureForbidden();
    }

    /// @notice Internal function to verify super admin transfer signature
    /// @param signer The current super admin
    /// @param newSuperAdmin The target super admin
    /// @param nonce The distinct nonce
    /// @param signature The ECDSA signature
    function _verifyTransferSuperAdminSignature(
        address signer,
        address newSuperAdmin,
        uint256 nonce,
        bytes calldata signature
    ) internal view {
        if (nonce != userToNonce[signer]) revert InvalidNonceForbidden();
        bytes32 digest = keccak256(
            abi.encodePacked(signer, newSuperAdmin, nonce)
        ).toEthSignedMessageHash();
        if (digest.recover(signature) != signer)
            revert InvalidSignatureForbidden();
    }
}
