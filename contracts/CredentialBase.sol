// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title Credential Base
/// @notice Shared base contract containing common errors and deployer protection.
/// @dev All contracts in the CredChain system should inherit from this contract.
abstract contract CredentialBase is Initializable {
    /// @notice Emitted when a zero address is provided where not allowed
    error InvalidAddressError();

    /// @notice Emitted when a signature verification fails
    error InvalidSignatureError();

    /// @notice Emitted when the nonce is incorrect or has already been used
    error InvalidNonceError();

    /// @notice Emitted when a function is called by an address other than the deployer
    error NotDeployerError();

    /// @notice Emitted when the caller does not have at least the Admin role
    error RoleBelowAdminError();

    /// @notice Emitted when the caller does not have at least the Issuer role
    error RoleBelowIssuerError();

    /// @notice Emitted when the caller does not have the SuperAdmin role
    error RoleNotSuperAdminError();

    /// @notice Emitted when the batch size exceeds the maximum allowed limit
    error MaxBatchExceededError();

    /// @notice The address that deployed this contract (immutable)
    /// @dev Set once in the constructor, cannot be changed
    address internal immutable deployer;

    /// @notice Sets the deployer address in the constructor
    constructor() {
        deployer = msg.sender;
    }

    /// @notice Reverts if the caller is not the deployer
    /// @dev Used to protect initialization functions
    function _requireDeployer() internal view {
        if (msg.sender != deployer) revert NotDeployerError();
    }
}