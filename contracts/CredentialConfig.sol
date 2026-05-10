// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "./CredentialBase.sol";

/// @title Credential Config
/// @notice Configuration contract acting as the source of truth for contract addresses.
/// @dev This contract stores the addresses of the Authority and Registry contracts.
/// @dev Inherits from CredentialBase for common error definitions and deployer protection.
contract CredentialConfig is CredentialBase {
    /// @notice The address of the CredentialAuthority contract
    address public authority;

    /// @notice The address of the CredentialRegistry contract
    address public registry;

    /// @notice Initializes the config with the deployed Authority and Registry addresses.
    /// @dev Can only be called by the deployer once.
    /// @param _authority Address of the authority contract
    /// @param _registry Address of the registry contract
    function initialize(
        address _authority,
        address _registry
    ) external initializer {
        _requireDeployer();
        
        if (_authority == address(0)) revert InvalidAddressError();
        if (_registry == address(0)) revert InvalidAddressError();
        
        authority = _authority;
        registry = _registry;
    }
}