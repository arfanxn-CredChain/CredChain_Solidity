// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

/// @title Credential Config
/// @notice Configuration contract acting as the source of truth for contract addresses.
contract CredentialConfig is Initializable {
    address public authority;
    address public registry;

    error OnlyDeployerForbidden();

    address private immutable deployer;

    constructor() {
        deployer = msg.sender;
    }

    /// @notice Initializes the config with the deployed addresses once
    /// @param _authority Address of the authority contract
    /// @param _registry Address of the registry contract
    function initialize(
        address _authority,
        address _registry
    ) external initializer {
        if (msg.sender != deployer) revert OnlyDeployerForbidden();
        
        authority = _authority;
        registry = _registry;
    }
}
