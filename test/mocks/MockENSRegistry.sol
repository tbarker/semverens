// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title MockENSRegistry
/// @notice Mock ENS Registry for testing
/// @dev Provides minimal ENS registry functionality for test environments
contract MockENSRegistry {
    mapping(bytes32 => address) public owners;
    mapping(address => mapping(address => bool)) public operators;

    function owner(bytes32 node) external view returns (address) {
        return owners[node];
    }

    function setOwner(bytes32 node, address _owner) external {
        owners[node] = _owner;
    }

    function isApprovedForAll(address _owner, address operator) external view returns (bool) {
        return operators[_owner][operator];
    }

    function setApprovalForAll(address operator, bool approved) external {
        operators[msg.sender][operator] = approved;
    }
}
