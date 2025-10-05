// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title MockNameWrapper
/// @notice Mock NameWrapper contract for testing SemverResolver NameWrapper integration
/// @dev Simulates the ownerOf function from NameWrapper
contract MockNameWrapper {
    mapping(uint256 => address) private _owners;
    mapping(uint256 => bool) private _shouldRevert;

    /// @notice Mock ownerOf function to simulate wrapped name ownership
    /// @param id The token ID (namehash as uint256)
    /// @return The owner address of the wrapped name
    function ownerOf(uint256 id) external view returns (address) {
        if (_shouldRevert[id]) {
            revert("NameWrapper: token does not exist");
        }
        return _owners[id];
    }

    /// @notice Set the owner of a wrapped name for testing
    /// @param id The token ID (namehash as uint256)
    /// @param owner The owner address to set
    function setOwner(uint256 id, address owner) external {
        _owners[id] = owner;
        _shouldRevert[id] = false;
    }

    /// @notice Configure whether ownerOf should revert for a given token
    /// @param id The token ID (namehash as uint256)
    /// @param shouldRevert Whether ownerOf should revert
    function setShouldRevert(uint256 id, bool shouldRevert) external {
        _shouldRevert[id] = shouldRevert;
    }
}
