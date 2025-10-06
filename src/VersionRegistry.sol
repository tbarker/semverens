// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SemverLib} from "./SemverLib.sol";

/// @title VersionRegistry
/// @notice Abstract contract for storing and querying versioned content by ENS namehash
/// @dev Uses component-wise version ordering: major/minor can be added out of order,
///      but patch versions must be strictly sequential within each major.minor
/// @dev Uses binary search for O(log n) version lookups
/// @dev Example valid sequence: 1.1.4 → 2.0.0 → 1.1.5 → 1.2.0 → 2.0.1
abstract contract VersionRegistry is SemverLib {
    /// @notice Represents a versioned content record
    /// @param version The semantic version (major.minor.patch)
    /// @param contentHash The IPFS or other content hash for this version
    struct VersionRecord {
        Version version;
        bytes32 contentHash;
    }

    /// @dev Maps ENS namehash to array of version records, stored in ascending order
    /// @dev Array is sorted to enable binary search for efficient lookups
    mapping(bytes32 => VersionRecord[]) private versionRegistry;

    error ZeroVersionNotAllowed();
    error PatchVersionNotSequential();

    /// @dev Validates component-wise version ordering rules in a single pass
    /// @param versions Array of existing version records (sorted)
    /// @param newVersion The new version to validate
    /// @notice Enforces rules:
    ///   - Major and minor versions can be added out of chronological order (gaps allowed)
    ///   - Patch versions must be strictly sequential within same major.minor (no gaps)
    ///   - Example: 1.0.0 → 1.0.1 → 1.0.2 (valid), 1.0.0 → 1.0.2 (invalid)
    function _validateComponentWiseOrder(VersionRecord[] storage versions, Version memory newVersion) private view {
        uint16 highestPatch = 0;
        bool foundMajorMinor = false;

        // Single pass: find highest patch for this major.minor AND check for duplicates
        for (uint256 i = 0; i < versions.length; i++) {
            Version memory existing = versions[i].version;
            if (existing.major == newVersion.major && existing.minor == newVersion.minor) {
                foundMajorMinor = true;
                // Duplicate check is implicit: if patch matches highestPatch,
                // the sequential check below will catch it
                if (existing.patch > highestPatch) {
                    highestPatch = existing.patch;
                }
            }
        }

        // For existing major.minor: patch must be exactly highestPatch + 1
        // For new major.minor: any patch value is allowed as the starting patch
        if (foundMajorMinor && newVersion.patch != highestPatch + 1) {
            revert PatchVersionNotSequential();
        }
    }

    /// @dev Finds the insertion point for a new version using binary search
    /// @param versions Array of existing version records (sorted)
    /// @param newVersion The version to find insertion point for
    /// @return The index where the new version should be inserted
    /// @notice Inspired by OpenZeppelin Arrays.sol lowerBound implementation
    function _findInsertionPoint(VersionRecord[] storage versions, Version memory newVersion)
        private
        view
        returns (uint256)
    {
        uint256 low = 0;
        uint256 high = versions.length;

        while (low < high) {
            uint256 mid = (low + high) / 2;

            if (_isGreater(newVersion, versions[mid].version)) {
                low = mid + 1;
            } else {
                high = mid;
            }
        }

        return low;
    }

    /// @dev Adds a new version to the registry using component-wise ordering
    /// @param namehash The ENS namehash to add the version for
    /// @param major The major version number (0-255)
    /// @param minor The minor version number (0-255)
    /// @param patch The patch version number (0-65535)
    /// @param contentHash The content hash for this version
    /// @notice Component-wise ordering rules:
    ///   - Major and minor versions can be added out of chronological order
    ///   - Patch versions must be strictly sequential within same major.minor
    ///   - Cannot add duplicate versions; no patch gaps allowed
    /// @notice Reverts if version is 0.0.0 (reserved as sentinel value)
    /// @notice Examples: 1.1.4 → 2.0.0 → 1.1.5 (valid), 1.1.4 → 1.1.3 (invalid)
    function addVersion(bytes32 namehash, uint8 major, uint8 minor, uint16 patch, bytes32 contentHash) internal {
        Version memory newVersion = _createVersion(major, minor, patch);

        // Reject version 0.0.0 as it's reserved for "no version" sentinel value
        // However, allow versions like 0.0.1, 0.1.0, etc. for pre-release/development
        if (major == 0 && minor == 0 && patch == 0) {
            revert ZeroVersionNotAllowed();
        }

        VersionRecord[] storage versions = versionRegistry[namehash];

        // Validate component-wise ordering rules
        _validateComponentWiseOrder(versions, newVersion);

        // Add the new version using binary search insertion (inspired by OpenZeppelin Arrays.sol)
        VersionRecord memory newRecord = VersionRecord({version: newVersion, contentHash: contentHash});

        // Find insertion point using binary search (O(log n))
        uint256 insertIndex = _findInsertionPoint(versions, newVersion);

        // Insert at correct position
        versions.push(newRecord);
        for (uint256 i = versions.length - 1; i > insertIndex; i--) {
            versions[i] = versions[i - 1];
        }
        versions[insertIndex] = newRecord;
    }

    /// @dev Gets the content hash of the latest version for a given namehash
    /// @param namehash The ENS namehash to query
    /// @return The content hash of the latest version, or bytes32(0) if no versions exist
    function getLatestContentHash(bytes32 namehash) internal view returns (bytes32) {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return bytes32(0);
        }

        return versions[versions.length - 1].contentHash;
    }

    /// @dev Gets the latest version for a given namehash
    /// @param namehash The ENS namehash to query
    /// @return The latest version, or Version(0,0,0) if no versions exist
    function getLatestVersion(bytes32 namehash) internal view returns (Version memory) {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return _createVersion(0, 0, 0);
        }

        return versions[versions.length - 1].version;
    }

    /// @dev Finds the highest version matching a given major version
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @return The highest version matching the major version, or zero version if not found
    /// @notice Example: targetMajor=1 finds highest version like 1.x.x
    function getHighestVersionForMajor(bytes32 namehash, uint8 targetMajor)
        internal
        view
        returns (VersionRecord memory)
    {
        return _getHighestVersionMatching(namehash, targetMajor, 0, false);
    }

    /// @dev Finds the highest version matching a given major.minor version
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @param targetMinor The minor version to match
    /// @return The highest version matching the major.minor version, or zero version if not found
    /// @notice Example: targetMajor=1, targetMinor=2 finds highest version like 1.2.x
    function getHighestVersionForMajorMinor(bytes32 namehash, uint8 targetMajor, uint8 targetMinor)
        internal
        view
        returns (VersionRecord memory)
    {
        return _getHighestVersionMatching(namehash, targetMajor, targetMinor, true);
    }

    /// @dev Finds an exact version match
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @param targetMinor The minor version to match
    /// @param targetPatch The patch version to match
    /// @return The exact version record if found, or zero version if not found
    /// @notice Example: targetMajor=1, targetMinor=2, targetPatch=3 finds version 1.2.3 only
    /// @notice Uses binary search for O(log n) lookup
    function getExactVersion(bytes32 namehash, uint8 targetMajor, uint8 targetMinor, uint16 targetPatch)
        internal
        view
        returns (VersionRecord memory)
    {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return VersionRecord({version: _createVersion(0, 0, 0), contentHash: bytes32(0)});
        }

        // Binary search for exact version match
        uint256 left = 0;
        uint256 right = versions.length;

        while (left < right) {
            uint256 mid = left + (right - left) / 2;

            // Invariant: Ensures calculated midpoint is always within search range to prevent algorithm errors.
            // Note: Array access safety (mid < versions.length) is automatically verified by outOfBounds target.
            assert(mid >= left && mid < right);

            int8 comparison = _compareVersionExact(versions[mid].version, targetMajor, targetMinor, targetPatch);

            // Invariant: Documents that comparison function contract returns only valid values (-1, 0, or 1)
            assert(comparison >= -1 && comparison <= 1);

            if (comparison < 0) {
                left = mid + 1;
            } else if (comparison > 0) {
                right = mid;
            } else {
                // Exact match found
                return versions[mid];
            }
        }

        // No exact match found
        return VersionRecord({version: _createVersion(0, 0, 0), contentHash: bytes32(0)});
    }

    /// @dev Finds the highest version matching a given major (and optionally minor) version prefix
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @param targetMinor The minor version to match (only used if includeMinor is true)
    /// @param includeMinor If true, match both major and minor; if false, match only major
    /// @return The highest matching version record, or zero version if no match found
    /// @notice Uses optimized binary search that finds the rightmost (highest) match directly in O(log n)
    function _getHighestVersionMatching(bytes32 namehash, uint8 targetMajor, uint8 targetMinor, bool includeMinor)
        private
        view
        returns (VersionRecord memory)
    {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return VersionRecord({version: _createVersion(0, 0, 0), contentHash: bytes32(0)});
        }

        // Modified binary search that finds the rightmost (highest) matching version
        // This eliminates the need for a linear scan
        uint256 left = 0;
        uint256 right = versions.length;
        uint256 bestIndex = type(uint256).max;

        while (left < right) {
            uint256 mid = left + (right - left) / 2;

            // Invariant: Ensures calculated midpoint is always within search range to prevent algorithm errors.
            // Note: Array access safety (mid < versions.length) is automatically verified by outOfBounds target.
            assert(mid >= left && mid < right);

            int8 comparison = _compareVersionPrefix(versions[mid].version, targetMajor, targetMinor, includeMinor);

            // Invariant: Documents that comparison function contract returns only valid values (-1, 0, or 1)
            assert(comparison >= -1 && comparison <= 1);

            if (comparison < 0) {
                // mid version is less than target, search right half
                left = mid + 1;
            } else if (comparison > 0) {
                // mid version is greater than target, search left half
                right = mid;
            } else {
                // Found a matching version, record it and continue searching right
                // This ensures we find the rightmost (highest patch) matching version
                bestIndex = mid;
                left = mid + 1;
            }
        }

        if (bestIndex == type(uint256).max) {
            // No matching version found
            return VersionRecord({version: _createVersion(0, 0, 0), contentHash: bytes32(0)});
        }

        return versions[bestIndex];
    }

    /// @dev Compares a version against an exact target version (major.minor.patch)
    /// @param version The version to compare
    /// @param targetMajor The target major version
    /// @param targetMinor The target minor version
    /// @param targetPatch The target patch version
    /// @return -1 if version < target, 0 if version == target, 1 if version > target
    function _compareVersionExact(Version memory version, uint8 targetMajor, uint8 targetMinor, uint16 targetPatch)
        private
        pure
        returns (int8)
    {
        // Compare major version
        if (version.major < targetMajor) return -1;
        if (version.major > targetMajor) return 1;

        // Compare minor version
        if (version.minor < targetMinor) return -1;
        if (version.minor > targetMinor) return 1;

        // Compare patch version
        if (version.patch < targetPatch) return -1;
        if (version.patch > targetPatch) return 1;

        // Exact match
        return 0;
    }

    /// @dev Compares a version against a target prefix (major or major.minor)
    /// @param version The version to compare
    /// @param targetMajor The target major version
    /// @param targetMinor The target minor version (only used if includeMinor is true)
    /// @param includeMinor If true, compare both major and minor; if false, compare only major
    /// @return -1 if version < target, 0 if version matches target prefix, 1 if version > target
    /// @notice When includeMinor is false, all versions with matching major are considered equal (return 0)
    /// @notice When includeMinor is true, only versions with matching major.minor are considered equal
    function _compareVersionPrefix(Version memory version, uint8 targetMajor, uint8 targetMinor, bool includeMinor)
        private
        pure
        returns (int8)
    {
        // Compare major version
        if (version.major < targetMajor) return -1;
        if (version.major > targetMajor) return 1;

        // If we're only comparing major, they match (patch version is ignored)
        if (!includeMinor) return 0;

        // Compare minor version
        if (version.minor < targetMinor) return -1;
        if (version.minor > targetMinor) return 1;

        // Major and minor match (patch version is ignored)
        return 0;
    }
}
