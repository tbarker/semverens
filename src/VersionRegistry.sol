// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {SemverLib} from "./SemverLib.sol";

/// @title VersionRegistry - Storage and retrieval constants
contract VersionRegistryConstants {
    // Version validation constants
    uint8 internal constant ZERO_VERSION_MAJOR = 0;
    uint8 internal constant ZERO_VERSION_MINOR = 0;
    uint16 internal constant ZERO_VERSION_PATCH = 0;

    // Binary search algorithm constants
    uint256 internal constant SEARCH_NOT_FOUND = type(uint256).max;
    uint256 internal constant ARRAY_START_INDEX = 0;

    // Version comparison result constants
    int8 internal constant COMPARISON_LESS = -1;
    int8 internal constant COMPARISON_EQUAL = 0;
    int8 internal constant COMPARISON_GREATER = 1;

    // Patch version sequencing constants
    uint16 internal constant PATCH_INCREMENT = 1;
}

/// @title VersionRegistry
/// @notice Abstract contract for storing and querying versioned content by ENS namehash
/// @dev Uses component-wise version ordering: major/minor can be added out of order,
///      but patch versions must be strictly sequential within each major.minor
/// @dev Uses binary search for O(log n) version lookups
/// @dev Example valid sequence: 1.1.4 → 2.0.0 → 1.1.5 → 1.2.0 → 2.0.1
abstract contract VersionRegistry is SemverLib, VersionRegistryConstants {
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

    /// @notice Validates that a new version follows the required ordering rules
    /// @param versions Array of existing version records (sorted)
    /// @param newVersion The new version to validate
    /// @dev Enforces rules:
    ///   - Major and minor versions can be added out of chronological order (gaps allowed)
    ///   - Patch versions must be strictly sequential within same major.minor (no gaps)
    ///   - Example: 1.0.0 → 1.0.1 → 1.0.2 (valid), 1.0.0 → 1.0.2 (invalid)
    /// @dev Validation rules:
    ///   - Major and minor versions can be added out of chronological order (gaps allowed)
    ///   - Patch versions must be strictly sequential within same major.minor (no gaps)
    ///   - Duplicate versions are implicitly rejected by sequential check
    /// @dev Complexity: O(n) where n is the number of existing versions
    /// @dev Algorithm: Single pass to find highest patch for matching major.minor
    ///      then validates new patch is exactly highest + 1 (for existing major.minor)
    ///      or allows any patch value for new major.minor combinations
    /// @dev Examples:
    ///   - Existing: [1.0.0, 1.0.1] + New: 1.0.2 → valid (sequential patch)
    ///   - Existing: [1.0.0, 1.0.1] + New: 1.0.0 → invalid (duplicate/backward)
    ///   - Existing: [1.0.0, 1.0.1] + New: 2.0.5 → valid (new major.minor)
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
        if (foundMajorMinor && newVersion.patch != highestPatch + PATCH_INCREMENT) {
            revert PatchVersionNotSequential();
        }
    }

    /// @notice Finds where to insert a new version in the sorted array to maintain order
    /// @param versions Array of existing version records (sorted)
    /// @param newVersion The version to find insertion point for
    /// @return The index where the new version should be inserted
    /// @dev Inspired by OpenZeppelin Arrays.sol lowerBound implementation
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

    /// @notice Adds a new version of content to the registry for an ENS name
    /// @param namehash The ENS namehash to add the version for
    /// @param major The major version number (0-255)
    /// @param minor The minor version number (0-255)
    /// @param patch The patch version number (0-65535)
    /// @param contentHash The content hash for this version
    /// @dev Component-wise ordering rules:
    ///   - Major and minor versions can be added out of chronological order
    ///   - Patch versions must be strictly sequential within same major.minor
    ///   - Cannot add duplicate versions; no patch gaps allowed
    /// @dev Reverts if version is 0.0.0 (reserved as sentinel value)
    /// @dev Examples: 1.1.4 → 2.0.0 → 1.1.5 (valid), 1.1.4 → 1.1.3 (invalid)
    /// @dev Component-wise ordering rules enforced:
    ///   - Major and minor versions can be added out of chronological order (gaps allowed)
    ///   - Patch versions must be strictly sequential within same major.minor (no gaps)
    ///   - Cannot add duplicate versions; ensures patch continuity
    /// @dev Complexity: O(n) for validation + O(log n) for insertion + O(n) for array shifting
    ///      Total: O(n) where n is number of existing versions
    /// @dev Version 0.0.0 is reserved as sentinel value and rejected
    /// @dev Examples of valid sequences:
    ///   - 1.1.0 → 1.1.1 → 2.0.0 → 1.1.2 (component-wise valid)
    ///   - 1.0.0 → 1.0.2 (invalid: missing 1.0.1)
    ///   - 2.0.0 → 1.0.0 (valid: different major versions)
    function addVersion(bytes32 namehash, uint8 major, uint8 minor, uint16 patch, bytes32 contentHash) internal {
        Version memory newVersion = _createVersion(major, minor, patch);

        // Reject version 0.0.0 as it's reserved for "no version" sentinel value
        // However, allow versions like 0.0.1, 0.1.0, etc. for pre-release/development
        if (major == ZERO_VERSION_MAJOR && minor == ZERO_VERSION_MINOR && patch == ZERO_VERSION_PATCH) {
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

    /// @notice Gets the content hash of the most recent version for an ENS name
    /// @param namehash The ENS namehash to query
    /// @return The content hash of the latest version, or bytes32(0) if no versions exist
    function getLatestContentHash(bytes32 namehash) internal view returns (bytes32) {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return bytes32(0);
        }

        return versions[versions.length - 1].contentHash;
    }

    /// @notice Gets the most recent version number for an ENS name
    /// @param namehash The ENS namehash to query
    /// @return The latest version, or Version(0,0,0) if no versions exist
    function getLatestVersion(bytes32 namehash) internal view returns (Version memory) {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return _createVersion(0, 0, 0);
        }

        return versions[versions.length - 1].version;
    }

    /// @notice Finds the highest version with a specific major version number (e.g., highest 1.x.x)
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @return The highest version matching the major version, or zero version if not found
    /// @dev Example: targetMajor=1 finds highest version like 1.x.x
    function getHighestVersionForMajor(bytes32 namehash, uint8 targetMajor)
        internal
        view
        returns (VersionRecord memory)
    {
        return _getHighestVersionMatching(namehash, targetMajor, 0, false);
    }

    /// @notice Finds the highest version with specific major.minor numbers (e.g., highest 1.2.x)
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @param targetMinor The minor version to match
    /// @return The highest version matching the major.minor version, or zero version if not found
    /// @dev Example: targetMajor=1, targetMinor=2 finds highest version like 1.2.x
    function getHighestVersionForMajorMinor(bytes32 namehash, uint8 targetMajor, uint8 targetMinor)
        internal
        view
        returns (VersionRecord memory)
    {
        return _getHighestVersionMatching(namehash, targetMajor, targetMinor, true);
    }

    /// @notice Finds an exact version match (e.g., finds 1.2.3 exactly, not 1.2.4)
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @param targetMinor The minor version to match
    /// @param targetPatch The patch version to match
    /// @return The exact version record if found, or zero version if not found
    /// @dev Example: targetMajor=1, targetMinor=2, targetPatch=3 finds version 1.2.3 only
    /// @dev Uses binary search for O(log n) lookup
    function getExactVersion(bytes32 namehash, uint8 targetMajor, uint8 targetMinor, uint16 targetPatch)
        internal
        view
        returns (VersionRecord memory)
    {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return _createZeroVersionRecord();
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
        return _createZeroVersionRecord();
    }

    /// @dev Finds the highest version matching a given major (and optionally minor) version prefix
    /// @param namehash The ENS namehash to search
    /// @param targetMajor The major version to match
    /// @param targetMinor The minor version to match (only used if includeMinor is true)
    /// @param includeMinor If true, match both major and minor; if false, match only major
    /// @return The highest matching version record, or zero version if no match found
    /// @notice Uses optimized binary search that finds the rightmost (highest) match directly in O(log n)
    /// @dev Complexity: Extracted binary search algorithm for better maintainability
    function _getHighestVersionMatching(bytes32 namehash, uint8 targetMajor, uint8 targetMinor, bool includeMinor)
        private
        view
        returns (VersionRecord memory)
    {
        VersionRecord[] storage versions = versionRegistry[namehash];

        if (versions.length == 0) {
            return _createZeroVersionRecord();
        }

        // Use specialized binary search to find the rightmost (highest) matching version
        uint256 matchIndex = _binarySearchRightmostMatch(versions, targetMajor, targetMinor, includeMinor);

        if (matchIndex == SEARCH_NOT_FOUND) {
            return _createZeroVersionRecord();
        }

        return versions[matchIndex];
    }

    /// @dev Creates a zero version record (sentinel value for "no version found")
    /// @return A version record with version 0.0.0 and empty content hash
    function _createZeroVersionRecord() private pure returns (VersionRecord memory) {
        return VersionRecord({
            version: _createVersion(ZERO_VERSION_MAJOR, ZERO_VERSION_MINOR, ZERO_VERSION_PATCH),
            contentHash: bytes32(0)
        });
    }

    /// @dev Binary search algorithm that finds the rightmost (highest) matching version
    /// @param versions Array of version records to search (must be sorted)
    /// @param targetMajor The major version to match
    /// @param targetMinor The minor version to match (only used if includeMinor is true)
    /// @param includeMinor If true, match both major and minor; if false, match only major
    /// @return Index of the rightmost matching version, or SEARCH_NOT_FOUND if no match
    /// @dev Time Complexity: O(log n) where n is the number of versions
    /// @dev Algorithm: Modified binary search that continues searching right after finding matches
    ///      to ensure we get the highest patch version within the matching major[.minor] range
    function _binarySearchRightmostMatch(
        VersionRecord[] storage versions,
        uint8 targetMajor,
        uint8 targetMinor,
        bool includeMinor
    ) private view returns (uint256) {
        uint256 left = ARRAY_START_INDEX;
        uint256 right = versions.length;
        uint256 bestIndex = SEARCH_NOT_FOUND;

        while (left < right) {
            uint256 mid = left + (right - left) / 2;

            // Invariant: Ensures calculated midpoint is always within search range
            assert(mid >= left && mid < right);

            int8 comparison = _compareVersionPrefix(versions[mid].version, targetMajor, targetMinor, includeMinor);

            // Invariant: Comparison function returns only valid values (COMPARISON_LESS, COMPARISON_EQUAL, or COMPARISON_GREATER)
            assert(comparison >= COMPARISON_LESS && comparison <= COMPARISON_GREATER);

            if (comparison < 0) {
                // Current version is less than target, search right half
                left = mid + 1;
            } else if (comparison > 0) {
                // Current version is greater than target, search left half
                right = mid;
            } else {
                // Found a matching version, record it and continue searching right
                // This ensures we find the rightmost (highest patch) matching version
                bestIndex = mid;
                left = mid + 1;
            }
        }

        return bestIndex;
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
        if (version.major < targetMajor) return COMPARISON_LESS;
        if (version.major > targetMajor) return COMPARISON_GREATER;

        // Compare minor version
        if (version.minor < targetMinor) return COMPARISON_LESS;
        if (version.minor > targetMinor) return COMPARISON_GREATER;

        // Compare patch version
        if (version.patch < targetPatch) return COMPARISON_LESS;
        if (version.patch > targetPatch) return COMPARISON_GREATER;

        // Exact match
        return COMPARISON_EQUAL;
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
        if (version.major < targetMajor) return COMPARISON_LESS;
        if (version.major > targetMajor) return COMPARISON_GREATER;

        // If we're only comparing major, they match (patch version is ignored)
        if (!includeMinor) return COMPARISON_EQUAL;

        // Compare minor version
        if (version.minor < targetMinor) return COMPARISON_LESS;
        if (version.minor > targetMinor) return COMPARISON_GREATER;

        // Major and minor match (patch version is ignored)
        return COMPARISON_EQUAL;
    }
}
