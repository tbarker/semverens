// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

/// @title SemverLib
/// @notice Mixin contract for semantic version parsing, comparison, and manipulation
/// @dev Supports major.minor.patch format with limited size (uint8.uint8.uint16)
abstract contract SemverLib {
    // ASCII character constants
    bytes1 private constant HYPHEN = 0x2D; // '-'
    bytes1 private constant NULL_TERMINATOR = 0x00;
    bytes1 private constant ASCII_ZERO = 0x30; // '0'
    bytes1 private constant ASCII_NINE = 0x39; // '9'
    uint8 private constant ASCII_ZERO_UINT = 48; // '0' as uint8

    // Numeric constants
    uint8 private constant DECIMAL_BASE = 10;

    // Version component limits (optimize for storage and common use cases)
    uint8 private constant MAX_MAJOR_VERSION = type(uint8).max; // 255
    uint8 private constant MAX_MINOR_VERSION = type(uint8).max; // 255
    uint16 private constant MAX_PATCH_VERSION = type(uint16).max; // 65535

    // String processing constants
    uint256 private constant INITIAL_POSITION = 0;
    uint256 private constant HYPHEN_SKIP_OFFSET = 1;

    struct Version {
        uint8 major; // Max 255
        uint8 minor; // Max 255
        uint16 patch; // Max 65535, total struct size = 32 bits
    }

    /// @notice Parsed version with metadata about which components were explicitly specified
    /// @dev Used for wildcard resolution to distinguish "2" from "2-0" from "2-0-0"
    struct ParsedVersion {
        Version version;
        bool hasMinor; // True if minor component was explicitly specified
        bool hasPatch; // True if patch component was explicitly specified
    }

    enum ComparisonResult {
        Less,
        Equal,
        Greater
    }

    error InvalidVersion();

    function _createVersion(uint8 major, uint8 minor, uint16 patch) internal pure returns (Version memory) {
        return Version({major: major, minor: minor, patch: patch});
    }

    function _versionToString(Version memory version) internal pure returns (string memory) {
        return string(
            abi.encodePacked(
                Strings.toString(version.major),
                ".",
                Strings.toString(version.minor),
                ".",
                Strings.toString(version.patch)
            )
        );
    }

    function _compare(Version memory a, Version memory b) internal pure returns (ComparisonResult) {
        if (a.major != b.major) {
            return a.major < b.major ? ComparisonResult.Less : ComparisonResult.Greater;
        }

        if (a.minor != b.minor) {
            return a.minor < b.minor ? ComparisonResult.Less : ComparisonResult.Greater;
        }

        if (a.patch != b.patch) {
            return a.patch < b.patch ? ComparisonResult.Less : ComparisonResult.Greater;
        }

        return ComparisonResult.Equal;
    }

    function _isGreater(Version memory a, Version memory b) internal pure returns (bool) {
        return _compare(a, b) == ComparisonResult.Greater;
    }

    /// @notice Parses a version string like "1-2-3" into its major, minor, and patch components
    /// @param label Version label in format "major", "major-minor", or "major-minor-patch"
    /// @return Parsed version struct with metadata about which components were explicitly specified
    /// @dev Used for wildcard resolution: "1" → 1.0.0 (hasMinor=false), "1-2" → 1.2.0 (hasMinor=true, hasPatch=false)
    /// @dev Hyphens used instead of dots to avoid conflicts with DNS label separators
    /// @dev Input validation: While DNS validates overall label format, we still need to validate:
    ///      - Empty components after hyphens (e.g., "1-" or "1-2-")
    ///      - Non-numeric characters (e.g., "abc")
    ///      - Numeric overflow beyond uint8/uint16 limits
    /// @dev Complexity: Refactored into smaller functions for better maintainability
    function _parseVersionFromLabel(string memory label) internal pure returns (ParsedVersion memory) {
        bytes memory data = bytes(label);

        // Parse major version (always required)
        (uint8 major, uint256 pos) = _parseMajorVersion(data);

        // Parse optional minor and patch components
        (uint8 minor, uint16 patch, bool hasMinor, bool hasPatch) = _parseMinorAndPatch(data, pos);

        return ParsedVersion({
            version: Version({major: major, minor: minor, patch: patch}),
            hasMinor: hasMinor,
            hasPatch: hasPatch
        });
    }

    /// @dev Parses the major version component from the beginning of the data
    /// @param data The bytes representation of the version label
    /// @return major The parsed major version (0-255)
    /// @return newPos The position after parsing the major component
    function _parseMajorVersion(bytes memory data) private pure returns (uint8 major, uint256 newPos) {
        (uint256 majorValue, uint256 pos) = _parseNumberUntil(data, INITIAL_POSITION, HYPHEN, MAX_MAJOR_VERSION);
        return (uint8(majorValue), pos);
    }

    /// @dev Parses optional minor and patch version components
    /// @param data The bytes representation of the version label
    /// @param startPos The position to start parsing from (after major component)
    /// @return minor The parsed minor version (0 if not present)
    /// @return patch The parsed patch version (0 if not present)
    /// @return hasMinor True if minor component was explicitly specified
    /// @return hasPatch True if patch component was explicitly specified
    function _parseMinorAndPatch(bytes memory data, uint256 startPos)
        private
        pure
        returns (uint8 minor, uint16 patch, bool hasMinor, bool hasPatch)
    {
        uint256 pos = startPos;

        // Check for minor version component
        if (_hasHyphenAt(data, pos)) {
            (minor, pos, hasMinor) = _parseMinorComponent(data, pos);

            // Check for patch version component
            if (_hasHyphenAt(data, pos)) {
                (patch, hasPatch) = _parsePatchComponent(data, pos);
            }
        }

        return (minor, patch, hasMinor, hasPatch);
    }

    /// @dev Checks if there's a hyphen at the specified position
    /// @param data The bytes to check
    /// @param pos The position to check
    /// @return True if there's a hyphen at the position
    function _hasHyphenAt(bytes memory data, uint256 pos) private pure returns (bool) {
        return pos < data.length && data[pos] == HYPHEN;
    }

    /// @dev Parses the minor version component
    /// @param data The bytes representation of the version label
    /// @param startPos The position of the hyphen before the minor component
    /// @return minor The parsed minor version
    /// @return newPos The position after parsing the minor component
    /// @return hasMinor Always returns true (minor component was found)
    function _parseMinorComponent(bytes memory data, uint256 startPos)
        private
        pure
        returns (uint8 minor, uint256 newPos, bool hasMinor)
    {
        uint256 pos = startPos + HYPHEN_SKIP_OFFSET;
        require(pos < data.length, InvalidVersion()); // Prevent empty components like "1-"

        (uint256 minorValue, uint256 finalPos) = _parseNumberUntil(data, pos, HYPHEN, MAX_MINOR_VERSION);
        return (uint8(minorValue), finalPos, true);
    }

    /// @dev Parses the patch version component
    /// @param data The bytes representation of the version label
    /// @param startPos The position of the hyphen before the patch component
    /// @return patch The parsed patch version
    /// @return hasPatch Always returns true (patch component was found)
    function _parsePatchComponent(bytes memory data, uint256 startPos)
        private
        pure
        returns (uint16 patch, bool hasPatch)
    {
        uint256 pos = startPos + HYPHEN_SKIP_OFFSET;
        require(pos < data.length, InvalidVersion()); // Prevent empty components like "1-2-"

        // Parse until end of string (NULL_TERMINATOR delimiter)
        (uint256 patchValue,) = _parseNumberUntil(data, pos, NULL_TERMINATOR, MAX_PATCH_VERSION);
        return (uint16(patchValue), true);
    }

    /// @dev Parses a numeric value from bytes until a delimiter is encountered
    /// @param data The bytes to parse from
    /// @param start The starting position in the bytes array
    /// @param delimiter The byte to stop parsing at (or NULL_TERMINATOR for end of string)
    /// @param maxValue Maximum allowed value to prevent overflow
    /// @return number The parsed numeric value
    /// @return newPos The position after the parsed number
    /// @dev Complexity: O(k) where k is the number of digits parsed
    /// @dev Edge cases handled:
    ///   - Empty numeric components (e.g., "1-" or "1-2-") → reverts
    ///   - Non-numeric characters → stops parsing (allows "1abc" → 1)
    ///   - Overflow protection → checks before multiplication to prevent silent overflow
    /// @dev Examples:
    ///   - parseNumberUntil("123-456", 0, '-', 255) → (123, 3)
    ///   - parseNumberUntil("123-456", 4, '\0', 255) → (456, 7)
    ///   - parseNumberUntil("999", 0, '-', 255) → reverts (overflow)
    function _parseNumberUntil(bytes memory data, uint256 start, bytes1 delimiter, uint256 maxValue)
        private
        pure
        returns (uint256 number, uint256 newPos)
    {
        uint256 pos = start;
        uint256 result = 0;
        bool hasDigits = false;

        while (pos < data.length && data[pos] != delimiter) {
            bytes1 b = data[pos];
            if (b >= ASCII_ZERO && b <= ASCII_NINE) {
                // '0'-'9'
                uint256 digit = uint256(uint8(b) - uint8(ASCII_ZERO));

                // Validate against max value to prevent overflow BEFORE multiplication
                // This check is CRITICAL - without it, versions like "999999" could cause silent overflow
                require(result <= (maxValue - digit) / DECIMAL_BASE, InvalidVersion());

                result = result * DECIMAL_BASE + digit;

                hasDigits = true;
                pos++;
            } else {
                // Stop parsing at first non-digit character (allows trailing chars like "1abc" → "1")
                // This is by design for DNS label compatibility
                break;
            }
        }

        // This check is NECESSARY - prevents labels like "abc" or ":" from being accepted
        require(hasDigits, InvalidVersion());

        return (result, pos);
    }
}
