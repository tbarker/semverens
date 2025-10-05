// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/// @title SemverLib
/// @notice Mixin contract for semantic version parsing, comparison, and manipulation
/// @dev Supports major.minor.patch format with limited size (uint8.uint8.uint16)
abstract contract SemverLib {
    // ASCII character constants
    bytes1 private constant COLON = 0x3A; // ':'
    bytes1 private constant NULL_TERMINATOR = 0x00;
    bytes1 private constant ASCII_ZERO = 0x30; // '0'
    bytes1 private constant ASCII_NINE = 0x39; // '9'
    uint8 private constant ASCII_ZERO_UINT = 48; // '0' as uint8

    // Numeric constants
    uint8 private constant DECIMAL_BASE = 10;

    struct Version {
        uint8 major; // Max 255
        uint8 minor; // Max 255
        uint16 patch; // Max 65535, total struct size = 32 bits
    }

    /// @notice Parsed version with metadata about which components were explicitly specified
    /// @dev Used for wildcard resolution to distinguish "2" from "2:0" from "2:0:0"
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
                _uintToString(version.major), ".", _uintToString(version.minor), ".", _uintToString(version.patch)
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

    /// @notice Parses a colon-separated version label (for DNS labels, e.g., "1:2:3")
    /// @param label Version label in format "major", "major:minor", or "major:minor:patch"
    /// @return Parsed version struct with metadata about which components were explicitly specified
    /// @dev Used for wildcard resolution: "1" → 1.0.0 (hasMinor=false), "1:2" → 1.2.0 (hasMinor=true, hasPatch=false)
    /// @dev Colons used instead of dots to avoid conflicts with DNS label separators
    function _parseVersionFromLabel(string memory label) internal pure returns (ParsedVersion memory) {
        bytes memory data = bytes(label);
        // Note: Empty labels are prevented by upstream DNS validation in NameCoder.namehash()
        // which validates DNS format before reaching this function

        uint256 pos = 0;
        uint8 major = 0;
        uint8 minor = 0;
        uint16 patch = 0;
        bool hasMinor = false;
        bool hasPatch = false;

        // Parse major version (always present)
        (uint256 majorValue, uint256 newPos) = _parseNumberUntil(data, pos, COLON, type(uint8).max);
        major = uint8(majorValue);
        pos = newPos;

        // Check if we have a colon for minor version
        if (pos < data.length && data[pos] == COLON) {
            pos++; // Skip the ':'
            require(pos < data.length, InvalidVersion());
            hasMinor = true;

            // Parse minor version
            (uint256 minorValue, uint256 newPos2) = _parseNumberUntil(data, pos, COLON, type(uint8).max);
            minor = uint8(minorValue);
            pos = newPos2;

            // Check if we have another colon for patch version
            if (pos < data.length && data[pos] == COLON) {
                pos++; // Skip the ':'
                require(pos < data.length, InvalidVersion());
                hasPatch = true;

                // Parse patch version (rest of string, delimiter NULL_TERMINATOR = parse until end)
                (uint256 patchValue, uint256 newPos3) = _parseNumberUntil(data, pos, NULL_TERMINATOR, type(uint16).max);
                patch = uint16(patchValue);
                pos = newPos3;
            }
        }

        // Note: Trailing characters are prevented by _parseNumberUntil validation
        // which ensures only valid numeric sequences are parsed

        return ParsedVersion({
            version: Version({major: major, minor: minor, patch: patch}),
            hasMinor: hasMinor,
            hasPatch: hasPatch
        });
    }

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
                require(result <= (maxValue - digit) / DECIMAL_BASE, InvalidVersion());

                result = result * DECIMAL_BASE + digit;

                hasDigits = true;
                pos++;
            } else {
                break;
            }
        }

        require(hasDigits, InvalidVersion());

        return (result, pos);
    }

    /// @dev Converts a uint256 to its string representation
    /// @param value The uint256 value to convert
    /// @return The string representation of the value
    /// @notice Generic implementation used for uint8, uint16, and uint256 conversions
    function _uintToString(uint256 value) private pure returns (string memory) {
        if (value == 0) {
            return "0";
        }

        uint256 temp = value;
        uint256 digits = 0;
        while (temp != 0) {
            digits++;
            temp /= DECIMAL_BASE;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(ASCII_ZERO_UINT + uint8(value % DECIMAL_BASE)));
            value /= DECIMAL_BASE;
        }

        return string(buffer);
    }
}
