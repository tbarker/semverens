// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {SemverResolver} from "../src/SemverResolver.sol";
import {SemverLib} from "../src/SemverLib.sol";
import {NameCoder} from "ens-contracts/utils/NameCoder.sol";
import {BytesUtils} from "ens-contracts/utils/BytesUtils.sol";
import {ENS} from "ens-contracts/registry/ENS.sol";
import {INameWrapper} from "ens-contracts/wrapper/INameWrapper.sol";
import {ITextResolver} from "ens-contracts/resolvers/profiles/ITextResolver.sol";
import {IContentHashResolver} from "ens-contracts/resolvers/profiles/IContentHashResolver.sol";
import {IExtendedResolver} from "ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {MockENSRegistry} from "./mocks/MockENSRegistry.sol";

/// @notice Test wrapper to expose SemverLib internal functions for unit testing
contract SemverLibWrapper is SemverLib {
    /// @notice Exposes the internal _parseVersionFromLabel function for testing
    function parseVersionFromLabel(string memory label) external pure returns (ParsedVersion memory) {
        return _parseVersionFromLabel(label);
    }

    /// @notice Exposes the internal _createVersion function for testing
    function createVersion(uint8 major, uint8 minor, uint16 patch) external pure returns (Version memory) {
        return _createVersion(major, minor, patch);
    }

    /// @notice Exposes the internal _versionToString function for testing
    function versionToString(Version memory version) external pure returns (string memory) {
        return _versionToString(version);
    }

    /// @notice Exposes the internal _compare function for testing
    function compare(Version memory a, Version memory b) external pure returns (ComparisonResult) {
        return _compare(a, b);
    }

    /// @notice Exposes the internal _isGreater function for testing
    function isGreater(Version memory a, Version memory b) external pure returns (bool) {
        return _isGreater(a, b);
    }
}

contract SemverResolverTest is Test {
    SemverResolver resolver;
    MockENSRegistry ens;
    SemverLibWrapper semverLibWrapper;

    address owner;
    address user;

    // Proper ENS namehashes computed via cast namehash
    bytes32 constant TEST_NODE = 0xeb4f647bea6caa36333c816d7b46fdcb05f9466ecacc140ea8c66faf15b3d9f1; // namehash("test.eth")
    bytes32 constant OTHER_NODE = 0x50da669aa0769b150392ab6c9ae66fa53d33365e4e9f630ee83cedccad763b02; // namehash("other.eth")

    bytes32 constant CONTENT_HASH_1 = keccak256("content1");
    bytes32 constant CONTENT_HASH_2 = keccak256("content2");
    bytes32 constant CONTENT_HASH_3 = keccak256("content3");

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");

        ens = new MockENSRegistry();
        resolver = new SemverResolver(ENS(address(ens)), INameWrapper(address(0)));
        semverLibWrapper = new SemverLibWrapper();

        // Set up ownership
        ens.setOwner(TEST_NODE, owner);
        ens.setOwner(OTHER_NODE, owner);
    }

    /// @dev Helper to create DNS-encoded name with version label
    function encodeDnsName(string memory versionLabel, string memory baseDomain) internal pure returns (bytes memory) {
        bytes memory label = bytes(versionLabel);
        bytes memory baseName = NameCoder.encode(baseDomain);

        bytes memory result = new bytes(1 + label.length + baseName.length);
        result[0] = bytes1(uint8(label.length));

        BytesUtils.copyBytes(label, 0, result, 1, label.length);
        BytesUtils.copyBytes(baseName, 0, result, 1 + label.length, baseName.length);

        return result;
    }

    /// @dev Helper to encode raw IPFS hash with proper multihash prefix
    function encodeIpfsContenthash(bytes32 rawHash) internal pure returns (bytes memory) {
        if (rawHash == bytes32(0)) {
            return "";
        }
        return abi.encodePacked(hex"e301701220", rawHash);
    }

    // === Version Text Resolution Tests ===

    function testTextVersionKeyNoVersions() public view {
        string memory version = resolver.text(TEST_NODE, "version");
        assertEq(version, "");
    }

    function testTextVersionKeySingleVersion() public {
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 3, CONTENT_HASH_1);

        string memory version = resolver.text(TEST_NODE, "version");
        assertEq(version, "1.2.3");
    }

    function testTextVersionKeyMultipleVersions() public {
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 5, CONTENT_HASH_2);
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 2, 1, 0, CONTENT_HASH_3);

        string memory version = resolver.text(TEST_NODE, "version");
        assertEq(version, "2.1.0");
    }

    function testTextVersionKeyMaxValues() public {
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 255, 255, 65535, CONTENT_HASH_1);

        string memory version = resolver.text(TEST_NODE, "version");
        assertEq(version, "255.255.65535");
    }

    function testTextVersionKeyZeroVersion() public {
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 0, 0, 1, CONTENT_HASH_1);

        string memory version = resolver.text(TEST_NODE, "version");
        assertEq(version, "0.0.1");
    }

    function testTextVersionKeyDifferentNodes() public {
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 3, CONTENT_HASH_1);
        vm.prank(owner);
        resolver.publishContent(OTHER_NODE, 4, 5, 6, CONTENT_HASH_2);

        string memory testVersion = resolver.text(TEST_NODE, "version");
        string memory otherVersion = resolver.text(OTHER_NODE, "version");

        assertEq(testVersion, "1.2.3");
        assertEq(otherVersion, "4.5.6");
    }

    // === Access Control Tests ===

    function testPublishContentUnauthorized() public {
        vm.expectRevert(abi.encodeWithSelector(SemverResolver.Unauthorised.selector, TEST_NODE, address(this)));
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);
    }

    function testPublishContentEmitsEvents() public {
        vm.prank(owner);

        // Expect ContenthashChanged event
        vm.expectEmit(true, false, false, true);
        emit IContentHashResolver.ContenthashChanged(TEST_NODE, encodeIpfsContenthash(CONTENT_HASH_1));

        // Expect TextChanged event for version
        vm.expectEmit(true, false, false, true);
        emit ITextResolver.TextChanged(TEST_NODE, "version", "version", "1.2.3");

        resolver.publishContent(TEST_NODE, 1, 2, 3, CONTENT_HASH_1);
    }

    function testPublishContentEmitsEventsMultiple() public {
        // First publication
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IContentHashResolver.ContenthashChanged(TEST_NODE, encodeIpfsContenthash(CONTENT_HASH_1));
        vm.expectEmit(true, false, false, true);
        emit ITextResolver.TextChanged(TEST_NODE, "version", "version", "1.0.0");
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Second publication - version should update
        vm.prank(owner);
        vm.expectEmit(true, false, false, true);
        emit IContentHashResolver.ContenthashChanged(TEST_NODE, encodeIpfsContenthash(CONTENT_HASH_2));
        vm.expectEmit(true, false, false, true);
        emit ITextResolver.TextChanged(TEST_NODE, "version", "version", "2.1.5");
        resolver.publishContent(TEST_NODE, 2, 1, 5, CONTENT_HASH_2);

        // Verify the version text reflects the latest
        string memory version = resolver.text(TEST_NODE, "version");
        assertEq(version, "2.1.5");
    }

    // === Edge Cases ===

    function testTextVersionKeyCaseSensitive() public {
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 3, CONTENT_HASH_1);

        // Test exact match (should work)
        string memory version1 = resolver.text(TEST_NODE, "version");
        assertEq(version1, "1.2.3");

        // Test different case (should not match - case sensitive)
        string memory version2 = resolver.text(TEST_NODE, "VERSION");
        assertEq(version2, "");

        string memory version3 = resolver.text(TEST_NODE, "Version");
        assertEq(version3, "");
    }

    function testTextVersionKeyWithWhitespace() public {
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 3, CONTENT_HASH_1);

        // Test with whitespace (should not match)
        string memory version1 = resolver.text(TEST_NODE, " version");
        assertEq(version1, "");

        string memory version2 = resolver.text(TEST_NODE, "version ");
        assertEq(version2, "");

        string memory version3 = resolver.text(TEST_NODE, " version ");
        assertEq(version3, "");
    }

    // === Fuzz Tests ===

    function testFuzzVersionTextResolution(uint8 major, uint8 minor, uint16 patch) public {
        // Skip the zero case since adding 0.0.0 should not be allowed or should be handled specially
        vm.assume(major > 0 || minor > 0 || patch > 0);

        vm.prank(owner);
        resolver.publishContent(TEST_NODE, major, minor, patch, CONTENT_HASH_1);

        string memory version = resolver.text(TEST_NODE, "version");
        string memory expected =
            string(abi.encodePacked(_uint8ToString(major), ".", _uint8ToString(minor), ".", _uint16ToString(patch)));

        assertEq(version, expected);
    }

    // Helper functions to match SemverLib internal functions
    function _uint8ToString(uint8 value) private pure returns (string memory) {
        if (value == 0) return "0";

        uint8 temp = value;
        uint256 digits = 0;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint8(value % 10)));
            value /= 10;
        }

        return string(buffer);
    }

    function _uint16ToString(uint16 value) private pure returns (string memory) {
        if (value == 0) return "0";

        uint16 temp = value;
        uint256 digits = 0;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint16(value % 10)));
            value /= 10;
        }

        return string(buffer);
    }

    // === DNS Label Parsing Security Tests ===

    function testDNSLabelExceedsRemainingBytes() public {
        // Create malformed DNS encoding where label length exceeds remaining bytes
        bytes memory malformedName = hex"0A746573740365746800"; // Label says 10 bytes, but only has "test" (4 bytes)

        vm.expectRevert(abi.encodeWithSelector(NameCoder.DNSDecodingFailed.selector, malformedName));
        resolver.resolve(malformedName, abi.encodeWithSelector(bytes4(keccak256("contenthash(bytes32)"))));
    }

    function testDNSLabelTooLong() public {
        // Create DNS label with length > 63 (DNS limit)
        bytes memory malformedName = new bytes(66);
        malformedName[0] = bytes1(uint8(64)); // Label length = 64 (exceeds limit of 63)
        for (uint256 i = 1; i < 65; i++) {
            malformedName[i] = bytes1(uint8(0x61)); // 'a'
        }
        malformedName[65] = bytes1(uint8(0)); // terminator

        vm.expectRevert(); // NameCoder will revert on invalid DNS encoding
        resolver.resolve(malformedName, abi.encodeWithSelector(bytes4(keccak256("contenthash(bytes32)"))));
    }

    function testDNSLabelValidMaxLength() public {
        // Test valid DNS label at max length (63 bytes)
        // Create a DNS name with 63-char first label that won't be parsed as version (use letters)
        bytes memory validName = new bytes(65);
        validName[0] = bytes1(uint8(63)); // Label length = 63 (valid)
        for (uint256 i = 1; i < 64; i++) {
            validName[i] = bytes1(uint8(0x61)); // 'a'
        }
        validName[64] = bytes1(uint8(0)); // terminator

        // This should not revert on DNS decoding (NameCoder accepts 63 byte labels)
        // It will fail on version parsing since "aaa..." cannot be parsed as a number
        // We expect SemverLib.InvalidVersion error, not a DNS-related error
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        resolver.resolve(validName, abi.encodeWithSelector(bytes4(keccak256("contenthash(bytes32)"))));
    }

    function testDNSLabelZeroLength() public {
        // Zero-length label is the root terminator
        // NameCoder will reject this as invalid DNS encoding (junk after root)
        bytes memory emptyLabel = hex"000365746800"; // Empty first label, then "eth"

        // Should revert with DNSDecodingFailed since root should be alone
        vm.expectRevert();
        resolver.resolve(emptyLabel, abi.encodeWithSelector(bytes4(keccak256("contenthash(bytes32)"))));
    }

    // === Version Parsing Overflow Tests (via resolve interface) ===

    function testVersionParsingOverflowMajor() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Try to resolve a version number that overflows uint8 for major
        bytes memory name = encodeDnsName("256", "test.eth"); // Max uint8 is 255
        bytes memory data = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        vm.expectRevert(SemverLib.InvalidVersion.selector);
        resolver.resolve(name, data);
    }

    function testVersionParsingOverflowMinor() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Try to resolve a version number that overflows uint8 for minor
        bytes memory name = encodeDnsName("1:256", "test.eth"); // Max uint8 is 255
        bytes memory data = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        vm.expectRevert(SemverLib.InvalidVersion.selector);
        resolver.resolve(name, data);
    }

    function testVersionParsingOverflowPatch() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 0, CONTENT_HASH_1);

        // Try to resolve a version number that overflows uint16 for patch
        bytes memory name = encodeDnsName("1:2:65536", "test.eth"); // Max uint16 is 65535
        bytes memory data = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        vm.expectRevert(SemverLib.InvalidVersion.selector);
        resolver.resolve(name, data);
    }

    function testVersionParsingHugeNumber() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Try to resolve an extremely large number
        bytes memory name =
            encodeDnsName("99999999999999999999999999999999999999999999999999999999999999999999", "test.eth");
        bytes memory data = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        vm.expectRevert(SemverLib.InvalidVersion.selector);
        resolver.resolve(name, data);
    }

    function testVersionParsingValidMaxValues() public {
        // Publish max value versions
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 255, 0, 0, CONTENT_HASH_1);
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 255, 255, 0, CONTENT_HASH_2);
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 255, 255, 65535, CONTENT_HASH_3);

        bytes memory selector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        // Test major-only query (255 → finds 255.255.65535 as highest 255.x.x)
        bytes memory result1 = resolver.resolve(encodeDnsName("255", "test.eth"), selector);
        bytes memory hash1 = abi.decode(result1, (bytes));
        assertGt(hash1.length, 0, "Should return contenthash");
        assertEq(hash1, encodeIpfsContenthash(CONTENT_HASH_3));

        // Test major.minor query (255:255 → finds 255.255.65535 as highest 255.255.x)
        bytes memory result2 = resolver.resolve(encodeDnsName("255:255", "test.eth"), selector);
        bytes memory hash2 = abi.decode(result2, (bytes));
        assertGt(hash2.length, 0, "Should return contenthash");
        assertEq(hash2, encodeIpfsContenthash(CONTENT_HASH_3));

        // Test exact query (255:255:65535 → finds exact match)
        bytes memory result3 = resolver.resolve(encodeDnsName("255:255:65535", "test.eth"), selector);
        bytes memory hash3 = abi.decode(result3, (bytes));
        assertGt(hash3.length, 0, "Should return contenthash");
        assertEq(hash3, encodeIpfsContenthash(CONTENT_HASH_3));
    }

    function testVersionParsingMalformedLabelsStillRevert() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        bytes memory selector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        // These should still revert because _parseVersionFromLabel will reject them
        // even though DNS validation passed

        // Test trailing colon (empty component after colon)
        vm.expectRevert(SemverLib.InvalidVersion.selector);
        resolver.resolve(encodeDnsName("1:", "test.eth"), selector);

        // Test double colon (empty component)
        vm.expectRevert(SemverLib.InvalidVersion.selector);
        resolver.resolve(encodeDnsName("1::", "test.eth"), selector);

        // Test non-digit label
        vm.expectRevert(SemverLib.InvalidVersion.selector);
        resolver.resolve(encodeDnsName("abc", "test.eth"), selector);
    }

    function testVersionParsingBoundaryValues() public {
        // Test boundary values through resolve interface
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 254, 254, 65534, CONTENT_HASH_1);
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 255, 255, 65535, CONTENT_HASH_2);

        bytes memory selector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        // Test exact match at max boundary
        bytes memory result1 = resolver.resolve(encodeDnsName("255:255:65535", "test.eth"), selector);
        bytes memory hash1 = abi.decode(result1, (bytes));
        assertGt(hash1.length, 0, "Should return contenthash");
        assertEq(hash1, encodeIpfsContenthash(CONTENT_HASH_2));

        // Test one below max
        bytes memory result2 = resolver.resolve(encodeDnsName("254:254:65534", "test.eth"), selector);
        bytes memory hash2 = abi.decode(result2, (bytes));
        assertGt(hash2.length, 0, "Should return contenthash");
        assertEq(hash2, encodeIpfsContenthash(CONTENT_HASH_1));
    }

    /// @notice Test that "2", "2:0", and "2:0:0" are distinguished correctly
    /// @dev Critical regression test - the parser must track hasMinor and hasPatch flags
    function testMajorVsMinorVsExactDistinction() public {
        // Build a version tree for v2.x
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 2, 0, 0, keccak256("2.0.0"));
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 2, 0, 1, keccak256("2.0.1"));
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 2, 0, 5, keccak256("2.0.5"));
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 2, 1, 0, keccak256("2.1.0"));
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 2, 1, 3, keccak256("2.1.3"));
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 2, 2, 0, keccak256("2.2.0"));

        bytes memory selector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        // Query "2" (major only, hasMinor=false) - should get highest 2.x.x
        bytes memory result2 = resolver.resolve(encodeDnsName("2", "test.eth"), selector);
        bytes memory hash2 = abi.decode(result2, (bytes));
        assertGt(hash2.length, 0, "Should return contenthash");
        assertEq(hash2, encodeIpfsContenthash(keccak256("2.2.0")), "Query '2' should resolve to highest 2.x.x (2.2.0)");

        // Query "2:0" (major.minor, hasMinor=true, hasPatch=false) - should get highest 2.0.x
        bytes memory result20 = resolver.resolve(encodeDnsName("2:0", "test.eth"), selector);
        bytes memory hash20 = abi.decode(result20, (bytes));
        assertGt(hash20.length, 0, "Should return contenthash");
        assertEq(
            hash20, encodeIpfsContenthash(keccak256("2.0.5")), "Query '2:0' should resolve to highest 2.0.x (2.0.5)"
        );

        // Query "2:1" (major.minor) - should get highest 2.1.x
        bytes memory result21 = resolver.resolve(encodeDnsName("2:1", "test.eth"), selector);
        bytes memory hash21 = abi.decode(result21, (bytes));
        assertGt(hash21.length, 0, "Should return contenthash");
        assertEq(
            hash21, encodeIpfsContenthash(keccak256("2.1.3")), "Query '2:1' should resolve to highest 2.1.x (2.1.3)"
        );

        // Query "2:0:0" (exact, hasMinor=true, hasPatch=true) - should get exact 2.0.0
        bytes memory result200 = resolver.resolve(encodeDnsName("2:0:0", "test.eth"), selector);
        bytes memory hash200 = abi.decode(result200, (bytes));
        assertGt(hash200.length, 0, "Should return contenthash");
        assertEq(
            hash200, encodeIpfsContenthash(keccak256("2.0.0")), "Query '2:0:0' should resolve to exact version 2.0.0"
        );

        // Query "2:0:1" (exact) - should get exact 2.0.1
        bytes memory result201 = resolver.resolve(encodeDnsName("2:0:1", "test.eth"), selector);
        bytes memory hash201 = abi.decode(result201, (bytes));
        assertGt(hash201.length, 0, "Should return contenthash");
        assertEq(
            hash201, encodeIpfsContenthash(keccak256("2.0.1")), "Query '2:0:1' should resolve to exact version 2.0.1"
        );

        // Query "2:1:0" (exact) - should get exact 2.1.0
        bytes memory result210 = resolver.resolve(encodeDnsName("2:1:0", "test.eth"), selector);
        bytes memory hash210 = abi.decode(result210, (bytes));
        assertGt(hash210.length, 0, "Should return contenthash");
        assertEq(
            hash210, encodeIpfsContenthash(keccak256("2.1.0")), "Query '2:1:0' should resolve to exact version 2.1.0"
        );

        // Verify text resolution also works correctly
        bytes memory textSelector = abi.encodeWithSelector(ITextResolver.text.selector, TEST_NODE, "version");

        bytes memory textResult2 = resolver.resolve(encodeDnsName("2", "test.eth"), textSelector);
        string memory text2 = abi.decode(textResult2, (string));
        assertEq(text2, "2.2.0", "Text for '2' should be 2.2.0");

        bytes memory textResult20 = resolver.resolve(encodeDnsName("2:0", "test.eth"), textSelector);
        string memory text20 = abi.decode(textResult20, (string));
        assertEq(text20, "2.0.5", "Text for '2:0' should be 2.0.5");

        bytes memory textResult200 = resolver.resolve(encodeDnsName("2:0:0", "test.eth"), textSelector);
        string memory text200 = abi.decode(textResult200, (string));
        assertEq(text200, "2.0.0", "Text for '2:0:0' should be 2.0.0");
    }

    // === Interface Support Tests ===

    function testSupportsInterface() public view {
        // Test IExtendedResolver
        assertTrue(resolver.supportsInterface(type(IExtendedResolver).interfaceId), "Should support IExtendedResolver");

        // Test IContentHashResolver
        assertTrue(
            resolver.supportsInterface(type(IContentHashResolver).interfaceId), "Should support IContentHashResolver"
        );

        // Test ENSIP-7 contenthash interface
        assertTrue(resolver.supportsInterface(0xbc1c58d1), "Should support ENSIP-7 contenthash");

        // Test ITextResolver
        assertTrue(resolver.supportsInterface(type(ITextResolver).interfaceId), "Should support ITextResolver");

        // Test ERC165
        assertTrue(resolver.supportsInterface(0x01ffc9a7), "Should support ERC165");

        // Test unsupported interface
        assertFalse(resolver.supportsInterface(0x12345678), "Should not support random interface");
    }

    // === Unsupported Resolver Profile Tests ===

    function testUnsupportedResolverProfile() public {
        bytes memory name = encodeDnsName("1:0:0", "test.eth");

        // Test with an unsupported selector (e.g., addr selector)
        bytes4 unsupportedSelector = bytes4(keccak256("addr(bytes32)"));
        bytes memory data = abi.encodeWithSelector(unsupportedSelector, TEST_NODE);

        vm.expectRevert(abi.encodeWithSelector(SemverResolver.UnsupportedResolverProfile.selector, unsupportedSelector));
        resolver.resolve(name, data);
    }

    function testUnsupportedResolverProfileWithShortData() public {
        bytes memory name = encodeDnsName("1:0:0", "test.eth");

        // Test with data that's too short (less than 4 bytes)
        bytes memory shortData = hex"123456";

        vm.expectRevert("Invalid data length");
        resolver.resolve(name, shortData);
    }

    // === Edge Case Tests for DNS Decoding Failures ===

    function testResolveWildcardVersionEmptyName() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Test with empty name - NameCoder.namehash will fail with DNSDecodingFailed
        bytes memory emptyName = "";
        bytes memory data = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        vm.expectRevert(abi.encodeWithSelector(NameCoder.DNSDecodingFailed.selector, emptyName));
        resolver.resolve(emptyName, data);
    }

    function testResolveWildcardVersionInvalidLabelLength() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Create a name with invalid label length (label length exceeds remaining bytes)
        bytes memory invalidName = hex"FF"; // Label says 255 bytes but no more data
        bytes memory data = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        vm.expectRevert(abi.encodeWithSelector(NameCoder.DNSDecodingFailed.selector, invalidName));
        resolver.resolve(invalidName, data);
    }

    function testResolveWildcardVersionZeroLabelLength() public {
        // Publish a version first
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Create a name with zero label length
        bytes memory zeroLabelName = hex"0003657468"; // Zero-length first label, then "eth"
        bytes memory data = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, TEST_NODE);

        vm.expectRevert(abi.encodeWithSelector(NameCoder.DNSDecodingFailed.selector, zeroLabelName));
        resolver.resolve(zeroLabelName, data);
    }

    // === Additional Contenthash Tests ===

    function testContenthashDirectResolution() public {
        // Test direct contenthash resolution (non-wildcard)
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 3, CONTENT_HASH_1);

        bytes memory hash = resolver.contenthash(TEST_NODE);
        bytes memory expectedHash = encodeIpfsContenthash(CONTENT_HASH_1);
        assertGt(hash.length, 0, "Should return non-empty hash");
        assertEq(hash, expectedHash, "Should return correct hash");
    }

    function testContenthashDirectResolutionEmpty() public view {
        // Test direct contenthash resolution with no versions
        bytes memory hash = resolver.contenthash(TEST_NODE);
        assertEq(hash.length, 0, "Should return empty hash");
    }

    // === Additional Text Resolution Tests ===

    function testTextNonVersionKey() public {
        // Test text resolution for non-"version" key
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 2, 3, CONTENT_HASH_1);

        string memory result = resolver.text(TEST_NODE, "description");
        assertEq(result, "", "Non-version keys should return empty string");
    }

    // === SemverLib Unit Tests for 100% Coverage ===

    function testParseVersionFromLabelEmpty() public {
        // Test empty label case - should trigger line 80: revert InvalidVersion()
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("");
    }

    function testParseVersionFromLabelValidCases() public view {
        // Verify that valid cases still work correctly (regression test)

        // Major only
        SemverLib.ParsedVersion memory result = semverLibWrapper.parseVersionFromLabel("1");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 0);
        assertEq(result.version.patch, 0);
        assertEq(result.hasMinor, false);
        assertEq(result.hasPatch, false);

        // Major:minor
        result = semverLibWrapper.parseVersionFromLabel("1:2");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 0);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, false);

        // Full version
        result = semverLibWrapper.parseVersionFromLabel("1:2:3");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 3);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, true);
    }

    // === Additional SemverLib Edge Case Tests ===

    function testParseVersionFromLabelEmptyAfterColon() public {
        // Test empty component after colon - covers line 97: require(pos < data.length, InvalidVersion())
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("1:");
    }

    function testParseVersionFromLabelEmptyAfterSecondColon() public {
        // Test empty component after second colon - covers line 108: require(pos < data.length, InvalidVersion())
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("1:2:");
    }

    function testParseVersionFromLabelInvalidCharacters() public view {
        // Test invalid characters in major component
        // Note: _parseNumberUntil stops at first non-digit character (line 151: break)
        // So "a" has no digits → hasDigits=false → requires InvalidVersion
        SemverLib.ParsedVersion memory result;

        // "1a" parses "1" then stops at "a", so it succeeds with major=1
        result = semverLibWrapper.parseVersionFromLabel("1a");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 0);
        assertEq(result.version.patch, 0);
        assertEq(result.hasMinor, false);
        assertEq(result.hasPatch, false);

        // "1:2b" parses "1" then "2" then stops at "b", so it succeeds
        result = semverLibWrapper.parseVersionFromLabel("1:2b");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 0);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, false);

        // "1:2:3c" parses all numbers then stops, succeeds
        result = semverLibWrapper.parseVersionFromLabel("1:2:3c");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 3);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, true);
    }

    function testParseVersionFromLabelSpecialCharacters() public view {
        // Test various special characters
        // These all parse the first number then stop at the special character
        SemverLib.ParsedVersion memory result;

        result = semverLibWrapper.parseVersionFromLabel("1-2");
        assertEq(result.version.major, 1);
        assertEq(result.hasMinor, false);

        result = semverLibWrapper.parseVersionFromLabel("1.2");
        assertEq(result.version.major, 1);
        assertEq(result.hasMinor, false);

        result = semverLibWrapper.parseVersionFromLabel("1_2");
        assertEq(result.version.major, 1);
        assertEq(result.hasMinor, false);

        result = semverLibWrapper.parseVersionFromLabel("1+2");
        assertEq(result.version.major, 1);
        assertEq(result.hasMinor, false);

        result = semverLibWrapper.parseVersionFromLabel("1 2");
        assertEq(result.version.major, 1);
        assertEq(result.hasMinor, false);
    }

    function testParseVersionFromLabelLeadingZeros() public view {
        // Test leading zeros - should be parsed correctly
        SemverLib.ParsedVersion memory result = semverLibWrapper.parseVersionFromLabel("01");
        assertEq(result.version.major, 1);
        assertEq(result.hasMinor, false);

        result = semverLibWrapper.parseVersionFromLabel("001:002");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.hasMinor, true);

        result = semverLibWrapper.parseVersionFromLabel("01:02:03");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 3);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, true);
    }

    function testParseVersionFromLabelZeroValues() public view {
        // Test zero values
        SemverLib.ParsedVersion memory result = semverLibWrapper.parseVersionFromLabel("0");
        assertEq(result.version.major, 0);
        assertEq(result.version.minor, 0);
        assertEq(result.version.patch, 0);
        assertEq(result.hasMinor, false);
        assertEq(result.hasPatch, false);

        result = semverLibWrapper.parseVersionFromLabel("0:0");
        assertEq(result.version.major, 0);
        assertEq(result.version.minor, 0);
        assertEq(result.version.patch, 0);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, false);

        result = semverLibWrapper.parseVersionFromLabel("0:0:0");
        assertEq(result.version.major, 0);
        assertEq(result.version.minor, 0);
        assertEq(result.version.patch, 0);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, true);
    }

    function testParseVersionFromLabelOverflowBoundaryMajor() public {
        // Test major version at uint8 boundary (255 should work, 256 should fail)
        SemverLib.ParsedVersion memory result = semverLibWrapper.parseVersionFromLabel("255");
        assertEq(result.version.major, 255);

        // Test overflow for major version
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("256");

        // Test much larger overflow
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("999999");
    }

    function testParseVersionFromLabelOverflowBoundaryMinor() public {
        // Test minor version at uint8 boundary
        SemverLib.ParsedVersion memory result = semverLibWrapper.parseVersionFromLabel("1:255");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 255);

        // Test overflow for minor version
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("1:256");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("1:999999");
    }

    function testParseVersionFromLabelOverflowBoundaryPatch() public {
        // Test patch version at uint16 boundary
        SemverLib.ParsedVersion memory result = semverLibWrapper.parseVersionFromLabel("1:2:65535");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 65535);

        // Test overflow for patch version
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("1:2:65536");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("1:2:999999999");
    }

    function testParseVersionFromLabelExtremeBoundaryValues() public view {
        // Test values at exact overflow boundaries to ensure proper validation

        // Test 254 vs 255 for major (both should work)
        SemverLib.ParsedVersion memory result = semverLibWrapper.parseVersionFromLabel("254");
        assertEq(result.version.major, 254);

        result = semverLibWrapper.parseVersionFromLabel("255");
        assertEq(result.version.major, 255);

        // Test 254 vs 255 for minor (both should work)
        result = semverLibWrapper.parseVersionFromLabel("1:254");
        assertEq(result.version.minor, 254);

        result = semverLibWrapper.parseVersionFromLabel("1:255");
        assertEq(result.version.minor, 255);

        // Test 65534 vs 65535 for patch (both should work)
        result = semverLibWrapper.parseVersionFromLabel("1:2:65534");
        assertEq(result.version.patch, 65534);

        result = semverLibWrapper.parseVersionFromLabel("1:2:65535");
        assertEq(result.version.patch, 65535);
    }

    function testParseVersionFromLabelNoDigitsAfterColon() public {
        // Test cases where there are no digits after parsing starts (covers line 155: require(hasDigits, InvalidVersion()))
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel(":");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("1::");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("::1");
    }

    function testParseVersionFromLabelTrailingCharacters() public view {
        // Test trailing non-digit characters that cause parsing to stop
        // These succeed because at least some digits were parsed
        SemverLib.ParsedVersion memory result;

        result = semverLibWrapper.parseVersionFromLabel("1x");
        assertEq(result.version.major, 1);
        assertEq(result.hasMinor, false);

        result = semverLibWrapper.parseVersionFromLabel("1:2x");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, false);

        result = semverLibWrapper.parseVersionFromLabel("1:2:3x");
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 3);
        assertEq(result.hasMinor, true);
        assertEq(result.hasPatch, true);

        result = semverLibWrapper.parseVersionFromLabel("123abc");
        assertEq(result.version.major, 123);
        assertEq(result.hasMinor, false);
    }

    function testParseVersionFromLabelTrueInvalidCases() public {
        // Test cases that actually trigger InvalidVersion errors

        // Pure non-digit characters (no digits parsed)
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("a");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("abc");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("xyz");

        // Starting with non-digit characters
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("x1");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("-1");

        // Only special characters
        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("---");

        vm.expectRevert(abi.encodeWithSelector(SemverLib.InvalidVersion.selector));
        semverLibWrapper.parseVersionFromLabel("...");
    }

    // === SemverLib Core Function Tests ===

    function testCreateVersion() public view {
        // Test _createVersion function with various inputs
        SemverLib.Version memory version = semverLibWrapper.createVersion(1, 2, 3);
        assertEq(version.major, 1);
        assertEq(version.minor, 2);
        assertEq(version.patch, 3);

        // Test with zero values
        version = semverLibWrapper.createVersion(0, 0, 0);
        assertEq(version.major, 0);
        assertEq(version.minor, 0);
        assertEq(version.patch, 0);

        // Test with max values
        version = semverLibWrapper.createVersion(255, 255, 65535);
        assertEq(version.major, 255);
        assertEq(version.minor, 255);
        assertEq(version.patch, 65535);
    }

    function testVersionToString() public view {
        // Test _versionToString function with various inputs
        SemverLib.Version memory version = semverLibWrapper.createVersion(1, 2, 3);
        string memory result = semverLibWrapper.versionToString(version);
        assertEq(result, "1.2.3");

        // Test with zero values
        version = semverLibWrapper.createVersion(0, 0, 0);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "0.0.0");

        // Test with single digit variations
        version = semverLibWrapper.createVersion(1, 0, 0);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "1.0.0");

        version = semverLibWrapper.createVersion(0, 1, 0);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "0.1.0");

        version = semverLibWrapper.createVersion(0, 0, 1);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "0.0.1");

        // Test with max values
        version = semverLibWrapper.createVersion(255, 255, 65535);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "255.255.65535");

        // Test with multi-digit numbers
        version = semverLibWrapper.createVersion(12, 34, 567);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "12.34.567");
    }

    function testCompareVersions() public view {
        // Test _compare function with all possible comparison results

        // Test equal versions
        SemverLib.Version memory v1 = semverLibWrapper.createVersion(1, 2, 3);
        SemverLib.Version memory v2 = semverLibWrapper.createVersion(1, 2, 3);
        SemverLib.ComparisonResult result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Equal));

        // Test major version differences
        v1 = semverLibWrapper.createVersion(1, 2, 3);
        v2 = semverLibWrapper.createVersion(2, 1, 1);
        result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Less));

        v1 = semverLibWrapper.createVersion(2, 1, 1);
        v2 = semverLibWrapper.createVersion(1, 2, 3);
        result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Greater));

        // Test minor version differences (when major is equal)
        v1 = semverLibWrapper.createVersion(1, 1, 3);
        v2 = semverLibWrapper.createVersion(1, 2, 1);
        result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Less));

        v1 = semverLibWrapper.createVersion(1, 2, 1);
        v2 = semverLibWrapper.createVersion(1, 1, 3);
        result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Greater));

        // Test patch version differences (when major and minor are equal)
        v1 = semverLibWrapper.createVersion(1, 2, 1);
        v2 = semverLibWrapper.createVersion(1, 2, 2);
        result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Less));

        v1 = semverLibWrapper.createVersion(1, 2, 2);
        v2 = semverLibWrapper.createVersion(1, 2, 1);
        result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Greater));
    }

    function testIsGreater() public view {
        // Test _isGreater function
        SemverLib.Version memory v1 = semverLibWrapper.createVersion(2, 0, 0);
        SemverLib.Version memory v2 = semverLibWrapper.createVersion(1, 9, 9);
        assertTrue(semverLibWrapper.isGreater(v1, v2));
        assertFalse(semverLibWrapper.isGreater(v2, v1));

        // Test equal versions
        v1 = semverLibWrapper.createVersion(1, 2, 3);
        v2 = semverLibWrapper.createVersion(1, 2, 3);
        assertFalse(semverLibWrapper.isGreater(v1, v2));
        assertFalse(semverLibWrapper.isGreater(v2, v1));

        // Test minor version greater
        v1 = semverLibWrapper.createVersion(1, 3, 0);
        v2 = semverLibWrapper.createVersion(1, 2, 9);
        assertTrue(semverLibWrapper.isGreater(v1, v2));
        assertFalse(semverLibWrapper.isGreater(v2, v1));

        // Test patch version greater
        v1 = semverLibWrapper.createVersion(1, 2, 4);
        v2 = semverLibWrapper.createVersion(1, 2, 3);
        assertTrue(semverLibWrapper.isGreater(v1, v2));
        assertFalse(semverLibWrapper.isGreater(v2, v1));

        // Test with zero versions
        v1 = semverLibWrapper.createVersion(0, 0, 1);
        v2 = semverLibWrapper.createVersion(0, 0, 0);
        assertTrue(semverLibWrapper.isGreater(v1, v2));
        assertFalse(semverLibWrapper.isGreater(v2, v1));
    }

    function testCompareVersionsEdgeCases() public view {
        // Test edge cases for version comparison

        // Test zero vs non-zero
        SemverLib.Version memory zero = semverLibWrapper.createVersion(0, 0, 0);
        SemverLib.Version memory nonZero = semverLibWrapper.createVersion(0, 0, 1);
        SemverLib.ComparisonResult result = semverLibWrapper.compare(zero, nonZero);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Less));

        // Test max values comparison
        SemverLib.Version memory max1 = semverLibWrapper.createVersion(255, 255, 65535);
        SemverLib.Version memory max2 = semverLibWrapper.createVersion(255, 255, 65534);
        result = semverLibWrapper.compare(max1, max2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Greater));

        // Test boundary conditions
        SemverLib.Version memory v1 = semverLibWrapper.createVersion(1, 0, 0);
        SemverLib.Version memory v2 = semverLibWrapper.createVersion(0, 255, 65535);
        result = semverLibWrapper.compare(v1, v2);
        assertEq(uint256(result), uint256(SemverLib.ComparisonResult.Greater));
    }

    function testVersionToStringUintConversion() public view {
        // Test _uintToString function indirectly through _versionToString with edge cases

        // Test various number sizes to ensure _uintToString works correctly
        SemverLib.Version memory version;
        string memory result;

        // Single digit numbers
        for (uint8 i = 0; i <= 9; i++) {
            version = semverLibWrapper.createVersion(i, i, i);
            result = semverLibWrapper.versionToString(version);
            // Verify the format is correct for single digits
            assertEq(bytes(result).length, 5); // "X.X.X" = 5 characters
        }

        // Two digit numbers
        version = semverLibWrapper.createVersion(10, 11, 12);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "10.11.12");

        // Three digit numbers
        version = semverLibWrapper.createVersion(100, 200, 300);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "100.200.300");

        // Max values for each component type
        version = semverLibWrapper.createVersion(255, 255, 65535);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "255.255.65535");

        // Test specific boundary values
        version = semverLibWrapper.createVersion(99, 99, 9999);
        result = semverLibWrapper.versionToString(version);
        assertEq(result, "99.99.9999");
    }

    function testVersionFunctionInteractions() public view {
        // Test interactions between different SemverLib functions

        // Create version -> convert to string -> verify consistency
        SemverLib.Version memory original = semverLibWrapper.createVersion(42, 13, 1337);
        string memory versionString = semverLibWrapper.versionToString(original);
        assertEq(versionString, "42.13.1337");

        // Test version comparison consistency
        SemverLib.Version memory lower = semverLibWrapper.createVersion(1, 0, 0);
        SemverLib.Version memory higher = semverLibWrapper.createVersion(1, 0, 1);

        assertTrue(semverLibWrapper.isGreater(higher, lower));
        assertFalse(semverLibWrapper.isGreater(lower, higher));
        assertEq(uint256(semverLibWrapper.compare(lower, higher)), uint256(SemverLib.ComparisonResult.Less));
        assertEq(uint256(semverLibWrapper.compare(higher, lower)), uint256(SemverLib.ComparisonResult.Greater));

        // Test version equality
        SemverLib.Version memory copy = semverLibWrapper.createVersion(42, 13, 1337);
        assertEq(uint256(semverLibWrapper.compare(original, copy)), uint256(SemverLib.ComparisonResult.Equal));
        assertFalse(semverLibWrapper.isGreater(original, copy));
        assertFalse(semverLibWrapper.isGreater(copy, original));
    }
}
