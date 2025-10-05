// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {VersionRegistry} from "../src/VersionRegistry.sol";
import {SemverLib} from "../src/SemverLib.sol";

// Concrete implementation of VersionRegistry for testing
contract TestVersionRegistry is VersionRegistry {
    // Public wrapper functions to test internal functions
    function addVersionPublic(bytes32 namehash, uint8 major, uint8 minor, uint16 patch, bytes32 contentHash) external {
        addVersion(namehash, major, minor, patch, contentHash);
    }

    function getLatestContentHashPublic(bytes32 namehash) external view returns (bytes32) {
        return getLatestContentHash(namehash);
    }

    function getLatestVersionPublic(bytes32 namehash) external view returns (Version memory) {
        return getLatestVersion(namehash);
    }

    function getHighestVersionForMajorPublic(bytes32 namehash, uint8 targetMajor)
        external
        view
        returns (VersionRecord memory)
    {
        return getHighestVersionForMajor(namehash, targetMajor);
    }

    function getHighestVersionForMajorMinorPublic(bytes32 namehash, uint8 targetMajor, uint8 targetMinor)
        external
        view
        returns (VersionRecord memory)
    {
        return getHighestVersionForMajorMinor(namehash, targetMajor, targetMinor);
    }

    function getExactVersionPublic(bytes32 namehash, uint8 targetMajor, uint8 targetMinor, uint16 targetPatch)
        external
        view
        returns (VersionRecord memory)
    {
        return getExactVersion(namehash, targetMajor, targetMinor, targetPatch);
    }
}

contract VersionRegistryTest is Test {
    TestVersionRegistry registry;

    bytes32 constant TEST_NAMEHASH = keccak256("test.eth");
    bytes32 constant OTHER_NAMEHASH = keccak256("other.eth");

    bytes32 constant CONTENT_HASH_1 = keccak256("content1");
    bytes32 constant CONTENT_HASH_2 = keccak256("content2");
    bytes32 constant CONTENT_HASH_3 = keccak256("content3");
    bytes32 constant CONTENT_HASH_4 = keccak256("content4");

    function setUp() public {
        registry = new TestVersionRegistry();
    }

    // === Version Addition Tests ===

    function testAddFirstVersion() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);

        bytes32 latestHash = registry.getLatestContentHashPublic(TEST_NAMEHASH);
        SemverLib.Version memory latestVersion = registry.getLatestVersionPublic(TEST_NAMEHASH);

        assertEq(latestHash, CONTENT_HASH_1);
        assertEq(latestVersion.major, 1);
        assertEq(latestVersion.minor, 0);
        assertEq(latestVersion.patch, 0);
    }

    function testAddMultipleVersionsInOrder() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 1, CONTENT_HASH_2);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 0, CONTENT_HASH_3);
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 0, CONTENT_HASH_4);

        bytes32 latestHash = registry.getLatestContentHashPublic(TEST_NAMEHASH);
        SemverLib.Version memory latestVersion = registry.getLatestVersionPublic(TEST_NAMEHASH);

        assertEq(latestHash, CONTENT_HASH_4);
        assertEq(latestVersion.major, 2);
        assertEq(latestVersion.minor, 0);
        assertEq(latestVersion.patch, 0);
    }

    function testAddVersionNotGreaterReverts() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 3, CONTENT_HASH_1);

        // Try to add a smaller version
        vm.expectRevert(abi.encodeWithSelector(VersionRegistry.VersionNotGreater.selector));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 2, CONTENT_HASH_2);

        // Try to add the same version
        vm.expectRevert(abi.encodeWithSelector(VersionRegistry.VersionNotGreater.selector));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 3, CONTENT_HASH_2);

        // Try to add smaller major version
        vm.expectRevert(abi.encodeWithSelector(VersionRegistry.VersionNotGreater.selector));
        registry.addVersionPublic(TEST_NAMEHASH, 0, 9, 9, CONTENT_HASH_2);

        // Try to add smaller minor version
        vm.expectRevert(abi.encodeWithSelector(VersionRegistry.VersionNotGreater.selector));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 9, CONTENT_HASH_2);
    }

    function testAddVersionToMultipleNamehashes() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);
        registry.addVersionPublic(OTHER_NAMEHASH, 2, 0, 0, CONTENT_HASH_2);

        bytes32 testHash = registry.getLatestContentHashPublic(TEST_NAMEHASH);
        bytes32 otherHash = registry.getLatestContentHashPublic(OTHER_NAMEHASH);

        assertEq(testHash, CONTENT_HASH_1);
        assertEq(otherHash, CONTENT_HASH_2);
    }

    // === Latest Version Retrieval Tests ===

    function testGetLatestContentHashEmpty() public view {
        bytes32 latestHash = registry.getLatestContentHashPublic(TEST_NAMEHASH);
        assertEq(latestHash, bytes32(0));
    }

    function testGetLatestVersionEmpty() public view {
        SemverLib.Version memory latestVersion = registry.getLatestVersionPublic(TEST_NAMEHASH);

        assertEq(latestVersion.major, 0);
        assertEq(latestVersion.minor, 0);
        assertEq(latestVersion.patch, 0);
    }

    function testGetLatestAfterMultipleAdditions() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 0, CONTENT_HASH_2);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 5, CONTENT_HASH_3);

        bytes32 latestHash = registry.getLatestContentHashPublic(TEST_NAMEHASH);
        SemverLib.Version memory latestVersion = registry.getLatestVersionPublic(TEST_NAMEHASH);

        assertEq(latestHash, CONTENT_HASH_3);
        assertEq(latestVersion.major, 1);
        assertEq(latestVersion.minor, 2);
        assertEq(latestVersion.patch, 5);
    }

    // === Major Version Search Tests ===

    function testGetHighestVersionForMajorEmpty() public view {
        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 1);

        assertEq(record.version.major, 0);
        assertEq(record.version.minor, 0);
        assertEq(record.version.patch, 0);
        assertEq(record.contentHash, bytes32(0));
    }

    function testGetHighestVersionForMajorSingleMatch() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 5, 3, CONTENT_HASH_1);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 1);

        assertEq(record.version.major, 1);
        assertEq(record.version.minor, 5);
        assertEq(record.version.patch, 3);
        assertEq(record.contentHash, CONTENT_HASH_1);
    }

    function testGetHighestVersionForMajorMultipleMatches() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 0, CONTENT_HASH_2);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 5, CONTENT_HASH_3);
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 0, CONTENT_HASH_4);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 1);

        assertEq(record.version.major, 1);
        assertEq(record.version.minor, 2);
        assertEq(record.version.patch, 5);
        assertEq(record.contentHash, CONTENT_HASH_3);
    }

    function testGetHighestVersionForMajorNoMatch() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 3, 0, 0, CONTENT_HASH_2);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 2);

        assertEq(record.version.major, 0);
        assertEq(record.version.minor, 0);
        assertEq(record.version.patch, 0);
        assertEq(record.contentHash, bytes32(0));
    }

    function testGetHighestVersionForMajorWithGaps() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 1, CONTENT_HASH_2);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 5, CONTENT_HASH_3);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 0, CONTENT_HASH_4);
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 0, keccak256("other"));

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 1);

        assertEq(record.version.major, 1);
        assertEq(record.version.minor, 1);
        assertEq(record.version.patch, 0);
        assertEq(record.contentHash, CONTENT_HASH_4);
    }

    // === Major.Minor Version Search Tests ===

    function testGetHighestVersionForMajorMinorEmpty() public view {
        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 2);

        assertEq(record.version.major, 0);
        assertEq(record.version.minor, 0);
        assertEq(record.version.patch, 0);
        assertEq(record.contentHash, bytes32(0));
    }

    function testGetHighestVersionForMajorMinorSingleMatch() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 5, CONTENT_HASH_1);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 2);

        assertEq(record.version.major, 1);
        assertEq(record.version.minor, 2);
        assertEq(record.version.patch, 5);
        assertEq(record.contentHash, CONTENT_HASH_1);
    }

    function testGetHighestVersionForMajorMinorMultipleMatches() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 0, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 3, CONTENT_HASH_2);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 7, CONTENT_HASH_3);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 3, 0, CONTENT_HASH_4);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 2);

        assertEq(record.version.major, 1);
        assertEq(record.version.minor, 2);
        assertEq(record.version.patch, 7);
        assertEq(record.contentHash, CONTENT_HASH_3);
    }

    function testGetHighestVersionForMajorMinorNoMatch() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 0, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 3, 0, CONTENT_HASH_2);
        registry.addVersionPublic(TEST_NAMEHASH, 2, 2, 0, CONTENT_HASH_3);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 2);

        assertEq(record.version.major, 0);
        assertEq(record.version.minor, 0);
        assertEq(record.version.patch, 0);
        assertEq(record.contentHash, bytes32(0));
    }

    function testGetHighestVersionForMajorMinorMajorNoMatch() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 5, CONTENT_HASH_1);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 2, 2);

        assertEq(record.version.major, 0);
        assertEq(record.version.minor, 0);
        assertEq(record.version.patch, 0);
        assertEq(record.contentHash, bytes32(0));
    }

    // === Complex Search Scenarios ===

    function testComplexVersionHistory() public {
        // Build a complex version history: 1.0.0, 1.0.1, 1.1.0, 1.1.2, 2.0.0, 2.0.1, 2.1.0, 3.0.0
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, keccak256("1.0.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 1, keccak256("1.0.1"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 0, keccak256("1.1.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 2, keccak256("1.1.2"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 0, keccak256("2.0.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 1, keccak256("2.0.1"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 1, 0, keccak256("2.1.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 3, 0, 0, keccak256("3.0.0"));

        // Test latest version
        SemverLib.Version memory latest = registry.getLatestVersionPublic(TEST_NAMEHASH);
        assertEq(latest.major, 3);
        assertEq(latest.minor, 0);
        assertEq(latest.patch, 0);

        // Test highest in major version 1
        VersionRegistry.VersionRecord memory v1 = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 1);
        assertEq(v1.version.major, 1);
        assertEq(v1.version.minor, 1);
        assertEq(v1.version.patch, 2);
        assertEq(v1.contentHash, keccak256("1.1.2"));

        // Test highest in major version 2
        VersionRegistry.VersionRecord memory v2 = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 2);
        assertEq(v2.version.major, 2);
        assertEq(v2.version.minor, 1);
        assertEq(v2.version.patch, 0);
        assertEq(v2.contentHash, keccak256("2.1.0"));

        // Test highest in major.minor 1.0
        VersionRegistry.VersionRecord memory v10 = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 0);
        assertEq(v10.version.major, 1);
        assertEq(v10.version.minor, 0);
        assertEq(v10.version.patch, 1);
        assertEq(v10.contentHash, keccak256("1.0.1"));

        // Test highest in major.minor 2.0
        VersionRegistry.VersionRecord memory v20 = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 2, 0);
        assertEq(v20.version.major, 2);
        assertEq(v20.version.minor, 0);
        assertEq(v20.version.patch, 1);
        assertEq(v20.contentHash, keccak256("2.0.1"));
    }

    // === Edge Cases and Boundary Tests ===

    function testMaxVersionValues() public {
        registry.addVersionPublic(TEST_NAMEHASH, 255, 255, 65535, CONTENT_HASH_1);

        SemverLib.Version memory latest = registry.getLatestVersionPublic(TEST_NAMEHASH);
        assertEq(latest.major, 255);
        assertEq(latest.minor, 255);
        assertEq(latest.patch, 65535);
    }

    function testZeroVersions() public {
        // 0.0.0 is no longer allowed (reserved as sentinel value)
        // But 0.0.1 and other pre-release versions are allowed
        registry.addVersionPublic(TEST_NAMEHASH, 0, 0, 1, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 0, 0, 2, CONTENT_HASH_2);

        VersionRegistry.VersionRecord memory record = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 0, 0);
        assertEq(record.version.major, 0);
        assertEq(record.version.minor, 0);
        assertEq(record.version.patch, 2);
        assertEq(record.contentHash, CONTENT_HASH_2);
    }

    function testSingleVersionMultipleQueries() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 5, 3, CONTENT_HASH_1);

        // All these should return the same version
        VersionRegistry.VersionRecord memory latest = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 1);
        VersionRegistry.VersionRecord memory majorMinor =
            registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 5);

        assertEq(latest.version.major, 1);
        assertEq(latest.version.minor, 5);
        assertEq(latest.version.patch, 3);
        assertEq(latest.contentHash, CONTENT_HASH_1);

        assertEq(majorMinor.version.major, 1);
        assertEq(majorMinor.version.minor, 5);
        assertEq(majorMinor.version.patch, 3);
        assertEq(majorMinor.contentHash, CONTENT_HASH_1);
    }

    // === Fuzz Tests ===

    function testFuzzAddVersionsInOrder(
        uint8 major1,
        uint8 minor1,
        uint16 patch1,
        uint8 major2,
        uint8 minor2,
        uint16 patch2
    ) public {
        // Exclude 0.0.0 as it's reserved as sentinel value
        vm.assume(!(major1 == 0 && minor1 == 0 && patch1 == 0));
        vm.assume(!(major2 == 0 && minor2 == 0 && patch2 == 0));

        // Ensure version2 > version1
        vm.assume(
            major2 > major1 || (major2 == major1 && minor2 > minor1)
                || (major2 == major1 && minor2 == minor1 && patch2 > patch1)
        );

        registry.addVersionPublic(TEST_NAMEHASH, major1, minor1, patch1, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, major2, minor2, patch2, CONTENT_HASH_2);

        SemverLib.Version memory latest = registry.getLatestVersionPublic(TEST_NAMEHASH);
        assertEq(latest.major, major2);
        assertEq(latest.minor, minor2);
        assertEq(latest.patch, patch2);
    }

    function testFuzzAddVersionsWrongOrder(
        uint8 major1,
        uint8 minor1,
        uint16 patch1,
        uint8 major2,
        uint8 minor2,
        uint16 patch2
    ) public {
        // Exclude 0.0.0 as it's reserved as sentinel value
        vm.assume(!(major1 == 0 && minor1 == 0 && patch1 == 0));
        vm.assume(!(major2 == 0 && minor2 == 0 && patch2 == 0));

        // Ensure version2 <= version1
        vm.assume(
            major2 < major1 || (major2 == major1 && minor2 < minor1)
                || (major2 == major1 && minor2 == minor1 && patch2 <= patch1)
        );

        registry.addVersionPublic(TEST_NAMEHASH, major1, minor1, patch1, CONTENT_HASH_1);

        vm.expectRevert(abi.encodeWithSelector(VersionRegistry.VersionNotGreater.selector));
        registry.addVersionPublic(TEST_NAMEHASH, major2, minor2, patch2, CONTENT_HASH_2);
    }

    function testFuzzMajorVersionSearch(uint8 targetMajor) public {
        // Add some versions with different majors
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, keccak256("1.0.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 3, keccak256("1.2.3"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 1, 0, keccak256("2.1.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 5, 0, 0, keccak256("5.0.0"));

        VersionRegistry.VersionRecord memory record =
            registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, targetMajor);

        if (targetMajor == 1) {
            assertEq(record.version.major, 1);
            assertEq(record.version.minor, 2);
            assertEq(record.version.patch, 3);
        } else if (targetMajor == 2) {
            assertEq(record.version.major, 2);
            assertEq(record.version.minor, 1);
            assertEq(record.version.patch, 0);
        } else if (targetMajor == 5) {
            assertEq(record.version.major, 5);
            assertEq(record.version.minor, 0);
            assertEq(record.version.patch, 0);
        } else {
            // No match - should return zero version
            assertEq(record.version.major, 0);
            assertEq(record.version.minor, 0);
            assertEq(record.version.patch, 0);
            assertEq(record.contentHash, bytes32(0));
        }
    }

    // === Exact Version Query Tests ===

    function testExactVersionQuery() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 3, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 4, CONTENT_HASH_2);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 5, keccak256("content5"));

        VersionRegistry.VersionRecord memory result = registry.getExactVersionPublic(TEST_NAMEHASH, 1, 2, 4);

        assertEq(result.contentHash, CONTENT_HASH_2);
        assertEq(result.version.major, 1);
        assertEq(result.version.minor, 2);
        assertEq(result.version.patch, 4);
    }

    function testExactVersionNotFound() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 3, CONTENT_HASH_1);

        VersionRegistry.VersionRecord memory result = registry.getExactVersionPublic(TEST_NAMEHASH, 1, 2, 4);

        assertEq(result.contentHash, bytes32(0));
        assertEq(result.version.major, 0);
        assertEq(result.version.minor, 0);
        assertEq(result.version.patch, 0);
    }

    function testExactVersionWithMultipleVersions() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, keccak256("v1.0.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 0, keccak256("v1.1.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 0, keccak256("v1.2.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 0, keccak256("v2.0.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 1, 5, keccak256("v2.1.5"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 1, 6, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 3, 0, 0, keccak256("v3.0.0"));

        VersionRegistry.VersionRecord memory result = registry.getExactVersionPublic(TEST_NAMEHASH, 2, 1, 6);

        assertEq(result.contentHash, CONTENT_HASH_1);
        assertEq(result.version.major, 2);
        assertEq(result.version.minor, 1);
        assertEq(result.version.patch, 6);
    }

    function testExactVersionVsMajorMinor() public {
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 3, CONTENT_HASH_1);
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 5, CONTENT_HASH_2);

        // Major.minor query should return highest patch (1.2.5)
        VersionRegistry.VersionRecord memory majorMinorResult =
            registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 2);
        assertEq(majorMinorResult.contentHash, CONTENT_HASH_2);

        // Exact query should return specific version (1.2.3)
        VersionRegistry.VersionRecord memory exactResult = registry.getExactVersionPublic(TEST_NAMEHASH, 1, 2, 3);
        assertEq(exactResult.contentHash, CONTENT_HASH_1);
    }

    // === Zero Version Validation Tests ===

    function testZeroVersionNotAllowed() public {
        vm.expectRevert(abi.encodeWithSelector(VersionRegistry.ZeroVersionNotAllowed.selector));
        registry.addVersionPublic(TEST_NAMEHASH, 0, 0, 0, CONTENT_HASH_1);
    }

    function testZeroMajorVersionsAllowed() public {
        // 0.0.1 should be allowed
        registry.addVersionPublic(TEST_NAMEHASH, 0, 0, 1, CONTENT_HASH_1);
        bytes32 hash = registry.getLatestContentHashPublic(TEST_NAMEHASH);
        assertEq(hash, CONTENT_HASH_1);

        // 0.1.0 should be allowed
        registry.addVersionPublic(TEST_NAMEHASH, 0, 1, 0, CONTENT_HASH_2);
        hash = registry.getLatestContentHashPublic(TEST_NAMEHASH);
        assertEq(hash, CONTENT_HASH_2);
    }

    function testPreReleaseVersionProgression() public {
        // Test pre-release version progression: 0.0.1 -> 0.1.0 -> 0.2.0 -> 1.0.0
        registry.addVersionPublic(TEST_NAMEHASH, 0, 0, 1, keccak256("v0.0.1"));
        SemverLib.Version memory v = registry.getLatestVersionPublic(TEST_NAMEHASH);
        assertEq(v.major, 0);
        assertEq(v.minor, 0);
        assertEq(v.patch, 1);

        registry.addVersionPublic(TEST_NAMEHASH, 0, 1, 0, keccak256("v0.1.0"));
        v = registry.getLatestVersionPublic(TEST_NAMEHASH);
        assertEq(v.major, 0);
        assertEq(v.minor, 1);
        assertEq(v.patch, 0);

        registry.addVersionPublic(TEST_NAMEHASH, 0, 2, 0, keccak256("v0.2.0"));
        v = registry.getLatestVersionPublic(TEST_NAMEHASH);
        assertEq(v.major, 0);
        assertEq(v.minor, 2);
        assertEq(v.patch, 0);

        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, CONTENT_HASH_1);
        v = registry.getLatestVersionPublic(TEST_NAMEHASH);
        assertEq(v.major, 1);
        assertEq(v.minor, 0);
        assertEq(v.patch, 0);
    }

    // === Additional Edge Case Tests ===

    function testExactVersionQueryOnEmptyRegistry() public view {
        // Test getExactVersion on empty registry to cover the uncovered branch
        VersionRegistry.VersionRecord memory result = registry.getExactVersionPublic(TEST_NAMEHASH, 1, 2, 3);

        assertEq(result.contentHash, bytes32(0), "Should return zero content hash for empty registry");
        assertEq(result.version.major, 0, "Should return zero version major for empty registry");
        assertEq(result.version.minor, 0, "Should return zero version minor for empty registry");
        assertEq(result.version.patch, 0, "Should return zero version patch for empty registry");
    }

    function testGetHighestVersionMatchingEdgeCases() public {
        // Test edge cases for the binary search in _getHighestVersionMatching
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 0, keccak256("1.0.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 0, keccak256("2.0.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 3, 0, 0, keccak256("3.0.0"));

        // Test search for version that doesn't exist (boundary case)
        VersionRegistry.VersionRecord memory result = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 255);
        assertEq(result.contentHash, bytes32(0), "Should return zero for non-existent major version");

        // Test search at boundaries
        result = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 0);
        assertEq(result.contentHash, bytes32(0), "Should return zero for major version 0 when none exist");
    }

    function testBinarySearchEdgeCases() public {
        // Build a larger set to test more binary search paths
        for (uint8 i = 1; i <= 10; i++) {
            registry.addVersionPublic(TEST_NAMEHASH, i, 0, 0, keccak256(abi.encodePacked("content", uint256(i))));
        }

        // Test exact match in the middle
        VersionRegistry.VersionRecord memory result = registry.getExactVersionPublic(TEST_NAMEHASH, 5, 0, 0);
        assertEq(result.version.major, 5, "Should find exact version 5.0.0");
        assertEq(
            result.contentHash, keccak256(abi.encodePacked("content", uint256(5))), "Should return correct content hash"
        );

        // Test no match between existing versions
        result = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 15);
        assertEq(result.contentHash, bytes32(0), "Should return zero for non-existent major version 15");
    }

    function testSingleVersionEdgeCases() public {
        // Test with only a single version to cover edge cases in binary search
        registry.addVersionPublic(TEST_NAMEHASH, 1, 5, 10, CONTENT_HASH_1);

        // Test exact match with single version
        VersionRegistry.VersionRecord memory result = registry.getExactVersionPublic(TEST_NAMEHASH, 1, 5, 10);
        assertEq(result.version.major, 1, "Should find exact version 1.5.10");
        assertEq(result.version.minor, 5, "Should find exact version 1.5.10");
        assertEq(result.version.patch, 10, "Should find exact version 1.5.10");
        assertEq(result.contentHash, CONTENT_HASH_1, "Should return correct content hash");

        // Test no match with single version
        result = registry.getExactVersionPublic(TEST_NAMEHASH, 1, 5, 11);
        assertEq(result.contentHash, bytes32(0), "Should return zero for non-matching patch");

        result = registry.getExactVersionPublic(TEST_NAMEHASH, 1, 6, 10);
        assertEq(result.contentHash, bytes32(0), "Should return zero for non-matching minor");

        result = registry.getExactVersionPublic(TEST_NAMEHASH, 2, 5, 10);
        assertEq(result.contentHash, bytes32(0), "Should return zero for non-matching major");
    }

    function testHighestVersionMatchingWithComplexTree() public {
        // Build a complex version tree to test all comparison paths
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 1, keccak256("1.0.1"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 0, 5, keccak256("1.0.5"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 0, keccak256("1.1.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 1, 3, keccak256("1.1.3"));
        registry.addVersionPublic(TEST_NAMEHASH, 1, 2, 0, keccak256("1.2.0"));
        registry.addVersionPublic(TEST_NAMEHASH, 2, 0, 0, keccak256("2.0.0"));

        // Test major-only search with multiple matches (should get highest)
        VersionRegistry.VersionRecord memory result = registry.getHighestVersionForMajorPublic(TEST_NAMEHASH, 1);
        assertEq(result.version.major, 1, "Should find major version 1");
        assertEq(result.version.minor, 2, "Should find highest minor version");
        assertEq(result.version.patch, 0, "Should find correct patch version");
        assertEq(result.contentHash, keccak256("1.2.0"), "Should return highest 1.x.x version");

        // Test major.minor search with multiple patches (should get highest patch)
        result = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 1);
        assertEq(result.version.major, 1, "Should find major version 1");
        assertEq(result.version.minor, 1, "Should find minor version 1");
        assertEq(result.version.patch, 3, "Should find highest patch version");
        assertEq(result.contentHash, keccak256("1.1.3"), "Should return highest 1.1.x version");

        // Test major.minor search with single match
        result = registry.getHighestVersionForMajorMinorPublic(TEST_NAMEHASH, 1, 2);
        assertEq(result.version.major, 1, "Should find major version 1");
        assertEq(result.version.minor, 2, "Should find minor version 2");
        assertEq(result.version.patch, 0, "Should find correct patch version");
        assertEq(result.contentHash, keccak256("1.2.0"), "Should return 1.2.0 version");
    }
}
