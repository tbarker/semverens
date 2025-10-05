// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {SemverResolver} from "../src/SemverResolver.sol";
import {ENS} from "ens-contracts/registry/ENS.sol";
import {INameWrapper} from "ens-contracts/wrapper/INameWrapper.sol";
import {ITextResolver} from "ens-contracts/resolvers/profiles/ITextResolver.sol";
import {IContentHashResolver} from "ens-contracts/resolvers/profiles/IContentHashResolver.sol";
import {NameCoder} from "ens-contracts/utils/NameCoder.sol";
import {BytesUtils} from "ens-contracts/utils/BytesUtils.sol";
import {MockENSRegistry} from "./mocks/MockENSRegistry.sol";

/// @title ScenarioTest
/// @notice Merged realistic test scenarios simulating Apache Accumulo and Drupal Core version histories
/// @dev Tests interleaved operations on two independent namehashes to verify isolation
/// @dev Uses only external official ENS interfaces (no test wrappers)
/// @dev Covers Accumulo (1.x-3.x) and Drupal (7.x-11.x) version progressions
contract ScenarioTest is Test {
    SemverResolver resolver;
    MockENSRegistry ens;

    address accumuloOwner;
    address drupalOwner;

    // Namehash for accumulo.feather.xyz
    bytes32 constant ACCUMULO_NODE = 0x0f2909f7147c7f3ea2c741f255035c6231a14cfd6fa3fe226dceca46bef8dbdb;
    // Namehash for drupal.web3.eth
    bytes32 constant DRUPAL_NODE = 0x731b1809cf951e386acb51afe14344ff2fe30aa7ffad61a7ce2f62d6ef07f876;

    function setUp() public {
        accumuloOwner = makeAddr("accumulo-owner");
        drupalOwner = makeAddr("drupal-maintainer");
        ens = new MockENSRegistry();
        resolver = new SemverResolver(ENS(address(ens)), INameWrapper(address(0)));
        ens.setOwner(ACCUMULO_NODE, accumuloOwner);
        ens.setOwner(DRUPAL_NODE, drupalOwner);
    }

    // ========== Accumulo Helpers ==========

    function publishAccumulo(string memory releaseName, uint8 major, uint8 minor, uint16 patch) internal {
        bytes32 contentHash = keccak256(abi.encodePacked("accumulo-", releaseName));
        vm.prank(accumuloOwner);
        resolver.publishContent(ACCUMULO_NODE, major, minor, patch, contentHash);
    }

    function getAccumuloHash(string memory releaseName) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("accumulo-", releaseName));
    }

    function dnsEncodeAccumulo(string memory versionLabel) internal pure returns (bytes memory) {
        bytes memory label = bytes(versionLabel);
        bytes memory baseName = NameCoder.encode("accumulo.feather.xyz");
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

    // ========== Drupal Helpers ==========

    function publishDrupal(string memory releaseName, uint8 major, uint8 minor, uint16 patch) internal {
        bytes32 contentHash = keccak256(abi.encodePacked("drupal-", releaseName));
        vm.prank(drupalOwner);
        resolver.publishContent(DRUPAL_NODE, major, minor, patch, contentHash);
    }

    function getDrupalHash(string memory releaseName) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("drupal-", releaseName));
    }

    function dnsEncodeDrupal(string memory versionLabel) internal pure returns (bytes memory) {
        bytes memory label = bytes(versionLabel);
        bytes memory baseName = NameCoder.encode("drupal.web3.eth");
        bytes memory result = new bytes(1 + label.length + baseName.length);
        result[0] = bytes1(uint8(label.length));
        BytesUtils.copyBytes(label, 0, result, 1, label.length);
        BytesUtils.copyBytes(baseName, 0, result, 1 + label.length, baseName.length);
        return result;
    }

    // ========== Shared Helper ==========

    function decodeContenthash(bytes memory name, bytes memory selector) internal view returns (bytes32) {
        bytes memory result = resolver.resolve(name, selector);
        bytes memory hashBytes = abi.decode(result, (bytes));
        if (hashBytes.length == 0) {
            return bytes32(0);
        }
        // Skip the 5-byte IPFS multihash prefix to get the raw hash
        if (hashBytes.length < 37) {
            // 5 byte prefix + 32 byte hash
            return bytes32(0);
        }
        return BytesUtils.readBytes32(hashBytes, 5);
    }

    /// @notice Comprehensive interleaved test of Accumulo and Drupal version histories
    /// @dev Publishes versions alternately to both projects to verify namespace isolation
    function testInterleavedVersionHistory() public {
        bytes memory accumuloSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, ACCUMULO_NODE);
        bytes memory drupalSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, DRUPAL_NODE);

        // Phase 1: Start Accumulo 1.3.x series
        publishAccumulo("1.3.6", 1, 3, 6);
        assertEq(resolver.text(ACCUMULO_NODE, "version"), "1.3.6", "Accumulo latest should be 1.3.6");

        // Phase 2: Start Drupal 7.x series (should not affect Accumulo)
        publishDrupal("7.95", 7, 95, 0);
        publishDrupal("7.96", 7, 96, 0);
        assertEq(resolver.text(DRUPAL_NODE, "version"), "7.96.0", "Drupal latest should be 7.96.0");
        // Verify Accumulo unchanged
        assertEq(resolver.text(ACCUMULO_NODE, "version"), "1.3.6", "Accumulo should still be 1.3.6");

        // Phase 3: Continue Accumulo 1.4.x series
        publishAccumulo("1.4.1", 1, 4, 1);
        publishAccumulo("1.4.5", 1, 4, 5);
        bytes32 accum14 = decodeContenthash(dnsEncodeAccumulo("1:4"), accumuloSelector);
        assertEq(accum14, getAccumuloHash("1.4.5"), "Accumulo 1:4 should resolve to 1.4.5");

        // Phase 4: Continue Drupal 7.x and start 8.x
        publishDrupal("7.103", 7, 103, 0);
        publishDrupal("8.8.11", 8, 8, 11);
        publishDrupal("8.9.16", 8, 9, 16);
        bytes32 drupal7 = decodeContenthash(dnsEncodeDrupal("7"), drupalSelector);
        assertEq(drupal7, getDrupalHash("7.103"), "Drupal 7 should resolve to 7.103");

        // Phase 5: Accumulo 1.5.x - 1.9.x progression
        publishAccumulo("1.5.0", 1, 5, 0);
        publishAccumulo("1.5.4", 1, 5, 4);
        publishAccumulo("1.6.6", 1, 6, 6);
        publishAccumulo("1.9.0", 1, 9, 0);
        publishAccumulo("1.9.3", 1, 9, 3);

        // Phase 6: Drupal 9.x series
        publishDrupal("9.0.14", 9, 0, 14);
        publishDrupal("9.1.15", 9, 1, 15);
        publishDrupal("9.5.11", 9, 5, 11);

        // Verify cross-isolation: Accumulo queries shouldn't see Drupal data
        bytes32 accum19 = decodeContenthash(dnsEncodeAccumulo("1:9"), accumuloSelector);
        assertEq(accum19, getAccumuloHash("1.9.3"), "Accumulo 1:9 should resolve to 1.9.3");
        bytes32 drupal9 = decodeContenthash(dnsEncodeDrupal("9"), drupalSelector);
        assertEq(drupal9, getDrupalHash("9.5.11"), "Drupal 9 should resolve to 9.5.11");

        // Phase 7: Accumulo 1.10.x and 2.x
        publishAccumulo("1.10.3", 1, 10, 3);
        publishAccumulo("2.0.0", 2, 0, 0);
        publishAccumulo("2.1.2", 2, 1, 2);

        // Phase 8: Drupal 10.x series
        publishDrupal("10.2.12", 10, 2, 12);
        publishDrupal("10.4.8", 10, 4, 8);

        // Verify major version queries for both
        bytes32 accum1 = decodeContenthash(dnsEncodeAccumulo("1"), accumuloSelector);
        assertEq(accum1, getAccumuloHash("1.10.3"), "Accumulo 1 should resolve to 1.10.3");
        bytes32 accum2 = decodeContenthash(dnsEncodeAccumulo("2"), accumuloSelector);
        assertEq(accum2, getAccumuloHash("2.1.2"), "Accumulo 2 should resolve to 2.1.2");

        bytes32 drupal10 = decodeContenthash(dnsEncodeDrupal("10"), drupalSelector);
        assertEq(drupal10, getDrupalHash("10.4.8"), "Drupal 10 should resolve to 10.4.8");

        // Phase 9: Final versions
        publishAccumulo("3.0.0", 3, 0, 0);
        publishDrupal("11.1.8", 11, 1, 8);

        // Final verification: Latest versions
        assertEq(resolver.text(ACCUMULO_NODE, "version"), "3.0.0", "Accumulo final should be 3.0.0");
        assertEq(resolver.text(DRUPAL_NODE, "version"), "11.1.8", "Drupal final should be 11.1.8");

        // Verify wildcards for both projects work correctly
        bytes memory accumuloTextSelector =
            abi.encodeWithSelector(ITextResolver.text.selector, ACCUMULO_NODE, "version");
        bytes memory drupalTextSelector = abi.encodeWithSelector(ITextResolver.text.selector, DRUPAL_NODE, "version");

        string memory accum1Text = abi.decode(resolver.resolve(dnsEncodeAccumulo("1"), accumuloTextSelector), (string));
        assertEq(accum1Text, "1.10.3", "Accumulo 1 text should be 1.10.3");

        string memory drupal9Text = abi.decode(resolver.resolve(dnsEncodeDrupal("9"), drupalTextSelector), (string));
        assertEq(drupal9Text, "9.5.11", "Drupal 9 text should be 9.5.11");
    }

    /// @notice Test wildcard resolution isolation between projects
    function testWildcardIsolation() public {
        // Publish overlapping version numbers to both projects
        publishAccumulo("1.9.2", 1, 9, 2);
        publishAccumulo("2.0.0", 2, 0, 0);
        publishDrupal("9.2.21", 9, 2, 21);
        publishDrupal("10.2.3", 10, 2, 3);

        bytes memory accumuloSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, ACCUMULO_NODE);
        bytes memory drupalSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, DRUPAL_NODE);

        // Query "2" for both - should return different results
        bytes32 accum2 = decodeContenthash(dnsEncodeAccumulo("2"), accumuloSelector);
        bytes32 drupal2 = decodeContenthash(dnsEncodeDrupal("2"), drupalSelector);

        assertEq(accum2, getAccumuloHash("2.0.0"), "Accumulo 2 should resolve to 2.0.0");
        assertEq(drupal2, bytes32(0), "Drupal has no version 2.x (should be zero)");

        // Query "9" for both - should return different results
        bytes32 accum9 = decodeContenthash(dnsEncodeAccumulo("9"), accumuloSelector);
        bytes32 drupal9 = decodeContenthash(dnsEncodeDrupal("9"), drupalSelector);

        assertEq(accum9, bytes32(0), "Accumulo has no version 9.x (should be zero)");
        assertEq(drupal9, getDrupalHash("9.2.21"), "Drupal 9 should resolve to 9.2.21");

        // Query "10:2" for both
        bytes32 accum102 = decodeContenthash(dnsEncodeAccumulo("10:2"), accumuloSelector);
        bytes32 drupal102 = decodeContenthash(dnsEncodeDrupal("10:2"), drupalSelector);

        assertEq(accum102, bytes32(0), "Accumulo has no version 10.2.x");
        assertEq(drupal102, getDrupalHash("10.2.3"), "Drupal 10:2 should resolve to 10.2.3");
    }

    /// @notice Test that unauthorized users cannot publish to wrong namehashes
    function testCrossNamehashAuthorization() public {
        publishAccumulo("1.0.0", 1, 0, 0);
        publishDrupal("7.0.0", 7, 0, 0);

        // Accumulo owner tries to publish to Drupal node (should fail)
        vm.prank(accumuloOwner);
        vm.expectRevert(abi.encodeWithSignature("Unauthorised(bytes32,address)", DRUPAL_NODE, accumuloOwner));
        resolver.publishContent(DRUPAL_NODE, 7, 1, 0, getDrupalHash("7.1.0"));

        // Drupal owner tries to publish to Accumulo node (should fail)
        vm.prank(drupalOwner);
        vm.expectRevert(abi.encodeWithSignature("Unauthorised(bytes32,address)", ACCUMULO_NODE, drupalOwner));
        resolver.publishContent(ACCUMULO_NODE, 1, 1, 0, getAccumuloHash("1.1.0"));

        // Verify versions unchanged
        assertEq(resolver.text(ACCUMULO_NODE, "version"), "1.0.0");
        assertEq(resolver.text(DRUPAL_NODE, "version"), "7.0.0");
    }

    /// @notice Test version ordering is enforced independently per namehash
    function testIndependentVersionOrdering() public {
        // Publish initial versions
        publishAccumulo("1.5.0", 1, 5, 0);
        publishDrupal("9.0.0", 9, 0, 0);

        // Advance Accumulo to 2.0.0
        publishAccumulo("2.0.0", 2, 0, 0);

        // Try to publish Accumulo 1.6.0 (should fail - not greater than 2.0.0)
        vm.prank(accumuloOwner);
        vm.expectRevert(abi.encodeWithSignature("VersionNotGreater()"));
        resolver.publishContent(ACCUMULO_NODE, 1, 6, 0, getAccumuloHash("1.6.0"));

        // Drupal should still be able to publish 10.0.0 (independent ordering)
        publishDrupal("10.0.0", 10, 0, 0);

        assertEq(resolver.text(ACCUMULO_NODE, "version"), "2.0.0");
        assertEq(resolver.text(DRUPAL_NODE, "version"), "10.0.0");
    }

    /// @notice Test querying non-existent versions doesn't cross-contaminate
    function testNonExistentVersionIsolation() public {
        publishAccumulo("1.9.3", 1, 9, 3);
        publishDrupal("9.5.11", 9, 5, 11);

        bytes memory accumuloSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, ACCUMULO_NODE);
        bytes memory drupalSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, DRUPAL_NODE);

        // Query version 9 on Accumulo (doesn't exist)
        bytes32 accum9 = decodeContenthash(dnsEncodeAccumulo("9"), accumuloSelector);
        assertEq(accum9, bytes32(0), "Accumulo 9 should not exist");

        // Query version 1 on Drupal (doesn't exist)
        bytes32 drupal1 = decodeContenthash(dnsEncodeDrupal("1"), drupalSelector);
        assertEq(drupal1, bytes32(0), "Drupal 1 should not exist");

        // Verify the actual versions are still queryable
        bytes32 accum1 = decodeContenthash(dnsEncodeAccumulo("1"), accumuloSelector);
        assertEq(accum1, getAccumuloHash("1.9.3"), "Accumulo 1 should exist");

        bytes32 drupal9 = decodeContenthash(dnsEncodeDrupal("9"), drupalSelector);
        assertEq(drupal9, getDrupalHash("9.5.11"), "Drupal 9 should exist");
    }

    /// @notice Test exact version queries with interleaved publishes
    function testExactVersionQueriesInterleaved() public {
        // Publish similar version numbers to both projects
        publishAccumulo("1.9.0", 1, 9, 0);
        publishDrupal("9.1.0", 9, 1, 0);
        publishAccumulo("1.9.2", 1, 9, 2);
        publishDrupal("9.1.2", 9, 1, 2);
        publishAccumulo("1.9.3", 1, 9, 3);
        publishDrupal("9.1.15", 9, 1, 15);

        bytes memory accumuloSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, ACCUMULO_NODE);
        bytes memory drupalSelector = abi.encodeWithSelector(IContentHashResolver.contenthash.selector, DRUPAL_NODE);

        // Query exact version 1:9:2 for both
        bytes32 accum192 = decodeContenthash(dnsEncodeAccumulo("1:9:2"), accumuloSelector);
        bytes32 drupal192 = decodeContenthash(dnsEncodeDrupal("1:9:2"), drupalSelector);

        assertEq(accum192, getAccumuloHash("1.9.2"), "Accumulo 1:9:2 should be exact");
        assertEq(drupal192, bytes32(0), "Drupal has no 1:9:2");

        // Query exact version 9:1:2 for both
        bytes32 accum912 = decodeContenthash(dnsEncodeAccumulo("9:1:2"), accumuloSelector);
        bytes32 drupal912 = decodeContenthash(dnsEncodeDrupal("9:1:2"), drupalSelector);

        assertEq(accum912, bytes32(0), "Accumulo has no 9:1:2");
        assertEq(drupal912, getDrupalHash("9.1.2"), "Drupal 9:1:2 should be exact");

        // Query highest in series
        bytes32 accum19 = decodeContenthash(dnsEncodeAccumulo("1:9"), accumuloSelector);
        bytes32 drupal91 = decodeContenthash(dnsEncodeDrupal("9:1"), drupalSelector);

        assertEq(accum19, getAccumuloHash("1.9.3"), "Accumulo 1:9 should be 1.9.3");
        assertEq(drupal91, getDrupalHash("9.1.15"), "Drupal 9:1 should be 9.1.15");
    }

    /// @notice Test text record resolution isolation
    function testTextResolutionIsolation() public {
        publishAccumulo("2.1.2", 2, 1, 2);
        publishDrupal("10.4.8", 10, 4, 8);

        // Direct text queries
        assertEq(resolver.text(ACCUMULO_NODE, "version"), "2.1.2");
        assertEq(resolver.text(DRUPAL_NODE, "version"), "10.4.8");

        // Wildcard text queries
        bytes memory accumuloTextSelector =
            abi.encodeWithSelector(ITextResolver.text.selector, ACCUMULO_NODE, "version");
        bytes memory drupalTextSelector = abi.encodeWithSelector(ITextResolver.text.selector, DRUPAL_NODE, "version");

        string memory accum2Text = abi.decode(resolver.resolve(dnsEncodeAccumulo("2"), accumuloTextSelector), (string));
        string memory drupal10Text = abi.decode(resolver.resolve(dnsEncodeDrupal("10"), drupalTextSelector), (string));

        assertEq(accum2Text, "2.1.2", "Accumulo wildcard text should be 2.1.2");
        assertEq(drupal10Text, "10.4.8", "Drupal wildcard text should be 10.4.8");

        // Cross-query should return empty (version doesn't exist)
        string memory accum10Text =
            abi.decode(resolver.resolve(dnsEncodeAccumulo("10"), accumuloTextSelector), (string));
        string memory drupal2Text = abi.decode(resolver.resolve(dnsEncodeDrupal("2"), drupalTextSelector), (string));

        assertEq(accum10Text, "", "Accumulo 10 text should be empty");
        assertEq(drupal2Text, "", "Drupal 2 text should be empty");
    }

    /// @notice Test contenthash direct queries (non-wildcard) are isolated
    function testContenthashDirectQueryIsolation() public {
        publishAccumulo("1.10.3", 1, 10, 3);
        publishDrupal("11.1.8", 11, 1, 8);

        // Direct contenthash queries
        bytes memory accumHash = resolver.contenthash(ACCUMULO_NODE);
        bytes memory drupalHash = resolver.contenthash(DRUPAL_NODE);

        assertEq(accumHash, encodeIpfsContenthash(getAccumuloHash("1.10.3")), "Accumulo contenthash should be 1.10.3");
        assertEq(drupalHash, encodeIpfsContenthash(getDrupalHash("11.1.8")), "Drupal contenthash should be 11.1.8");

        // Verify they're different
        assertTrue(keccak256(accumHash) != keccak256(drupalHash), "Hashes should be different");
    }
}
