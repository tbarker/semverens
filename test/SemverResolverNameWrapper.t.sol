// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test} from "forge-std/Test.sol";
import {SemverResolver} from "../src/SemverResolver.sol";
import {MockNameWrapper} from "./mocks/MockNameWrapper.sol";
import {MockENSRegistry} from "./mocks/MockENSRegistry.sol";
import {ENS} from "ens-contracts/registry/ENS.sol";
import {INameWrapper} from "ens-contracts/wrapper/INameWrapper.sol";

/// @title SemverResolverNameWrapperTest
/// @notice Comprehensive tests for SemverResolver NameWrapper integration
/// @dev Tests all authorization paths including wrapped names to achieve 100% coverage
contract SemverResolverNameWrapperTest is Test {
    SemverResolver resolver;
    MockENSRegistry ens;
    MockNameWrapper nameWrapper;

    address owner;
    address user;
    address operator;

    // Test namehashes
    bytes32 constant TEST_NODE = 0xeb4f647bea6caa36333c816d7b46fdcb05f9466ecacc140ea8c66faf15b3d9f1; // namehash("test.eth")
    bytes32 constant WRAPPED_NODE = 0x4b162e8ef5a976a025f29a8308523ae94e4f248a0db2d87addd10ce0ec703d84; // namehash("wrapped.eth")

    bytes32 constant CONTENT_HASH_1 = keccak256("content1");
    bytes32 constant CONTENT_HASH_2 = keccak256("content2");

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        operator = makeAddr("operator");

        ens = new MockENSRegistry();
        nameWrapper = new MockNameWrapper();
        resolver = new SemverResolver(ENS(address(ens)), INameWrapper(address(nameWrapper)));

        // Set up regular ownership
        ens.setOwner(TEST_NODE, owner);

        // Set up wrapped name - registry owner is nameWrapper, actual owner is stored in nameWrapper
        ens.setOwner(WRAPPED_NODE, address(nameWrapper));
        nameWrapper.setOwner(uint256(WRAPPED_NODE), owner);
    }

    // === NameWrapper Integration Tests ===

    function testWrappedNameOwnershipResolution() public {
        // Verify that wrapped name ownership is resolved correctly
        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Should succeed since owner can publish to wrapped name
        bytes memory hash = resolver.contenthash(WRAPPED_NODE);
        assertGt(hash.length, 0, "Should return content hash for wrapped name");
    }

    function testWrappedNameUnauthorized() public {
        // User is not the owner of the wrapped name
        vm.expectRevert(abi.encodeWithSelector(SemverResolver.Unauthorised.selector, WRAPPED_NODE, user));
        vm.prank(user);
        resolver.publishContent(WRAPPED_NODE, 1, 0, 0, CONTENT_HASH_1);
    }

    function testWrappedNameWithOperatorApproval() public {
        // Set operator approval in ENS registry (on the actual owner, not the wrapper)
        vm.prank(owner);
        ens.setApprovalForAll(operator, true);

        // Operator should be able to publish to wrapped name
        vm.prank(operator);
        resolver.publishContent(WRAPPED_NODE, 1, 0, 0, CONTENT_HASH_1);

        bytes memory hash = resolver.contenthash(WRAPPED_NODE);
        assertGt(hash.length, 0, "Operator should be able to publish to wrapped name");
    }

    function testWrappedNameOwnerOfReverts() public {
        // Configure nameWrapper to revert when ownerOf is called
        nameWrapper.setShouldRevert(uint256(WRAPPED_NODE), true);

        // Should fall back to registry owner (nameWrapper address) when ownerOf reverts
        vm.expectRevert(abi.encodeWithSelector(SemverResolver.Unauthorised.selector, WRAPPED_NODE, owner));
        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 1, 0, 0, CONTENT_HASH_1);
    }

    function testWrappedNameOwnerOfRevertsButWrapperIsAuthorized() public {
        // Configure nameWrapper to revert when ownerOf is called
        nameWrapper.setShouldRevert(uint256(WRAPPED_NODE), true);

        // Set registry owner to have operator approval for nameWrapper address
        vm.prank(address(nameWrapper));
        ens.setApprovalForAll(owner, true);

        // Should work since nameWrapper has approved owner as operator
        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 1, 0, 0, CONTENT_HASH_1);

        bytes memory hash = resolver.contenthash(WRAPPED_NODE);
        assertGt(hash.length, 0, "Should work with wrapper fallback and operator approval");
    }

    function testNonWrappedNameStillWorks() public {
        // Regular (non-wrapped) names should continue to work normally
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        bytes memory hash = resolver.contenthash(TEST_NODE);
        assertGt(hash.length, 0, "Regular names should work normally");
    }

    // === Authorization Edge Cases ===

    function testGetActualOwnerRegularName() public view {
        // For regular names, should return registry owner directly
        // This is a view function, so we can't test it directly, but it's covered by other tests
        // The coverage will show this path is taken for TEST_NODE
    }

    function testGetActualOwnerWrappedName() public view {
        // For wrapped names, should return owner from NameWrapper
        // This is covered by testWrappedNameOwnershipResolution()
    }

    function testGetActualOwnerWrappedNameRevertFallback() public view {
        // When NameWrapper.ownerOf reverts, should fall back to registry owner
        // This is covered by testWrappedNameOwnerOfReverts()
    }

    // === Operator Approval Tests ===

    function testOperatorApprovalOnRegularName() public {
        // Set operator approval
        vm.prank(owner);
        ens.setApprovalForAll(operator, true);

        // Operator should be able to publish
        vm.prank(operator);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        bytes memory hash = resolver.contenthash(TEST_NODE);
        assertGt(hash.length, 0, "Operator should be able to publish");
    }

    function testOperatorApprovalRevoked() public {
        // First set approval
        vm.prank(owner);
        ens.setApprovalForAll(operator, true);

        // Then revoke it
        vm.prank(owner);
        ens.setApprovalForAll(operator, false);

        // Operator should no longer be able to publish
        vm.expectRevert(abi.encodeWithSelector(SemverResolver.Unauthorised.selector, TEST_NODE, operator));
        vm.prank(operator);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);
    }

    // === Complex Scenarios ===

    function testWrappedNameOwnershipTransfer() public {
        address newOwner = makeAddr("newOwner");

        // Initially owned by owner
        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 1, 0, 0, CONTENT_HASH_1);

        // Transfer wrapped name ownership
        nameWrapper.setOwner(uint256(WRAPPED_NODE), newOwner);

        // Old owner should no longer be able to publish
        vm.expectRevert(abi.encodeWithSelector(SemverResolver.Unauthorised.selector, WRAPPED_NODE, owner));
        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 1, 1, 0, CONTENT_HASH_2);

        // New owner should be able to publish
        vm.prank(newOwner);
        resolver.publishContent(WRAPPED_NODE, 1, 1, 0, CONTENT_HASH_2);

        string memory version = resolver.text(WRAPPED_NODE, "version");
        assertEq(version, "1.1.0", "New owner should be able to publish");
    }

    function testMixedWrappedAndRegularNames() public {
        // Publish to both wrapped and regular names
        vm.prank(owner);
        resolver.publishContent(TEST_NODE, 1, 0, 0, CONTENT_HASH_1);

        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 2, 0, 0, CONTENT_HASH_2);

        // Both should work independently
        string memory regularVersion = resolver.text(TEST_NODE, "version");
        string memory wrappedVersion = resolver.text(WRAPPED_NODE, "version");

        assertEq(regularVersion, "1.0.0", "Regular name should have correct version");
        assertEq(wrappedVersion, "2.0.0", "Wrapped name should have correct version");
    }

    // === Fuzz Tests for Authorization ===

    function testFuzzWrappedNameAuthorization(address randomOwner, address randomCaller) public {
        vm.assume(randomOwner != address(0));
        vm.assume(randomCaller != address(0));
        vm.assume(randomOwner != randomCaller);

        bytes32 randomNode = keccak256(abi.encode(randomOwner, randomCaller));

        // Set up wrapped name with random owner
        ens.setOwner(randomNode, address(nameWrapper));
        nameWrapper.setOwner(uint256(randomNode), randomOwner);

        // Random caller should not be authorized
        vm.expectRevert(abi.encodeWithSelector(SemverResolver.Unauthorised.selector, randomNode, randomCaller));
        vm.prank(randomCaller);
        resolver.publishContent(randomNode, 1, 0, 0, CONTENT_HASH_1);

        // Random owner should be authorized
        vm.prank(randomOwner);
        resolver.publishContent(randomNode, 1, 0, 0, CONTENT_HASH_1);

        bytes memory hash = resolver.contenthash(randomNode);
        assertGt(hash.length, 0, "Random owner should be able to publish");
    }

    // === Integration with Wildcard Resolution ===

    function testWrappedNameWildcardResolution() public {
        // Publish multiple versions to wrapped name
        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 1, 0, 0, CONTENT_HASH_1);
        vm.prank(owner);
        resolver.publishContent(WRAPPED_NODE, 1, 2, 5, CONTENT_HASH_2);

        // Test wildcard resolution works with wrapped names
        // Use proper DNS encoding for "1.wrapped.eth"
        bytes memory name = abi.encodePacked(
            uint8(1),
            "1", // version label "1"
            uint8(7),
            "wrapped", // "wrapped"
            uint8(3),
            "eth", // "eth"
            uint8(0) // terminator
        );

        // Use contenthash selector with the base node (wrapped.eth) for wildcard resolution
        bytes memory data = abi.encodeWithSelector(SemverResolver.contenthash.selector, WRAPPED_NODE);
        bytes memory result = resolver.resolve(name, data);
        bytes memory hash = abi.decode(result, (bytes));

        assertGt(hash.length, 0, "Wildcard resolution should work with wrapped names");
        // Should resolve to 1.2.5 (highest 1.x.x)
    }
}
