// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Using IERC165 from forge-std to avoid OpenZeppelin version conflicts
import {IERC165} from "forge-std/interfaces/IERC165.sol";
import {ENS} from "ens-contracts/registry/ENS.sol";
import {IExtendedResolver} from "ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {IContentHashResolver} from "ens-contracts/resolvers/profiles/IContentHashResolver.sol";
import {ITextResolver} from "ens-contracts/resolvers/profiles/ITextResolver.sol";
import {INameWrapper} from "ens-contracts/wrapper/INameWrapper.sol";
import {NameCoder} from "ens-contracts/utils/NameCoder.sol";
import {BytesUtils} from "ens-contracts/utils/BytesUtils.sol";
import {VersionRegistry} from "./VersionRegistry.sol";

/// @title SemverResolver
/// @notice ENS resolver with semantic versioning support and wildcard resolution
/// @dev Implements IExtendedResolver for wildcard queries (e.g., "1-2.myapp.eth" resolves to highest 1.2.x version)
/// @dev Supports contenthash and text("version") resolution for versioned content
contract SemverResolver is VersionRegistry, IExtendedResolver, IContentHashResolver, ITextResolver, IERC165 {
    // ABI encoding constants
    uint256 private constant SELECTOR_SIZE = 4;

    // Precomputed hash for "version" key to save gas
    bytes32 private constant VERSION_KEY_HASH = keccak256("version");

    // IPFS CIDv1 dag-pb contenthash with multihash prefix for ENS (EIP-1577)
    // Format: <protocol><cid-version><content-type><hash-function><hash-length>
    // 0xe3 = IPFS protocol, 0x01 = CIDv1, 0x70 = dag-pb, 0x12 = sha2-256, 0x20 = 32 bytes
    bytes5 private constant IPFS_CONTENTHASH_PREFIX = hex"e301701220";

    ENS public immutable ENS_REGISTRY;
    INameWrapper public immutable NAME_WRAPPER;

    // Standard ENS errors (same signatures as defined in ENS ecosystem)
    // These match the errors defined in:
    // - Unauthorised: ens-contracts/wrapper/NameWrapper.sol:19
    // - UnsupportedResolverProfile: ens-contracts/universalResolver/IUniversalResolver.sol:17
    error Unauthorised(bytes32 node, address addr);
    error UnsupportedResolverProfile(bytes4 selector);

    /// @dev Gets the actual owner of an ENS name, handling wrapped names
    /// @param node The namehash of the ENS name
    /// @return The actual owner address (unwrapped if necessary)
    function _getActualOwner(bytes32 node) internal view returns (address) {
        address owner = ENS_REGISTRY.owner(node);

        // If the owner is the NameWrapper contract, get the actual owner from the wrapper
        if (owner == address(NAME_WRAPPER)) {
            try NAME_WRAPPER.ownerOf(uint256(node)) returns (address actualOwner) {
                return actualOwner;
            } catch {
                // If the call fails, fall back to the registry owner
                return owner;
            }
        }

        return owner;
    }

    /// @dev Checks if the caller is authorized for the given node
    /// @param node The namehash of the ENS name
    /// @param caller The address to check authorization for
    /// @return True if authorized, false otherwise
    function _isAuthorised(bytes32 node, address caller) internal view returns (bool) {
        address actualOwner = _getActualOwner(node);

        // Check if caller is the owner or approved by the owner
        return caller == actualOwner || ENS_REGISTRY.isApprovedForAll(actualOwner, caller);
    }

    /// @dev Restricts access to ENS name owner or approved operators
    /// @dev Now properly handles wrapped ENS names via NameWrapper contract
    modifier authorised(bytes32 node) {
        if (!_isAuthorised(node, msg.sender)) {
            revert Unauthorised(node, msg.sender);
        }
        _;
    }

    /// @notice Creates a new SemverResolver instance
    /// @param _ens The ENS registry contract address
    /// @param _nameWrapper The NameWrapper contract address
    constructor(ENS _ens, INameWrapper _nameWrapper) {
        ENS_REGISTRY = _ens;
        NAME_WRAPPER = _nameWrapper;
    }

    /// @dev Encodes a raw IPFS hash for ENS contenthash (EIP-1577)
    /// @param rawHash Raw 32-byte IPFS hash (sha256 digest)
    /// @return Properly encoded contenthash with IPFS CIDv1 dag-pb multihash prefix (0xe301701220)
    function _encodeIpfsContenthash(bytes32 rawHash) internal pure returns (bytes memory) {
        if (rawHash == bytes32(0)) {
            return "";
        }
        // Encode IPFS hash with proper multihash prefix for ENS contenthash (EIP-1577)
        return abi.encodePacked(IPFS_CONTENTHASH_PREFIX, rawHash);
    }

    /// @notice Checks if this contract implements a given interface
    /// @param interfaceId The interface identifier to check (ERC-165)
    /// @return True if the interface is supported, false otherwise
    /// @dev Supports IExtendedResolver, IContentHashResolver, ITextResolver, and ERC165
    function supportsInterface(bytes4 interfaceId) public pure override returns (bool) {
        return interfaceId == type(IExtendedResolver).interfaceId
            || interfaceId == type(IContentHashResolver).interfaceId || interfaceId == 0xbc1c58d1 // ENSIP-7 contenthash
            || interfaceId == type(ITextResolver).interfaceId || interfaceId == 0x01ffc9a7; // ERC165
    }

    /// @notice Wildcard resolution entry point (ENSIP-10)
    /// @param name DNS-encoded name (e.g., "\x031-2\x06myapp\x03eth\x00")
    /// @param data ABI-encoded function call (selector + arguments)
    /// @return ABI-encoded return value from the resolved function
    /// @dev First tries direct resolution, falls back to wildcard if no result
    function resolve(bytes memory name, bytes memory data) external view override returns (bytes memory) {
        require(data.length >= SELECTOR_SIZE, "Invalid data length");
        bytes4 selector = bytes4(data);

        if (selector == IContentHashResolver.contenthash.selector) {
            bytes32 node = NameCoder.namehash(name, 0);
            bytes memory hash = this.contenthash(node);
            // If no direct match, try wildcard resolution
            if (hash.length == 0) {
                hash = _resolveWildcardContenthash(name, data);
            }
            return abi.encode(hash);
        }

        if (selector == ITextResolver.text.selector) {
            // Strip the selector to get the arguments
            assert(data.length >= SELECTOR_SIZE); // SMTChecker: ensure valid data length
            (, string memory key) =
                abi.decode(BytesUtils.substring(data, SELECTOR_SIZE, data.length - SELECTOR_SIZE), (bytes32, string));
            string memory value = _resolveWildcardText(name, key);

            return abi.encode(value);
        }

        revert UnsupportedResolverProfile(selector);
    }

    /// @notice Returns the content hash for the latest version of a name
    /// @param node The ENS namehash to query
    /// @return The content hash of the latest version as bytes, or empty if no versions exist
    /// @dev Implements IContentHashResolver interface for direct (non-wildcard) queries
    function contenthash(bytes32 node) external view override returns (bytes memory) {
        bytes32 hash = getLatestContentHash(node);
        return _encodeIpfsContenthash(hash);
    }

    /// @notice Returns text data for a given key
    /// @param node The ENS namehash to query
    /// @param key The text record key (only "version" is supported)
    /// @return The text value for the key, or empty string if not found or unsupported
    /// @dev Only supports key "version" which returns the latest version as a string (e.g., "1.2.3")
    /// @dev All other keys return empty string as manual text records are not supported
    function text(bytes32 node, string calldata key) external view override returns (string memory) {
        // Special handling for "version" key - return latest version as string
        if (keccak256(bytes(key)) == VERSION_KEY_HASH) {
            Version memory latestVersion = getLatestVersion(node);

            // If no versions exist, return empty string
            if (latestVersion.major == 0 && latestVersion.minor == 0 && latestVersion.patch == 0) {
                return "";
            }

            return _versionToString(latestVersion);
        }

        // For all other keys, return empty string (no manual text setting allowed)
        return "";
    }

    /// @dev Core wildcard version resolution logic
    /// @param name DNS-encoded name where first label is version (e.g., "\x031-2\x06myapp\x03eth\x00")
    /// @return Version record with the highest matching version, or zero version if not found
    /// @notice Supports three query types:
    ///   - Major-only: "1" → finds highest 1.x.x version
    ///   - Major.minor: "1-2" → finds highest 1.2.x version
    ///   - Exact: "1-2-3" → finds exact 1.2.3 version
    /// @notice Uses hyphen separators instead of dots to avoid DNS label conflicts
    /// @notice Returns zero version (0.0.0) if no matching version exists
    function _resolveWildcardVersion(bytes memory name) internal view returns (VersionRecord memory) {
        // Extract the first label from the DNS-encoded name
        // Note: DNS name validation is handled upstream by NameCoder.namehash() in the resolve() function
        // which will revert with DNSDecodingFailed for invalid names before reaching this point
        uint256 labelLength = uint256(uint8(name[0]));

        // Extract the version label (first label, e.g., "1-2" from "1-2.myapp.eth")
        bytes memory versionLabel = BytesUtils.substring(name, 1, labelLength);

        // Extract the remainder (base name, e.g., "myapp.eth" from "1-2.myapp.eth")
        bytes memory baseName = BytesUtils.substring(name, labelLength + 1, name.length - labelLength - 1);

        // Compute the namehash of the base name
        bytes32 baseNode = NameCoder.namehash(baseName, 0);

        // Parse the version from the label (uses hyphen-separated format: "1-2-3")
        // Note: _parseVersionFromLabel will revert if the label is invalid
        // The resolve() function in IExtendedResolver will catch any reverts
        ParsedVersion memory parsedVersion = _parseVersionFromLabel(string(versionLabel));

        // Determine query type based on which components were explicitly specified
        // "1" (hasMinor=false) → find highest 1.x.x
        // "1-2" (hasMinor=true, hasPatch=false) → find highest 1.2.x
        // "1-2-3" (hasPatch=true) → find exact 1.2.3
        VersionRecord memory result;

        if (!parsedVersion.hasMinor) {
            // Major-only query: find highest version with matching major (e.g., "1" matches 1.x.x)
            result = getHighestVersionForMajor(baseNode, parsedVersion.version.major);
        } else if (!parsedVersion.hasPatch) {
            // Major.minor query: find highest version with matching major.minor (e.g., "1-2" matches 1.2.x)
            result = getHighestVersionForMajorMinor(baseNode, parsedVersion.version.major, parsedVersion.version.minor);
        } else {
            // Exact version query: find exact match (e.g., "1-2-3" matches 1.2.3 only)
            result = getExactVersion(
                baseNode, parsedVersion.version.major, parsedVersion.version.minor, parsedVersion.version.patch
            );
        }

        return result;
    }

    /// @dev Resolves contenthash for wildcard version queries
    /// @param name DNS-encoded name with version prefix (e.g., "\x031-2\x06myapp\x03eth\x00")
    /// @return ABI-encoded content hash of the matched version, or empty bytes if no match
    /// @notice This function is called by resolve() when direct contenthash lookup fails
    function _resolveWildcardContenthash(bytes memory name, bytes memory /* data */ )
        internal
        view
        returns (bytes memory)
    {
        VersionRecord memory result = _resolveWildcardVersion(name);

        // If no matching version found, return empty
        if (result.contentHash == bytes32(0)) {
            return "";
        }

        return _encodeIpfsContenthash(result.contentHash);
    }

    /// @dev Resolves text record (version string) for wildcard version queries
    /// @param name DNS-encoded name with version prefix (e.g., "\x031-2\x06myapp\x03eth\x00")
    /// @return Version string of the matched version (e.g., "1.2.3"), or empty if no match
    /// @notice This function is called by resolve() for text("version") wildcard queries
    function _resolveWildcardText(bytes memory name, string memory /* key */ ) internal view returns (string memory) {
        VersionRecord memory result = _resolveWildcardVersion(name);

        // If no matching version found, return empty
        if (result.contentHash == bytes32(0)) {
            return "";
        }

        // Return the version as a string
        return _versionToString(result.version);
    }

    /// @notice Publishes new versioned content for an ENS name
    /// @param namehash The ENS namehash to publish content for
    /// @param major The major version number (0-255)
    /// @param minor The minor version number (0-255)
    /// @param patch The patch version number (0-65535)
    /// @param contentHash Raw IPFS hash (32 bytes, sha256 digest only)
    /// @dev contentHash should be the raw sha256 hash from IPFS CID, not the full CID
    /// @dev For JavaScript: use `ipfs.add()` then extract hash from CID using libraries like:
    /// @dev - multiformats: `CID.parse(cid).multihash.digest`
    /// @dev - ipfs-http-client: built-in hash extraction utilities
    /// @dev The resolver automatically encodes this as EIP-1577 contenthash for ENS compatibility
    /// @dev Only callable by the ENS name owner or approved operators
    /// @dev Version must be strictly greater than all existing versions (enforced by addVersion)
    /// @dev Emits ContenthashChanged and TextChanged events
    function publishContent(bytes32 namehash, uint8 major, uint8 minor, uint16 patch, bytes32 contentHash)
        external
        authorised(namehash)
    {
        addVersion(namehash, major, minor, patch, contentHash);

        // Emit ContenthashChanged event for the new content hash
        emit ContenthashChanged(namehash, _encodeIpfsContenthash(contentHash));

        // Emit TextChanged event for the "version" key since it will now return the new version
        string memory newVersion = _versionToString(_createVersion(major, minor, patch));
        emit TextChanged(namehash, "version", "version", newVersion);
    }
}
