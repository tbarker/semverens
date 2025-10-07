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

    // DNS encoding constants
    uint256 private constant DNS_LABEL_LENGTH_OFFSET = 0; // Position of length byte in DNS label
    uint256 private constant DNS_LABEL_DATA_OFFSET = 1; // Position where label data starts

    // Array indexing constants
    uint256 private constant FIRST_ELEMENT_INDEX = 0;

    // Precomputed hash for "version" key to save gas
    bytes32 private constant VERSION_KEY_HASH = keccak256("version");

    // IPFS CIDv1 dag-pb contenthash with multihash prefix for ENS (EIP-1577)
    // Format: <protocol><cid-version><multicodec><hash-function><hash-length>
    // 0xe3 = IPFS protocol, 0x01 = CIDv1, 0x01 = raw, 0x70 = dag-pb, 0x12 = sha2-256, 0x20 = 32 bytes
    bytes6 private constant IPFS_CONTENTHASH_PREFIX = hex"e30101701220";

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

    /// @notice Creates a new SemverResolver that enables version-aware ENS resolution
    /// @param _ens The ENS registry contract address
    /// @param _nameWrapper The NameWrapper contract address
    constructor(ENS _ens, INameWrapper _nameWrapper) {
        ENS_REGISTRY = _ens;
        NAME_WRAPPER = _nameWrapper;
    }

    /// @dev Encodes a raw IPFS hash for ENS contenthash (EIP-1577 compliance)
    /// @param rawHash Raw 32-byte IPFS hash (sha256 digest only, not full CID)
    /// @return Properly encoded contenthash with IPFS CIDv1 dag-pb multihash prefix
    /// @dev Encoding format: 0xe3 (IPFS) + 0x01 (CIDv1) + 0x70 (dag-pb) + 0x12 (sha2-256) + 0x20 (32 bytes)
    /// @dev Null safety: Returns empty bytes for zero hash (indicates no content)
    /// @dev Examples:
    ///   - _encodeIpfsContenthash(0x0) → "" (empty)
    ///   - _encodeIpfsContenthash(sha256("content")) → 0xe30101701220{32-byte-hash}
    function _encodeIpfsContenthash(bytes32 rawHash) internal pure returns (bytes memory) {
        if (rawHash == bytes32(0)) {
            return "";
        }
        // Encode IPFS hash with proper multihash prefix for ENS contenthash (EIP-1577)
        return abi.encodePacked(IPFS_CONTENTHASH_PREFIX, rawHash);
    }

    /// @notice Checks if this resolver supports a specific interface like contenthash or text resolution
    /// @param interfaceId The interface identifier to check (ERC-165)
    /// @return True if the interface is supported, false otherwise
    /// @dev Supports IExtendedResolver, IContentHashResolver, ITextResolver, and ERC165
    function supportsInterface(bytes4 interfaceId) public pure override returns (bool) {
        return interfaceId == type(IExtendedResolver).interfaceId
            || interfaceId == type(IContentHashResolver).interfaceId || interfaceId == 0xbc1c58d1 // ENSIP-7 contenthash
            || interfaceId == type(ITextResolver).interfaceId || interfaceId == 0x01ffc9a7; // ERC165
    }

    /// @notice Resolves version-aware ENS queries like "1-2.myapp.eth" to find the highest matching 1.2.x version
    /// @param name DNS-encoded name (e.g., "\x031-2\x06myapp\x03eth\x00" for "1-2.myapp.eth")
    /// @param data ABI-encoded function call (selector + arguments)
    /// @return ABI-encoded return value from the resolved function
    /// @dev Supports two resolution profiles:
    ///   1. IContentHashResolver.contenthash → returns IPFS content hash for version
    ///   2. ITextResolver.text → returns version string for key="version"
    /// @dev Resolution strategy:
    ///   - First attempts direct resolution (exact name match)
    ///   - Falls back to wildcard resolution if no direct match found
    /// @dev Complexity: O(log n) where n is number of versions for the base name
    /// @dev Examples:
    ///   - resolve("1-2.myapp.eth", contenthash.selector) → content hash for highest 1.2.x version
    ///   - resolve("1.myapp.eth", text.selector + "version") → version string for highest 1.x.x
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

    /// @notice Gets the IPFS content hash for the latest version of an ENS name
    /// @param node The ENS namehash to query
    /// @return The content hash of the latest version as bytes, or empty if no versions exist
    /// @dev Implements IContentHashResolver interface for direct (non-wildcard) queries
    function contenthash(bytes32 node) external view override returns (bytes memory) {
        bytes32 hash = getLatestContentHash(node);
        return _encodeIpfsContenthash(hash);
    }

    /// @notice Gets text data for an ENS name, currently only supports the "version" key
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
    /// @dev Complexity: Refactored into smaller functions for better readability
    function _resolveWildcardVersion(bytes memory name) internal view returns (VersionRecord memory) {
        // Parse the DNS-encoded name to extract version and base components
        (string memory versionLabel, bytes32 baseNode) = _extractVersionAndBaseName(name);

        // Parse the version label to determine query parameters
        ParsedVersion memory parsedVersion = _parseVersionFromLabel(versionLabel);

        // Execute the appropriate version query based on parsed components
        return _executeVersionQuery(baseNode, parsedVersion);
    }

    /// @dev Extracts version label and base name from DNS-encoded name
    /// @param name DNS-encoded name (e.g., "\x031-2\x06myapp\x03eth\x00")
    /// @return versionLabel The version string from first label (e.g., "1-2")
    /// @return baseNode The namehash of the base name (e.g., namehash("myapp.eth"))
    /// @dev Example: "\x031-2\x06myapp\x03eth\x00" → ("1-2", namehash("myapp.eth"))
    function _extractVersionAndBaseName(bytes memory name)
        private
        pure
        returns (string memory versionLabel, bytes32 baseNode)
    {
        // Extract the first label length from DNS encoding
        // Note: DNS name validation is handled upstream by NameCoder.namehash()
        uint256 labelLength = uint256(uint8(name[DNS_LABEL_LENGTH_OFFSET]));

        // Extract version label (first label after length byte)
        bytes memory versionBytes = BytesUtils.substring(name, DNS_LABEL_DATA_OFFSET, labelLength);
        versionLabel = string(versionBytes);

        // Extract base name (remainder after version label)
        bytes memory baseName = BytesUtils.substring(
            name, labelLength + DNS_LABEL_DATA_OFFSET, name.length - labelLength - DNS_LABEL_DATA_OFFSET
        );
        baseNode = NameCoder.namehash(baseName, FIRST_ELEMENT_INDEX);

        return (versionLabel, baseNode);
    }

    /// @dev Executes the appropriate version query based on parsed version components
    /// @param baseNode The namehash of the base ENS name
    /// @param parsedVersion The parsed version with component flags
    /// @return The matching version record or zero version if not found
    /// @dev Query types:
    ///   - Major only: hasMinor=false → getHighestVersionForMajor()
    ///   - Major.minor: hasMinor=true, hasPatch=false → getHighestVersionForMajorMinor()
    ///   - Exact: hasPatch=true → getExactVersion()
    function _executeVersionQuery(bytes32 baseNode, ParsedVersion memory parsedVersion)
        private
        view
        returns (VersionRecord memory)
    {
        Version memory version = parsedVersion.version;

        if (!parsedVersion.hasMinor) {
            // Major-only query: find highest version with matching major (e.g., "1" matches 1.x.x)
            return getHighestVersionForMajor(baseNode, version.major);
        } else if (!parsedVersion.hasPatch) {
            // Major.minor query: find highest version with matching major.minor (e.g., "1-2" matches 1.2.x)
            return getHighestVersionForMajorMinor(baseNode, version.major, version.minor);
        } else {
            // Exact version query: find exact match (e.g., "1-2-3" matches 1.2.3 only)
            return getExactVersion(baseNode, version.major, version.minor, version.patch);
        }
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

    /// @notice Publishes a new version of content for your ENS name (e.g., version `major`.`minor`.`patch of your hash `contentHash`).
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
