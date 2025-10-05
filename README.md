# SemverResolver - Semantic Versioning for ENS

An ENS resolver implementing semantic versioning support for decentralized content distribution. Enables version-aware content resolution through ENS wildcard queries using semantic version labels.

## Overview

SemverResolver is an ENS wildcard resolver (ENSIP-10) that implements semantic versioning for content hash resolution. It allows developers to version their decentralized applications and content using familiar semver (major.minor.patch) while leveraging ENS for resolution.

### Key Features

- **Semantic Versioning**: Full semver support with optimized `uint8.uint8.uint16` storage
- **Wildcard Resolution**: ENSIP-10 wildcard queries for version-specific content
- **Version Registry**: Efficient storage and retrieval of versioned content hashes
- **Binary Search**: Optimized version lookup for major and major.minor constraints
- **Content Hash Resolution**: IPFS/Swarm content addressing via ENSIP-7 contenthash

## Project Structure

```
src/
├── SemverResolver.sol           # Main resolver with wildcard version resolution
├── VersionRegistry.sol          # Abstract version storage and retrieval
└── SemverLib.sol                # Core semantic versioning mixin

test/
├── SemverResolver.t.sol        # Resolver integration tests (12 tests)
└── VersionRegistry.t.sol       # Version registry tests (24 tests)

script/
└── DeploySemverResolver.s.sol  # Deployment scripts
```

## Core Components

### SemverResolver

Main resolver implementing:
- **ENSIP-10 Wildcard Resolution**: `resolve(bytes name, bytes data)`
- **ENSIP-7 Content Hash**: `contenthash(bytes32 node)`
- **Text Records**: `text(bytes32 node, string key)` - Returns "version" key
- **Version Publishing**: `publishContent()` - Add new versioned content

## Usage Examples

### Version-Aware ENS Queries

```
# Latest version
app.myproject.eth → latest content hash

# Specific major version
1.app.myproject.eth → latest v1.x.x content hash

# Specific major.minor version
1:2.app.myproject.eth → latest v1.2.x content hash
```

**Note**: Colons (`:`) are used instead of dots in version labels to avoid conflicts with DNS label separators.

### Publishing Versions

```solidity
// Publish a new version with content hash
resolver.publishContent(
    namehash("myproject.eth"),
    1, 2, 3,  // version 1.2.3
    contentHash  // IPFS/Swarm hash
);
```

### Resolving Content

```solidity
// Get latest version
bytes32 latest = resolver.getLatestContentHash(namehash("myproject.eth"));

// Get latest v1.x.x
VersionRecord memory v1 = resolver.getHighestVersionForMajor(
    namehash("myproject.eth"),
    1
);
```

## Development

### Building

```bash
forge build
```

### Testing

```bash
forge test                                    # Run all tests (36 total)
forge test --match-contract SemverResolverTest    # 12 tests
forge test --match-contract VersionRegistryTest   # 24 tests
```

### Deploying SemverResolver Contract

Deploy a new SemverResolver instance using Forge script with automatic Etherscan verification.

#### Option 1: Using Private Key

```bash
# Set environment variables
export PRIVATE_KEY=0x...
export ENS_REGISTRY=0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e  # Mainnet ENS registry
export ETHERSCAN_API_KEY=your_api_key

# Deploy with verification
forge script script/DeploySemverResolver.s.sol:DeploySemverResolver \
  --rpc-url https://eth.llamarpc.com \
  --broadcast \
  --verify \
  -vvvv
```

**Environment Variables:**
- `PRIVATE_KEY` (required): Deployer's private key
- `ENS_REGISTRY` (required): ENS registry address (mainnet: `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`)
- `ETHERSCAN_API_KEY` (required for verification): Your Etherscan API key

## Official ENS Contract Addresses

The following are the official ENS contract addresses on Ethereum mainnet (correct as of October 5th, 2025):

- **ENS Registry**: `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`
- **ENS Name Wrapper**: `0xd4416b13d2b3a9abae7acd5d6c2bbdbe25686401`

These addresses are used throughout the SemverResolver for ENS integration and can be referenced in the `.env` file as `ENS_REGISTRY` and `NAME_WRAPPER` respectively.

#### Option 2: Using Trezor/Ledger Hardware Wallet

For production deployments, use a hardware wallet for enhanced security:

```bash
# Set environment variables
export ENS_REGISTRY=0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e
export ETHERSCAN_API_KEY=your_api_key

# Deploy with Trezor/Ledger
forge script script/DeploySemverResolver.s.sol:DeploySemverResolver \
  --rpc-url https://eth.llamarpc.com \
  --broadcast \
  --verify \
  --ledger \
  --hd-paths "m/44'/60'/0'/0/0"  # Optional: specify derivation path
```

**Prerequisites:**
- Trezor Bridge or Ledger Live installed and running
- Hardware device connected and unlocked
- You'll need to confirm the transaction on your device

**Gas Cost:** ~2.82M gas for deployment (≈$8.47 at 1 gwei / $3000 ETH)

#### Manual Verification (Post-Deployment)

If you deployed without `--verify`, you can verify the contract afterward:

```bash
forge verify-contract <CONTRACT_ADDRESS> \
  src/SemverResolver.sol:SemverResolver \
  --chain mainnet \
  --constructor-args $(cast abi-encode "constructor(address)" 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e) \
  --etherscan-api-key $ETHERSCAN_API_KEY \
  --watch
```

### Registering Demo Content

Register demo content to an existing SemverResolver. You can register all 23 demo versions (1.0.0 through 1.8.4) or just a single version for testing.

#### Option 1: Using Private Key

```bash
# 1. Build contracts
forge build

# 2. (Optional) View CIDs for demo content
npm run show-cids

# 3. Register content
export PRIVATE_KEY=0x...
export RESOLVER_ADDRESS=0x...
export TARGET_ENS_NAME=yourdomain.eth  # Optional

# Register all 23 versions
npm run deploy

# Or register just the latest version for testing
node script/deploy-demo.js --single-version

# Or register a specific version
node script/deploy-demo.js --single-version=1.8.4
```

**Environment Variables:**
- `PRIVATE_KEY` (required): Account private key (must be authorized to publish to the ENS name)
- `RESOLVER_ADDRESS` (required): Address of deployed SemverResolver contract
- `RPC_URL` (optional): Ethereum RPC endpoint (default: `https://eth.llamarpc.com`)
- `TARGET_ENS_NAME` (optional): ENS name to register versions under (default: `ebooks.thomasoncrypto.eth`)

#### Option 2: Using Trezor/Ledger Hardware Wallet


```bash
# 1. Build contracts
forge build

# 2. Register with Trezor
export USE_TREZOR=true
export TREZOR_PATH="m/44'/60'/0'/0/0"  # Optional, this is the default
export RESOLVER_ADDRESS=0x...
export TARGET_ENS_NAME=yourdomain.eth

# Register all 23 versions
npm run deploy

# Or register just the latest version
node script/deploy-demo.js --single-version

# Or register a specific version
node script/deploy-demo.js --single-version=1.8.4
```

**Important:** You will need to confirm each transaction on your hardware device. For all 23 versions, this means 23 confirmations. For single version deployment, only 1 confirmation is needed.

**Additional Environment Variables for Hardware Wallets:**
- `USE_TREZOR=true` (required): Enable Trezor signing
- `TREZOR_PATH` (optional): Derivation path (default: `m/44'/60'/0'/0/0`)

**Gas Cost per version:** ~115k gas (≈$0.35 at 1 gwei / $3000 ETH)
**Gas Cost for 23 versions:** ~2.65M gas (≈$7.95 at 1 gwei / $3000 ETH)

## Implementation Details

### Version Ordering

Versions must be strictly increasing:
- `1.0.0` → `1.0.1` → `1.1.0` → `2.0.0` ✅
- `1.1.0` → `1.0.1` ❌ (reverts with `VersionNotGreater`)

### Binary Search Algorithm

- **Time Complexity**: O(log n) for version queries
- **Space Complexity**: O(1) additional storage per version
- **Supports**: Partial version matching (major only, major.minor only)

## ENS Integration

### Supported Standards

- **ENSIP-7**: Content hash resolution
- **ENSIP-10**: Wildcard resolution for versioned subdomains
- **ERC-165**: Interface detection

### Wildcard Resolution Flow

1. DNS-encoded name received (e.g., `\x031:2\x06myapp\x03eth\x00`)
2. Extract first label as version query (`1:2`)
3. Parse version using `parseVersionFromLabel()` → `1.2.0`
4. Binary search for highest matching version (`1.2.x`)
5. Return corresponding content hash

## Use Cases

### Decentralized Application Versioning

```
app.myproject.eth              # Production (latest)
2.staging.myproject.eth        # Staging (latest v2.x)
1.legacy.myproject.eth         # Legacy (latest v1.x)
```

### Library Distribution

```
lib.mypackage.eth              # Latest stable
1.lib.mypackage.eth            # v1.x.x compatibility
2.lib.mypackage.eth            # v2.x.x latest
```

### Content Versioning

```
docs.myproject.eth             # Latest documentation
1:2.docs.myproject.eth         # v1.2.x specific docs
```

## Dependencies

- **OpenZeppelin Contracts**: Access control (`Ownable`)
- **ENS Contracts**: Official ENS interfaces
- **Forge Standard Library**: Testing framework
- **Solidity ^0.8.19**: Compiler version

## Demo Content Attribution

The demo content in `test/demo/` consists of versioned HTML files mirrored from the [Standard Ebooks Manual](https://standardebooks.org/manual), which documents their ebook production standards and style guide.

**Standard Ebooks Licensing:**
- Content produced by or for Standard Ebooks L³C is dedicated to the **public domain** via the [CC0 1.0 Universal Public Domain Dedication](https://creativecommons.org/publicdomain/zero/1.0/)
- Standard Ebooks creates high-quality, carefully produced public domain ebooks that are free and liberated
- All work Standard Ebooks puts into their ebooks is released into the public domain

Visit [standardebooks.org](https://standardebooks.org) to explore their collection of free, high-quality public domain ebooks.

## License

MIT License - see contract files for details.
