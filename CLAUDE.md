# Claude Code Assistant Documentation

This file contains commands and information for AI assistants working with the SemverResolver project.

NO TASK IS COMPLETE UNTIL:
1. forge fmt is run
2. All linting errors have been resolved
3. All compiler warnings have been resolved
4. Unit test coverage of code in the src folder is maintained at 100%

Constants and credentials are in the file `.env`. You will need to pass things to forge with flags.

ENS names will often be NameWrapper-controlled names.
Use cast for simply tasks.
DO NOT DEPLOY TO MAINNET WITHOUT BEING ASKED TO.

## Project Overview

SemverResolver is an ENS resolver implementing semantic versioning support for decentralized content distribution. It enables version-aware content resolution through ENS wildcard queries.

## Key Commands

### Building and Testing
```bash
# Build contracts
forge build

# Run all tests
forge test

# Run specific test contract
forge test --match-contract SemverResolverTest
forge test --match-contract VersionRegistryTest

# Generate coverage report
forge coverage --no-match-coverage "script/.*" --report lcov && genhtml lcov.info --branch-coverage --output-dir coverage

# Run linter
forge fmt --check
```

### Development Workflow
```bash
# Format code
forge fmt

# Check for compilation warnings
forge build --force

# Run gas snapshot
forge snapshot

# Clean build artifacts
forge clean
```

### Deployment Commands
```bash
# Deploy SemverResolver (requires PRIVATE_KEY, ENS_REGISTRY, ETHERSCAN_API_KEY)
forge script script/DeploySemverResolver.s.sol:DeploySemverResolver \
  --rpc-url https://eth.llamarpc.com \
  --broadcast \
  --verify \
  -vvvv

# Deploy demo content (requires PRIVATE_KEY, RESOLVER_ADDRESS)
npm run demo-deploy

# Deploy single version for testing
node script/deploy-demo.js --single-version
```

## Project Structure

- `src/SemverResolver.sol` - Main resolver with wildcard version resolution
- `src/VersionRegistry.sol` - Abstract version storage and retrieval
- `src/SemverLib.sol` - Core semantic versioning mixin
- `test/` - Comprehensive test suite with 4 test files
- `script/` - Deployment and utility scripts

## Important Notes

- Uses component-wise version ordering (major/minor can be out of order, patches must be sequential)
- Implements ENSIP-10 wildcard resolution and ENSIP-7 contenthash
- Binary search optimization for O(log n) version lookups
- Supports hyphen-separated version labels (e.g., "1-2-3" for DNS compatibility)

## Environment Variables

- `PRIVATE_KEY` - Deployer's private key
- `ENS_REGISTRY` - ENS registry address (mainnet: 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e)
- `NAME_WRAPPER` - ENS Name Wrapper address (mainnet: 0xd4416b13d2b3a9abae7acd5d6c2bbdbe25686401)
- `ETHERSCAN_API_KEY` - For contract verification
- `RESOLVER_ADDRESS` - Deployed resolver address for demo content
- `TARGET_ENS_NAME` - ENS name for demo deployment (default: ebooks.thomasoncrypto.eth)

## Common Issues

- Version 0.0.0 is reserved and not allowed
- Patch versions must be strictly sequential within major.minor
- Ensure proper ENS authorization before publishing content
- Use raw IPFS hashes (32 bytes) not full CIDs for content publishing