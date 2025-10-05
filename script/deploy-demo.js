#!/usr/bin/env node

/**
 * Demo content registration script using only ethers.js
 *
 * This script:
 * 1. Computes CIDs for all demo HTML files on-the-fly
 * 2. Connects to an existing SemverResolver contract
 * 3. Registers all content editions with their CIDs
 */

const fs = require('fs');
const path = require('path');
const { ethers } = require('ethers');
const { computeCIDs } = require('./computeCIDs');

// Mainnet ENS Registry address
const ENS_REGISTRY_ADDRESS = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e';

/**
 * Converts an ENS name to a namehash
 */
function namehash(name) {
  let node = '0x0000000000000000000000000000000000000000000000000000000000000000';

  if (name) {
    const labels = name.split('.');
    for (let i = labels.length - 1; i >= 0; i--) {
      const labelHash = ethers.keccak256(ethers.toUtf8Bytes(labels[i]));
      node = ethers.keccak256(ethers.concat([node, labelHash]));
    }
  }

  return node;
}


/**
 * Loads SemverResolver ABI
 */
function loadContractABI() {
  const artifactPath = path.join(__dirname, '../out/SemverResolver.sol/SemverResolver.json');

  if (!fs.existsSync(artifactPath)) {
    throw new Error(
      `Contract artifact not found. Please run: forge build\n` +
      `Expected: ${artifactPath}`
    );
  }

  try {
    const artifact = JSON.parse(fs.readFileSync(artifactPath, 'utf8'));
    
    if (!artifact.abi || !Array.isArray(artifact.abi)) {
      throw new Error('Invalid contract artifact: missing or invalid ABI');
    }
    
    // Verify publishContent function exists in ABI
    const hasPublishContent = artifact.abi.some(
      item => item.type === 'function' && item.name === 'publishContent'
    );
    
    if (!hasPublishContent) {
      throw new Error('Contract ABI missing publishContent function - contract may be outdated');
    }
    
    return artifact.abi;
  } catch (error) {
    if (error.message.includes('publishContent')) {
      throw error;
    }
    throw new Error(`Failed to parse contract artifact: ${error.message}`);
  }
}

async function main() {
  console.log('='.repeat(80));
  console.log('SemverENS Demo Content Registration Script');
  console.log('='.repeat(80));

  // Pre-flight checks
  console.log('\n[Pre-flight] Validating environment...');
  
  // Check if contract build artifacts exist
  const artifactPath = path.join(__dirname, '../out/SemverResolver.sol/SemverResolver.json');
  if (!fs.existsSync(artifactPath)) {
    console.error('\n✗ ERROR: Contract artifacts not found');
    console.log('Please run: forge build');
    console.log(`Expected: ${artifactPath}`);
    process.exit(1);
  }
  console.log('✓ Contract artifacts found');

  // Check demo files exist
  const demoDir = path.join(__dirname, '../test/demo');
  if (!fs.existsSync(demoDir)) {
    console.error('\n✗ ERROR: Demo directory not found');
    console.log(`Expected: ${demoDir}`);
    process.exit(1);
  }
  
  const demoFiles = fs.readdirSync(demoDir).filter(f => f.endsWith('.html'));
  if (demoFiles.length === 0) {
    console.error('\n✗ ERROR: No demo HTML files found');
    console.log(`Expected HTML files in: ${demoDir}`);
    process.exit(1);
  }
  console.log(`✓ Found ${demoFiles.length} demo files`);

  // Step 1: Compute CIDs
  console.log('\n[Step 1/4] Computing IPFS CIDs for demo files...');
  let cids, versions;
  try {
    cids = await computeCIDs();
    versions = Object.values(cids);
    console.log(`✓ Computed ${versions.length} CIDs`);
  } catch (error) {
    console.error('\n✗ ERROR: Failed to compute CIDs');
    console.error(`Details: ${error.message}`);
    console.log('\nPossible fixes:');
    console.log('  1. Ensure demo HTML files exist in test/demo/');
    console.log('  2. Check file naming follows X.Y.Z.html format');
    console.log('  3. Run: npm install (for IPFS dependencies)');
    process.exit(1);
  }

  // Step 2: Setup provider and signer
  console.log('\n[Step 2/4] Setting up Ethereum connection...');
  const rpcUrl = process.env.RPC_URL || process.env.ETH_RPC_URL || 'https://eth.llamarpc.com';
  console.log(`Using RPC URL: ${rpcUrl}`);

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const network = await provider.getNetwork();
  console.log(`✓ Connected to network: ${network.name} (chainId: ${network.chainId})`);

  if (network.chainId !== 1n) {
    console.warn(`⚠️  WARNING: Not connected to mainnet (chainId 1). Connected to chainId ${network.chainId}`);

    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const answer = await new Promise(resolve => {
      readline.question('Continue anyway? (yes/no): ', resolve);
    });
    readline.close();

    if (answer.toLowerCase() !== 'yes') {
      console.log('Deployment cancelled');
      process.exit(0);
    }
  }

  // Check for wallet method
  let signer;
  let signerAddress;

  if (process.env.USE_TREZOR === 'true') {
    console.log('Using Trezor wallet...');
    const TrezorSigner = require('./trezor-signer');
    const trezorPath = process.env.TREZOR_PATH || "m/44'/60'/0'/0/0";
    signer = new TrezorSigner(provider, trezorPath);
    signerAddress = await signer.getAddress();
    console.log(`✓ Trezor address: ${signerAddress}`);
    console.log(`  Derivation path: ${trezorPath}`);
  } else {
    if (!process.env.PRIVATE_KEY) {
      console.error('\n✗ ERROR: PRIVATE_KEY environment variable not set');
      console.log('\nTo deploy, either:');
      console.log('  1. Set your private key: export PRIVATE_KEY=0x...');
      console.log('  2. Use Trezor: export USE_TREZOR=true');
      process.exit(1);
    }

    signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
    signerAddress = signer.address;
    console.log(`✓ Deployer address: ${signerAddress}`);
  }

  const balance = await provider.getBalance(signerAddress);
  console.log(`✓ Balance: ${ethers.formatEther(balance)} ETH`);

  // Step 3: Get resolver address
  console.log('\n[Step 3/4] Getting SemverResolver contract address...');
  const resolverAddress = process.env.RESOLVER_ADDRESS;

  if (!resolverAddress) {
    console.error('\n✗ ERROR: RESOLVER_ADDRESS environment variable not set');
    console.log('\nTo register content, set the resolver address:');
    console.log('  export RESOLVER_ADDRESS=0x...');
    process.exit(1);
  }

  if (!ethers.isAddress(resolverAddress)) {
    console.error(`\n✗ ERROR: Invalid resolver address: ${resolverAddress}`);
    process.exit(1);
  }

  console.log(`✓ Using SemverResolver at: ${resolverAddress}`);

  // Connect to existing contract
  let abi, contract;
  try {
    abi = loadContractABI();
    contract = new ethers.Contract(resolverAddress, abi, signer);
    
    // Verify contract exists and has expected interface
    const code = await provider.getCode(resolverAddress);
    if (code === '0x') {
      throw new Error('No contract found at resolver address - address may be invalid or contract not deployed');
    }
    
    // Test contract connection by calling supportsInterface
    try {
      await contract.supportsInterface('0x01ffc9a7'); // ERC165
      console.log('✓ Contract connection verified');
    } catch (interfaceError) {
      console.warn('⚠️  Could not verify contract interface - proceeding anyway');
    }
  } catch (error) {
    console.error('\n✗ ERROR: Failed to connect to resolver contract');
    console.error(`Details: ${error.message}`);
    console.log('\nPossible fixes:');
    console.log('  1. Verify RESOLVER_ADDRESS is correct');
    console.log('  2. Ensure contract is deployed at that address');
    console.log('  3. Run: forge build (to update contract artifacts)');
    process.exit(1);
  }

  // Determine target namehash
  const targetName = process.env.TARGET_ENS_NAME || 'ebooks.thomasoncrypto.eth';
  const targetNamehash = namehash(targetName);
  console.log(`Target ENS name for version registration: ${targetName}`);
  console.log(`Target namehash: ${targetNamehash}`);

  // Step 4: Register versions
  console.log(`\n[Step 4/4] Registering ${versions.length} versions...`);
  console.log('This will take several minutes...\n');

  for (let i = 0; i < versions.length; i++) {
    const v = versions[i];
    const versionStr = `${v.major}.${v.minor}.${v.patch}`;

    console.log(`[${i + 1}/${versions.length}] Registering version ${versionStr}...`);

    try {
      const tx = await contract.publishContent(
        targetNamehash,
        v.major,
        v.minor,
        v.patch,
        v.bytes32
      );

      console.log(`  Transaction: ${tx.hash}`);
      await tx.wait();
      console.log(`  ✓ Confirmed`);
    } catch (error) {
      console.error(`  ✗ Failed: ${error.message}`);
      throw error;
    }
  }

  console.log(`\n✓ All ${versions.length} versions registered successfully`);

  // Summary
  console.log('\n' + '='.repeat(80));
  console.log('✓ Content registration completed successfully!');
  console.log('='.repeat(80));
  console.log(`\nResolver address: ${resolverAddress}`);
  console.log(`Versions registered: ${versions.length}`);
  console.log(`Target namehash: ${targetNamehash}`);
  console.log(`Target ENS name: ${targetName}`);

  console.log('\nView on Etherscan:');
  console.log(`https://etherscan.io/address/${resolverAddress}`);
}

if (require.main === module) {
  main().catch(error => {
    console.error('\n✗ Content registration failed:', error);
    process.exit(1);
  });
}

module.exports = { namehash };
