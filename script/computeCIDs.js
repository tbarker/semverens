#!/usr/bin/env node

/**
 * Computes IPFS CIDs for all HTML files in the demo directory
 * Returns a mapping of version -> CID (as bytes32)
 */

const fs = require('fs');
const path = require('path');
const Hash = require('ipfs-only-hash');

/**
 * Computes CIDs for all demo HTML files
 * @param {string} [demoDir] - Optional custom demo directory path
 * @returns {Promise<Object>} - Sorted mapping of version -> {cid, bytes32, major, minor, patch}
 */
async function computeCIDs(demoDir) {
  if (!demoDir) {
    demoDir = path.join(__dirname, '../test/demo');
  }

  if (!fs.existsSync(demoDir)) {
    throw new Error(`Demo directory not found: ${demoDir}`);
  }

  const files = fs.readdirSync(demoDir).filter(f => f.endsWith('.html'));

  if (files.length === 0) {
    throw new Error(`No HTML files found in ${demoDir}`);
  }

  const cidMap = {};

  for (const file of files) {
    const filePath = path.join(demoDir, file);
    const content = fs.readFileSync(filePath);

    // Compute CIDv1 with rawLeaves (matches IPFS upload behavior)
    const cid = await Hash.of(content, { cidVersion: 1, rawLeaves: true });

    // Parse version from filename (e.g., "1.2.3.html" -> "1.2.3")
    const version = file.replace('.html', '');
    const [major, minor, patch] = version.split('.').map(Number);

    // Validate version numbers
    if (isNaN(major) || isNaN(minor) || isNaN(patch)) {
      console.warn(`⚠️  Skipping invalid version filename: ${file}`);
      continue;
    }

    // Convert CIDv1 to bytes32 for Solidity
    // CIDv1 raw format: bafkrei... (base32 encoded)
    // Parse CID and extract the 32-byte hash from the multihash
    const CID = require('cids');
    
    const cidObj = new CID(cid);
    // Extract just the hash digest (without multihash prefix)
    // For IPFS CIDv1 with sha256, we skip the multihash prefix (0x12 0x20)
    const hash = cidObj.multihash.slice(2); // Skip 0x12 0x20 (sha256 + 32 bytes indicator)
    const bytes32 = '0x' + Buffer.from(hash).toString('hex');

    cidMap[version] = {
      cid: cid,
      bytes32: bytes32,
      major,
      minor,
      patch
    };
  }

  // Sort by version
  const sorted = Object.entries(cidMap)
    .sort(([a], [b]) => {
      const [aMaj, aMin, aPatch] = a.split('.').map(Number);
      const [bMaj, bMin, bPatch] = b.split('.').map(Number);
      return aMaj !== bMaj ? aMaj - bMaj :
             aMin !== bMin ? aMin - bMin :
             aPatch - bPatch;
    });

  const sortedMap = Object.fromEntries(sorted);

  return sortedMap;
}

// When run directly, display the CIDs
if (require.main === module) {
  computeCIDs().then(cids => {
    console.log(`\nComputed CIDs for ${Object.keys(cids).length} versions:\n`);

    for (const [version, data] of Object.entries(cids)) {
      console.log(`${version.padEnd(10)} ${data.cid}`);
      console.log(`${' '.repeat(10)} ${data.bytes32}\n`);
    }
  }).catch(console.error);
}

module.exports = { computeCIDs };
