#!/usr/bin/env node

/**
 * Stitches together multi-page manual versions that don't have single-page versions
 * For versions 1.0.0-1.3.0, fetches all section pages and combines them
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { promisify } = require('util');

const writeFile = promisify(fs.writeFile);

const BASE_URL = 'https://standardebooks.org';

/**
 * Fetches a resource from a URL
 */
function fetchResource(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        return fetchResource(res.headers.location).then(resolve, reject);
      }

      if (res.statusCode !== 200) {
        reject(new Error(`Failed to fetch ${url}: ${res.statusCode}`));
        return;
      }

      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

/**
 * Extracts section links from a TOC page
 */
function extractSectionLinks(html, version) {
  const linkRegex = /<a href="\/manual\/[^"]+\/([^"]+)">/g;
  const links = [];
  let match;

  while ((match = linkRegex.exec(html)) !== null) {
    const section = match[1];
    // Skip the TOC link itself
    if (section && section !== '' && !section.includes('single-page')) {
      const fullUrl = `${BASE_URL}/manual/${version}/${section}`;
      if (!links.includes(fullUrl)) {
        links.push(fullUrl);
      }
    }
  }

  return links;
}

/**
 * Extracts the main content from a page (everything inside <article>)
 */
function extractArticleContent(html) {
  const articleMatch = html.match(/<article>([\s\S]*?)<\/article>/);
  if (articleMatch) {
    return articleMatch[1];
  }
  return '';
}

/**
 * Downloads all sections and stitches them together
 */
async function stitchVersion(version, outputPath) {
  console.log(`\nStitching version ${version}...`);

  // Fetch the TOC page
  const tocUrl = `${BASE_URL}/manual/${version}`;
  console.log(`  Fetching TOC: ${tocUrl}`);
  const tocHtml = (await fetchResource(tocUrl)).toString('utf-8');

  // Extract section links
  const sectionLinks = extractSectionLinks(tocHtml, version);
  console.log(`  Found ${sectionLinks.length} sections`);

  if (sectionLinks.length === 0) {
    console.warn(`  ⚠️  No sections found for ${version}`);
    return;
  }

  // Fetch all sections
  const sectionContents = [];

  for (let i = 0; i < sectionLinks.length; i++) {
    const url = sectionLinks[i];
    console.log(`  [${i + 1}/${sectionLinks.length}] Fetching: ${url}`);

    try {
      const sectionHtml = (await fetchResource(url)).toString('utf-8');
      const content = extractArticleContent(sectionHtml);
      if (content) {
        sectionContents.push(content);
      }
    } catch (err) {
      console.warn(`    Warning: Failed to fetch ${url}: ${err.message}`);
    }
  }

  // Use the first section page as the base template
  console.log(`  Fetching base template from first section...`);
  const baseHtml = (await fetchResource(sectionLinks[0])).toString('utf-8');

  // Combine all section contents
  const combinedContent = sectionContents.join('\n\n');

  // Replace the article content in the base template
  const stitchedHtml = baseHtml.replace(
    /<article>[\s\S]*?<\/article>/,
    `<article>\n${combinedContent}\n</article>`
  );

  console.log(`  Writing to ${outputPath}...`);
  await writeFile(outputPath, stitchedHtml, 'utf-8');
  console.log(`  ✓ Done!`);
}

/**
 * Process all multi-page versions
 */
async function processMultiPageVersions() {
  const versions = ['1.0.0', '1.1.0', '1.1.1', '1.2.0', '1.3.0'];
  const demoDir = path.join(__dirname, '../test/demo');

  for (const version of versions) {
    const outputPath = path.join(demoDir, `${version}.html`);

    try {
      await stitchVersion(version, outputPath);
    } catch (err) {
      console.error(`Error processing ${version}:`, err.message);
    }
  }

  console.log('\n✓ All multi-page versions stitched!');
}

// Run if called directly
if (require.main === module) {
  processMultiPageVersions().catch(console.error);
}

module.exports = { stitchVersion, processMultiPageVersions };
