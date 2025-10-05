#!/usr/bin/env node

/**
 * Inlines external resources (CSS, fonts) into HTML files
 * to make them self-contained for IPFS
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { promisify } = require('util');

const readFile = promisify(fs.readFile);
const writeFile = promisify(fs.writeFile);

const BASE_URL = 'https://standardebooks.org';

/**
 * Fetches a resource from a URL
 * @param {string} url - URL to fetch
 * @returns {Promise<Buffer>} - Resource content
 */
function fetchResource(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
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
 * Converts a font file to base64 data URI
 * @param {Buffer} content - Font file content
 * @param {string} url - Original URL (to determine mime type)
 * @returns {string} - Data URI
 */
function fontToDataUri(content, url) {
  const ext = path.extname(url);
  const mimeTypes = {
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf',
    '.otf': 'font/otf'
  };
  const mimeType = mimeTypes[ext] || 'application/octet-stream';
  return `data:${mimeType};base64,${content.toString('base64')}`;
}

/**
 * Processes CSS to inline fonts referenced within it
 * @param {string} css - CSS content
 * @param {string} baseUrl - Base URL for resolving relative paths
 * @returns {Promise<string>} - Processed CSS with inlined fonts
 */
async function inlineFontsInCss(css, baseUrl) {
  // Find all url() references in the CSS
  const urlRegex = /url\(['"]?([^'")\s]+)['"]?\)/g;
  const matches = [...css.matchAll(urlRegex)];

  for (const match of matches) {
    const url = match[1];

    // Only process font files
    if (!/\.(woff2?|ttf|otf)$/i.test(url)) {
      continue;
    }

    try {
      const fullUrl = url.startsWith('http') ? url : `${baseUrl}${url}`;
      console.log(`  Fetching font: ${fullUrl}`);
      const fontContent = await fetchResource(fullUrl);
      const dataUri = fontToDataUri(fontContent, url);
      css = css.replace(match[0], `url('${dataUri}')`);
    } catch (err) {
      console.warn(`  Warning: Failed to fetch font ${url}:`, err.message);
    }
  }

  return css;
}

/**
 * Inlines external resources in an HTML file
 * @param {string} htmlPath - Path to HTML file
 * @returns {Promise<void>}
 */
async function inlineResources(htmlPath) {
  console.log(`Processing ${path.basename(htmlPath)}...`);

  let html = await readFile(htmlPath, 'utf-8');

  // Extract all <link> tags for CSS
  const cssLinkRegex = /<link[^>]*href=["']([^"']+\.css[^"']*)["'][^>]*>/g;
  const cssMatches = [...html.matchAll(cssLinkRegex)];

  for (const match of cssMatches) {
    const fullTag = match[0];
    const href = match[1];

    // Skip if not a stylesheet
    if (!fullTag.includes('stylesheet')) {
      continue;
    }

    try {
      const url = href.startsWith('http') ? href : `${BASE_URL}${href.split('?')[0]}`;
      console.log(`  Fetching CSS: ${url}`);
      const cssContent = await fetchResource(url);
      let css = cssContent.toString('utf-8');

      // Inline fonts within the CSS
      css = await inlineFontsInCss(css, BASE_URL);

      // Replace the <link> tag with an inline <style> tag
      const styleTag = `<style>\n${css}\n</style>`;
      html = html.replace(fullTag, styleTag);
    } catch (err) {
      console.warn(`  Warning: Failed to fetch CSS ${href}:`, err.message);
    }
  }

  // Remove font preload tags (no longer needed)
  html = html.replace(/<link[^>]*rel=["']preload["'][^>]*as=["']font["'][^>]*>/g, '');

  // Write the modified HTML back
  await writeFile(htmlPath, html, 'utf-8');
  console.log(`  ✓ Done\n`);
}

/**
 * Process all HTML files in a directory
 * @param {string} dir - Directory containing HTML files
 */
async function processDirectory(dir) {
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.html'));

  console.log(`Found ${files.length} HTML files to process\n`);

  for (const file of files) {
    const filePath = path.join(dir, file);
    await inlineResources(filePath);
  }

  console.log('All files processed!');
}

// Run if called directly
if (require.main === module) {
  const demoDir = path.join(__dirname, '../test/demo');
  processDirectory(demoDir).catch(console.error);
}

module.exports = { inlineResources, processDirectory };
