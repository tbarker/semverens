#!/usr/bin/env node

/**
 * Downloads complete HTML pages from standardebooks.org and inlines all resources
 * including CSS, fonts, images, and SVGs to create self-contained HTML files
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { promisify } = require('util');

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
      if (res.statusCode === 301 || res.statusCode === 302) {
        // Follow redirect
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
 * Converts a resource to base64 data URI
 * @param {Buffer} content - Resource content
 * @param {string} url - Original URL (to determine mime type)
 * @returns {string} - Data URI
 */
function toDataUri(content, url) {
  const ext = path.extname(url).toLowerCase();
  const mimeTypes = {
    '.woff2': 'font/woff2',
    '.woff': 'font/woff',
    '.ttf': 'font/ttf',
    '.otf': 'font/otf',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.webp': 'image/webp'
  };
  const mimeType = mimeTypes[ext] || 'application/octet-stream';

  // SVG can be inlined as text
  if (ext === '.svg') {
    return `data:${mimeType};charset=utf-8,${encodeURIComponent(content.toString('utf-8'))}`;
  }

  return `data:${mimeType};base64,${content.toString('base64')}`;
}

/**
 * Processes CSS to inline fonts and images referenced within it
 * @param {string} css - CSS content
 * @param {string} baseUrl - Base URL for resolving relative paths
 * @param {string} cssUrl - The URL of the CSS file being processed (for relative path resolution)
 * @returns {Promise<string>} - Processed CSS with inlined resources
 */
async function inlineResourcesInCss(css, baseUrl, cssUrl) {
  // First, handle @import statements
  const importRegex = /@import\s+url\(['"]?([^'")\s]+)['"]?\);?/g;
  const importMatches = [...css.matchAll(importRegex)];

  for (const match of importMatches) {
    const url = match[1];

    try {
      let cssPath = url;

      // Resolve relative paths relative to the CSS file's location
      if (!cssPath.startsWith('/') && !cssPath.startsWith('http')) {
        if (cssUrl) {
          // Get directory of current CSS file
          const cssDir = path.dirname(cssUrl);
          cssPath = path.join(cssDir, cssPath).replace(/\\/g, '/');
        } else {
          cssPath = '/' + cssPath;
        }
      }

      const fullUrl = cssPath.startsWith('http') ? cssPath : `${baseUrl}${cssPath}`;
      console.log(`    Fetching @import: ${fullUrl}`);
      const importedCssContent = await fetchResource(fullUrl);
      let importedCss = importedCssContent.toString('utf-8');

      // Recursively inline resources in the imported CSS
      importedCss = await inlineResourcesInCss(importedCss, baseUrl, cssPath);

      // Replace the @import statement with the actual CSS content
      css = css.replace(match[0], `/* Inlined from ${url} */\n${importedCss}\n`);
    } catch (err) {
      console.warn(`    Warning: Failed to fetch @import ${url}:`, err.message);
    }
  }

  // Then handle url() references
  const urlRegex = /url\(['"]?([^'")\s]+)['"]?\)/g;
  const matches = [...css.matchAll(urlRegex)];

  for (const match of matches) {
    const url = match[1];

    // Skip data URIs
    if (url.startsWith('data:')) {
      continue;
    }

    try {
      const fullUrl = url.startsWith('http') ? url : `${baseUrl}${url}`;
      console.log(`    Fetching: ${fullUrl}`);
      const resourceContent = await fetchResource(fullUrl);
      const dataUri = toDataUri(resourceContent, url);
      css = css.replace(match[0], `url('${dataUri}')`);
    } catch (err) {
      console.warn(`    Warning: Failed to fetch ${url}:`, err.message);
    }
  }

  return css;
}

/**
 * Downloads and inlines all resources in an HTML page
 * @param {string} url - URL of the page to download
 * @param {string} outputPath - Path to save the inlined HTML
 */
async function downloadAndInline(url, outputPath) {
  console.log(`\nDownloading: ${url}`);

  // Fetch the HTML
  const htmlBuffer = await fetchResource(url);
  let html = htmlBuffer.toString('utf-8');

  console.log(`  Processing CSS...`);
  // Inline all CSS files
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
      let cssPath = href.split('?')[0];
      if (!cssPath.startsWith('/') && !cssPath.startsWith('http')) {
        cssPath = '/' + cssPath;
      }
      const cssUrl = cssPath.startsWith('http') ? cssPath : `${BASE_URL}${cssPath}`;
      console.log(`    Fetching CSS: ${cssUrl}`);
      const cssContent = await fetchResource(cssUrl);
      let css = cssContent.toString('utf-8');

      // Inline fonts and images within the CSS
      css = await inlineResourcesInCss(css, BASE_URL, cssPath);

      // Replace the <link> tag with an inline <style> tag
      const styleTag = `<style>\n${css}\n</style>`;
      html = html.replace(fullTag, styleTag);
    } catch (err) {
      console.warn(`    Warning: Failed to fetch CSS ${href}:`, err.message);
    }
  }

  console.log(`  Processing images...`);
  // Inline all images
  const imgRegex = /<img[^>]*src=["']([^"']+)["'][^>]*>/g;
  const imgMatches = [...html.matchAll(imgRegex)];

  for (const match of imgMatches) {
    const fullTag = match[0];
    const src = match[1];

    // Skip data URIs
    if (src.startsWith('data:')) {
      continue;
    }

    try {
      const imgUrl = src.startsWith('http') ? src : `${BASE_URL}${src}`;
      console.log(`    Fetching image: ${imgUrl}`);
      const imgContent = await fetchResource(imgUrl);
      const dataUri = toDataUri(imgContent, src);
      const newTag = fullTag.replace(src, dataUri);
      html = html.replace(fullTag, newTag);
    } catch (err) {
      console.warn(`    Warning: Failed to fetch image ${src}:`, err.message);
    }
  }

  console.log(`  Processing SVGs...`);
  // Inline SVG images in CSS background-image
  const bgImageRegex = /background-image:\s*url\(['"]?([^'")\s]+\.svg[^'")\s]*)['"]?\)/g;
  const bgMatches = [...html.matchAll(bgImageRegex)];

  for (const match of bgMatches) {
    const url = match[1];

    if (url.startsWith('data:')) {
      continue;
    }

    try {
      const svgUrl = url.startsWith('http') ? url : `${BASE_URL}${url}`;
      console.log(`    Fetching SVG: ${svgUrl}`);
      const svgContent = await fetchResource(svgUrl);
      const dataUri = toDataUri(svgContent, url);
      html = html.replace(match[0], `background-image: url('${dataUri}')`);
    } catch (err) {
      console.warn(`    Warning: Failed to fetch SVG ${url}:`, err.message);
    }
  }

  // Remove font preload tags (no longer needed)
  html = html.replace(/<link[^>]*rel=["']preload["'][^>]*>/g, '');

  // Remove other external resource links that are not essential
  html = html.replace(/<link[^>]*rel=["'](apple-touch-icon|icon|manifest|alternate|search)["'][^>]*>/g, '');

  console.log(`  Writing to ${outputPath}...`);
  await writeFile(outputPath, html, 'utf-8');
  console.log(`  ✓ Done!`);
}

/**
 * Process all manual versions
 */
async function processAllVersions() {
  // Only versions with single-page available (1.3.1+)
  const versions = [
    '1.3.1', '1.4.0', '1.5.0',
    '1.6.0', '1.6.1', '1.6.2', '1.6.3', '1.6.4',
    '1.7.0', '1.7.1', '1.7.2', '1.7.3', '1.7.4',
    '1.8.0', '1.8.1', '1.8.2', '1.8.3', '1.8.4'
  ];

  const demoDir = path.join(__dirname, '../test/demo');

  for (const version of versions) {
    const url = `${BASE_URL}/manual/${version}/single-page`;
    const outputPath = path.join(demoDir, `${version}.html`);

    try {
      await downloadAndInline(url, outputPath);
    } catch (err) {
      console.error(`Error processing ${version}:`, err.message);
    }
  }

  console.log('\n✓ All versions processed!');
}

// Run if called directly
if (require.main === module) {
  processAllVersions().catch(console.error);
}

module.exports = { downloadAndInline, processAllVersions };
