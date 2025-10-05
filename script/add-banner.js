#!/usr/bin/env node

/**
 * Adds a banner to the top of all HTML files
 */

const fs = require('fs');
const path = require('path');

const banner = `<div style="width: 100%; text-align:center; background-color: #6629d6; padding: 0px 0px; font-family: sans-serif; font-size: 16pt; border-bottom: 1px solid #90caf9;">
Mirrored from <a href="https://standardebooks.org" style="color: #1976d2; text-decoration: none;">Standard Ebooks</a>.
</div>
`;

function addBanner(htmlPath) {
  console.log(`Processing ${path.basename(htmlPath)}...`);

  let html = fs.readFileSync(htmlPath, 'utf-8');

  // Remove any existing banners (multiline pattern)
  // Match <div style="...">...Mirrored from...Standard Ebooks...</div>
  html = html.replace(/<div style="[^"]*">\s*Mirrored from\s*<a[^>]*>[^<]*<\/a>\.\s*<\/div>\s*/g, '');

  // Insert new banner right after <body> tag
  html = html.replace(/<body>/, `<body>\n${banner}`);

  fs.writeFileSync(htmlPath, html, 'utf-8');
  console.log(`  ✓ Done`);
}

// Process all HTML files
const demoDir = path.join(__dirname, '../test/demo');
const files = fs.readdirSync(demoDir).filter(f => f.endsWith('.html'));

console.log(`Adding banner to ${files.length} files...\n`);

for (const file of files) {
  const filePath = path.join(demoDir, file);
  addBanner(filePath);
}

console.log(`\n✓ All files updated!`);
