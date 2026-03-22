'use strict';

/**
 * Parse an MRT file and output BGP elements as JSON, one per line.
 *
 * Usage:
 *   node parse-mrt.js <url-or-file>
 *   node parse-mrt.js https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz
 *   node parse-mrt.js updates.20260322.2105.gz
 *
 * Supports .gz (gzip) compressed and uncompressed MRT files.
 * URLs are fetched and decompressed in memory (no download needed).
 */

const fs = require('fs');
const zlib = require('zlib');
const path = require('path');
const { parseMrtFile } = require('@bgpkit/parser');

const input = process.argv[2];
if (!input) {
  console.error('Usage: node parse-mrt.js <url-or-file>');
  console.error('  node parse-mrt.js https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz');
  console.error('  node parse-mrt.js updates.20260322.2105.gz');
  process.exit(1);
}

async function fetchUrl(url) {
  process.stderr.write(`Fetching ${url}...\n`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
  return Buffer.from(await res.arrayBuffer());
}

function decompress(buf, name) {
  if (name.endsWith('.gz')) {
    process.stderr.write('Decompressing gzip...\n');
    return zlib.gunzipSync(buf);
  }
  if (name.endsWith('.bz2')) {
    console.error('bzip2 is not supported by Node.js zlib. Decompress the file first.');
    process.exit(1);
  }
  return buf;
}

async function main() {
  const isUrl = input.startsWith('http://') || input.startsWith('https://');
  const buf = isUrl ? await fetchUrl(input) : fs.readFileSync(input);
  const raw = decompress(buf, input);

  process.stderr.write(`Parsing ${raw.length} bytes of MRT data...\n`);
  const elems = parseMrtFile(raw);
  process.stderr.write(`Parsed ${elems.length} BGP elements\n`);

  for (const elem of elems) {
    console.log(JSON.stringify(elem));
  }
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
