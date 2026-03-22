'use strict';

/**
 * Parse an MRT file and output BGP elements as JSON, one per line.
 *
 * Supports two modes:
 *   --batch   Load entire file, parse all at once (parseMrtFile)
 *   --stream  Parse records one at a time using parseMrtRecords (default)
 *
 * Usage:
 *   node parse-mrt.js <url-or-file> [--batch|--stream]
 *   node parse-mrt.js https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz
 *   node parse-mrt.js updates.20260322.2105.gz --batch
 *
 * Supports .gz (gzip) compressed and uncompressed MRT files.
 * URLs are streamed via HTTP and decompressed incrementally.
 */

const fs = require('fs');
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const { parseMrtFile, parseMrtRecords } = require('@bgpkit/parser');

const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const flags = new Set(process.argv.slice(2).filter((a) => a.startsWith('--')));
const input = args[0];
const batchMode = flags.has('--batch');

if (!input) {
  console.error('Usage: node parse-mrt.js <url-or-file> [--batch|--stream]');
  console.error('  node parse-mrt.js https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz');
  console.error('  node parse-mrt.js updates.20260322.2105.gz --batch');
  process.exit(1);
}

/**
 * Open a gzip stream from a URL, following redirects.
 * Returns a readable stream of decompressed bytes.
 */
function openGzipStream(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    lib
      .get(url, (res) => {
        if (res.statusCode === 301 || res.statusCode === 302) {
          openGzipStream(res.headers.location).then(resolve, reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        if (url.endsWith('.gz')) {
          resolve(res.pipe(zlib.createGunzip()));
        } else {
          resolve(res);
        }
      })
      .on('error', reject);
  });
}

/**
 * Collect a readable stream into a single Buffer.
 */
function collectStream(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

/**
 * Get decompressed MRT bytes from a URL or local file.
 */
async function loadMrtData(input) {
  const isUrl = input.startsWith('http://') || input.startsWith('https://');

  if (isUrl) {
    process.stderr.write(`Streaming ${input}...\n`);
    const stream = await openGzipStream(input);
    return collectStream(stream);
  }

  const buf = fs.readFileSync(input);
  if (input.endsWith('.gz')) {
    process.stderr.write('Decompressing gzip...\n');
    return zlib.gunzipSync(buf);
  }
  if (input.endsWith('.bz2')) {
    console.error('bzip2 is not supported by Node.js zlib. Decompress the file first.');
    process.exit(1);
  }
  return buf;
}

async function main() {
  const raw = await loadMrtData(input);
  process.stderr.write(`Loaded ${raw.length} bytes of MRT data\n`);

  let count = 0;

  if (batchMode) {
    // Parse all records at once
    const elems = parseMrtFile(raw);
    for (const elem of elems) {
      console.log(JSON.stringify(elem));
      count++;
    }
  } else {
    // Stream: parse one MRT record at a time
    for (const { elems } of parseMrtRecords(raw)) {
      for (const elem of elems) {
        console.log(JSON.stringify(elem));
        count++;
      }
    }
  }

  process.stderr.write(`Output ${count} BGP elements\n`);
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
