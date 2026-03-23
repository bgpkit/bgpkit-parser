'use strict';

/**
 * Parse an MRT file and output BGP elements as JSON, one per line.
 *
 * Usage:
 *   node parse-mrt.js <url-or-file>
 *   node parse-mrt.js https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz
 *   node parse-mrt.js https://archive.routeviews.org/route-views.amsix/bgpdata/2025.01/UPDATES/updates.20250101.0000.bz2
 *   node parse-mrt.js updates.20260322.2105.gz
 *
 * Supports .gz (gzip) and .bz2 (bzip2, requires: npm install seek-bzip) compressed
 * and uncompressed MRT files. URLs and local paths are both supported.
 */

const { streamMrtFrom } = require('@bgpkit/parser');

const input = process.argv[2];

if (!input) {
  console.error('Usage: node parse-mrt.js <url-or-file>');
  console.error('  node parse-mrt.js https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz');
  console.error('  node parse-mrt.js updates.20260322.2105.gz');
  process.exit(1);
}

async function main() {
  process.stderr.write(`Parsing ${input}...\n`);

  let count = 0;

  for await (const { elems } of streamMrtFrom(input)) {
    for (const elem of elems) {
      console.log(JSON.stringify(elem));
      count++;
    }
  }

  process.stderr.write(`Output ${count} BGP elements\n`);
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
