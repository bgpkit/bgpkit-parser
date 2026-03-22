# Parse MRT File — Node.js Example

> **Experimental**: The `@bgpkit/parser` npm package is experimental. The API
> surface, output format, and build process may change in future releases.

This example parses an MRT file into BGP elements using
[`@bgpkit/parser`](https://www.npmjs.com/package/@bgpkit/parser) and outputs
one JSON object per line. It accepts both URLs and local files.

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18

## Run

```sh
cd examples/wasm/parse-mrt-file
npm install

# Parse directly from a URL (fetches and decompresses in memory)
node parse-mrt.js https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz

# Or parse a local file
node parse-mrt.js updates.20260322.2105.gz
```

## Output

Each line is a JSON object representing a single BGP element:

```json
{"timestamp":1742677500.0,"type":"ANNOUNCE","peer_ip":"2001:7f8:4::...","peer_asn":6939,...}
{"timestamp":1742677500.0,"type":"WITHDRAW","peer_ip":"80.249.211.155","peer_asn":34549,...}
```

You can pipe the output through `jq` for pretty-printing or filtering:

```sh
URL=https://data.ris.ripe.net/rrc06/2026.03/updates.20260322.2105.gz

# Pretty-print first element
node parse-mrt.js $URL | head -1 | jq .

# Count announcements vs withdrawals
node parse-mrt.js $URL | jq -r '.type' | sort | uniq -c

# Filter by prefix
node parse-mrt.js $URL | jq -r 'select(.prefix == "1.0.0.0/24")'
```
