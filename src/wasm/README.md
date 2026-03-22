# @bgpkit/parser — WebAssembly Bindings

> **Experimental**: The WASM bindings are experimental. The API surface, output
> format, and build process may change in future releases.

This module compiles bgpkit-parser's BGP/BMP/MRT parsing code to WebAssembly
for use in JavaScript and TypeScript environments (Node.js, bundlers, Cloudflare
Workers).

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/):
  ```sh
  cargo install wasm-pack
  ```
- The `wasm32-unknown-unknown` target:
  ```sh
  rustup target add wasm32-unknown-unknown
  ```

### Building and Publishing

The build script compiles all three targets (Node.js, bundler, web) and
assembles a single npm package in `pkg/`:

```sh
# From the repository root
bash src/wasm/build.sh

# Publish to npm
cd pkg && npm publish
```

The resulting `pkg/` directory contains:

```
pkg/
├── nodejs/          # CommonJS, sync WASM loading (Node.js)
├── bundler/         # ES modules (webpack, vite, rollup)
├── web/             # ES modules + init() (browsers, Cloudflare Workers)
├── index.js         # CJS entry point
├── index.mjs        # ESM entry point
├── index.d.ts       # TypeScript types
├── web.mjs          # Web entry point (requires init())
├── web.d.ts         # Web TypeScript types
└── package.json     # npm package manifest with conditional exports
```

The `package.json` uses [conditional exports](https://nodejs.org/api/packages.html#conditional-exports)
so that `require('@bgpkit/parser')` loads the Node.js target and
`import '@bgpkit/parser'` loads the bundler target automatically. The web
target is available as a separate subpath import (`@bgpkit/parser/web`).

### Building a single target

If you only need one target (e.g. for the Kafka example), you can build it
directly:

```sh
wasm-pack build --target nodejs --no-default-features --features wasm
```

## API

Four parsing functions are exported, all accepting `Uint8Array` input and
returning parsed JavaScript objects:

### `parseOpenBmpMessage(data: Uint8Array): BmpParsedMessage | null`

Parse an OpenBMP-wrapped BMP message as received from the
[RouteViews Kafka stream](http://www.routeviews.org/routeviews/).
Returns `null` for non-router OpenBMP frames (e.g. collector heartbeats).

```js
const { parseOpenBmpMessage } = require('@bgpkit/parser');

// `raw` is a Buffer/Uint8Array from a Kafka message value
const msg = parseOpenBmpMessage(raw);
if (msg && msg.type === 'RouteMonitoring') {
  for (const elem of msg.elems) {
    console.log(elem.type, elem.prefix, elem.as_path);
  }
}
```

### `parseBmpMessage(data: Uint8Array, timestamp: number): BmpParsedMessage`

Parse a raw BMP message without an OpenBMP wrapper. The `timestamp` parameter
provides the collection time in seconds since Unix epoch.

```js
const { parseBmpMessage } = require('@bgpkit/parser');

const msg = parseBmpMessage(bmpBytes, Date.now() / 1000);
switch (msg.type) {
  case 'RouteMonitoring':
    console.log(`${msg.elems.length} BGP elements`);
    break;
  case 'PeerUpNotification':
    console.log(`Peer up: ${msg.peerHeader.peerIp}`);
    break;
  case 'PeerDownNotification':
    console.log(`Peer down: ${msg.peerHeader.peerIp} (${msg.reason})`);
    break;
}
```

### `parseMrtFile(data: Uint8Array): BgpElem[]`

Parse a fully decompressed MRT file into an array of BGP elements. Handles
TABLE_DUMP, TABLE_DUMP_V2, and BGP4MP record types. The caller is responsible
for bzip2/gzip decompression before passing the raw bytes.

```js
const fs = require('fs');
const zlib = require('zlib');
const { parseMrtFile } = require('@bgpkit/parser');

const compressed = fs.readFileSync('rib.20260101.0000.bz2');
const raw = zlib.bunzip2Sync(compressed); // or use a bzip2 library
const elems = parseMrtFile(raw);

console.log(`Parsed ${elems.length} BGP elements`);
for (const elem of elems.slice(0, 10)) {
  console.log(elem.type, elem.prefix, elem.as_path);
}
```

### `parseBgpUpdate(data: Uint8Array): BgpElem[]`

Parse a single BGP UPDATE message into BGP elements. Expects the full BGP
message including the 16-byte marker, 2-byte length, and 1-byte type header.
Assumes 4-byte ASN encoding.

The returned elements have `timestamp: 0` and unspecified peer IP/ASN since
those are not part of the BGP message itself.

```js
const { parseBgpUpdate } = require('@bgpkit/parser');

// bgpBytes includes the 16-byte marker + length + type header
const elems = parseBgpUpdate(bgpBytes);
for (const elem of elems) {
  console.log(elem.prefix, elem.next_hop);
}
```

## BMP Message Types

The BMP parsing functions return a discriminated union on the `type` field.
All message types include a `timestamp` and an optional `openBmpHeader`
(present only when parsed via `parseOpenBmpMessage`).

| `type` | Additional fields |
|---|---|
| `RouteMonitoring` | `peerHeader`, `elems` (array of `BgpElem`) |
| `PeerUpNotification` | `peerHeader`, `localIp`, `localPort`, `remotePort` |
| `PeerDownNotification` | `peerHeader`, `reason` |
| `InitiationMessage` | `tlvs` (array of `{type, value}`) |
| `TerminationMessage` | `tlvs` (array of `{type, value}`) |
| `StatisticsReport` | `peerHeader` |
| `RouteMirroringMessage` | `peerHeader` |

## Platform Support

| Platform | Import | Notes |
|---|---|---|
| Node.js (CJS) | `require('@bgpkit/parser')` | Uses `nodejs` target, sync WASM loading |
| Node.js (ESM) | `import { ... } from '@bgpkit/parser'` | Uses `bundler` target |
| Bundler | `import { ... } from '@bgpkit/parser'` | webpack, vite, rollup |
| Browser / CF Workers | `import { init, ... } from '@bgpkit/parser/web'` | Must call `await init()` first |

### Web target usage

The web target requires explicit initialization before calling any parsing
functions:

```js
import { init, parseOpenBmpMessage } from '@bgpkit/parser/web';

await init();  // load and compile the WASM module

const msg = parseOpenBmpMessage(data);
```

You can optionally pass a URL or `ArrayBuffer` of the `.wasm` file to `init()`
if the default path doesn't work in your environment:

```js
await init(new URL('./bgpkit_parser_bg.wasm', import.meta.url));
```

### Cloudflare Workers

Use the `@bgpkit/parser/web` entry point. Note that Workers cannot connect to
Kafka directly (no raw TCP sockets), so BMP message bytes must arrive via HTTP
(e.g. from a proxy service).
