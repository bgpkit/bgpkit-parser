# @bgpkit/parser — WebAssembly Bindings

> **Experimental**: The WASM bindings are experimental. The API surface, output
> format, and build process may change in future releases.

This module compiles bgpkit-parser's BGP/BMP/MRT parsing code to WebAssembly
for use in JavaScript and TypeScript environments.

## Install

```sh
npm install @bgpkit/parser
```

## Use Cases and Examples

### 1. Real-time BMP stream processing (Node.js)

Parse OpenBMP messages from the RouteViews Kafka stream. Each Kafka message
is a small binary frame — no memory concerns.

**Requires Node.js** — Kafka clients need raw TCP sockets, which are not
available in browsers or Cloudflare Workers.

```js
const { Kafka } = require('kafkajs');
const { parseOpenBmpMessage } = require('@bgpkit/parser');

const kafka = new Kafka({
  brokers: ['stream.routeviews.org:9092'],
});

const consumer = kafka.consumer({ groupId: 'my-app' });
await consumer.connect();
await consumer.subscribe({ topic: /^routeviews\.amsix\..+\.bmp_raw$/ });

await consumer.run({
  eachMessage: async ({ message }) => {
    const msg = parseOpenBmpMessage(message.value);
    if (!msg) return; // non-router frame (e.g. collector heartbeat)

    switch (msg.type) {
      case 'RouteMonitoring':
        for (const elem of msg.elems) {
          console.log(elem.type, elem.prefix, elem.as_path);
        }
        break;
      case 'PeerUpNotification':
        console.log(`Peer up: ${msg.peerHeader.peerIp} AS${msg.peerHeader.peerAsn}`);
        break;
      case 'PeerDownNotification':
        console.log(`Peer down: ${msg.peerHeader.peerIp} (${msg.reason})`);
        break;
    }
  },
});
```

If you have raw BMP messages without the OpenBMP wrapper (e.g. from your own
BMP collector), use `parseBmpMessage` instead:

```js
const { parseBmpMessage } = require('@bgpkit/parser');

const msg = parseBmpMessage(bmpBytes, Date.now() / 1000);
```

### 2. MRT updates file analysis (Node.js)

Parse MRT updates files from RouteViews or RIPE RIS archives. Updates files
are typically 5–50 MB compressed (20–200 MB decompressed) and fit comfortably
in memory.

Supports gzip (`.gz`, RIPE RIS) and bzip2 (`.bz2`, RouteViews) compression.
For bz2, install an optional dependency: `npm install seek-bzip`.

**Using `streamMrtFrom`** (handles fetch + decompression):

```js
const { streamMrtFrom } = require('@bgpkit/parser');

// RIPE RIS (gzip)
for await (const { elems } of streamMrtFrom('https://data.ris.ripe.net/rrc00/2025.01/updates.20250101.0000.gz')) {
  for (const elem of elems) {
    console.log(elem.type, elem.prefix, elem.as_path);
  }
}

// RouteViews (bzip2 — requires: npm install seek-bzip)
for await (const { elems } of streamMrtFrom('https://archive.routeviews.org/route-views.amsix/bgpdata/2025.01/UPDATES/updates.20250101.0000.bz2')) {
  for (const elem of elems) {
    console.log(elem.type, elem.prefix, elem.as_path);
  }
}
```

**Using `parseMrtRecords`** with manual I/O:

```js
const fs = require('fs');
const zlib = require('zlib');
const { parseMrtRecords } = require('@bgpkit/parser');

const raw = zlib.gunzipSync(fs.readFileSync('updates.20250101.0000.gz'));

for (const { elems } of parseMrtRecords(raw)) {
  for (const elem of elems) {
    if (elem.type === 'ANNOUNCE') {
      console.log(elem.prefix, elem.next_hop, elem.as_path);
    }
  }
}
```

### 3. MRT file analysis (browser)

Parse MRT files dropped or fetched in the browser. Uses the web entry point
which requires calling `init()` before any parsing.

**Live demo**: [mrt-explorer.labs.bgpkit.com](https://mrt-explorer.labs.bgpkit.com/)

```js
import { init, parseMrtRecords } from '@bgpkit/parser/web';

await init();

// Fetch and decompress a gzip-compressed MRT file
const res = await fetch('https://data.ris.ripe.net/rrc00/2025.01/updates.20250101.0000.gz');
const stream = res.body.pipeThrough(new DecompressionStream('gzip'));
const raw = new Uint8Array(await new Response(stream).arrayBuffer());

for (const { elems } of parseMrtRecords(raw)) {
  for (const elem of elems) {
    console.log(elem.type, elem.prefix, elem.as_path);
  }
}
```

### 4. Individual BGP UPDATE parsing (all platforms)

Parse a single BGP UPDATE message extracted from a pcap capture or received
via an API. The message must include the 16-byte marker, 2-byte length, and
1-byte type header.

```js
const { parseBgpUpdate } = require('@bgpkit/parser');

const elems = parseBgpUpdate(bgpMessageBytes);
for (const elem of elems) {
  console.log(elem.type, elem.prefix, elem.next_hop, elem.as_path);
}
```

## Memory Considerations

MRT parsing requires the **entire decompressed file** in memory as a
`Uint8Array` before parsing begins. `parseMrtRecords` then iterates
record-by-record, so parsed output stays small — but the raw bytes remain in
memory throughout.

| File type | Typical decompressed size | Practical? |
|---|---|---|
| MRT updates (5-min) | 20–200 MB | Yes, all platforms |
| MRT updates (15-min) | 50–500 MB | Yes, Node.js; may exceed browser/Worker limits |
| Full RIB dump | 500 MB – 2+ GB | Not recommended — use the native Rust crate |

BMP and BGP UPDATE messages are small (KB-sized) and have no memory concerns.

## API Reference

### Core parsing functions (all platforms)

| Function | Input | Output | Use case |
|---|---|---|---|
| `parseOpenBmpMessage(data)` | `Uint8Array` | `BmpParsedMessage \| null` | Real-time BMP streams |
| `parseBmpMessage(data, timestamp)` | `Uint8Array`, `number` | `BmpParsedMessage` | Real-time BMP streams |
| `parseBgpUpdate(data)` | `Uint8Array` | `BgpElem[]` | Individual BGP messages |
| `parseMrtRecords(data)` | `Uint8Array` | `Generator<MrtRecordResult>` | MRT file analysis |
| `parseMrtRecord(data)` | `Uint8Array` | `MrtRecordResult \| null` | MRT file analysis (low-level) |
| `resetMrtParser()` | — | `void` | Clear state between MRT files |

### Node.js I/O helpers

| Function | Input | Output | Description |
|---|---|---|---|
| `streamMrtFrom(pathOrUrl)` | `string` | `AsyncGenerator<MrtRecordResult>` | Fetch + decompress + stream-parse |
| `openMrt(pathOrUrl)` | `string` | `Promise<Buffer>` | Fetch + decompress only |

These use Node.js `fs`, `http`, `https`, and `zlib` modules. They are **not
available** in bundler, browser, or Cloudflare Worker environments.

### BMP message types

BMP parsing functions return a discriminated union on the `type` field. All
types include `timestamp` and `openBmpHeader` (present only via
`parseOpenBmpMessage`).

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

| Platform | Import | Parsing | I/O helpers | Kafka |
|---|---|---|---|---|
| Node.js (CJS) | `require('@bgpkit/parser')` | Yes | Yes | Yes (via kafkajs) |
| Node.js (ESM) | `import from '@bgpkit/parser'` | Yes | No | Yes (via kafkajs) |
| Bundler (webpack, vite) | `import from '@bgpkit/parser'` | Yes | No | No |
| Browser | `import from '@bgpkit/parser/web'` | Yes (after `init()`) | No | No |
| Cloudflare Workers | `import from '@bgpkit/parser/web'` | Yes (after `init()`) | No | No (no TCP sockets) |

### Web target

The web target requires calling `init()` before any parsing functions:

```js
import { init, parseOpenBmpMessage } from '@bgpkit/parser/web';

await init();
const msg = parseOpenBmpMessage(data);
```

You can pass a custom URL to the `.wasm` file if the default path doesn't work:

```js
await init(new URL('./bgpkit_parser_bg.wasm', import.meta.url));
```

### Cloudflare Workers

Use the `@bgpkit/parser/web` entry point. Workers cannot connect to Kafka
(no raw TCP sockets), so BMP/BGP data must arrive via HTTP requests.

Workers have a 128 MB memory limit on the free plan (up to 256 MB on paid),
which is sufficient for MRT updates files and individual message parsing, but
not for full RIB dumps.

## Versioning

The npm package version tracks the Rust crate's minor version. For Rust crate
version `0.X.Y`, the npm package is published as `0.X.Z` where `Z` increments
independently for JS-specific changes.

## Building from Source

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/):
  `cargo install wasm-pack`
- The `wasm32-unknown-unknown` target:
  `rustup target add wasm32-unknown-unknown`

### Build

```sh
# From the repository root — builds all targets (nodejs, bundler, web)
bash src/wasm/build.sh

# Output is in pkg/
cd pkg && npm publish
```

To build a single target:

```sh
wasm-pack build --target nodejs --no-default-features --features wasm
```
