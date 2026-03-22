# RouteViews Kafka Stream — Node.js Example

> **Experimental**: The `@bgpkit/parser` npm package is experimental. The API
> surface, output format, and build process may change in future releases.

This example consumes the [RouteViews](http://www.routeviews.org/routeviews/)
real-time Kafka stream of OpenBMP messages and parses them into JSON using
[`@bgpkit/parser`](https://www.npmjs.com/package/@bgpkit/parser).

## Prerequisites

- [Node.js](https://nodejs.org/) >= 18

## Run

```sh
cd examples/wasm/kafka-openbmp-stream
npm install
npm start
```

## Configuration

Edit the constants at the top of `kafka-stream.js`:

| Variable | Default | Description |
|---|---|---|
| `BROKER` | `stream.routeviews.org:9092` | Kafka broker address |
| `TOPIC_PATTERN` | `/^routeviews\.amsix\..+\.bmp_raw$/` | Regex to filter Kafka topics |
| `GROUP_ID` | `bgpkit-parser-nodejs-example` | Kafka consumer group ID |

### Selecting collectors

Topics follow the naming pattern `routeviews.<collector>.<peer_asn>.bmp_raw`:

```js
// All AMS-IX topics
const TOPIC_PATTERN = /^routeviews\.amsix\..+\.bmp_raw$/;

// A specific collector/peer
const TOPIC_PATTERN = /^routeviews\.amsix\.ams\.6777\.bmp_raw$/;

// All collectors (high volume!)
const TOPIC_PATTERN = /^routeviews\..+\.bmp_raw$/;
```

## Output

Each line is a JSON object representing a parsed BMP message. RouteMonitoring
messages include an `elems` array of BGP elements (announcements/withdrawals).

## How it works

1. `@bgpkit/parser` is a WebAssembly build of bgpkit-parser's BMP/BGP parsing
   core, published as an npm package.
2. `parseOpenBmpMessage(bytes)` accepts raw Kafka message bytes (an OpenBMP
   header + BMP frame) and returns a parsed JavaScript object.
3. [KafkaJS](https://kafka.js.org/) is used to consume messages from the
   RouteViews broker.
