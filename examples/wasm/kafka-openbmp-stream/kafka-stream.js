'use strict';

/**
 * Route-views Kafka stream consumer using @bgpkit/parser.
 *
 * Prerequisites:
 *   1. Install Node.js dependencies:
 *        npm install
 *   2. Run:
 *        npm start
 *
 * The RouteViews Kafka stream is publicly accessible at stream.routeviews.org:9092.
 * Topics follow the pattern: routeviews.<collector>.<peer>.bmp_raw
 * Each message value is an OpenBMP-wrapped BMP frame (binary).
 */

const { Kafka, logLevel } = require('kafkajs');
const { parseOpenBmpMessage } = require('@bgpkit/parser');

// ── Configuration ────────────────────────────────────────────────────────────

const BROKER = 'stream.routeviews.org:9092';

// Regex filter applied to Kafka topic names. Adjust to taste:
//   All collectors:      /^routeviews\..+\.bmp_raw$/
//   Specific collector:  /^routeviews\.amsix\.ams\..+\.bmp_raw$/
const TOPIC_PATTERN = /^routeviews\.amsix\..+\.bmp_raw$/;

// Consumer group ID. Change this to start reading from the latest offset
// in a fresh group, or reuse a group to resume from where you left off.
const GROUP_ID = 'bgpkit-parser-nodejs-example';

// ── Main ─────────────────────────────────────────────────────────────────────

async function run() {
  const kafka = new Kafka({
    clientId: 'bgpkit-parser-example',
    brokers: [BROKER],
    logLevel: logLevel.NOTHING,
  });

  const admin = kafka.admin();
  await admin.connect();
  const allTopics = await admin.listTopics();
  await admin.disconnect();

  const topics = allTopics.filter((t) => TOPIC_PATTERN.test(t));
  if (topics.length === 0) {
    console.error(`No topics matching ${TOPIC_PATTERN} found on ${BROKER}`);
    process.exit(1);
  }
  process.stderr.write(`Subscribed to ${topics.length} topics on ${BROKER}\n`);

  const consumer = kafka.consumer({
    groupId: GROUP_ID,
    sessionTimeout: 30000,
  });
  await consumer.connect();

  for (const topic of topics) {
    await consumer.subscribe({ topic, fromBeginning: false });
  }

  await consumer.run({
    eachMessage: async ({ message }) => {
      if (!message.value) return;

      let msg;
      try {
        msg = parseOpenBmpMessage(message.value);
      } catch {
        return;
      }

      if (!msg) return;

      console.log(JSON.stringify(msg));
    },
  });
}

run().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
