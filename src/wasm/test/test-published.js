#!/usr/bin/env node
'use strict';

/**
 * Test script for the published @bgpkit/parser npm package.
 *
 * Usage:
 *   cd src/wasm/test
 *   npm install @bgpkit/parser
 *   node test-published.js
 */

const https = require('https');
const { parseOpenBmpMessage, parseBmpMessage, parseBgpUpdate, parseMrtFile } = require('@bgpkit/parser');

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    console.log(`  ✓ ${msg}`);
    passed++;
  } else {
    console.error(`  ✗ ${msg}`);
    failed++;
  }
}

// ── Test 1: parseOpenBmpMessage (PeerDownNotification) ───────────────────────

function testOpenBmpPeerDown() {
  console.log('\n[1/5] parseOpenBmpMessage (PeerDownNotification)');

  // Complete OpenBMP PeerDownNotification from the bgpkit-parser test suite
  const hex =
    '4f424d500107006400000033800c6184b9c2000c602cbf4f072f3ae149d23486024bc3dadfc4000a' +
    '69732d63632d626d7031c677060bdd020a9e92be000200de2e3180df3369000000000000000000000' +
    '000000c726f7574652d76696577733500000001030000003302000000000000000000000000000000' +
    '000000000000003fda060e00000da30000000061523c36000c0e1c0200000a';

  const data = Buffer.from(hex, 'hex');
  const msg = parseOpenBmpMessage(data);

  assert(msg !== null, 'returns non-null for valid message');
  assert(msg.type === 'PeerDownNotification', `type is PeerDownNotification (got ${msg.type})`);
  assert(msg.openBmpHeader !== null, 'openBmpHeader is present');
  assert(typeof msg.openBmpHeader.routerIp === 'string', `routerIp: ${msg.openBmpHeader.routerIp}`);
  assert(msg.peerHeader !== undefined, 'peerHeader is present');
  assert(typeof msg.peerHeader.peerAsn === 'number', `peerAsn: ${msg.peerHeader.peerAsn}`);
  assert(typeof msg.reason === 'string', `reason: ${msg.reason}`);
  assert(typeof msg.timestamp === 'number', `timestamp: ${msg.timestamp}`);
}

// ── Test 2: parseOpenBmpMessage — null for non-router frames ─────────────────

function testOpenBmpNull() {
  console.log('\n[2/5] parseOpenBmpMessage (non-router frame)');

  // OpenBMP header with object_type = 0x00 (not 0x0C = router message)
  const hex =
    '4f424d500100005c000000b0800c618881530002f643fef880938d19e9d632c815d1e95a87e1000a' +
    '69732d61682d626d7031eb4de4e596b282c6a995b067df4abc8cc342f192';
  const data = Buffer.from(hex, 'hex');

  let result;
  try {
    result = parseOpenBmpMessage(data);
  } catch {
    result = 'threw';
  }
  assert(result === null, 'returns null for non-router OpenBMP frame');
}

// ── Test 3: parseBmpMessage ──────────────────────────────────────────────────

function testBmpMessage() {
  console.log('\n[3/5] parseBmpMessage');

  // Extract the BMP portion from the PeerDown test (skip the OpenBMP header).
  // The OpenBMP header is the first 100 bytes (0x64 hex in the length field).
  // BMP message starts after the OpenBMP header.
  const fullHex =
    '4f424d500107006400000033800c6184b9c2000c602cbf4f072f3ae149d23486024bc3dadfc4000a' +
    '69732d63632d626d7031c677060bdd020a9e92be000200de2e3180df3369000000000000000000000' +
    '000000c726f7574652d76696577733500000001030000003302000000000000000000000000000000' +
    '000000000000003fda060e00000da30000000061523c36000c0e1c0200000a';

  // OpenBMP header: magic(4) + ver(2) + hdr_len(2) + msg_len(4) + flags(1) +
  //   obj_type(1) + timestamp_sec(4) + timestamp_usec(4) + collector_hash(16) +
  //   admin_id_len(2) + admin_id(variable) + router_hash(16) + router_ip(4/16) +
  //   router_group_len(2) + router_group(variable) + row_count(4)
  // The msg_len field (bytes 6-9) tells us BMP message length: 0x00000033 = 51 bytes
  // The hdr_len field (bytes 4-5) tells us OpenBMP header length: 0x0064 = 100 bytes
  const fullData = Buffer.from(fullHex, 'hex');
  const hdrLen = fullData.readUInt16BE(6);
  const bmpData = fullData.subarray(hdrLen);
  const now = Date.now() / 1000;

  const msg = parseBmpMessage(bmpData, now);

  assert(msg !== null, 'returns non-null');
  assert(msg.type === 'PeerDownNotification', `type is PeerDownNotification (got ${msg.type})`);
  assert(msg.openBmpHeader === null, 'openBmpHeader is null (no OpenBMP wrapper)');
  assert(typeof msg.timestamp === 'number', 'timestamp is a number');
}

// ── Test 4: parseBgpUpdate ───────────────────────────────────────────────────

function testBgpUpdate() {
  console.log('\n[4/5] parseBgpUpdate');

  // Minimal BGP UPDATE announcing 198.51.100.0/24 via next-hop 192.0.2.1
  // 16-byte marker + 2-byte length + 1-byte type(2=UPDATE)
  // + withdrawn_len(0) + path_attr_len + attrs + NLRI
  const hex =
    'ffffffffffffffffffffffffffffffff' + // marker
    '00380200' +                           // length=56, type=UPDATE
    '0000' +                               // withdrawn routes length = 0
    '001b' +                               // total path attr length = 27
    '40010100' +                           // ORIGIN: IGP
    '40020a0202000000fd00000065' +         // AS_PATH: 253 101
    '400304c0000201' +                     // NEXT_HOP: 192.0.2.1
    '18c63364';                            // NLRI: 198.51.100.0/24

  const data = Buffer.from(hex, 'hex');
  const elems = parseBgpUpdate(data);

  assert(Array.isArray(elems), 'returns an array');
  assert(elems.length === 1, `has ${elems.length} element(s)`);

  const elem = elems[0];
  assert(elem.type === 'ANNOUNCE', `type is ANNOUNCE (got ${elem.type})`);
  assert(elem.prefix === '198.51.100.0/24', `prefix is ${elem.prefix}`);
  assert(elem.next_hop === '192.0.2.1', `next_hop is ${elem.next_hop}`);
}

// ── Test 5: parseMrtFile ─────────────────────────────────────────────────────

function testMrtFile() {
  return new Promise((resolve) => {
    console.log('\n[5/5] parseMrtFile');
    console.log('  ↓ downloading test MRT file...');

    const url = 'https://spaces.bgpkit.org/parser/update-example';

    https.get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        https.get(res.headers.location, (res2) => handleResponse(res2, resolve));
        return;
      }
      handleResponse(res, resolve);
    }).on('error', (err) => {
      console.log(`  ⚠ skipped (download failed: ${err.message})`);
      resolve();
    });
  });
}

function handleResponse(res, resolve) {
  const chunks = [];
  res.on('data', (chunk) => chunks.push(chunk));
  res.on('end', () => {
    const raw = Buffer.concat(chunks);
    console.log(`  ↓ downloaded ${(raw.length / 1024).toFixed(0)} KB`);

    const elems = parseMrtFile(raw);

    assert(Array.isArray(elems), 'returns an array');
    assert(elems.length > 0, `parsed ${elems.length} elements`);

    const announce = elems.find((e) => e.type === 'ANNOUNCE');
    if (announce) {
      assert(typeof announce.prefix === 'string', `sample prefix: ${announce.prefix}`);
      assert(typeof announce.peer_ip === 'string', `sample peer_ip: ${announce.peer_ip}`);
      assert(typeof announce.peer_asn === 'number', `sample peer_asn: ${announce.peer_asn}`);
    }

    resolve();
  });
  res.on('error', (err) => {
    console.log(`  ⚠ skipped (download failed: ${err.message})`);
    resolve();
  });
}

// ── Run ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('Testing @bgpkit/parser npm package\n');

  testOpenBmpPeerDown();
  testOpenBmpNull();
  testBmpMessage();
  testBgpUpdate();
  await testMrtFile();

  console.log(`\n${passed + failed} assertions: ${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main();
