/**
 * Runtime literal checks for the golden fixtures.
 *
 * TypeScript widens JSON string literals to `string`, so literal-union values
 * (discriminator tags, enum-like strings) are verified here instead.
 * Run by `npm run check` after `tsc --noEmit`.
 */
'use strict';

const path = require('path');

const fixtures = {};
for (const name of [
  'attribute_values',
  'bgp_elem_announce',
  'bgp_elem_withdraw',
  'bgp_validation_warnings',
  'ris_live_raw_full',
]) {
  fixtures[name] = require(path.join(__dirname, '..', 'fixtures', `${name}.json`));
}

let failures = 0;
function check(cond, msg) {
  if (!cond) {
    failures += 1;
    console.error(`FAIL: ${msg}`);
  }
}

// Elem type discriminators
check(fixtures.bgp_elem_announce.type === 'ANNOUNCE', 'announce elem type');
check(fixtures.bgp_elem_withdraw.type === 'WITHDRAW', 'withdraw elem type');
for (const [i, elem] of fixtures.ris_live_raw_full.elems.entries()) {
  check(
    elem.type === 'ANNOUNCE' || elem.type === 'WITHDRAW',
    `ris_live elems[${i}].type`
  );
}

// Origin values
check(fixtures.attribute_values.values[0].Origin === 'IGP', 'Origin literal');

// Community string variants
const communities = fixtures.attribute_values.values.find(
  (v) => typeof v === 'object' && 'Communities' in v
).Communities;
check(communities.includes('NoExport'), 'Community NoExport literal');

// Attribute flags are pipe-joined bitflag names
for (const [i, attr] of fixtures.attribute_values.attributes.entries()) {
  check(typeof attr.flag === 'string' && attr.flag.length > 0, `flag[${i}]`);
}

// Validation warning discriminator tags
const warningTags = new Set(
  fixtures.bgp_validation_warnings.map((w) => Object.keys(w)[0])
);
check(warningTags.has('AttributeFlagsError'), 'AttributeFlagsError tag');
check(warningTags.has('MissingWellKnownAttribute'), 'MissingWellKnownAttribute tag');
check(warningTags.has('MalformedNlri'), 'MalformedNlri tag');

// AttributeValue variant tags present in the fixtures (unit variants are
// bare strings, the rest are single-key objects)
const variantTags = new Set(
  fixtures.attribute_values.values.map((v) =>
    typeof v === 'string' ? v : Object.keys(v)[0]
  )
);
for (const tag of [
  'Origin',
  'AsPath',
  'As4Path',
  'NextHop',
  'MultiExitDiscriminator',
  'LocalPreference',
  'OnlyToCustomer',
  'AtomicAggregate',
  'Aggregator',
  'As4Aggregator',
  'Communities',
  'ExtendedCommunities',
  'Ipv6AddressSpecificExtendedCommunities',
  'LargeCommunities',
  'OriginatorId',
  'Clusters',
  'MpReachNlri',
  'MpUnreachNlri',
  'Development',
  'Raw',
  'Deprecated',
  'Unknown',
]) {
  check(variantTags.has(tag), `AttributeValue variant ${tag}`);
}

if (failures > 0) {
  console.error(`\n${failures} fixture literal check(s) failed`);
  process.exit(1);
}
console.log('fixture literal checks passed');
