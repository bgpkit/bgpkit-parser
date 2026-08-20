/**
 * Type-drift guard (compile-time structural check).
 *
 * The JSON fixtures in ../fixtures/ are serialized from the Rust models by
 * `cargo test --features ts-rs,rislive --test test_wasm_type_fixtures`. This
 * file asserts that those fixtures are structurally assignable to the
 * TypeScript definitions shipped with the package (../../js/index.d.ts and
 * the ts-rs generated bindings). If a Rust change alters the serde output —
 * added/renamed/removed fields, number<->string flips — `tsc --noEmit`
 * fails here.
 *
 * JSON module imports widen string literals to `string`, so literal-union
 * fields (e.g. `type: "ANNOUNCE" | "WITHDRAW"`) are compared through the
 * `Widen<T>` helper; the literal values themselves are checked at runtime by
 * verify.cjs.
 *
 * Run with: npm install && npm run check
 */
import type {
  AsPath,
  AsPathWire,
  Attribute,
  Attributes,
  AttributeValue,
  BgpElem,
  BgpValidationWarning,
  RisLiveRawFull,
} from '../../js/index';

import attributeValues from '../fixtures/attribute_values.json';
import bgpElemAnnounce from '../fixtures/bgp_elem_announce.json';
import bgpElemWithdraw from '../fixtures/bgp_elem_withdraw.json';
import bgpValidationWarnings from '../fixtures/bgp_validation_warnings.json';
import risLiveRawFull from '../fixtures/ris_live_raw_full.json';

/** Recursively widen literal-union leaves so JSON inference can match. */
type Widen<T> = T extends string
  ? string
  : T extends number
    ? number
    : T extends boolean
      ? boolean
      : T extends (infer U)[]
        ? Widen<U>[]
        : T extends object
          ? { [K in keyof T]: Widen<T[K]> }
          : T;

// ── Generated attribute surface ──────────────────────────────────────────────

export const attributes: Widen<Attributes> = attributeValues.attributes;
export const attributeValuesTyped: Widen<AttributeValue>[] =
  attributeValues.values;

// Every fixture entry must narrow to a distinct known variant tag.
const originAttr = attributeValuesTyped.find((v) => typeof v === 'object' && 'Origin' in v);
if (originAttr === undefined) throw new Error('fixture missing Origin variant');

const largeCommunities = attributeValuesTyped.find(
  (v) => typeof v === 'object' && 'LargeCommunities' in v
);
if (largeCommunities === undefined)
  throw new Error('fixture missing LargeCommunities variant');

const mpReach = attributeValuesTyped.find((v) => typeof v === 'object' && 'MpReachNlri' in v);
if (mpReach === undefined) throw new Error('fixture missing MpReachNlri variant');

// AsPath payloads inside AttributeValue use the same wire encoding as the
// hand-written AsPath type on BgpElem.
const asPathAttr = attributeValuesTyped.find((v) => typeof v === 'object' && 'AsPath' in v);
if (asPathAttr === undefined) throw new Error('fixture missing AsPath variant');
const asPathFromAttr: Widen<AsPathWire> = (asPathAttr as { AsPath: Widen<AsPathWire> }).AsPath;

// ── Hand-written elem surface ────────────────────────────────────────────────

export const elemAnnounce: Widen<BgpElem> = bgpElemAnnounce;
export const elemWithdraw: Widen<BgpElem> = bgpElemWithdraw;
const asPath: Widen<AsPath> | null = elemAnnounce.as_path;
const asPathWire: Widen<AsPathWire> | null = asPath;
if (asPathWire !== null && typeof asPathWire[0] !== 'number')
  throw new Error('unexpected AsPathWire shape');

// ── Warnings ─────────────────────────────────────────────────────────────────

export const warnings: Widen<BgpValidationWarning>[] = bgpValidationWarnings;
const missingAttr = warnings.find((w) => typeof w === 'object' && 'MissingWellKnownAttribute' in w);
if (missingAttr === undefined)
  throw new Error('fixture missing MissingWellKnownAttribute variant');

// ── End-to-end RIS Live raw result ───────────────────────────────────────────

export const risLiveResult: Widen<RisLiveRawFull> = risLiveRawFull;
if (risLiveResult.elems.length === 0)
  throw new Error('RIS Live fixture has no elems');
if (risLiveResult.attributes.length === 0)
  throw new Error('RIS Live fixture has no attributes');

// Attribute flags serialize as strings like "OPTIONAL | TRANSITIVE".
const flag: string = risLiveResult.attributes[0].flag;
export const _flag = flag;
