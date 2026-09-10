# RIS Live frame fixtures

Captured RIS Live `ris_message` frames, one JSON object per line, used by
`tests/rislive_frames.rs`. Tests must use these local copies and must not
download data.

The fixture guards a failure mode that is easy to reintroduce: `RisMessage::msg`
is a flattened `Option`, so a body-level deserialisation failure looks exactly
like a frame without a body, and the frame's routes disappear without an error.
These frames pin the forms the live stream actually sends, in particular
RFC 2545 next hops that RIS Live comma-joins into one string
(`"next_hop": "2001:7f8:4::3:2be1:1,fe80::3efd:feff:feee:62ca"`).

| File | Original source | Size | SHA-256 |
| --- | --- | ---: | --- |
| `ris-live-frames.jsonl` | RIS Live full stream, <https://ris-live.ripe.net/v1/stream/?format=json>, captured 2026-09-10 | 3,801 bytes | `a2930691c91a81ebfea6854c0b8c469e0ef2c6e6a5dfa5954b1f1ac4f0dfe5ca` |

## What the tests require of the file

- one frame per message type this crate decodes: UPDATE, KEEPALIVE, OPEN,
  NOTIFICATION, STATE
- at least one UPDATE whose announcement next hop is a comma-joined pair
- `raw` present on the UPDATE frames, so the JSON and raw-bytes parsers can be
  compared against each other

Tests select frames by content, never by line position, so the file can be
extended freely.

## Regenerating

Capture a sample of the full stream:

```sh
timeout 20 curl -s "https://ris-live.ripe.net/v1/stream/?format=json&client=<client-id>" -o capture.jsonl
```

`timeout` kills curl mid-frame, so the capture ends with a partial line: drop it
to keep the file valid NDJSON. Keep one frame per form a test asserts on rather
than the whole capture, and update the size and SHA-256 above when the file
changes.
