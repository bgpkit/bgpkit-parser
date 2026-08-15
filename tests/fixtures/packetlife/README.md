# PacketLife capture fixtures

Packet captures from the PacketLife.net capture archive, mirrored at
<https://github.com/epiecs/packetlife-backup>. Retained byte-for-byte as
regression fixtures. Tests must use these local copies and must not download
data.

| File | Original name | Size | SHA-256 |
| --- | --- | ---: | --- |
| `bgp_orf_prefix_advertisement.pcapng.cap` | `bgp orf prefix advertisement.pcapng.cap` | 336 bytes | `18a4270082b58f5ee31d8c3a8cac09bf031d3e2c056d9b7436e4bf392370bc9f` |

The ORF capture contains a single TCP segment on port 179 carrying two BGP
messages: a KEEPALIVE followed by a ROUTE-REFRESH (RFC 2918) with an RFC 5291
ORF prefix advertisement (when-to-refresh IMMEDIATE, ORF type 128 — the
pre-standard Address Prefix ORF — with 19 bytes of entries).
