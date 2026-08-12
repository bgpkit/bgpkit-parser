# Early RIPE RIS MRT fixtures

Unless noted otherwise, these files are retained byte-for-byte as regression
fixtures for historical MRT formats. Tests must use these local copies and
must not download data.

| File | Original source | Size | SHA-256 |
| --- | --- | ---: | --- |
| `rrc00/1999.09/updates.19990903.1041.gz` | <https://data.ris.ripe.net/rrc00/1999.09/updates.19990903.1041.gz> | 382,767 bytes | `26c64b77122482f8f60d91b8b321fefdeb113fd0af57cbba53cc132fa0b28975` |
| `rrc00/1999.12/updates.19991214.1621.gz` | <https://data.ris.ripe.net/rrc00/1999.12/updates.19991214.1621.gz> | 305,644 bytes | `8e4b0ed378464f68397d60e2775a310117b23ffe6dc7f79fbb0d5039a743c91e` |
| `rrc00/2000.01/updates.20000102.2014.gz` | <https://data.ris.ripe.net/rrc00/2000.01/updates.20000102.2014.gz> | 32,455 bytes | `e15119ada15bed7b524f9cef91a2ae1002f28e65360b32a8f40531d76fdc0a5f` |
| `rrc00/2000.01/bview.20000111.0032.gz` | <https://data.ris.ripe.net/rrc00/2000.01/bview.20000111.0032.gz> | 2,932,008 bytes | `1456fd58551374c6222c3f2f88606bac327ffdb3bdd931dd150fabae68800009` |
| `rrc00/2000.03/updates.20000325.0345.gz` | <https://data.ris.ripe.net/rrc00/2000.03/updates.20000325.0345.gz> | 28,128 bytes | `f5acf0a6d5bc2610c05350c75b2eaf4e3bc100701836e6cf004fbcf635f3fc78` |
| `rrc01/2000.11/updates.20001104.0124.gz` | <https://data.ris.ripe.net/rrc01/2000.11/updates.20001104.0124.gz> | 8,815 bytes | `89985919e4a1f8726b1e1a6391b12ce1c5576f9d066d84e729414d922e4052f1` |
| `rrc03/2010.02/updates.20100227.1600.first-796-records.gz` | <https://data.ris.ripe.net/rrc03/2010.02/updates.20100227.1600.gz> | 12,953 bytes | `cca59f359818c3dacc18014e50ce3b656cbc4d86be97cbfbdd6771047a2e71fd` |
| `rrc15/2010.02/updates.20100227.1600.gz` | <https://data.ris.ripe.net/rrc15/2010.02/updates.20100227.1600.gz> | 213,264 bytes | `68e03340030f3c44a9eb3dd22baa7739f910466cd82ee844fc8c0147f86b7028` |
| `rrc15/2010.02/updates.20100227.1610.gz` | <https://data.ris.ripe.net/rrc15/2010.02/updates.20100227.1610.gz> | 36,818 bytes | `6e30980401c92509dcb72a4a2e288f0b79a858b467538d290b93478b06e5313f` |

The September and December 1999 and January 2000 update files use deprecated
MRT Type 5 BGP records. The December fixture includes one BGP OPEN and one BGP
NOTIFY record. The March 2000 fixture contains two damaged MRT boundaries and
is retained to test opt-in framing recovery. The bview uses early TABLE_DUMP records that batch many entries
and declare each physical record four bytes shorter than the bytes written by
the historical MRT producer.
The rrc01 update file contains shortened BGP4MP state-change and OPEN records
produced by historical Zebra corruption.

The rrc03 fixture is a deterministic prefix derived from the original archive:
it contains the first 796 complete MRT records (88,636 uncompressed bytes) and
ends immediately after the last BGP state 7 record in the source file. It was
recompressed with `gzip -n`. The rrc03 and rrc15 fixtures contain Quagga's
implementation-specific `Clearing` (7) and `Deleted` (8) BGP FSM states.

The historical September 1999 `view.*` files, including
`view.19990906.1223.gz`, are plain-text Zebra `show ip bgp` output rather than
MRT data, so they are intentionally not included as parser fixtures.

The fixtures and their integration tests are excluded from the crates.io
package to avoid increasing the published archive.
