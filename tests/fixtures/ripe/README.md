# Early RIPE RIS MRT fixtures

These files are retained byte-for-byte as regression fixtures for historical
MRT formats. Tests must use these local copies and must not download data.

| File | Original source | Size | SHA-256 |
| --- | --- | ---: | --- |
| `rrc00/1999.09/updates.19990903.1041.gz` | <https://data.ris.ripe.net/rrc00/1999.09/updates.19990903.1041.gz> | 382,767 bytes | `26c64b77122482f8f60d91b8b321fefdeb113fd0af57cbba53cc132fa0b28975` |
| `rrc00/2000.01/updates.20000102.2014.gz` | <https://data.ris.ripe.net/rrc00/2000.01/updates.20000102.2014.gz> | 32,455 bytes | `e15119ada15bed7b524f9cef91a2ae1002f28e65360b32a8f40531d76fdc0a5f` |
| `rrc00/2000.01/bview.20000111.0032.gz` | <https://data.ris.ripe.net/rrc00/2000.01/bview.20000111.0032.gz> | 2,932,008 bytes | `1456fd58551374c6222c3f2f88606bac327ffdb3bdd931dd150fabae68800009` |
| `rrc01/2000.11/updates.20001104.0124.gz` | <https://data.ris.ripe.net/rrc01/2000.11/updates.20001104.0124.gz> | 8,815 bytes | `89985919e4a1f8726b1e1a6391b12ce1c5576f9d066d84e729414d922e4052f1` |

The September 1999 and January 2000 update files use deprecated MRT Type 5 BGP
records. The bview uses early TABLE_DUMP records that batch many entries and
declare each physical record four bytes shorter than the bytes written by the
historical MRT producer.
The rrc01 update file contains shortened BGP4MP state-change and OPEN records
produced by historical Zebra corruption.

The historical September 1999 `view.*` files, including
`view.19990906.1223.gz`, are plain-text Zebra `show ip bgp` output rather than
MRT data, so they are intentionally not included as parser fixtures.

The fixtures and their integration test are excluded from the crates.io
package to avoid increasing the published archive by about 3.2 MiB.
