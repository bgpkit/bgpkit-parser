# Early RIPE RIS MRT fixtures

These files are retained byte-for-byte as regression fixtures for historical
MRT formats. Tests must use these local copies and must not download data.

| File | Original source | Size | SHA-256 |
| --- | --- | ---: | --- |
| `rrc00/2000.01/updates.20000102.2014.gz` | <https://data.ris.ripe.net/rrc00/2000.01/updates.20000102.2014.gz> | 32,455 bytes | `e15119ada15bed7b524f9cef91a2ae1002f28e65360b32a8f40531d76fdc0a5f` |
| `rrc00/2000.01/bview.20000111.0032.gz` | <https://data.ris.ripe.net/rrc00/2000.01/bview.20000111.0032.gz> | 2,932,008 bytes | `1456fd58551374c6222c3f2f88606bac327ffdb3bdd931dd150fabae68800009` |

The update file uses deprecated MRT Type 5 BGP records. The bview uses early
TABLE_DUMP records that batch many entries and declare each physical record
four bytes shorter than the bytes written by the historical MRT producer.

The fixtures and their integration test are excluded from the crates.io
package to avoid increasing the published archive by about 2.8 MiB.
