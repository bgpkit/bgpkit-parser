# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Build Commands
- `cargo build` - Build the library
- `cargo build --features cli` - Build with CLI features
- `cargo build --no-default-features` - Build with minimal features
- `cargo build --examples` - Build all examples

### Testing
- `cargo test` - Run basic tests
- `cargo test --all-features` - Run tests with all features enabled

### Code Quality
- `cargo clippy --all-targets --all-features -- -D warnings` - Run linting (used in CI)
- `cargo fmt` - Format code

### CLI Usage
- `cargo install --path . --features cli` - Install CLI locally
- `cargo run --features cli -- <file>` - Run CLI directly with cargo

## Architecture Overview

BGPKIT Parser is a Rust library for parsing MRT (Multi-Threaded Routing Toolkit), BGP, and BMP messages. The codebase is structured around two main data representations:

### Core Data Structures

1. **MrtRecord**: Raw, unmodified MRT information preserving the original format structure
2. **BgpElem**: Processed, per-prefix BGP information that's MRT-format-agnostic and easier to analyze

### Module Structure

- `src/models/` - Core data structures (BgpElem, MrtRecord, BGP attributes, communities, etc.)
- `src/parser/` - Main parsing logic organized by protocol:
  - `mrt/` - MRT format parsing (BGP4MP, TableDump, TableDumpV2)
  - `bgp/` - BGP message parsing and attributes
  - `bmp/` - BGP Monitoring Protocol parsing
  - `rislive/` - Real-time RIS Live websocket parsing
- `src/encoder/` - MRT file encoding capabilities
- `src/bin/` - CLI implementation

### Parser Flow

The parser processes MRT records through this hierarchy:
1. MrtRecord → MrtMessage (BGP4MP/TableDump/TableDumpV2)
2. BGP messages → BgpUpdateMessage with path attributes and NLRI
3. Elementor converts MRT records to BgpElem objects for easier analysis

### Key Features

- **Multi-format support**: BGP4MP, TableDump V1/V2, BMP, RIS Live
- **Filtering system**: Built-in filters for prefix, AS path, peer info, timestamps
- **Streaming capable**: Handle remote files, compressed data (bzip2, gzip)
- **Real-time processing**: WebSocket and Kafka stream support

### Feature Flags

- `default = ["parser", "rustls"]` - Standard parsing with TLS
- `cli` - Command-line interface
- `rislive` - RIS Live websocket support  
- `serde` - Serialization support
- `local` - Local files only (no remote)
- `native-tls`/`rustls` - TLS backend choice

### RFC Compliance

The parser implements most BGP, MRT, BMP, and BGP Communities RFCs. See the README for the complete list of supported RFCs.

## Development Notes

- Uses `oneio` for unified file I/O (local/remote, compressed/uncompressed)
- Extensive use of iterators for memory-efficient processing
- `Filter` enum provides type-safe filtering capabilities
- Error handling through custom `ParserError` and `ParserErrorWithBytes` types
- BGP attributes are parsed in dedicated modules under `parser/bgp/attributes/`

## Development Workflow Preferences

### Code Quality
- Always run `cargo fmt` after finishing each round of code editing
- Run clippy checks before committing changes
- **IMPORTANT**: Before committing any changes, run all relevant tests and checks from `.github/workflows/rust.yaml`:
  - `cargo fmt --check` - Check code formatting
  - `cargo build --no-default-features` - Build with no features
  - `cargo build` - Build with default features
  - `cargo test` - Run all tests
  - `cargo clippy --all-features -- -D warnings` - Run clippy on all features
  - `cargo clippy --no-default-features` - Run clippy with no features
  - Fix any issues before committing

### Documentation
- Update CHANGELOG.md when implementing fixes or features
- Add changes to the "Unreleased changes" section with appropriate subsections (Feature flags, Bug fixes, Code improvements, etc.)
- **IMPORTANT**: When changing lib.rs documentation, always run `cargo readme > README.md` and commit the README.md changes with a simple message "docs: update README.md from lib.rs documentation"

### Git Operations
- Do not prompt for git operations unless explicitly requested by the user
- Let the user initiate commits and other git actions when they're ready
- **IMPORTANT**: When pushing commits, always list all commits to be pushed first using `git log --oneline origin/[branch]..HEAD` and ask for user confirmation

### Commit Messages and Changelog Writing Guidelines
- **Keep language factual and professional**: Avoid subjective or exaggerated descriptive words
- **Avoid words like**: "comprehensive", "extensive", "amazing", "powerful", "robust", "excellent", etc.
- **Use objective language**: State what was added, changed, or fixed without editorial commentary
- **Good examples**: "Added RPKI documentation", "Fixed validation logic", "Updated error handling"
- **Poor examples**: "Added comprehensive RPKI documentation", "Significantly improved validation", "Enhanced robust error handling"
- **Exception**: Technical precision words are acceptable when factually accurate (e.g., "efficient lookup", "atomic operation")

### Release Process
When preparing a release, follow these steps in order:
1. **Update CHANGELOG.md**:
   - Move all "Unreleased changes" to a new version section with the release version number and date
   - Add any missing changes that were implemented but not documented
   - Follow the existing format: `## v[VERSION] - YYYY-MM-DD`
2. **Update Cargo.toml**:
   - Update the `version` field to the new version number
   - Follow semantic versioning (major.minor.patch)
3. **Review changes before committing**:
   - Run `git diff` to show all changes
   - Ask the user to confirm the diff is correct
   - Check for accidental version mismatches or unwanted changelog entries
4. **Commit the release preparation**:
   - After user confirmation, commit with message: `release: prepare v[VERSION]`
5. **Create and push git tag**:
   - Create a new git tag with the version number: `git tag v[VERSION]`
   - Push commits first: `git push origin [branch-name]`
   - Then push the tag: `git push origin v[VERSION]`
