# Local files only example

In this example, we create a new MRT parsing project that processes
only the files on the local filesystem.

We will disable the remote processing features altogether so that we won't bring in irrelevant dependencies.

In the `Cargo.toml` file, we will add the following lines:

```toml
bgpkit-parser = { path = "../..", default-features = false, features = ["parser"] }
```

You should replace the `path` with the `version` that supports local-only processing.

The `default-features = false` line disables the default features, and the `features = ["parser"]` line enables the
parser feature only. By default, `bgpkit-parser` will have both `parser` and `remote` features enabled.

The following content is the `cargo tree` output for this example. You can see that `oneio` library that handles data IO
has only compression-related dependencies without any remote processing dependencies.

```text
local_only v0.1.0 (/Users/mingwei/Warehouse/BGPKIT/bgpkit-git/bgpkit-parser/examples/local_only)
└── bgpkit-parser v0.10.10 (/Users/mingwei/Warehouse/BGPKIT/bgpkit-git/bgpkit-parser)
    ├── bitflags v2.6.0
    │   └── serde v1.0.210
    ├── bytes v1.7.1
    ├── chrono v0.4.38
    │   ├── iana-time-zone v0.1.60
    │   │   └── core-foundation-sys v0.8.7
    │   └── num-traits v0.2.19
    │       [build-dependencies]
    │       └── autocfg v1.3.0
    ├── env_logger v0.11.5
    │   ├── anstream v0.6.15
    │   │   ├── anstyle v1.0.8
    │   │   ├── anstyle-parse v0.2.5
    │   │   │   └── utf8parse v0.2.2
    │   │   ├── anstyle-query v1.1.1
    │   │   ├── colorchoice v1.0.2
    │   │   ├── is_terminal_polyfill v1.70.1
    │   │   └── utf8parse v0.2.2
    │   ├── anstyle v1.0.8
    │   ├── env_filter v0.1.2
    │   │   ├── log v0.4.22
    │   │   └── regex v1.10.6
    │   │       ├── aho-corasick v1.1.3
    │   │       │   └── memchr v2.7.4
    │   │       ├── memchr v2.7.4
    │   │       ├── regex-automata v0.4.7
    │   │       │   ├── aho-corasick v1.1.3 (*)
    │   │       │   ├── memchr v2.7.4
    │   │       │   └── regex-syntax v0.8.4
    │   │       └── regex-syntax v0.8.4
    │   ├── humantime v2.1.0
    │   └── log v0.4.22
    ├── ipnet v2.10.0
    ├── itertools v0.13.0
    │   └── either v1.13.0
    ├── log v0.4.22
    ├── num_enum v0.7.3
    │   └── num_enum_derive v0.7.3 (proc-macro)
    │       ├── proc-macro-crate v3.2.0
    │       │   └── toml_edit v0.22.20
    │       │       ├── indexmap v2.5.0
    │       │       │   ├── equivalent v1.0.1
    │       │       │   └── hashbrown v0.14.5
    │       │       ├── toml_datetime v0.6.8
    │       │       └── winnow v0.6.18
    │       ├── proc-macro2 v1.0.86
    │       │   └── unicode-ident v1.0.13
    │       ├── quote v1.0.37
    │       │   └── proc-macro2 v1.0.86 (*)
    │       └── syn v2.0.77
    │           ├── proc-macro2 v1.0.86 (*)
    │           ├── quote v1.0.37 (*)
    │           └── unicode-ident v1.0.13
    ├── oneio v0.17.0
    │   ├── bzip2 v0.4.4
    │   │   ├── bzip2-sys v0.1.11+1.0.8
    │   │   │   └── libc v0.2.158
    │   │   │   [build-dependencies]
    │   │   │   ├── cc v1.1.18
    │   │   │   │   └── shlex v1.3.0
    │   │   │   └── pkg-config v0.3.30
    │   │   └── libc v0.2.158
    │   ├── dotenvy v0.15.7
    │   ├── flate2 v1.0.33
    │   │   ├── crc32fast v1.4.2
    │   │   │   └── cfg-if v1.0.0
    │   │   └── miniz_oxide v0.8.0
    │   │       └── adler2 v2.0.0
    │   └── thiserror v1.0.63
    │       └── thiserror-impl v1.0.63 (proc-macro)
    │           ├── proc-macro2 v1.0.86 (*)
    │           ├── quote v1.0.37 (*)
    │           └── syn v2.0.77 (*)
    └── regex v1.10.6 (*)
```

To run this example, `cd` into `examples/local_only` and run `cargo run --release`.