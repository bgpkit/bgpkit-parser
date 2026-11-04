use md5::Digest;
use std::fs::{create_dir_all, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Once;

/// List of files to download for testing and their md5 hashes. Hashes are used to avoid
/// re-downloading files on every run. Additionally, they also protect against tests using partial
/// data due to an incomplete downloads on an earlier run.
///
/// When adding a new file, the hash can easily be obtained by using `md5sum [file name]`. Checks
/// are done using the `md5` crate to be compatible with systems where the `md5sum` command is not
/// available.
pub const DATA_SOURCES: &[(&str, &str)] = &[
    (
        "https://spaces.bgpkit.org/parser/rib-example-small.bz2",
        "fb06ea281008c19e479d91433c99c599",
    ),
    (
        "https://spaces.bgpkit.org/parser/update-example.gz",
        "6338710910b20d7c2335b22e0ed112a0",
    ),
];

/// Returns the path of the specified test data file from [DATA_SOURCES]. Upon the first call to
/// this function, any missing data files are also downloaded.
pub fn test_data_file(name: &str) -> PathBuf {
    static ONCE: Once = Once::new();
    ONCE.call_once(download_test_data);

    test_data_dir().join(name)
}

/// Returns the path named by an environment variable pointing at a local corpus, or `None`.
///
/// Used for opt-in benchmarks against real archives, which are neither checked in nor downloaded
/// by the benchmark itself.
#[allow(dead_code)] // only the internals benchmark reads opt-in corpora; bench_main includes this module too
pub fn env_corpus(var: &str) -> Option<PathBuf> {
    let value = std::env::var_os(var)?;
    if value.is_empty() {
        return None;
    }
    let path = PathBuf::from(value);
    if path.is_file() {
        Some(path)
    } else {
        eprintln!("ignoring {var}: {} is not a file", path.display());
        None
    }
}

/// Downloads any missing test data files listed in [DATA_SOURCES]. If an error is encountered
/// during this process the program panics with a (hopefully) helpful error.
pub fn download_test_data() {
    let test_data = test_data_dir();

    if let Err(e) = create_dir_all(&test_data) {
        panic!(
            "Unable to create test data folder {}: {}",
            test_data.display(),
            e
        )
    }

    for &(url, checksum) in DATA_SOURCES {
        let data_file_path = match url.rsplit_once('/') {
            Some((_, file_name)) => test_data.join(file_name),
            None => test_data.join(url),
        };

        // Check if file is already downloaded and matches out expected checksum
        if data_file_path.exists() {
            let computed_checksum = match md5_checksum_for_file(&data_file_path) {
                Ok(v) => v,
                Err(err) => panic!(
                    "Unable to compute md5 checksum for test file {}: {}",
                    data_file_path.display(),
                    err
                ),
            };

            if format!("{computed_checksum:x}").as_str() == checksum {
                continue;
            }
        }

        println!(
            "Downloading test file {} from {}",
            data_file_path.display(),
            url
        );

        match download_file(url, &data_file_path) {
            Ok(download_checksum) => {
                if format!("{download_checksum:x}").as_str() != checksum {
                    println!("MD5 checksum for downloaded file ({download_checksum:x}) does not match expected checksum ({checksum:?}).");
                    println!("Perhaps a different file is being used?");

                    panic!("Unable to find expected test data file")
                }
            }
            Err(e) => panic!(
                "Failed to download test file {}: {}",
                data_file_path.display(),
                e
            ),
        }
    }
}

fn md5_checksum_for_file<P: AsRef<Path>>(path: P) -> io::Result<Digest> {
    let mut context = md5::Context::new();
    let mut file = File::open(path)?;

    io::copy(&mut file, &mut context)?;
    Ok(context.finalize())
}

/// Download `url` to `target`, returning the md5 of the raw (still compressed) bytes.
///
/// The download goes to a sibling `.part` file that is renamed only after the checksum is
/// computed, so an interrupted run leaves nothing a later run would accept as complete. The
/// checksum is computed over the bytes as downloaded: decompressing first would both mismatch the
/// published hashes and truncate the file being read.
fn download_file<P: AsRef<Path>>(url: &str, target: P) -> io::Result<Digest> {
    let target = target.as_ref();
    let mut part = target.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);

    let part_str = part
        .to_str()
        .ok_or_else(|| io::Error::other("test data path is not valid UTF-8"))?;
    oneio::download(url, part_str).map_err(io::Error::other)?;

    let digest = md5_checksum_for_file(&part)?;
    std::fs::rename(&part, target)?;
    Ok(digest)
}

pub fn test_data_dir() -> PathBuf {
    locate_target_dir().join("test_data")
}

/// The cargo target directory this benchmark was built into.
///
/// Cargo exports `CARGO_TARGET_TMPDIR` (`<target>/tmp`) for benchmark targets, which keeps the
/// lookup correct when `build.target-dir` or `CARGO_TARGET_DIR` moves artifacts out of the source
/// tree. Falling back to the historical "walk up until a `target/` directory appears" keeps older
/// toolchains working.
pub fn locate_target_dir() -> PathBuf {
    if let Some(tmp_dir) = option_env!("CARGO_TARGET_TMPDIR") {
        let tmp_dir = PathBuf::from(tmp_dir);
        if let Some(target_dir) = tmp_dir.parent() {
            return target_dir.to_path_buf();
        }
    }

    // CARGO_MANIFEST_DIR is an absolute path that is always present at compile time when building
    // with cargo. We know the target directory is most likely in the same directory as the manifest
    // or in a parent directory in the case of a normal workspace.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut search_path = manifest.as_path();
    loop {
        let check_dir = search_path.join("target");
        if check_dir.is_dir() {
            return check_dir;
        }

        // Move to parent directory and try again
        if let Some(parent) = search_path.parent() {
            search_path = parent;
        } else {
            // If we still can't find it, then it is likely defined by a workspace in some strange
            // location. At this point, we just give up as it will be near impossible to find.
            panic!(
                "Unable to find cargo target directory (set CARGO_TARGET_DIR, or use a toolchain \
                 that exports CARGO_TARGET_TMPDIR for benchmark targets)"
            )
        }
    }
}
