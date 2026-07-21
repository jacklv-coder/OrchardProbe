//! Deterministic, bounded discovery of conventional IPA code candidates.
//!
//! Bundle naming conventions select candidates only. Every returned code
//! object has also passed the bounded Mach-O parser. This first inventory is
//! intentionally incomplete for framework or extension bundles whose
//! `CFBundleExecutable` differs from the conventional bundle stem.

use std::collections::BTreeMap;
use std::io::{Read, Seek};

use serde::Serialize;
use thiserror::Error;

use crate::BinaryRole;
use crate::ipa::{
    IpaEntry, IpaEntryKind, IpaEntryReadError, IpaInventory, MAX_IPA_ENTRY_COPY_BYTES,
    MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES, copy_ipa_entry_bounded,
};
use crate::ipa_app::IpaAppMetadata;
use crate::ipa_code::{IpaMainExecutableError, inspect_ipa_main_executable_with_inventory};
use crate::macho::{MachOParseError, MachOReport, parse_macho};

/// Maximum distinct conventional code candidates, including the main entry.
pub const MAX_IPA_CODE_CANDIDATES: usize = 256;
/// Maximum aggregate declared compressed and uncompressed candidate bytes.
pub const MAX_IPA_CODE_CANDIDATE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The discovery coverage represented by an IPA code inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaCodeInventoryCoverage {
    /// Root main plus conventional framework, dylib, and extension candidates.
    ConventionalCandidates,
}

/// One candidate confirmed as Mach-O by the bounded parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaCodeObject {
    pub path: String,
    pub role: BinaryRole,
    pub entry: IpaEntry,
    pub macho: MachOReport,
}

/// Stable reason a convention-selected entry was not classified as code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaCodeCandidateRejectionReason {
    EntryTooLarge,
    NotMacho,
    InvalidMacho,
}

/// One visible candidate rejection; omission is never presented as success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaRejectedCodeCandidate {
    pub path: String,
    pub role: BinaryRole,
    pub reason: IpaCodeCandidateRejectionReason,
}

/// Deterministic result for the current convention-based discovery scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaCodeInventory {
    pub coverage: IpaCodeInventoryCoverage,
    pub app: IpaAppMetadata,
    pub binaries: Vec<IpaCodeObject>,
    pub rejected_candidates: Vec<IpaRejectedCodeCandidate>,
}

/// Failure before a deterministic candidate inventory can be returned.
#[derive(Debug, Error)]
pub enum IpaCodeInventoryError {
    #[error("root IPA executable inspection failed: {0}")]
    MainExecutable(#[from] IpaMainExecutableError),

    #[error("IPA exposes {actual} code candidates; maximum is {maximum}")]
    TooManyCandidates { actual: usize, maximum: usize },

    #[error("candidate {field} byte total overflowed")]
    CandidateSizeOverflow { field: &'static str },

    #[error("aggregate candidate {field} bytes {actual} exceed the {maximum}-byte limit")]
    CandidateAggregateTooLarge {
        field: &'static str,
        actual: u64,
        maximum: u64,
    },

    #[error("could not create an anonymous temporary file for candidate `{path}`: {source}")]
    TemporaryFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("bounded copy of candidate `{path}` failed: {source}")]
    EntryCopy {
        path: String,
        #[source]
        source: IpaEntryReadError,
    },

    #[error("IPA inventory changed while inspecting candidate `{path}`")]
    InventoryChanged { path: String },
}

/// Build the current bounded, convention-based IPA code candidate inventory.
///
/// The reader must be the secured regular-file handle used to obtain
/// `archive_size`. Candidates are copied and parsed sequentially. The source
/// IPA is never modified, and Mach-O metadata never proves plaintext.
pub fn inspect_ipa_code_inventory<R: Read + Seek>(
    mut reader: R,
    archive_size: u64,
) -> Result<IpaCodeInventory, IpaCodeInventoryError> {
    let (main, authoritative_inventory) =
        inspect_ipa_main_executable_with_inventory(&mut reader, archive_size)?;
    let candidates = discover_candidates(&authoritative_inventory, &main.app.executable_path);
    validate_candidate_set(&candidates)?;

    let mut binaries = vec![IpaCodeObject {
        path: main.entry.path.clone(),
        role: BinaryRole::MainExecutable,
        entry: main.entry,
        macho: main.macho,
    }];
    let mut rejected_candidates = Vec::new();

    for (path, (role, entry)) in candidates {
        if role == BinaryRole::MainExecutable {
            continue;
        }
        if entry.uncompressed_size > MAX_IPA_ENTRY_COPY_BYTES
            || entry.compressed_size > MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES
        {
            rejected_candidates.push(rejected(
                path,
                role,
                IpaCodeCandidateRejectionReason::EntryTooLarge,
            ));
            continue;
        }

        let mut temporary =
            tempfile::tempfile().map_err(|source| IpaCodeInventoryError::TemporaryFile {
                path: path.clone(),
                source,
            })?;
        let copied = copy_ipa_entry_bounded(
            &mut reader,
            archive_size,
            &path,
            MAX_IPA_ENTRY_COPY_BYTES,
            &mut temporary,
        )
        .map_err(|source| IpaCodeInventoryError::EntryCopy {
            path: path.clone(),
            source,
        })?;
        if copied.inventory != authoritative_inventory {
            return Err(IpaCodeInventoryError::InventoryChanged { path });
        }

        match parse_macho(&mut temporary) {
            Ok(macho) => binaries.push(IpaCodeObject {
                path: path.clone(),
                role,
                entry,
                macho,
            }),
            Err(source) => {
                rejected_candidates.push(rejected(path, role, classify_macho_rejection(&source)))
            }
        }
    }

    binaries.sort_by(|left, right| left.path.cmp(&right.path));
    rejected_candidates.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(IpaCodeInventory {
        coverage: IpaCodeInventoryCoverage::ConventionalCandidates,
        app: main.app,
        binaries,
        rejected_candidates,
    })
}

fn discover_candidates(
    inventory: &IpaInventory,
    main_path: &str,
) -> BTreeMap<String, (BinaryRole, IpaEntry)> {
    let mut candidates = BTreeMap::new();
    for entry in &inventory.entries {
        if entry.kind != IpaEntryKind::File {
            continue;
        }
        let role = if entry.path == main_path {
            Some(BinaryRole::MainExecutable)
        } else if is_conventional_bundle_executable(&entry.path, ".framework") {
            Some(BinaryRole::Framework)
        } else if entry
            .path
            .rsplit('/')
            .next()
            .is_some_and(|name| name.ends_with(".dylib"))
        {
            Some(BinaryRole::DynamicLibrary)
        } else if is_conventional_bundle_executable(&entry.path, ".appex") {
            Some(BinaryRole::Extension)
        } else {
            None
        };
        if let Some(role) = role {
            candidates.insert(entry.path.clone(), (role, entry.clone()));
        }
    }
    candidates
}

fn is_conventional_bundle_executable(path: &str, bundle_suffix: &str) -> bool {
    let mut components = path.rsplit('/');
    let Some(file_name) = components.next() else {
        return false;
    };
    let Some(bundle_name) = components.next() else {
        return false;
    };
    bundle_name
        .strip_suffix(bundle_suffix)
        .is_some_and(|stem| !stem.is_empty() && file_name == stem)
}

fn validate_candidate_set(
    candidates: &BTreeMap<String, (BinaryRole, IpaEntry)>,
) -> Result<(), IpaCodeInventoryError> {
    if candidates.len() > MAX_IPA_CODE_CANDIDATES {
        return Err(IpaCodeInventoryError::TooManyCandidates {
            actual: candidates.len(),
            maximum: MAX_IPA_CODE_CANDIDATES,
        });
    }
    validate_candidate_total(candidates, "compressed", |entry| entry.compressed_size)?;
    validate_candidate_total(candidates, "uncompressed", |entry| entry.uncompressed_size)
}

fn validate_candidate_total(
    candidates: &BTreeMap<String, (BinaryRole, IpaEntry)>,
    field: &'static str,
    value: impl Fn(&IpaEntry) -> u64,
) -> Result<(), IpaCodeInventoryError> {
    let total = candidates.values().try_fold(0u64, |total, (_, entry)| {
        total
            .checked_add(value(entry))
            .ok_or(IpaCodeInventoryError::CandidateSizeOverflow { field })
    })?;
    if total > MAX_IPA_CODE_CANDIDATE_BYTES {
        return Err(IpaCodeInventoryError::CandidateAggregateTooLarge {
            field,
            actual: total,
            maximum: MAX_IPA_CODE_CANDIDATE_BYTES,
        });
    }
    Ok(())
}

fn classify_macho_rejection(source: &MachOParseError) -> IpaCodeCandidateRejectionReason {
    match source {
        MachOParseError::FileTooSmall { .. } | MachOParseError::UnsupportedMagic { .. } => {
            IpaCodeCandidateRejectionReason::NotMacho
        }
        _ => IpaCodeCandidateRejectionReason::InvalidMacho,
    }
}

fn rejected(
    path: String,
    role: BinaryRole,
    reason: IpaCodeCandidateRejectionReason,
) -> IpaRejectedCodeCandidate {
    IpaRejectedCodeCandidate { path, role, reason }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::macho::PlaintextStatus;

    const APP_ROOT: &str = "Payload/Demo.app";
    const MAIN_PATH: &str = "Payload/Demo.app/Demo";

    fn options() -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644)
    }

    fn minimal_arm64_macho() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
        bytes.extend_from_slice(&0x0100_000cu32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }

    fn invalid_macho() -> Vec<u8> {
        let mut bytes = minimal_arm64_macho();
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&8u32.to_le_bytes());
        bytes
    }

    fn info_plist() -> &'static [u8] {
        br#"<plist><dict>
<key>CFBundleIdentifier</key><string>com.example.demo</string>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleExecutable</key><string>Demo</string>
</dict></plist>"#
    }

    fn make_inventory_ipa() -> Vec<u8> {
        let macho = minimal_arm64_macho();
        let invalid = invalid_macho();
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for directory in [
            "Payload/",
            "Payload/Demo.app/",
            "Payload/Demo.app/Frameworks/",
            "Payload/Demo.app/Frameworks/DemoKit.framework/",
            "Payload/Demo.app/PlugIns/",
            "Payload/Demo.app/PlugIns/Share.appex/",
            "Payload/Demo.app/PlugIns/Share.appex/Frameworks/",
            "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework/",
        ] {
            writer
                .add_directory(directory, options())
                .expect("add directory");
        }
        let files: [(&str, &[u8]); 8] = [
            ("Payload/Demo.app/Info.plist", info_plist()),
            (MAIN_PATH, &macho),
            (
                "Payload/Demo.app/Frameworks/DemoKit.framework/DemoKit",
                &macho,
            ),
            ("Payload/Demo.app/Frameworks/libHelper.dylib", &macho),
            ("Payload/Demo.app/PlugIns/Share.appex/Share", &macho),
            (
                "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework/Nested",
                &macho,
            ),
            ("Payload/Demo.app/Assets/fake.dylib", b"not Mach-O"),
            (
                "Payload/Demo.app/Frameworks/Broken.framework/Broken",
                &invalid,
            ),
        ];
        for (path, bytes) in files {
            writer.start_file(path, options()).expect("start file");
            writer.write_all(bytes).expect("write file");
        }
        writer.finish().expect("finish IPA").into_inner()
    }

    #[test]
    fn inventories_confirmed_roles_and_visible_rejections_deterministically() {
        let bytes = make_inventory_ipa();
        let first = inspect_ipa_code_inventory(Cursor::new(&bytes), bytes.len() as u64)
            .expect("inspect code inventory");
        let second = inspect_ipa_code_inventory(Cursor::new(&bytes), bytes.len() as u64)
            .expect("repeat code inventory");

        assert_eq!(first, second);
        assert_eq!(
            first.coverage,
            IpaCodeInventoryCoverage::ConventionalCandidates
        );
        assert_eq!(
            first
                .binaries
                .iter()
                .map(|binary| (binary.path.as_str(), binary.role))
                .collect::<Vec<_>>(),
            vec![
                (MAIN_PATH, BinaryRole::MainExecutable),
                (
                    "Payload/Demo.app/Frameworks/DemoKit.framework/DemoKit",
                    BinaryRole::Framework,
                ),
                (
                    "Payload/Demo.app/Frameworks/libHelper.dylib",
                    BinaryRole::DynamicLibrary,
                ),
                (
                    "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework/Nested",
                    BinaryRole::Framework,
                ),
                (
                    "Payload/Demo.app/PlugIns/Share.appex/Share",
                    BinaryRole::Extension,
                ),
            ]
        );
        assert!(first.binaries.iter().all(|binary| {
            binary
                .macho
                .slices
                .iter()
                .all(|slice| slice.plaintext_status == PlaintextStatus::NotProven)
        }));
        assert_eq!(
            first
                .rejected_candidates
                .iter()
                .map(|candidate| (candidate.path.as_str(), candidate.reason))
                .collect::<Vec<_>>(),
            vec![
                (
                    "Payload/Demo.app/Assets/fake.dylib",
                    IpaCodeCandidateRejectionReason::NotMacho,
                ),
                (
                    "Payload/Demo.app/Frameworks/Broken.framework/Broken",
                    IpaCodeCandidateRejectionReason::InvalidMacho,
                ),
            ]
        );
    }

    #[test]
    fn discovery_requires_exact_conventional_names_and_regular_files() {
        let inventory = IpaInventory {
            archive_size: 1,
            app_root: APP_ROOT.to_owned(),
            entry_count: 4,
            file_count: 3,
            directory_count: 1,
            total_compressed_size: 3,
            total_uncompressed_size: 3,
            entries: vec![
                entry(MAIN_PATH, 1),
                entry("Payload/Demo.app/F.framework/Other", 1),
                entry("Payload/Demo.app/E.appex/E/Nested", 1),
                IpaEntry {
                    path: "Payload/Demo.app/libDirectory.dylib".to_owned(),
                    kind: IpaEntryKind::Directory,
                    compressed_size: 0,
                    uncompressed_size: 0,
                    crc32: 0,
                },
            ],
        };

        let candidates = discover_candidates(&inventory, MAIN_PATH);
        assert_eq!(candidates.len(), 1);
        assert!(candidates.contains_key(MAIN_PATH));
    }

    #[test]
    fn candidate_count_and_aggregate_limits_fail_closed() {
        let too_many = (0..=MAX_IPA_CODE_CANDIDATES)
            .map(|index| {
                let entry = entry(&format!("{APP_ROOT}/lib{index}.dylib"), 1);
                (entry.path.clone(), (BinaryRole::DynamicLibrary, entry))
            })
            .collect();
        assert!(matches!(
            validate_candidate_set(&too_many),
            Err(IpaCodeInventoryError::TooManyCandidates { .. })
        ));

        let oversized = entry(
            "Payload/Demo.app/libHuge.dylib",
            MAX_IPA_CODE_CANDIDATE_BYTES + 1,
        );
        let candidates = BTreeMap::from([(
            oversized.path.clone(),
            (BinaryRole::DynamicLibrary, oversized),
        )]);
        assert!(matches!(
            validate_candidate_set(&candidates),
            Err(IpaCodeInventoryError::CandidateAggregateTooLarge {
                field: "compressed",
                ..
            })
        ));
    }

    #[test]
    fn malformed_archive_propagates_before_candidate_discovery() {
        let malformed = b"not an IPA";
        assert!(matches!(
            inspect_ipa_code_inventory(Cursor::new(malformed), malformed.len() as u64),
            Err(IpaCodeInventoryError::MainExecutable(_))
        ));
    }

    fn entry(path: &str, size: u64) -> IpaEntry {
        IpaEntry {
            path: path.to_owned(),
            kind: IpaEntryKind::File,
            compressed_size: size,
            uncompressed_size: size,
            crc32: 0,
        }
    }
}
