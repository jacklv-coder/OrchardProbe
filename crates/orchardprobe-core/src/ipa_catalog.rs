//! Deterministic, bounded inventory of declared standard-bundle IPA code.
//!
//! The root app and every supported framework or extension contribute their
//! exact `CFBundleExecutable` declaration. Lowercase dylib names remain a
//! bounded convention only within the same closed ancestry. Every returned
//! code object has passed the bounded Mach-O parser; unsupported bundle types
//! and arbitrary executable-looking resources are outside this coverage.

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
use crate::ipa_bundle::{
    IpaNestedBundle, IpaNestedBundleMetadataError, IpaNestedBundleRole,
    inspect_ipa_nested_bundle_metadata_from_inventory,
};
use crate::ipa_code::{IpaMainExecutableError, inspect_ipa_main_executable_with_inventory};
use crate::macho::{MachOParseError, MachOReport, parse_macho};

/// Maximum distinct declared or in-scope dylib candidates, including main.
pub const MAX_IPA_CODE_CANDIDATES: usize = 256;
/// Maximum aggregate declared compressed and uncompressed candidate bytes.
pub const MAX_IPA_CODE_CANDIDATE_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// The discovery coverage represented by an IPA code inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaCodeInventoryCoverage {
    /// Root and supported nested declarations plus in-scope lowercase dylibs.
    DeclaredStandardBundles,
}

/// One candidate confirmed as Mach-O by the bounded parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaCodeObject {
    pub path: String,
    pub role: BinaryRole,
    pub entry: IpaEntry,
    pub macho: MachOReport,
}

/// Stable reason a selected entry was not classified as code.
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

/// Deterministic result for the current declared-standard-bundle scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaCodeInventory {
    pub coverage: IpaCodeInventoryCoverage,
    pub app: IpaAppMetadata,
    pub nested_bundles: Vec<IpaNestedBundle>,
    pub binaries: Vec<IpaCodeObject>,
    pub rejected_candidates: Vec<IpaRejectedCodeCandidate>,
}

/// Failure before a deterministic candidate inventory can be returned.
#[derive(Debug, Error)]
pub enum IpaCodeInventoryError {
    #[error("root IPA executable inspection failed: {0}")]
    MainExecutable(#[from] IpaMainExecutableError),

    #[error("nested IPA bundle metadata inspection failed: {0}")]
    NestedBundleMetadata(#[from] IpaNestedBundleMetadataError),

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

/// Build the bounded declared-standard-bundle IPA code inventory.
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
    let nested_metadata = inspect_ipa_nested_bundle_metadata_from_inventory(
        &mut reader,
        archive_size,
        main.app.clone(),
        &authoritative_inventory,
    )?;
    let candidates = discover_candidates(
        &authoritative_inventory,
        &main.app.executable_path,
        &nested_metadata.bundles,
    );
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
        if let Some(reason) = candidate_size_rejection(&entry) {
            rejected_candidates.push(rejected(path, role, reason));
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
        ensure_candidate_inventory_unchanged(&path, &authoritative_inventory, &copied.inventory)?;

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
        coverage: IpaCodeInventoryCoverage::DeclaredStandardBundles,
        app: main.app,
        nested_bundles: nested_metadata.bundles,
        binaries,
        rejected_candidates,
    })
}

fn discover_candidates(
    inventory: &IpaInventory,
    main_path: &str,
    nested_bundles: &[IpaNestedBundle],
) -> BTreeMap<String, (BinaryRole, IpaEntry)> {
    let mut candidates = BTreeMap::new();

    // Filename conventions are the weakest signal and are inserted first.
    for entry in &inventory.entries {
        if entry.kind == IpaEntryKind::File && is_in_scope_dylib(inventory, &entry.path) {
            candidates.insert(
                entry.path.clone(),
                (BinaryRole::DynamicLibrary, entry.clone()),
            );
        }
    }

    // Exact nested declarations override a `.dylib` suffix for the same path.
    for bundle in nested_bundles {
        let role = match bundle.role {
            IpaNestedBundleRole::Framework => BinaryRole::Framework,
            IpaNestedBundleRole::Extension => BinaryRole::Extension,
        };
        candidates.insert(
            bundle.executable_path.clone(),
            (role, bundle.executable_entry.clone()),
        );
    }

    // The root declaration is mandatory and always has highest precedence.
    if let Some(entry) = inventory
        .entries
        .iter()
        .find(|entry| entry.path == main_path)
    {
        candidates.insert(
            main_path.to_owned(),
            (BinaryRole::MainExecutable, entry.clone()),
        );
    }
    candidates
}

fn is_in_scope_dylib(inventory: &IpaInventory, path: &str) -> bool {
    if !path
        .rsplit('/')
        .next()
        .is_some_and(|name| name.ends_with(".dylib"))
    {
        return false;
    }
    let Some(relative) = path
        .strip_prefix(&inventory.app_root)
        .and_then(|suffix| suffix.strip_prefix('/'))
    else {
        return false;
    };
    let components = relative.split('/').collect::<Vec<_>>();
    if components.is_empty()
        || components
            .iter()
            .any(|component| is_nonempty_bundle_component(component, ".app"))
    {
        return false;
    }

    let extension_indexes = components
        .iter()
        .enumerate()
        .filter_map(|(index, component)| {
            is_nonempty_bundle_component(component, ".appex").then_some(index)
        })
        .collect::<Vec<_>>();
    if !(extension_indexes.is_empty()
        || (extension_indexes == [1] && components.first() == Some(&"PlugIns")))
    {
        return false;
    }

    components
        .iter()
        .filter(|component| is_nonempty_bundle_component(component, ".framework"))
        .count()
        <= 1
}

fn is_nonempty_bundle_component(component: &str, suffix: &str) -> bool {
    component
        .strip_suffix(suffix)
        .is_some_and(|stem| !stem.is_empty())
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

fn candidate_size_rejection(entry: &IpaEntry) -> Option<IpaCodeCandidateRejectionReason> {
    (entry.uncompressed_size > MAX_IPA_ENTRY_COPY_BYTES
        || entry.compressed_size > MAX_IPA_ENTRY_COPY_COMPRESSED_BYTES)
        .then_some(IpaCodeCandidateRejectionReason::EntryTooLarge)
}

fn ensure_candidate_inventory_unchanged(
    path: &str,
    expected: &IpaInventory,
    actual: &IpaInventory,
) -> Result<(), IpaCodeInventoryError> {
    if expected != actual {
        return Err(IpaCodeInventoryError::InventoryChanged {
            path: path.to_owned(),
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
    use std::io::{Cursor, Read, Seek, SeekFrom, Write};
    use std::ops::Range;

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::macho::PlaintextStatus;

    const APP_ROOT: &str = "Payload/Demo.app";
    const MAIN_PATH: &str = "Payload/Demo.app/Demo";
    const UNREAD_CANDIDATE: &[u8] = b"candidate payload must stay unread";

    struct DenyRangeReader {
        inner: Cursor<Vec<u8>>,
        denied: Range<u64>,
    }

    impl DenyRangeReader {
        fn new(bytes: Vec<u8>, needle: &[u8]) -> Self {
            let start = bytes
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("find denied fixture payload") as u64;
            Self {
                inner: Cursor::new(bytes),
                denied: start..start + needle.len() as u64,
            }
        }
    }

    impl Read for DenyRangeReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let start = self.inner.position();
            if self.denied.contains(&start) {
                return Err(std::io::Error::other(
                    "optional candidate payload was read before metadata failed",
                ));
            }
            self.inner.read(buffer)
        }
    }

    impl Seek for DenyRangeReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    fn options() -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o644)
    }

    fn stored_options() -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
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

    fn info_plist(identifier: &str, executable: &str) -> Vec<u8> {
        format!(
            "<plist><dict>\
             <key>CFBundleIdentifier</key><string>{identifier}</string>\
             <key>CFBundleVersion</key><string>1</string>\
             <key>CFBundleExecutable</key><string>{executable}</string>\
             </dict></plist>"
        )
        .into_bytes()
    }

    fn make_inventory_ipa() -> Vec<u8> {
        let macho = minimal_arm64_macho();
        let invalid = invalid_macho();
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let files = vec![
            (
                "Payload/Demo.app/Info.plist",
                info_plist("com.example.demo", "Demo"),
            ),
            (MAIN_PATH, macho.clone()),
            (
                "Payload/Demo.app/Frameworks/DemoKit.framework/Info.plist",
                info_plist("com.example.demo.kit", "RenamedKit.dylib"),
            ),
            (
                "Payload/Demo.app/Frameworks/DemoKit.framework/RenamedKit.dylib",
                macho.clone(),
            ),
            (
                "Payload/Demo.app/Frameworks/DemoKit.framework/DemoKit",
                macho.clone(),
            ),
            (
                "Payload/Demo.app/PlugIns/Share.appex/Info.plist",
                info_plist("com.example.demo.share", "ShareWorker.dylib"),
            ),
            (
                "Payload/Demo.app/PlugIns/Share.appex/ShareWorker.dylib",
                macho.clone(),
            ),
            ("Payload/Demo.app/PlugIns/Share.appex/Share", macho.clone()),
            (
                "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework/Info.plist",
                info_plist("com.example.demo.nested", "NestedWorker"),
            ),
            (
                "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework/NestedWorker",
                macho.clone(),
            ),
            (
                "Payload/Demo.app/Frameworks/A.framework/Info.plist",
                info_plist("com.example.demo.a", "AWorker"),
            ),
            (
                "Payload/Demo.app/Frameworks/A.framework/AWorker",
                macho.clone(),
            ),
            ("Payload/Demo.app/Frameworks/libHelper.dylib", macho.clone()),
            (
                "Payload/Demo.app/PlugIns/Share.appex/libExtension.dylib",
                macho.clone(),
            ),
            ("Payload/Demo.app/Assets/fake.dylib", b"not Mach-O".to_vec()),
            ("Payload/Demo.app/Frameworks/libInvalid.dylib", invalid),
            (
                "Payload/Demo.app/Watch/Watch.app/libWatch.dylib",
                macho.clone(),
            ),
            ("Payload/Demo.app/Nested.app/libNested.dylib", macho.clone()),
            (
                "Payload/Demo.app/Extensions/Other.appex/libOther.dylib",
                macho.clone(),
            ),
            (
                "Payload/Demo.app/Frameworks/A.framework/Frameworks/B.framework/libDeep.dylib",
                macho.clone(),
            ),
            ("Payload/Demo.app/libUpper.DYLIB", macho),
        ];
        for (path, bytes) in files {
            writer.start_file(path, options()).expect("start file");
            writer.write_all(&bytes).expect("write file");
        }
        writer.finish().expect("finish IPA").into_inner()
    }

    fn make_nested_metadata_failure_ipa(nested_plist: Option<&[u8]>) -> Vec<u8> {
        let macho = minimal_arm64_macho();
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (path, bytes) in [
            (
                "Payload/Demo.app/Info.plist",
                info_plist("com.example.demo", "Demo"),
            ),
            (MAIN_PATH, macho.clone()),
            ("Payload/Demo.app/Frameworks/F.framework/F", macho.clone()),
        ] {
            writer.start_file(path, options()).expect("start file");
            writer.write_all(&bytes).expect("write file");
        }
        writer
            .start_file("Payload/Demo.app/Assets/late.dylib", stored_options())
            .expect("start denied candidate");
        writer
            .write_all(UNREAD_CANDIDATE)
            .expect("write denied candidate");
        if let Some(bytes) = nested_plist {
            writer
                .start_file(
                    "Payload/Demo.app/Frameworks/F.framework/Info.plist",
                    options(),
                )
                .expect("start nested plist");
            writer.write_all(bytes).expect("write nested plist");
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
            IpaCodeInventoryCoverage::DeclaredStandardBundles
        );
        assert_eq!(
            first
                .nested_bundles
                .iter()
                .map(|bundle| {
                    (
                        bundle.executable_path.as_str(),
                        bundle.role,
                        bundle.executable_name.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (
                    "Payload/Demo.app/Frameworks/A.framework/AWorker",
                    IpaNestedBundleRole::Framework,
                    "AWorker",
                ),
                (
                    "Payload/Demo.app/Frameworks/DemoKit.framework/RenamedKit.dylib",
                    IpaNestedBundleRole::Framework,
                    "RenamedKit.dylib",
                ),
                (
                    "Payload/Demo.app/PlugIns/Share.appex/ShareWorker.dylib",
                    IpaNestedBundleRole::Extension,
                    "ShareWorker.dylib",
                ),
                (
                    "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework/NestedWorker",
                    IpaNestedBundleRole::Framework,
                    "NestedWorker",
                ),
            ]
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
                    "Payload/Demo.app/Frameworks/A.framework/AWorker",
                    BinaryRole::Framework,
                ),
                (
                    "Payload/Demo.app/Frameworks/DemoKit.framework/RenamedKit.dylib",
                    BinaryRole::Framework,
                ),
                (
                    "Payload/Demo.app/Frameworks/libHelper.dylib",
                    BinaryRole::DynamicLibrary,
                ),
                (
                    "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework/NestedWorker",
                    BinaryRole::Framework,
                ),
                (
                    "Payload/Demo.app/PlugIns/Share.appex/ShareWorker.dylib",
                    BinaryRole::Extension,
                ),
                (
                    "Payload/Demo.app/PlugIns/Share.appex/libExtension.dylib",
                    BinaryRole::DynamicLibrary,
                ),
            ]
        );
        for excluded in [
            "Payload/Demo.app/Frameworks/DemoKit.framework/DemoKit",
            "Payload/Demo.app/PlugIns/Share.appex/Share",
            "Payload/Demo.app/Watch/Watch.app/libWatch.dylib",
            "Payload/Demo.app/Nested.app/libNested.dylib",
            "Payload/Demo.app/Extensions/Other.appex/libOther.dylib",
            "Payload/Demo.app/Frameworks/A.framework/Frameworks/B.framework/libDeep.dylib",
            "Payload/Demo.app/libUpper.DYLIB",
        ] {
            assert!(
                first.binaries.iter().all(|binary| binary.path != excluded)
                    && first
                        .rejected_candidates
                        .iter()
                        .all(|candidate| candidate.path != excluded),
                "out-of-scope path must be omitted: {excluded}"
            );
        }
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
                    "Payload/Demo.app/Frameworks/libInvalid.dylib",
                    IpaCodeCandidateRejectionReason::InvalidMacho,
                ),
            ]
        );
    }

    #[test]
    fn discovery_uses_declarations_precedence_and_closed_dylib_ancestry() {
        let main_path = "Payload/Demo.app/Demo.dylib";
        let declared_path = "Payload/Demo.app/Frameworks/F.framework/Declared.dylib";
        let entries = vec![
            entry(main_path, 1),
            entry(declared_path, 1),
            entry("Payload/Demo.app/Frameworks/F.framework/F", 1),
            entry("Payload/Demo.app/libRoot.dylib", 1),
            entry("Payload/Demo.app/PlugIns/E.appex/libExt.dylib", 1),
            entry("Payload/Demo.app/Frameworks/F.framework/libWithin.dylib", 1),
            entry("Payload/Demo.app/Nested.app/libNested.dylib", 1),
            entry("Payload/Demo.app/Other/E.appex/libOther.dylib", 1),
            entry(
                "Payload/Demo.app/Frameworks/F.framework/G.framework/libDeep.dylib",
                1,
            ),
            entry("Payload/Demo.app/libUpper.DYLIB", 1),
            IpaEntry {
                path: "Payload/Demo.app/libDirectory.dylib".to_owned(),
                kind: IpaEntryKind::Directory,
                compressed_size: 0,
                uncompressed_size: 0,
                crc32: 0,
            },
        ];
        let inventory = IpaInventory {
            archive_size: 1,
            app_root: APP_ROOT.to_owned(),
            entry_count: entries.len(),
            file_count: entries.len() - 1,
            directory_count: 1,
            total_compressed_size: (entries.len() - 1) as u64,
            total_uncompressed_size: (entries.len() - 1) as u64,
            entries,
        };
        let declared_entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == declared_path)
            .expect("declared entry")
            .clone();
        let nested = vec![nested_bundle(
            IpaNestedBundleRole::Framework,
            "Payload/Demo.app/Frameworks/F.framework",
            "Declared.dylib",
            declared_entry,
        )];

        let candidates = discover_candidates(&inventory, main_path, &nested);
        assert_eq!(
            candidates
                .iter()
                .map(|(path, (role, _))| (path.as_str(), *role))
                .collect::<Vec<_>>(),
            vec![
                (main_path, BinaryRole::MainExecutable),
                (declared_path, BinaryRole::Framework),
                (
                    "Payload/Demo.app/Frameworks/F.framework/libWithin.dylib",
                    BinaryRole::DynamicLibrary,
                ),
                (
                    "Payload/Demo.app/PlugIns/E.appex/libExt.dylib",
                    BinaryRole::DynamicLibrary,
                ),
                ("Payload/Demo.app/libRoot.dylib", BinaryRole::DynamicLibrary,),
            ]
        );
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

        let too_large = entry(
            "Payload/Demo.app/libTooLarge.dylib",
            MAX_IPA_ENTRY_COPY_BYTES + 1,
        );
        assert_eq!(
            candidate_size_rejection(&too_large),
            Some(IpaCodeCandidateRejectionReason::EntryTooLarge)
        );

        let expected = IpaInventory {
            archive_size: 1,
            app_root: APP_ROOT.to_owned(),
            entry_count: 0,
            file_count: 0,
            directory_count: 0,
            total_compressed_size: 0,
            total_uncompressed_size: 0,
            entries: vec![],
        };
        let mut changed = expected.clone();
        changed.archive_size += 1;
        assert!(matches!(
            ensure_candidate_inventory_unchanged(MAIN_PATH, &expected, &changed),
            Err(IpaCodeInventoryError::InventoryChanged { .. })
        ));
    }

    #[test]
    fn nested_metadata_failures_precede_optional_candidate_payload_reads() {
        let missing = make_nested_metadata_failure_ipa(None);
        let missing_size = missing.len() as u64;
        let missing_error = inspect_ipa_code_inventory(
            DenyRangeReader::new(missing, UNREAD_CANDIDATE),
            missing_size,
        )
        .expect_err("missing nested plist must fail");
        assert!(
            matches!(
                &missing_error,
                IpaCodeInventoryError::NestedBundleMetadata(
                    IpaNestedBundleMetadataError::MissingInfoPlist { .. }
                )
            ),
            "unexpected error: {missing_error:?}"
        );

        let malformed = make_nested_metadata_failure_ipa(Some(b"not a plist"));
        let malformed_size = malformed.len() as u64;
        let malformed_error = inspect_ipa_code_inventory(
            DenyRangeReader::new(malformed, UNREAD_CANDIDATE),
            malformed_size,
        )
        .expect_err("malformed nested plist must fail");
        assert!(
            matches!(
                &malformed_error,
                IpaCodeInventoryError::NestedBundleMetadata(
                    IpaNestedBundleMetadataError::InvalidInfoPlist { .. }
                )
            ),
            "unexpected error: {malformed_error:?}"
        );
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

    fn nested_bundle(
        role: IpaNestedBundleRole,
        bundle_root: &str,
        executable_name: &str,
        executable_entry: IpaEntry,
    ) -> IpaNestedBundle {
        IpaNestedBundle {
            role,
            bundle_root: bundle_root.to_owned(),
            info_plist_path: format!("{bundle_root}/Info.plist"),
            info_plist_entry: entry(&format!("{bundle_root}/Info.plist"), 1),
            bundle_identifier: "com.example.fixture".to_owned(),
            bundle_version: "1".to_owned(),
            short_version: None,
            executable_name: executable_name.to_owned(),
            executable_path: executable_entry.path.clone(),
            executable_entry,
        }
    }
}
