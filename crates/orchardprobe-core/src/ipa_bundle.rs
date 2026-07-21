//! Bounded metadata resolution for conventional nested IPA bundles.
//!
//! This layer discovers framework bundles and direct `PlugIns/*.appex`
//! extensions from canonical IPA inventory paths. It reads each exact direct
//! `Info.plist` through the bounded entry API, reuses the root app's closed
//! XML/binary event parser, and resolves only the declared executable entry.
//! It never reads executable payload bytes or interprets archive paths as host
//! paths.

use std::collections::BTreeMap;
use std::io::{Read, Seek};

use serde::Serialize;
use thiserror::Error;

use crate::ipa::{
    IpaEntry, IpaEntryKind, IpaEntryReadError, IpaInventory, read_ipa_entry_bounded_with_inventory,
};
use crate::ipa_app::{
    IpaAppMetadata, IpaAppMetadataError, MAX_IPA_INFO_PLIST_BYTES,
    inspect_ipa_app_metadata_with_inventory, parse_info_plist,
};

/// Maximum conventional nested bundles accepted from one IPA.
pub const MAX_IPA_NESTED_BUNDLES: usize = 256;
/// Maximum aggregate declared compressed or uncompressed nested plist bytes.
pub const MAX_IPA_NESTED_INFO_PLIST_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// The supported metadata-only nested bundle roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IpaNestedBundleRole {
    Framework,
    Extension,
}

/// Validated metadata for one conventional nested bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaNestedBundle {
    pub role: IpaNestedBundleRole,
    pub bundle_root: String,
    pub info_plist_path: String,
    pub info_plist_entry: IpaEntry,
    pub bundle_identifier: String,
    pub bundle_version: String,
    pub short_version: Option<String>,
    pub executable_name: String,
    pub executable_path: String,
    pub executable_entry: IpaEntry,
}

/// Deterministic root-app and nested-bundle metadata from one IPA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaNestedBundleMetadata {
    pub app: IpaAppMetadata,
    pub bundles: Vec<IpaNestedBundle>,
}

/// Failure while discovering or resolving conventional nested bundles.
#[derive(Debug, Error)]
pub enum IpaNestedBundleMetadataError {
    #[error("root app metadata inspection failed: {0}")]
    AppMetadata(#[from] IpaAppMetadataError),

    #[error("IPA exposes {actual} nested bundles; maximum is {maximum}")]
    TooManyBundles { actual: usize, maximum: usize },

    #[error("nested bundle `{bundle_root}` has no direct Info.plist at `{path}`")]
    MissingInfoPlist { bundle_root: String, path: String },

    #[error("nested bundle Info.plist `{path}` is a directory")]
    InfoPlistIsDirectory { path: String },

    #[error("nested bundle Info.plist `{path}` declares {actual} bytes; maximum is {maximum}")]
    InfoPlistTooLarge {
        path: String,
        actual: u64,
        maximum: u64,
    },

    #[error("aggregate nested Info.plist {field} byte count overflowed")]
    AggregateInfoPlistSizeOverflow { field: &'static str },

    #[error("aggregate nested Info.plist {field} bytes {actual} exceed the {maximum}-byte limit")]
    AggregateInfoPlistTooLarge {
        field: &'static str,
        actual: u64,
        maximum: u64,
    },

    #[error("bounded read of nested Info.plist `{path}` failed: {source}")]
    EntryRead {
        path: String,
        #[source]
        source: IpaEntryReadError,
    },

    #[error("IPA inventory changed while reading nested Info.plist `{path}`")]
    InventoryChanged { path: String },

    #[error("nested Info.plist `{path}` is invalid: {source}")]
    InvalidInfoPlist {
        path: String,
        #[source]
        source: IpaAppMetadataError,
    },

    #[error("nested bundle `{bundle_root}` declares missing executable `{path}`")]
    MissingExecutable { bundle_root: String, path: String },

    #[error("nested bundle executable `{path}` is a directory")]
    ExecutableIsDirectory { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedBundlePlist {
    role: IpaNestedBundleRole,
    bundle_root: String,
    info_plist_path: String,
    info_plist_entry: IpaEntry,
}

/// Resolve bounded metadata for conventional nested framework and extension
/// bundles.
///
/// The reader must be the secured regular-file handle used to obtain
/// `archive_size`. The source IPA is never modified. Success confirms metadata
/// and exact regular entries only; it does not inspect nested executable bytes
/// as Mach-O or prove plaintext.
pub fn inspect_ipa_nested_bundle_metadata<R: Read + Seek>(
    reader: R,
    archive_size: u64,
) -> Result<IpaNestedBundleMetadata, IpaNestedBundleMetadataError> {
    inspect_ipa_nested_bundle_metadata_with_inventory(reader, archive_size)
        .map(|(metadata, _)| metadata)
}

pub(crate) fn inspect_ipa_nested_bundle_metadata_with_inventory<R: Read + Seek>(
    mut reader: R,
    archive_size: u64,
) -> Result<(IpaNestedBundleMetadata, IpaInventory), IpaNestedBundleMetadataError> {
    let (app, authoritative_inventory) =
        inspect_ipa_app_metadata_with_inventory(&mut reader, archive_size)?;
    let roots = discover_bundle_roots(&authoritative_inventory);
    let selected = select_bundle_plists(&authoritative_inventory, &roots)?;
    let mut bundles = Vec::with_capacity(selected.len());

    for selected_bundle in selected {
        let (bytes, observed_inventory) = read_ipa_entry_bounded_with_inventory(
            &mut reader,
            archive_size,
            &selected_bundle.info_plist_path,
            MAX_IPA_INFO_PLIST_BYTES,
        )
        .map_err(|source| IpaNestedBundleMetadataError::EntryRead {
            path: selected_bundle.info_plist_path.clone(),
            source,
        })?;
        ensure_inventory_unchanged(
            &selected_bundle.info_plist_path,
            &authoritative_inventory,
            &observed_inventory,
        )?;

        let parsed = parse_info_plist(&bytes).map_err(|source| {
            IpaNestedBundleMetadataError::InvalidInfoPlist {
                path: selected_bundle.info_plist_path.clone(),
                source,
            }
        })?;
        let executable_path = format!("{}/{}", selected_bundle.bundle_root, parsed.executable_name);
        let executable_entry = authoritative_inventory
            .entries
            .iter()
            .find(|entry| entry.path == executable_path)
            .ok_or_else(|| IpaNestedBundleMetadataError::MissingExecutable {
                bundle_root: selected_bundle.bundle_root.clone(),
                path: executable_path.clone(),
            })?
            .clone();
        if executable_entry.kind == IpaEntryKind::Directory {
            return Err(IpaNestedBundleMetadataError::ExecutableIsDirectory {
                path: executable_path,
            });
        }

        bundles.push(IpaNestedBundle {
            role: selected_bundle.role,
            bundle_root: selected_bundle.bundle_root,
            info_plist_path: selected_bundle.info_plist_path,
            info_plist_entry: selected_bundle.info_plist_entry,
            bundle_identifier: parsed.bundle_identifier,
            bundle_version: parsed.bundle_version,
            short_version: parsed.short_version,
            executable_name: parsed.executable_name,
            executable_path,
            executable_entry,
        });
    }

    Ok((
        IpaNestedBundleMetadata { app, bundles },
        authoritative_inventory,
    ))
}

fn discover_bundle_roots(inventory: &IpaInventory) -> BTreeMap<String, IpaNestedBundleRole> {
    let mut roots = BTreeMap::new();
    for entry in &inventory.entries {
        let Some(relative) = entry
            .path
            .strip_prefix(&inventory.app_root)
            .and_then(|suffix| suffix.strip_prefix('/'))
        else {
            continue;
        };
        let components = relative.split('/').collect::<Vec<_>>();

        if is_conventional_extension_root(&components, entry.kind) {
            roots.insert(
                format!("{}/PlugIns/{}", inventory.app_root, components[1]),
                IpaNestedBundleRole::Extension,
            );
        }

        for index in 0..components.len() {
            if is_bundle_component(components[index], ".framework")
                && component_represents_container(index, components.len(), entry.kind)
                && framework_ancestry_is_in_scope(&components[..index])
            {
                roots.insert(
                    format!("{}/{}", inventory.app_root, components[..=index].join("/")),
                    IpaNestedBundleRole::Framework,
                );
            }
        }
    }
    roots
}

fn is_conventional_extension_root(components: &[&str], kind: IpaEntryKind) -> bool {
    components.len() >= 2
        && components[0] == "PlugIns"
        && is_bundle_component(components[1], ".appex")
        && component_represents_container(1, components.len(), kind)
}

fn framework_ancestry_is_in_scope(components: &[&str]) -> bool {
    if components.iter().any(|component| {
        is_bundle_component(component, ".app") || is_bundle_component(component, ".framework")
    }) {
        return false;
    }

    let extension_indexes = components
        .iter()
        .enumerate()
        .filter_map(|(index, component)| is_bundle_component(component, ".appex").then_some(index))
        .collect::<Vec<_>>();
    extension_indexes.is_empty()
        || (extension_indexes == [1] && components.first() == Some(&"PlugIns"))
}

fn component_represents_container(
    index: usize,
    component_count: usize,
    kind: IpaEntryKind,
) -> bool {
    index + 1 < component_count || kind == IpaEntryKind::Directory
}

fn is_bundle_component(component: &str, suffix: &str) -> bool {
    component
        .strip_suffix(suffix)
        .is_some_and(|stem| !stem.is_empty())
}

fn select_bundle_plists(
    inventory: &IpaInventory,
    roots: &BTreeMap<String, IpaNestedBundleRole>,
) -> Result<Vec<SelectedBundlePlist>, IpaNestedBundleMetadataError> {
    if roots.len() > MAX_IPA_NESTED_BUNDLES {
        return Err(IpaNestedBundleMetadataError::TooManyBundles {
            actual: roots.len(),
            maximum: MAX_IPA_NESTED_BUNDLES,
        });
    }

    let mut selected = Vec::with_capacity(roots.len());
    for (bundle_root, role) in roots {
        let info_plist_path = format!("{bundle_root}/Info.plist");
        let info_plist_entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == info_plist_path)
            .ok_or_else(|| IpaNestedBundleMetadataError::MissingInfoPlist {
                bundle_root: bundle_root.clone(),
                path: info_plist_path.clone(),
            })?
            .clone();
        if info_plist_entry.kind == IpaEntryKind::Directory {
            return Err(IpaNestedBundleMetadataError::InfoPlistIsDirectory {
                path: info_plist_path,
            });
        }
        if info_plist_entry.uncompressed_size > MAX_IPA_INFO_PLIST_BYTES {
            return Err(IpaNestedBundleMetadataError::InfoPlistTooLarge {
                path: info_plist_path,
                actual: info_plist_entry.uncompressed_size,
                maximum: MAX_IPA_INFO_PLIST_BYTES,
            });
        }
        selected.push(SelectedBundlePlist {
            role: *role,
            bundle_root: bundle_root.clone(),
            info_plist_path,
            info_plist_entry,
        });
    }

    validate_aggregate_plist_bytes(&selected, "compressed", |entry| {
        entry.info_plist_entry.compressed_size
    })?;
    validate_aggregate_plist_bytes(&selected, "uncompressed", |entry| {
        entry.info_plist_entry.uncompressed_size
    })?;
    Ok(selected)
}

fn validate_aggregate_plist_bytes(
    selected: &[SelectedBundlePlist],
    field: &'static str,
    value: impl Fn(&SelectedBundlePlist) -> u64,
) -> Result<(), IpaNestedBundleMetadataError> {
    let total = selected.iter().try_fold(0u64, |total, entry| {
        total
            .checked_add(value(entry))
            .ok_or(IpaNestedBundleMetadataError::AggregateInfoPlistSizeOverflow { field })
    })?;
    if total > MAX_IPA_NESTED_INFO_PLIST_TOTAL_BYTES {
        return Err(IpaNestedBundleMetadataError::AggregateInfoPlistTooLarge {
            field,
            actual: total,
            maximum: MAX_IPA_NESTED_INFO_PLIST_TOTAL_BYTES,
        });
    }
    Ok(())
}

fn ensure_inventory_unchanged(
    path: &str,
    expected: &IpaInventory,
    actual: &IpaInventory,
) -> Result<(), IpaNestedBundleMetadataError> {
    if expected != actual {
        return Err(IpaNestedBundleMetadataError::InventoryChanged {
            path: path.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use plist::{Dictionary, Value};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;
    use crate::ipa::IpaInspectError;

    const APP_ROOT: &str = "Payload/Demo.app";
    const ROOT_INFO: &str = "Payload/Demo.app/Info.plist";
    const ROOT_EXECUTABLE: &str = "Payload/Demo.app/Demo";
    const FRAMEWORK_ROOT: &str = "Payload/Demo.app/Frameworks/Kit.framework";
    const EXTENSION_ROOT: &str = "Payload/Demo.app/PlugIns/Share.appex";
    const NESTED_FRAMEWORK_ROOT: &str =
        "Payload/Demo.app/PlugIns/Share.appex/Frameworks/Nested.framework";

    enum FixtureEntry {
        File(String, Vec<u8>),
        Directory(String),
    }

    fn options() -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644)
    }

    fn bundle_plist(identifier: &str, executable: &str) -> Vec<u8> {
        format!(
            r#"<plist><dict>
<key>CFBundleIdentifier</key><string>{identifier}</string>
<key>CFBundleVersion</key><string>7</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
<key>CFBundleExecutable</key><string>{executable}</string>
</dict></plist>"#
        )
        .into_bytes()
    }

    fn binary_bundle_plist(identifier: &str, executable: &str) -> Vec<u8> {
        let mut dictionary = Dictionary::new();
        dictionary.insert(
            "CFBundleIdentifier".to_owned(),
            Value::String(identifier.to_owned()),
        );
        dictionary.insert("CFBundleVersion".to_owned(), Value::String("7".to_owned()));
        dictionary.insert(
            "CFBundleExecutable".to_owned(),
            Value::String(executable.to_owned()),
        );
        let mut output = Cursor::new(Vec::new());
        Value::Dictionary(dictionary)
            .to_writer_binary(&mut output)
            .expect("write binary plist");
        output.into_inner()
    }

    fn make_ipa(extra: Vec<FixtureEntry>) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer.start_file(ROOT_INFO, options()).expect("root plist");
        writer
            .write_all(&bundle_plist("com.example.demo", "Demo"))
            .expect("write root plist");
        writer
            .start_file(ROOT_EXECUTABLE, options())
            .expect("root executable");
        writer.write_all(b"root").expect("write root executable");
        for entry in extra {
            match entry {
                FixtureEntry::File(path, bytes) => {
                    writer.start_file(path, options()).expect("start file");
                    writer.write_all(&bytes).expect("write file");
                }
                FixtureEntry::Directory(path) => writer
                    .add_directory(format!("{path}/"), options())
                    .expect("add directory"),
            }
        }
        writer.finish().expect("finish IPA").into_inner()
    }

    fn file(path: impl Into<String>, bytes: impl Into<Vec<u8>>) -> FixtureEntry {
        FixtureEntry::File(path.into(), bytes.into())
    }

    fn directory(path: impl Into<String>) -> FixtureEntry {
        FixtureEntry::Directory(path.into())
    }

    #[test]
    fn resolves_nonstandard_declared_executables_without_explicit_directories() {
        let bytes = make_ipa(vec![
            file(
                format!("{FRAMEWORK_ROOT}/Info.plist"),
                bundle_plist("com.example.demo.kit", "UnexpectedKitBinary"),
            ),
            file(format!("{FRAMEWORK_ROOT}/UnexpectedKitBinary"), b"kit"),
            file(
                format!("{EXTENSION_ROOT}/Info.plist"),
                binary_bundle_plist("com.example.demo.share", "ShareWorker"),
            ),
            file(format!("{EXTENSION_ROOT}/ShareWorker"), b"extension"),
            file(
                format!("{NESTED_FRAMEWORK_ROOT}/Info.plist"),
                bundle_plist("com.example.demo.nested", "NestedWorker"),
            ),
            file(format!("{NESTED_FRAMEWORK_ROOT}/NestedWorker"), b"nested"),
        ]);
        let original = bytes.clone();

        let first = inspect_ipa_nested_bundle_metadata(Cursor::new(&bytes), bytes.len() as u64)
            .expect("inspect nested metadata");
        let second = inspect_ipa_nested_bundle_metadata(Cursor::new(&bytes), bytes.len() as u64)
            .expect("repeat nested metadata");

        assert_eq!(bytes, original);
        assert_eq!(first, second);
        assert_eq!(first.app.app_root, APP_ROOT);
        assert_eq!(
            first
                .bundles
                .iter()
                .map(|bundle| {
                    (
                        bundle.bundle_root.as_str(),
                        bundle.role,
                        bundle.executable_name.as_str(),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                (
                    FRAMEWORK_ROOT,
                    IpaNestedBundleRole::Framework,
                    "UnexpectedKitBinary",
                ),
                (
                    EXTENSION_ROOT,
                    IpaNestedBundleRole::Extension,
                    "ShareWorker",
                ),
                (
                    NESTED_FRAMEWORK_ROOT,
                    IpaNestedBundleRole::Framework,
                    "NestedWorker",
                ),
            ]
        );
        assert!(first.bundles.iter().all(|bundle| {
            bundle.info_plist_entry.kind == IpaEntryKind::File
                && bundle.executable_entry.kind == IpaEntryKind::File
        }));
    }

    #[test]
    fn rejects_missing_directory_and_oversized_nested_plists() {
        let missing = make_ipa(vec![file(format!("{FRAMEWORK_ROOT}/Kit"), b"kit")]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(Cursor::new(&missing), missing.len() as u64),
            Err(IpaNestedBundleMetadataError::MissingInfoPlist { .. })
        ));

        let plist_directory = make_ipa(vec![
            directory(format!("{FRAMEWORK_ROOT}/Info.plist")),
            file(format!("{FRAMEWORK_ROOT}/Kit"), b"kit"),
        ]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(
                Cursor::new(&plist_directory),
                plist_directory.len() as u64,
            ),
            Err(IpaNestedBundleMetadataError::InfoPlistIsDirectory { .. })
        ));

        let oversized = make_ipa(vec![
            file(
                format!("{FRAMEWORK_ROOT}/Info.plist"),
                vec![b'x'; MAX_IPA_INFO_PLIST_BYTES as usize + 1],
            ),
            file(format!("{FRAMEWORK_ROOT}/Kit"), b"kit"),
        ]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(Cursor::new(&oversized), oversized.len() as u64),
            Err(IpaNestedBundleMetadataError::InfoPlistTooLarge { .. })
        ));
    }

    #[test]
    fn rejects_invalid_nested_plists_with_context() {
        let malformed = make_ipa(vec![
            file(format!("{FRAMEWORK_ROOT}/Info.plist"), b"not a plist"),
            file(format!("{FRAMEWORK_ROOT}/Kit"), b"kit"),
        ]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(Cursor::new(&malformed), malformed.len() as u64),
            Err(IpaNestedBundleMetadataError::InvalidInfoPlist {
                source: IpaAppMetadataError::UnsupportedEncoding,
                ..
            })
        ));

        let duplicate = bundle_plist("com.example.demo.kit", "Kit");
        let duplicate = String::from_utf8(duplicate)
            .expect("fixture UTF-8")
            .replace(
                "</dict>",
                "<key>CFBundleExecutable</key><string>Other</string></dict>",
            );
        let duplicate = make_ipa(vec![
            file(format!("{FRAMEWORK_ROOT}/Info.plist"), duplicate),
            file(format!("{FRAMEWORK_ROOT}/Kit"), b"kit"),
        ]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(Cursor::new(&duplicate), duplicate.len() as u64),
            Err(IpaNestedBundleMetadataError::InvalidInfoPlist {
                source: IpaAppMetadataError::DuplicateTopLevelKey { .. },
                ..
            })
        ));

        let unsafe_name = make_ipa(vec![file(
            format!("{FRAMEWORK_ROOT}/Info.plist"),
            bundle_plist("com.example.demo.kit", "bin/Kit"),
        )]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(Cursor::new(&unsafe_name), unsafe_name.len() as u64,),
            Err(IpaNestedBundleMetadataError::InvalidInfoPlist {
                source: IpaAppMetadataError::InvalidField {
                    field: "CFBundleExecutable",
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn rejects_missing_and_directory_nested_executables() {
        let missing = make_ipa(vec![file(
            format!("{FRAMEWORK_ROOT}/Info.plist"),
            bundle_plist("com.example.demo.kit", "Absent"),
        )]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(Cursor::new(&missing), missing.len() as u64),
            Err(IpaNestedBundleMetadataError::MissingExecutable { .. })
        ));

        let executable_directory = make_ipa(vec![
            file(
                format!("{FRAMEWORK_ROOT}/Info.plist"),
                bundle_plist("com.example.demo.kit", "Kit"),
            ),
            directory(format!("{FRAMEWORK_ROOT}/Kit")),
        ]);
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(
                Cursor::new(&executable_directory),
                executable_directory.len() as u64,
            ),
            Err(IpaNestedBundleMetadataError::ExecutableIsDirectory { .. })
        ));
    }

    #[test]
    fn ignores_out_of_scope_nested_apps_extensions_and_bundle_named_files() {
        let bytes = make_ipa(vec![
            file("Payload/Demo.app/Assets/Fake.framework", b"resource"),
            file(
                "Payload/Demo.app/Extensions/Hidden.appex/Info.plist",
                bundle_plist("com.example.hidden", "Hidden"),
            ),
            file("Payload/Demo.app/Extensions/Hidden.appex/Hidden", b"hidden"),
            file(
                "Payload/Demo.app/Watch/Watch.app/Frameworks/WatchKit.framework/Info.plist",
                bundle_plist("com.example.watch.kit", "WatchKit"),
            ),
            file(
                "Payload/Demo.app/Watch/Watch.app/Frameworks/WatchKit.framework/WatchKit",
                b"watch",
            ),
        ]);

        let result = inspect_ipa_nested_bundle_metadata(Cursor::new(&bytes), bytes.len() as u64)
            .expect("ignore out-of-scope bundle shapes");
        assert!(result.bundles.is_empty());
    }

    #[test]
    fn bundle_count_and_aggregate_plist_limits_fail_closed() {
        let too_many_entries = (0..=MAX_IPA_NESTED_BUNDLES)
            .map(|index| {
                synthetic_entry(
                    &format!("{APP_ROOT}/Frameworks/F{index}.framework/Info.plist"),
                    1,
                    1,
                )
            })
            .collect::<Vec<_>>();
        let too_many_inventory = synthetic_inventory(too_many_entries);
        let too_many_roots = discover_bundle_roots(&too_many_inventory);
        assert!(matches!(
            select_bundle_plists(&too_many_inventory, &too_many_roots),
            Err(IpaNestedBundleMetadataError::TooManyBundles { .. })
        ));

        let aggregate_entries = (0..65)
            .map(|index| {
                synthetic_entry(
                    &format!("{APP_ROOT}/Frameworks/F{index}.framework/Info.plist"),
                    1024 * 1024,
                    1024 * 1024,
                )
            })
            .collect::<Vec<_>>();
        let aggregate_inventory = synthetic_inventory(aggregate_entries);
        let aggregate_roots = discover_bundle_roots(&aggregate_inventory);
        assert!(matches!(
            select_bundle_plists(&aggregate_inventory, &aggregate_roots),
            Err(IpaNestedBundleMetadataError::AggregateInfoPlistTooLarge {
                field: "compressed",
                ..
            })
        ));

        let overflow_inventory = synthetic_inventory(vec![
            synthetic_entry(
                &format!("{APP_ROOT}/Frameworks/A.framework/Info.plist"),
                u64::MAX,
                1,
            ),
            synthetic_entry(
                &format!("{APP_ROOT}/Frameworks/B.framework/Info.plist"),
                1,
                1,
            ),
        ]);
        let overflow_roots = discover_bundle_roots(&overflow_inventory);
        assert!(matches!(
            select_bundle_plists(&overflow_inventory, &overflow_roots),
            Err(
                IpaNestedBundleMetadataError::AggregateInfoPlistSizeOverflow {
                    field: "compressed"
                }
            )
        ));
    }

    #[test]
    fn inventory_identity_and_preflight_fail_closed() {
        let expected = synthetic_inventory(vec![]);
        let mut changed = expected.clone();
        changed.archive_size += 1;
        assert!(matches!(
            ensure_inventory_unchanged("Info.plist", &expected, &changed),
            Err(IpaNestedBundleMetadataError::InventoryChanged { .. })
        ));

        let malformed = b"not an IPA";
        assert!(matches!(
            inspect_ipa_nested_bundle_metadata(Cursor::new(malformed), malformed.len() as u64),
            Err(IpaNestedBundleMetadataError::AppMetadata(
                IpaAppMetadataError::Inspect(IpaInspectError::InvalidArchive { .. })
            ))
        ));
    }

    fn synthetic_entry(path: &str, compressed_size: u64, uncompressed_size: u64) -> IpaEntry {
        IpaEntry {
            path: path.to_owned(),
            kind: IpaEntryKind::File,
            compressed_size,
            uncompressed_size,
            crc32: 0,
        }
    }

    fn synthetic_inventory(entries: Vec<IpaEntry>) -> IpaInventory {
        IpaInventory {
            archive_size: 1,
            app_root: APP_ROOT.to_owned(),
            entry_count: entries.len(),
            file_count: entries.len(),
            directory_count: 0,
            total_compressed_size: 0,
            total_uncompressed_size: 0,
            entries,
        }
    }
}
