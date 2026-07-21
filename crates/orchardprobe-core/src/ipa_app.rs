//! Bounded app identity parsing from a validated IPA `Info.plist`.
//!
//! This module reads only the root app's exact `Info.plist` entry through the
//! bounded IPA reader. It parses a limited XML or binary plist event stream,
//! returns identity fields, and confirms the declared main executable is a
//! regular file in the same validated inventory. It never writes to disk.

use std::collections::HashSet;
use std::io::{BufReader, Cursor, Read, Seek};

use plist::stream::{BinaryReader, Event, XmlReader};
use serde::Serialize;
use thiserror::Error;

use crate::ipa::{
    IpaEntryKind, IpaEntryReadError, IpaInspectError, inspect_ipa,
    read_ipa_entry_bounded_with_inventory,
};

/// Maximum accepted uncompressed bytes for the root app's `Info.plist`.
pub const MAX_IPA_INFO_PLIST_BYTES: u64 = 1024 * 1024;
/// Maximum number of parser events emitted by one `Info.plist`.
pub const MAX_INFO_PLIST_EVENTS: u64 = 8_192;
/// Maximum collection nesting depth, including the root dictionary.
pub const MAX_INFO_PLIST_DEPTH: u64 = 32;
/// Maximum declared items in one array or key/value pairs in one dictionary.
pub const MAX_INFO_PLIST_COLLECTION_ITEMS: u64 = 4_096;
/// Maximum keys accepted in the root `Info.plist` dictionary.
pub const MAX_INFO_PLIST_TOP_LEVEL_KEYS: u64 = 512;
/// Maximum UTF-8 bytes in one root dictionary key.
pub const MAX_INFO_PLIST_KEY_BYTES: u64 = 1_024;
/// Maximum cumulative string and data bytes emitted by the parser.
pub const MAX_INFO_PLIST_SCALAR_BYTES: u64 = 2 * 1024 * 1024;

const MAX_BUNDLE_IDENTIFIER_BYTES: usize = 255;
const MAX_EXECUTABLE_NAME_BYTES: usize = 255;
const MAX_VERSION_BYTES: usize = 128;

/// Validated identity metadata for the root app bundle in one IPA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IpaAppMetadata {
    pub app_root: String,
    pub info_plist_path: String,
    pub bundle_identifier: String,
    pub bundle_version: String,
    pub short_version: Option<String>,
    pub executable_name: String,
    pub executable_path: String,
}

/// Failure while locating and parsing root app metadata from an IPA.
#[derive(Debug, Error)]
pub enum IpaAppMetadataError {
    #[error("IPA preflight failed before app metadata parsing: {0}")]
    Inspect(#[from] IpaInspectError),

    #[error("bounded Info.plist read failed: {0}")]
    EntryRead(#[from] IpaEntryReadError),

    #[error("validated IPA has no root app Info.plist at `{path}`")]
    MissingInfoPlist { path: String },

    #[error("root app Info.plist path `{path}` is a directory")]
    InfoPlistIsDirectory { path: String },

    #[error("root app Info.plist declares {actual} bytes; maximum is {maximum}")]
    InfoPlistTooLarge { actual: u64, maximum: u64 },

    #[error("IPA inventory changed while reading root app metadata")]
    InventoryChanged,

    #[error("Info.plist is neither binary plist nor UTF-8 XML plist")]
    UnsupportedEncoding,

    #[error("invalid Info.plist event stream: {reason}")]
    InvalidPlist { reason: String },

    #[error("Info.plist exceeded the {limit} limit: {actual} > {maximum}")]
    PlistLimitExceeded {
        limit: &'static str,
        actual: u64,
        maximum: u64,
    },

    #[error("Info.plist root dictionary repeats key `{key}`")]
    DuplicateTopLevelKey { key: String },

    #[error("Info.plist is missing required string field `{field}`")]
    MissingField { field: &'static str },

    #[error("Info.plist field `{field}` must be a string, found {actual}")]
    InvalidFieldType {
        field: &'static str,
        actual: &'static str,
    },

    #[error("Info.plist field `{field}` is invalid: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },

    #[error("declared main executable `{path}` is absent from the validated IPA")]
    MissingExecutable { path: String },

    #[error("declared main executable `{path}` is a directory")]
    ExecutableIsDirectory { path: String },
}

#[derive(Default)]
struct InfoPlistFields {
    bundle_identifier: Option<String>,
    bundle_version: Option<String>,
    short_version: Option<String>,
    executable_name: Option<String>,
}

#[derive(Debug)]
struct ParsedInfoPlist {
    bundle_identifier: String,
    bundle_version: String,
    short_version: Option<String>,
    executable_name: String,
}

/// Parse the root iOS app's bounded identity metadata from an IPA.
///
/// The reader must be the same secured regular-file handle that supplied
/// `archive_size`. The function performs a complete IPA preflight, reads only
/// the exact root `Info.plist` through the bounded entry API, and returns no
/// plist payload bytes.
pub fn inspect_ipa_app_metadata<R: Read + Seek>(
    mut reader: R,
    archive_size: u64,
) -> Result<IpaAppMetadata, IpaAppMetadataError> {
    let initial_inventory = inspect_ipa(&mut reader, archive_size)?;
    let app_root = initial_inventory.app_root.clone();
    let info_plist_path = format!("{app_root}/Info.plist");
    let info_entry = initial_inventory
        .entries
        .iter()
        .find(|entry| entry.path == info_plist_path)
        .ok_or_else(|| IpaAppMetadataError::MissingInfoPlist {
            path: info_plist_path.clone(),
        })?;
    if info_entry.kind == IpaEntryKind::Directory {
        return Err(IpaAppMetadataError::InfoPlistIsDirectory {
            path: info_plist_path,
        });
    }
    if info_entry.uncompressed_size > MAX_IPA_INFO_PLIST_BYTES {
        return Err(IpaAppMetadataError::InfoPlistTooLarge {
            actual: info_entry.uncompressed_size,
            maximum: MAX_IPA_INFO_PLIST_BYTES,
        });
    }

    let (bytes, inventory) = read_ipa_entry_bounded_with_inventory(
        &mut reader,
        archive_size,
        &info_plist_path,
        MAX_IPA_INFO_PLIST_BYTES,
    )?;
    if inventory.app_root != app_root {
        return Err(IpaAppMetadataError::InventoryChanged);
    }

    let parsed = parse_info_plist(&bytes)?;

    let executable_path = format!("{app_root}/{}", parsed.executable_name);
    let executable = inventory
        .entries
        .iter()
        .find(|entry| entry.path == executable_path)
        .ok_or_else(|| IpaAppMetadataError::MissingExecutable {
            path: executable_path.clone(),
        })?;
    if executable.kind == IpaEntryKind::Directory {
        return Err(IpaAppMetadataError::ExecutableIsDirectory {
            path: executable_path,
        });
    }

    Ok(IpaAppMetadata {
        app_root,
        info_plist_path,
        bundle_identifier: parsed.bundle_identifier,
        bundle_version: parsed.bundle_version,
        short_version: parsed.short_version,
        executable_name: parsed.executable_name,
        executable_path,
    })
}

fn parse_info_plist(bytes: &[u8]) -> Result<ParsedInfoPlist, IpaAppMetadataError> {
    let parsed = if bytes.starts_with(b"bplist00") {
        parse_info_events(BinaryReader::new(Cursor::new(bytes)))
    } else if looks_like_xml(bytes) {
        parse_info_events(XmlReader::new(BufReader::new(Cursor::new(bytes))))
    } else {
        return Err(IpaAppMetadataError::UnsupportedEncoding);
    }?;
    validate_bundle_identifier(&parsed.bundle_identifier)?;
    validate_version("CFBundleVersion", &parsed.bundle_version)?;
    if let Some(short_version) = &parsed.short_version {
        validate_version("CFBundleShortVersionString", short_version)?;
    }
    validate_executable_name(&parsed.executable_name)?;
    Ok(parsed)
}

fn looks_like_xml(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'<')
}

fn parse_info_events<I>(events: I) -> Result<ParsedInfoPlist, IpaAppMetadataError>
where
    I: IntoIterator<Item = Result<Event<'static>, plist::Error>>,
{
    let mut events = events.into_iter();
    let mut budget = EventBudget::default();
    let first =
        next_event(&mut events, &mut budget)?.ok_or_else(|| IpaAppMetadataError::InvalidPlist {
            reason: "event stream is empty".to_owned(),
        })?;
    let declared_keys = match first {
        Event::StartDictionary(len) => len,
        other => {
            return Err(IpaAppMetadataError::InvalidPlist {
                reason: format!("root must be a dictionary, found {}", event_kind(&other)),
            });
        }
    };
    if let Some(actual) = declared_keys {
        enforce_limit(
            "root dictionary key count",
            actual,
            MAX_INFO_PLIST_TOP_LEVEL_KEYS,
        )?;
    }

    let mut parsed = InfoPlistFields::default();
    let mut keys = HashSet::new();
    loop {
        let event = next_required_event(&mut events, &mut budget, "root dictionary key")?;
        let key = match event {
            Event::EndCollection => break,
            Event::String(key) => key.into_owned(),
            other => {
                return Err(IpaAppMetadataError::InvalidPlist {
                    reason: format!(
                        "root dictionary key must be a string, found {}",
                        event_kind(&other)
                    ),
                });
            }
        };
        enforce_limit(
            "root dictionary key bytes",
            key.len() as u64,
            MAX_INFO_PLIST_KEY_BYTES,
        )?;
        let key_count = keys.len() as u64 + 1;
        enforce_limit(
            "root dictionary key count",
            key_count,
            MAX_INFO_PLIST_TOP_LEVEL_KEYS,
        )?;
        if !keys.insert(key.clone()) {
            return Err(IpaAppMetadataError::DuplicateTopLevelKey { key });
        }

        let value = next_required_event(&mut events, &mut budget, "root dictionary value")?;
        match key.as_str() {
            "CFBundleIdentifier" => {
                parsed.bundle_identifier = Some(require_string(value, "CFBundleIdentifier")?);
            }
            "CFBundleVersion" => {
                parsed.bundle_version = Some(require_string(value, "CFBundleVersion")?);
            }
            "CFBundleShortVersionString" => {
                parsed.short_version = Some(require_string(value, "CFBundleShortVersionString")?);
            }
            "CFBundleExecutable" => {
                parsed.executable_name = Some(require_string(value, "CFBundleExecutable")?);
            }
            _ => skip_value(value, &mut events, &mut budget, 2)?,
        }
    }
    if let Some(event) = next_event(&mut events, &mut budget)? {
        return Err(IpaAppMetadataError::InvalidPlist {
            reason: format!(
                "trailing event after root dictionary: {}",
                event_kind(&event)
            ),
        });
    }

    Ok(ParsedInfoPlist {
        bundle_identifier: parsed
            .bundle_identifier
            .ok_or(IpaAppMetadataError::MissingField {
                field: "CFBundleIdentifier",
            })?,
        bundle_version: parsed
            .bundle_version
            .ok_or(IpaAppMetadataError::MissingField {
                field: "CFBundleVersion",
            })?,
        short_version: parsed.short_version,
        executable_name: parsed
            .executable_name
            .ok_or(IpaAppMetadataError::MissingField {
                field: "CFBundleExecutable",
            })?,
    })
}

fn skip_value<I>(
    first: Event<'static>,
    events: &mut I,
    budget: &mut EventBudget,
    depth: u64,
) -> Result<(), IpaAppMetadataError>
where
    I: Iterator<Item = Result<Event<'static>, plist::Error>>,
{
    enforce_limit("collection depth", depth, MAX_INFO_PLIST_DEPTH)?;
    match first {
        Event::StartArray(_) => {
            let mut items = 0u64;
            loop {
                let event = next_required_event(events, budget, "array value or end")?;
                if matches!(event, Event::EndCollection) {
                    return Ok(());
                }
                items = items
                    .checked_add(1)
                    .ok_or(IpaAppMetadataError::PlistLimitExceeded {
                        limit: "collection items",
                        actual: u64::MAX,
                        maximum: MAX_INFO_PLIST_COLLECTION_ITEMS,
                    })?;
                enforce_limit("collection items", items, MAX_INFO_PLIST_COLLECTION_ITEMS)?;
                skip_value(event, events, budget, depth + 1)?;
            }
        }
        Event::StartDictionary(_) => {
            let mut items = 0u64;
            loop {
                let event = next_required_event(events, budget, "dictionary key or end")?;
                if matches!(event, Event::EndCollection) {
                    return Ok(());
                }
                if !matches!(event, Event::String(_)) {
                    return Err(IpaAppMetadataError::InvalidPlist {
                        reason: format!(
                            "nested dictionary key must be a string, found {}",
                            event_kind(&event)
                        ),
                    });
                }
                items = items
                    .checked_add(1)
                    .ok_or(IpaAppMetadataError::PlistLimitExceeded {
                        limit: "collection items",
                        actual: u64::MAX,
                        maximum: MAX_INFO_PLIST_COLLECTION_ITEMS,
                    })?;
                enforce_limit("collection items", items, MAX_INFO_PLIST_COLLECTION_ITEMS)?;
                let value = next_required_event(events, budget, "nested dictionary value")?;
                if matches!(value, Event::EndCollection) {
                    return Err(IpaAppMetadataError::InvalidPlist {
                        reason: "nested dictionary key has no value".to_owned(),
                    });
                }
                skip_value(value, events, budget, depth + 1)?;
            }
        }
        Event::EndCollection => Err(IpaAppMetadataError::InvalidPlist {
            reason: "unexpected collection end where a value was required".to_owned(),
        }),
        _ => Ok(()),
    }
}

fn require_string(
    event: Event<'static>,
    field: &'static str,
) -> Result<String, IpaAppMetadataError> {
    match event {
        Event::String(value) => Ok(value.into_owned()),
        other => Err(IpaAppMetadataError::InvalidFieldType {
            field,
            actual: event_kind(&other),
        }),
    }
}

#[derive(Default)]
struct EventBudget {
    events: u64,
    scalar_bytes: u64,
}

fn next_required_event<I>(
    events: &mut I,
    budget: &mut EventBudget,
    expected: &'static str,
) -> Result<Event<'static>, IpaAppMetadataError>
where
    I: Iterator<Item = Result<Event<'static>, plist::Error>>,
{
    next_event(events, budget)?.ok_or_else(|| IpaAppMetadataError::InvalidPlist {
        reason: format!("event stream ended while reading {expected}"),
    })
}

fn next_event<I>(
    events: &mut I,
    budget: &mut EventBudget,
) -> Result<Option<Event<'static>>, IpaAppMetadataError>
where
    I: Iterator<Item = Result<Event<'static>, plist::Error>>,
{
    let Some(event) = events.next() else {
        return Ok(None);
    };
    let event = event.map_err(|error| IpaAppMetadataError::InvalidPlist {
        reason: error.to_string(),
    })?;

    budget.events =
        budget
            .events
            .checked_add(1)
            .ok_or(IpaAppMetadataError::PlistLimitExceeded {
                limit: "event count",
                actual: u64::MAX,
                maximum: MAX_INFO_PLIST_EVENTS,
            })?;
    enforce_limit("event count", budget.events, MAX_INFO_PLIST_EVENTS)?;

    let scalar_bytes = match &event {
        Event::String(value) => value.len() as u64,
        Event::Data(value) => value.len() as u64,
        _ => 0,
    };
    budget.scalar_bytes = budget.scalar_bytes.checked_add(scalar_bytes).ok_or(
        IpaAppMetadataError::PlistLimitExceeded {
            limit: "cumulative scalar bytes",
            actual: u64::MAX,
            maximum: MAX_INFO_PLIST_SCALAR_BYTES,
        },
    )?;
    enforce_limit(
        "cumulative scalar bytes",
        budget.scalar_bytes,
        MAX_INFO_PLIST_SCALAR_BYTES,
    )?;

    match &event {
        Event::StartArray(Some(actual)) | Event::StartDictionary(Some(actual)) => {
            enforce_limit(
                "declared collection items",
                *actual,
                MAX_INFO_PLIST_COLLECTION_ITEMS,
            )?;
        }
        _ => {}
    }
    Ok(Some(event))
}

fn enforce_limit(
    limit: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), IpaAppMetadataError> {
    if actual > maximum {
        return Err(IpaAppMetadataError::PlistLimitExceeded {
            limit,
            actual,
            maximum,
        });
    }
    Ok(())
}

fn validate_bundle_identifier(value: &str) -> Result<(), IpaAppMetadataError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_BUNDLE_IDENTIFIER_BYTES
        && value.is_ascii()
        && value.split('.').all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(IpaAppMetadataError::InvalidField {
            field: "CFBundleIdentifier",
            reason: "must be at most 255 ASCII bytes with non-empty alphanumeric or hyphen components separated by periods",
        });
    }
    Ok(())
}

fn validate_version(field: &'static str, value: &str) -> Result<(), IpaAppMetadataError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_VERSION_BYTES
        && value.split('.').all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        });
    if !valid {
        return Err(IpaAppMetadataError::InvalidField {
            field,
            reason: "must be at most 128 bytes of non-empty decimal components separated by periods",
        });
    }
    Ok(())
}

fn validate_executable_name(value: &str) -> Result<(), IpaAppMetadataError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_EXECUTABLE_NAME_BYTES
        && value != "."
        && value != ".."
        && !value.contains(['/', '\\'])
        && !value.chars().any(char::is_control);
    if !valid {
        return Err(IpaAppMetadataError::InvalidField {
            field: "CFBundleExecutable",
            reason: "must be one non-empty, non-dot archive path component of at most 255 UTF-8 bytes",
        });
    }
    Ok(())
}

fn event_kind(event: &Event<'_>) -> &'static str {
    match event {
        Event::StartArray(_) => "array",
        Event::StartDictionary(_) => "dictionary",
        Event::EndCollection => "collection end",
        Event::Boolean(_) => "boolean",
        Event::Data(_) => "data",
        Event::Date(_) => "date",
        Event::Integer(_) => "integer",
        Event::Real(_) => "real",
        Event::String(_) => "string",
        Event::Uid(_) => "uid",
        _ => "unsupported event",
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::fmt::Write as _;
    use std::io::{Cursor, Write};

    use plist::{Dictionary, Value};
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    const APP_ROOT: &str = "Payload/Demo.app";
    const INFO_PATH: &str = "Payload/Demo.app/Info.plist";
    const EXECUTABLE_PATH: &str = "Payload/Demo.app/Demo";

    enum ExecutableFixture {
        File,
        Directory,
        Missing,
    }

    fn zip_options() -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .unix_permissions(0o644)
    }

    fn make_ipa(info_plist: &[u8], executable: ExecutableFixture) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .add_directory("Payload/", zip_options())
            .expect("add Payload");
        writer
            .add_directory(format!("{APP_ROOT}/"), zip_options())
            .expect("add app root");
        writer
            .start_file(INFO_PATH, zip_options())
            .expect("start Info.plist");
        writer.write_all(info_plist).expect("write Info.plist");
        match executable {
            ExecutableFixture::File => {
                writer
                    .start_file(EXECUTABLE_PATH, zip_options())
                    .expect("start executable");
                writer.write_all(b"macho").expect("write executable");
            }
            ExecutableFixture::Directory => writer
                .add_directory(format!("{EXECUTABLE_PATH}/"), zip_options())
                .expect("add executable directory"),
            ExecutableFixture::Missing => {}
        }
        writer.finish().expect("finish IPA").into_inner()
    }

    fn make_ipa_with_non_file_info_plist(directory: bool) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .add_directory("Payload/", zip_options())
            .expect("add Payload");
        writer
            .add_directory(format!("{APP_ROOT}/"), zip_options())
            .expect("add app root");
        if directory {
            writer
                .add_directory(format!("{INFO_PATH}/"), zip_options())
                .expect("add Info.plist directory");
        }
        writer
            .start_file(EXECUTABLE_PATH, zip_options())
            .expect("start executable");
        writer.write_all(b"macho").expect("write executable");
        writer.finish().expect("finish IPA").into_inner()
    }

    fn xml_with_fields(extra: &str) -> Vec<u8> {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.demo</string>
<key>CFBundleVersion</key><string>42</string>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
<key>CFBundleExecutable</key><string>Demo</string>
{extra}
</dict></plist>"#
        )
        .into_bytes()
    }

    fn binary_info_plist() -> Vec<u8> {
        let mut dictionary = Dictionary::new();
        dictionary.insert(
            "CFBundleIdentifier".to_owned(),
            Value::String("com.example.demo".to_owned()),
        );
        dictionary.insert("CFBundleVersion".to_owned(), Value::String("42".to_owned()));
        dictionary.insert(
            "CFBundleShortVersionString".to_owned(),
            Value::String("1.2.3".to_owned()),
        );
        dictionary.insert(
            "CFBundleExecutable".to_owned(),
            Value::String("Demo".to_owned()),
        );
        let mut output = Cursor::new(Vec::new());
        Value::Dictionary(dictionary)
            .to_writer_binary(&mut output)
            .expect("write binary plist");
        output.into_inner()
    }

    fn inspect(bytes: &[u8]) -> Result<IpaAppMetadata, IpaAppMetadataError> {
        inspect_ipa_app_metadata(Cursor::new(bytes), bytes.len() as u64)
    }

    #[test]
    fn parses_xml_metadata_and_skips_bounded_unknown_values() {
        let xml = xml_with_fields(
            "<key>Unknown</key><dict><key>Nested</key><array><true/><integer>7</integer></array></dict>",
        );
        let ipa = make_ipa(&xml, ExecutableFixture::File);

        let metadata = inspect(&ipa).expect("parse XML Info.plist");

        assert_eq!(
            metadata,
            IpaAppMetadata {
                app_root: APP_ROOT.to_owned(),
                info_plist_path: INFO_PATH.to_owned(),
                bundle_identifier: "com.example.demo".to_owned(),
                bundle_version: "42".to_owned(),
                short_version: Some("1.2.3".to_owned()),
                executable_name: "Demo".to_owned(),
                executable_path: EXECUTABLE_PATH.to_owned(),
            }
        );
    }

    #[test]
    fn parses_binary_metadata() {
        let ipa = make_ipa(&binary_info_plist(), ExecutableFixture::File);
        let metadata = inspect(&ipa).expect("parse binary Info.plist");

        assert_eq!(metadata.bundle_identifier, "com.example.demo");
        assert_eq!(metadata.executable_path, EXECUTABLE_PATH);
    }

    #[test]
    fn rejects_missing_wrong_type_and_duplicate_identity_fields() {
        let missing = br#"<plist><dict><key>CFBundleIdentifier</key><string>com.example.demo</string></dict></plist>"#;
        assert!(matches!(
            parse_info_plist(missing),
            Err(IpaAppMetadataError::MissingField {
                field: "CFBundleVersion"
            })
        ));

        let duplicate = xml_with_fields("<key>CFBundleIdentifier</key><integer>7</integer>");
        assert!(matches!(
            parse_info_plist(&duplicate),
            Err(IpaAppMetadataError::DuplicateTopLevelKey { .. })
        ));

        let wrong_type = br#"<plist><dict>
<key>CFBundleIdentifier</key><integer>7</integer>
<key>CFBundleVersion</key><string>1</string>
<key>CFBundleExecutable</key><string>Demo</string>
</dict></plist>"#;
        assert!(matches!(
            parse_info_plist(wrong_type),
            Err(IpaAppMetadataError::InvalidFieldType {
                field: "CFBundleIdentifier",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_identity_values() {
        for bundle_identifier in ["", ".com.example", "com..example", "com.example_app"] {
            let xml = xml_with_fields("");
            let xml = String::from_utf8(xml)
                .expect("fixture UTF-8")
                .replace("com.example.demo", bundle_identifier);
            let result = parse_info_plist(xml.as_bytes());
            assert!(
                matches!(
                    &result,
                    Err(IpaAppMetadataError::InvalidField {
                        field: "CFBundleIdentifier",
                        ..
                    })
                ),
                "bundle identifier {bundle_identifier:?}: {result:?}"
            );
        }

        for executable in ["", ".", "..", "bin/Demo", "bin\\Demo", "Demo\0bad"] {
            let xml = xml_with_fields("");
            let xml = String::from_utf8(xml).expect("fixture UTF-8").replace(
                "<string>Demo</string>",
                &format!("<string>{executable}</string>"),
            );
            assert!(matches!(
                parse_info_plist(xml.as_bytes()),
                Err(IpaAppMetadataError::InvalidField {
                    field: "CFBundleExecutable",
                    ..
                }) | Err(IpaAppMetadataError::InvalidPlist { .. })
            ));
        }

        for version in ["", ".1", "1.", "1..2", "1a"] {
            let xml = xml_with_fields("");
            let xml = String::from_utf8(xml).expect("fixture UTF-8").replace(
                "<string>42</string>",
                &format!("<string>{version}</string>"),
            );
            assert!(matches!(
                parse_info_plist(xml.as_bytes()),
                Err(IpaAppMetadataError::InvalidField {
                    field: "CFBundleVersion",
                    ..
                })
            ));
        }
    }

    #[test]
    fn rejects_missing_or_directory_executable() {
        let xml = xml_with_fields("");
        let missing = make_ipa(&xml, ExecutableFixture::Missing);
        assert!(matches!(
            inspect(&missing),
            Err(IpaAppMetadataError::MissingExecutable { .. })
        ));

        let directory = make_ipa(&xml, ExecutableFixture::Directory);
        assert!(matches!(
            inspect(&directory),
            Err(IpaAppMetadataError::ExecutableIsDirectory { .. })
        ));
    }

    #[test]
    fn rejects_missing_or_directory_info_plist() {
        let missing = make_ipa_with_non_file_info_plist(false);
        assert!(matches!(
            inspect(&missing),
            Err(IpaAppMetadataError::MissingInfoPlist { .. })
        ));

        let directory = make_ipa_with_non_file_info_plist(true);
        assert!(matches!(
            inspect(&directory),
            Err(IpaAppMetadataError::InfoPlistIsDirectory { .. })
        ));
    }

    #[test]
    fn rejects_malformed_trailing_non_dictionary_and_ascii_plists() {
        assert!(matches!(
            parse_info_plist(b"<plist><dict>"),
            Err(IpaAppMetadataError::InvalidPlist { .. })
        ));
        assert!(matches!(
            parse_info_plist(b"<plist><dict></dict><true/></plist>"),
            Err(IpaAppMetadataError::InvalidPlist { .. })
        ));
        assert!(matches!(
            parse_info_plist(b"<plist><array></array></plist>"),
            Err(IpaAppMetadataError::InvalidPlist { .. })
        ));
        assert!(matches!(
            parse_info_plist(br#"{ CFBundleIdentifier = "com.example.demo"; }"#),
            Err(IpaAppMetadataError::UnsupportedEncoding)
        ));
    }

    #[test]
    fn enforces_info_plist_input_and_parser_limits() {
        let oversized = vec![b'x'; MAX_IPA_INFO_PLIST_BYTES as usize + 1];
        let ipa = make_ipa(&oversized, ExecutableFixture::File);
        assert!(matches!(
            inspect(&ipa),
            Err(IpaAppMetadataError::InfoPlistTooLarge { .. })
        ));

        let many_events = format!(
            "<key>Unknown</key><array>{}</array>",
            "<array><true/></array>".repeat(3_000)
        );
        assert!(matches!(
            parse_info_plist(&xml_with_fields(&many_events)),
            Err(IpaAppMetadataError::PlistLimitExceeded {
                limit: "event count",
                ..
            })
        ));

        let too_many_items = format!(
            "<key>Unknown</key><array>{}</array>",
            "<true/>".repeat(MAX_INFO_PLIST_COLLECTION_ITEMS as usize + 1)
        );
        assert!(matches!(
            parse_info_plist(&xml_with_fields(&too_many_items)),
            Err(IpaAppMetadataError::PlistLimitExceeded {
                limit: "collection items",
                ..
            })
        ));

        let deep = format!(
            "<key>Unknown</key>{}true{}",
            "<array>".repeat(MAX_INFO_PLIST_DEPTH as usize),
            "</array>".repeat(MAX_INFO_PLIST_DEPTH as usize)
        );
        assert!(matches!(
            parse_info_plist(&xml_with_fields(&deep)),
            Err(IpaAppMetadataError::PlistLimitExceeded {
                limit: "collection depth",
                ..
            })
        ));

        let mut budget = EventBudget::default();
        let mut events = [Ok(Event::StartArray(Some(
            MAX_INFO_PLIST_COLLECTION_ITEMS + 1,
        )))]
        .into_iter();
        assert!(matches!(
            next_event(&mut events, &mut budget),
            Err(IpaAppMetadataError::PlistLimitExceeded {
                limit: "declared collection items",
                ..
            })
        ));

        let mut many_keys = String::new();
        for index in 0..=MAX_INFO_PLIST_TOP_LEVEL_KEYS {
            write!(many_keys, "<key>Unknown{index}</key><true/>").expect("write synthetic keys");
        }
        assert!(matches!(
            parse_info_plist(&xml_with_fields(&many_keys)),
            Err(IpaAppMetadataError::PlistLimitExceeded {
                limit: "root dictionary key count",
                ..
            })
        ));

        let long_key = format!(
            "<key>{}</key><true/>",
            "k".repeat(MAX_INFO_PLIST_KEY_BYTES as usize + 1)
        );
        assert!(matches!(
            parse_info_plist(&xml_with_fields(&long_key)),
            Err(IpaAppMetadataError::PlistLimitExceeded {
                limit: "root dictionary key bytes",
                ..
            })
        ));
    }

    #[test]
    fn bounds_repeated_binary_scalar_expansion() {
        let repeated = "x".repeat(300_000);
        let mut dictionary = Dictionary::new();
        dictionary.insert(
            "CFBundleIdentifier".to_owned(),
            Value::String("com.example.demo".to_owned()),
        );
        dictionary.insert("CFBundleVersion".to_owned(), Value::String("1".to_owned()));
        dictionary.insert(
            "CFBundleExecutable".to_owned(),
            Value::String("Demo".to_owned()),
        );
        dictionary.insert(
            "Unknown".to_owned(),
            Value::Array((0..8).map(|_| Value::String(repeated.clone())).collect()),
        );
        let mut output = Cursor::new(Vec::new());
        Value::Dictionary(dictionary)
            .to_writer_binary(&mut output)
            .expect("write repeated binary plist");

        assert!(output.get_ref().len() < MAX_IPA_INFO_PLIST_BYTES as usize);
        assert!(matches!(
            parse_info_plist(output.get_ref()),
            Err(IpaAppMetadataError::PlistLimitExceeded {
                limit: "cumulative scalar bytes",
                ..
            })
        ));
    }

    #[test]
    fn propagates_full_ipa_preflight_failures() {
        let malformed = b"not an IPA";
        assert!(matches!(
            inspect(malformed),
            Err(IpaAppMetadataError::Inspect(
                IpaInspectError::InvalidArchive { .. }
            ))
        ));
    }

    #[test]
    fn reports_scalar_event_kinds() {
        let values = [
            Event::Boolean(false),
            Event::Data(Cow::Borrowed(b"x")),
            Event::String(Cow::Borrowed("x")),
        ];
        assert_eq!(
            values.map(|value| event_kind(&value)),
            ["boolean", "data", "string"]
        );
    }
}
