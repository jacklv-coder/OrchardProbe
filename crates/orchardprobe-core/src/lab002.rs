//! Device-free LAB-002 canonical encodings, authorization signatures, and
//! two-run evidence comparison.
//!
//! This module has no device transport, App Group access, signing identity, or
//! decryption operation. It validates synthetic and user-mediated evidence for
//! OrchardProbe's repository-owned DemoLab fixture only.

#[path = "lab002_artifacts.rs"]
pub mod artifacts;
#[path = "lab002_host.rs"]
pub mod host;

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use plist::stream::{
    BinaryReader as PlistBinaryReader, Event as PlistEvent, XmlReader as PlistXmlReader,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

use crate::macho::{EncryptionInfo, Endianness, MachOContainer, parse_macho};

const BUILD_BINDING_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.build-binding.v1\0";
const TARGET_IDENTITY_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.target-identity.v1\0";
const TARGET_IDENTITY_SET_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.target-identity-set.v1\0";
const DEVICE_INSTALLATION_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.device-installation.v1\0";
const AUTHORIZED_OPERATION_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.authorized-operation.v1\0";

pub const LAB002_PROFILE: &str = "orchardprobe.demolab.lab002.observation.v1";
pub const AUTHORIZATION_POLICY_VERSION: &str = "orchardprobe.authorized-use.v1";
pub const MAX_AUTHORIZATION_OBJECT_BYTES: usize = 3 * 1024;
pub const MAX_AUTHORIZATION_ENVELOPE_BYTES: usize = 16 * 1024;
pub const MAX_INTERNAL_REPORT_BYTES: usize = 32 * 1024;
pub const MAX_SESSION_EXPORT_BYTES: usize = 512 * 1024;
pub const MAX_FIELD_SCALARS: usize = 256;
pub const MAX_LAB002_LOAD_COMMAND_BYTES: u32 = 4 * 1024 * 1024;
pub const MAX_LAB002_EXECUTABLE_BYTES: u64 = 100 * 1024 * 1024;
const MAX_JCS_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TARGET_IDENTIFIER_BYTES: usize = 255;
const MAX_FIXUP_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;
const MAX_ENTITLEMENTS_EVENTS: u64 = 1_024;
const MAX_ENTITLEMENTS_DEPTH: u64 = 16;
const MAX_ENTITLEMENTS_COLLECTION_ITEMS: u64 = 256;
const MAX_ENTITLEMENTS_ROOT_KEYS: u64 = 128;
const MAX_ENTITLEMENTS_KEY_BYTES: u64 = 256;
const MAX_ENTITLEMENTS_SCALAR_BYTES: u64 = 64 * 1024;
const MAX_APPLICATION_GROUPS: u64 = 16;
const MAX_ENTITLEMENTS_BINARY_OBJECTS: u64 = MAX_ENTITLEMENTS_EVENTS;
const FIXUP_LAYOUT_DOMAIN: &[u8] = b"orchardprobe.lab002.fixup-layout.v1\0";
const LC_DYSYMTAB: u32 = 0x0b;
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
const SECTION_TYPE_MASK: u32 = 0xff;
const S_ZEROFILL: u32 = 0x01;
const S_GB_ZEROFILL: u32 = 0x0c;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;

fn is_zero_fill_section(flags: u32) -> bool {
    matches!(
        flags & SECTION_TYPE_MASK,
        S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
    )
}

/// The closed DemoLab executable-role order used by every LAB-002 binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabRole {
    MainApp,
    Framework,
    ShareExtension,
}

impl LabRole {
    pub const ALL: [Self; 3] = [Self::MainApp, Self::Framework, Self::ShareExtension];

    pub const fn fixture_relative_path(self) -> &'static str {
        match self {
            Self::MainApp => "DemoLab.app/DemoLab",
            Self::Framework => "DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework",
            Self::ShareExtension => {
                "DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension"
            }
        }
    }

    fn binding_byte(self) -> u8 {
        match self {
            Self::MainApp => 1,
            Self::Framework => 2,
            Self::ShareExtension => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildBindingInput {
    pub source_commit: String,
    pub marketing_version: String,
    pub build_number: String,
    pub configuration: String,
    pub observer_revision: String,
    pub authorized_target_manifest_sha256: String,
    pub xcode_version: String,
    pub xcode_build: String,
    pub iphoneos_sdk_version: String,
    pub iphoneos_sdk_build: String,
    pub xcodegen_version: String,
    pub xcodegen_architecture: String,
    pub xcodegen_executable_sha256: String,
    pub fastlane_version: String,
    pub gemfile_lock_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntitlementValue {
    RequiredAbsent,
    Present(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppGroups {
    RequiredAbsent,
    Present(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetIdentityInput {
    pub identity_nonce_hex: String,
    pub role: LabRole,
    pub bundle_id: String,
    pub code_directory_identifier: String,
    pub code_directory_team_identifier: String,
    pub application_identifier: EntitlementValue,
    pub developer_team_identifier: EntitlementValue,
    pub app_groups: AppGroups,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInstallationInput {
    pub identity_nonce_hex: String,
    pub enrollment_public_key_hex: String,
    pub installation_nonce_hex: String,
    pub identifier_for_vendor: String,
    pub hardware_model: String,
    pub ios_product_version: String,
    pub ios_build: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Lab002Error {
    #[error("{field} must be exactly {bytes} lowercase-hex bytes")]
    InvalidHex { field: &'static str, bytes: usize },
    #[error("{field} is empty, too long, not NFC, or contains a forbidden scalar")]
    InvalidText { field: &'static str },
    #[error("{field} does not satisfy its closed LAB-002 grammar")]
    InvalidFieldGrammar { field: &'static str },
    #[error("configuration must be exactly Release")]
    InvalidConfiguration,
    #[error("app groups must be non-empty, unique, and already sorted by UTF-8 bytes")]
    InvalidAppGroups,
    #[error("target identity set must contain exactly one digest for each role in fixed order")]
    InvalidTargetIdentitySet,
    #[error("canonical JSON exceeds its {maximum}-byte limit")]
    CanonicalJsonTooLarge { maximum: usize },
    #[error("JSON is invalid, contains duplicate keys, or has trailing data")]
    InvalidJson,
    #[error("JSON contains a non-integer number or an integer outside the JCS safe range")]
    NonIntegerJsonNumber,
    #[error("JSON contains non-NFC or forbidden text")]
    InvalidJsonText,
    #[error("JSON is not the exact RFC-8785 canonical encoding")]
    NonCanonicalJson,
    #[error("authorization key or signature has an invalid length or encoding")]
    InvalidSignatureEncoding,
    #[error("authorization key id does not match the raw public key")]
    AuthorizationKeyIdMismatch,
    #[error("authorization signature is invalid")]
    InvalidAuthorizationSignature,
    #[error("authorization policy, scope, operation, time window, or one-time binding is invalid")]
    InvalidAuthorizationScope,
    #[error("LAB-002 evidence is incomplete or contradictory: {0}")]
    InvalidEvidence(&'static str),
    #[error("LAB-002 Mach-O is invalid: {0}")]
    InvalidMachO(String),
    #[error("I/O error while reading LAB-002 Mach-O: {0}")]
    Io(String),
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}

fn decode_hex<const N: usize>(field: &'static str, value: &str) -> Result<[u8; N], Lab002Error> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Lab002Error::InvalidHex { field, bytes: N });
    }
    let mut output = [0_u8; N];
    for (index, slot) in output.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2]);
        let low = hex_nibble(value.as_bytes()[index * 2 + 1]);
        *slot = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lowercase hex"),
    }
}

fn valid_text(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    if value.is_empty()
        || value.chars().count() > MAX_FIELD_SCALARS
        || value.nfc().ne(value.chars())
        || value
            .chars()
            .any(|scalar| scalar == '\0' || scalar.is_control())
    {
        return Err(Lab002Error::InvalidText { field });
    }
    Ok(())
}

fn validate_identifier_for_vendor(value: &str) -> Result<(), Lab002Error> {
    if value.len() != 36 || value == "00000000-0000-0000-0000-000000000000" {
        return Err(Lab002Error::InvalidFieldGrammar {
            field: "identifier_for_vendor",
        });
    }
    for (index, byte) in value.bytes().enumerate() {
        let expected_hyphen = matches!(index, 8 | 13 | 18 | 23);
        if (expected_hyphen && byte != b'-')
            || !(expected_hyphen || byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Lab002Error::InvalidFieldGrammar {
                field: "identifier_for_vendor",
            });
        }
    }
    Ok(())
}

fn validate_ascii_token(
    field: &'static str,
    value: &str,
    punctuation: &[u8],
) -> Result<(), Lab002Error> {
    valid_text(field, value)?;
    if value.len() > 32
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !punctuation.contains(&byte))
    {
        return Err(Lab002Error::InvalidFieldGrammar { field });
    }
    Ok(())
}

fn validate_device_environment(
    hardware_model: &str,
    ios_product_version: &str,
    ios_build: &str,
) -> Result<(), Lab002Error> {
    validate_ascii_token("hardware_model", hardware_model, b",")?;
    let Some((family, model)) = hardware_model.split_once(',') else {
        return Err(Lab002Error::InvalidFieldGrammar {
            field: "hardware_model",
        });
    };
    if family.is_empty()
        || model.is_empty()
        || !family.bytes().all(|byte| byte.is_ascii_alphanumeric())
        || !model.bytes().all(|byte| byte.is_ascii_digit())
        || hardware_model.matches(',').count() != 1
    {
        return Err(Lab002Error::InvalidFieldGrammar {
            field: "hardware_model",
        });
    }

    validate_ascii_token("ios_product_version", ios_product_version, b".")?;
    if ios_product_version
        .split('.')
        .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(Lab002Error::InvalidFieldGrammar {
            field: "ios_product_version",
        });
    }

    validate_ascii_token("ios_build", ios_build, b"")?;
    if !ios_build.bytes().any(|byte| byte.is_ascii_uppercase())
        || ios_build.bytes().any(|byte| byte.is_ascii_lowercase())
    {
        return Err(Lab002Error::InvalidFieldGrammar { field: "ios_build" });
    }
    Ok(())
}

fn validate_dotted_numeric_version(
    field: &'static str,
    value: &str,
    maximum_components: usize,
) -> Result<(), Lab002Error> {
    validate_ascii_token(field, value, b".")?;
    let mut components = 0_usize;
    for component in value.split('.') {
        components += 1;
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(Lab002Error::InvalidFieldGrammar { field });
        }
    }
    if components > maximum_components {
        return Err(Lab002Error::InvalidFieldGrammar { field });
    }
    Ok(())
}

fn validate_apple_build(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    validate_ascii_token(field, value, b"")?;
    if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_digit())
        || !value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value.bytes().any(|byte| byte.is_ascii_lowercase())
    {
        return Err(Lab002Error::InvalidFieldGrammar { field });
    }
    Ok(())
}

fn validate_observer_revision(value: &str) -> Result<(), Lab002Error> {
    const FIELD: &str = "observer_revision";
    validate_ascii_token(FIELD, value, b"-._")?;
    if !value
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        || !value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(Lab002Error::InvalidFieldGrammar { field: FIELD });
    }
    Ok(())
}

fn validate_build_fields(input: &BuildBindingInput) -> Result<(), Lab002Error> {
    validate_dotted_numeric_version("marketing_version", &input.marketing_version, 3)?;
    validate_dotted_numeric_version("build_number", &input.build_number, 3)?;
    validate_observer_revision(&input.observer_revision)?;
    validate_dotted_numeric_version("xcode_version", &input.xcode_version, 4)?;
    validate_apple_build("xcode_build", &input.xcode_build)?;
    validate_dotted_numeric_version("iphoneos_sdk_version", &input.iphoneos_sdk_version, 4)?;
    validate_apple_build("iphoneos_sdk_build", &input.iphoneos_sdk_build)?;
    validate_dotted_numeric_version("xcodegen_version", &input.xcodegen_version, 4)?;
    if !matches!(input.xcodegen_architecture.as_str(), "arm64" | "x86_64") {
        return Err(Lab002Error::InvalidFieldGrammar {
            field: "xcodegen_architecture",
        });
    }
    validate_dotted_numeric_version("fastlane_version", &input.fastlane_version, 4)?;
    Ok(())
}

fn validate_bundle_identifier(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    valid_text(field, value)?;
    if value.len() > MAX_TARGET_IDENTIFIER_BYTES
        || !value.is_ascii()
        || value.split('.').any(|component| {
            component.is_empty()
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(Lab002Error::InvalidFieldGrammar { field });
    }
    Ok(())
}

fn validate_team_identifier(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    valid_text(field, value)?;
    if value.len() != 10
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
    {
        return Err(Lab002Error::InvalidFieldGrammar { field });
    }
    Ok(())
}

fn validate_target_identity(input: &TargetIdentityInput) -> Result<(), Lab002Error> {
    validate_bundle_identifier("bundle_id", &input.bundle_id)?;
    validate_bundle_identifier(
        "code_directory_identifier",
        &input.code_directory_identifier,
    )?;
    validate_team_identifier(
        "code_directory_team_identifier",
        &input.code_directory_team_identifier,
    )?;
    if let EntitlementValue::Present(value) = &input.application_identifier {
        let expected = format!(
            "{}.{}",
            input.code_directory_team_identifier, input.bundle_id
        );
        if value != &expected {
            return Err(Lab002Error::InvalidFieldGrammar {
                field: "application_identifier",
            });
        }
    }
    if let EntitlementValue::Present(value) = &input.developer_team_identifier {
        validate_team_identifier("developer_team_identifier", value)?;
        if value != &input.code_directory_team_identifier {
            return Err(Lab002Error::InvalidFieldGrammar {
                field: "developer_team_identifier",
            });
        }
    }
    if let AppGroups::Present(groups) = &input.app_groups {
        if groups.is_empty()
            || groups
                .windows(2)
                .any(|pair| pair[0].as_bytes().cmp(pair[1].as_bytes()) != Ordering::Less)
        {
            return Err(Lab002Error::InvalidAppGroups);
        }
        for group in groups {
            let Some(identifier) = group.strip_prefix("group.") else {
                return Err(Lab002Error::InvalidFieldGrammar {
                    field: "application_group",
                });
            };
            validate_bundle_identifier("application_group", identifier)?;
            if group.len() > MAX_TARGET_IDENTIFIER_BYTES {
                return Err(Lab002Error::InvalidFieldGrammar {
                    field: "application_group",
                });
            }
        }
    }
    Ok(())
}

fn append_framed(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &str,
) -> Result<(), Lab002Error> {
    valid_text(field, value)?;
    let size = u32::try_from(value.len()).map_err(|_| Lab002Error::InvalidText { field })?;
    output.extend_from_slice(&size.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

pub fn build_binding_sha256(input: &BuildBindingInput) -> Result<String, Lab002Error> {
    if input.configuration != "Release" {
        return Err(Lab002Error::InvalidConfiguration);
    }
    validate_build_fields(input)?;
    decode_hex::<20>("source_commit", &input.source_commit)?;
    decode_hex::<32>(
        "authorized_target_manifest_sha256",
        &input.authorized_target_manifest_sha256,
    )?;
    decode_hex::<32>(
        "xcodegen_executable_sha256",
        &input.xcodegen_executable_sha256,
    )?;
    decode_hex::<32>("gemfile_lock_sha256", &input.gemfile_lock_sha256)?;

    let mut bytes = Vec::with_capacity(1024);
    bytes.extend_from_slice(BUILD_BINDING_DOMAIN);
    for (field, value) in [
        ("source_commit", input.source_commit.as_str()),
        ("marketing_version", input.marketing_version.as_str()),
        ("build_number", input.build_number.as_str()),
        ("configuration", input.configuration.as_str()),
        ("observer_revision", input.observer_revision.as_str()),
        (
            "authorized_target_manifest_sha256",
            input.authorized_target_manifest_sha256.as_str(),
        ),
        ("xcode_version", input.xcode_version.as_str()),
        ("xcode_build", input.xcode_build.as_str()),
        ("iphoneos_sdk_version", input.iphoneos_sdk_version.as_str()),
        ("iphoneos_sdk_build", input.iphoneos_sdk_build.as_str()),
        ("xcodegen_version", input.xcodegen_version.as_str()),
        (
            "xcodegen_architecture",
            input.xcodegen_architecture.as_str(),
        ),
        (
            "xcodegen_executable_sha256",
            input.xcodegen_executable_sha256.as_str(),
        ),
        ("fastlane_version", input.fastlane_version.as_str()),
        ("gemfile_lock_sha256", input.gemfile_lock_sha256.as_str()),
    ] {
        append_framed(&mut bytes, field, value)?;
    }
    Ok(sha256_hex(&bytes))
}

fn append_entitlement(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &EntitlementValue,
) -> Result<(), Lab002Error> {
    match value {
        EntitlementValue::RequiredAbsent => output.push(0),
        EntitlementValue::Present(value) => {
            output.push(1);
            append_framed(output, field, value)?;
        }
    }
    Ok(())
}

pub fn target_identity_binding_sha256(input: &TargetIdentityInput) -> Result<String, Lab002Error> {
    let nonce = decode_hex::<32>("identity_nonce_hex", &input.identity_nonce_hex)?;
    validate_target_identity(input)?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(TARGET_IDENTITY_DOMAIN);
    bytes.extend_from_slice(&nonce);
    bytes.push(input.role.binding_byte());
    append_framed(&mut bytes, "bundle_id", &input.bundle_id)?;
    append_framed(
        &mut bytes,
        "code_directory_identifier",
        &input.code_directory_identifier,
    )?;
    append_framed(
        &mut bytes,
        "code_directory_team_identifier",
        &input.code_directory_team_identifier,
    )?;
    append_entitlement(
        &mut bytes,
        "application_identifier",
        &input.application_identifier,
    )?;
    append_entitlement(
        &mut bytes,
        "developer_team_identifier",
        &input.developer_team_identifier,
    )?;
    match &input.app_groups {
        AppGroups::RequiredAbsent => bytes.push(0),
        AppGroups::Present(groups) => {
            bytes.push(1);
            let count = u32::try_from(groups.len()).map_err(|_| Lab002Error::InvalidAppGroups)?;
            bytes.extend_from_slice(&count.to_be_bytes());
            for group in groups {
                append_framed(&mut bytes, "application_group", group)?;
            }
        }
    }
    Ok(sha256_hex(&bytes))
}

pub fn target_identity_set_sha256(
    ordered_digests: &[(LabRole, String)],
) -> Result<String, Lab002Error> {
    if ordered_digests.len() != LabRole::ALL.len()
        || ordered_digests
            .iter()
            .zip(LabRole::ALL)
            .any(|((actual, _), expected)| *actual != expected)
    {
        return Err(Lab002Error::InvalidTargetIdentitySet);
    }
    let mut bytes = Vec::with_capacity(TARGET_IDENTITY_SET_DOMAIN.len() + 96);
    bytes.extend_from_slice(TARGET_IDENTITY_SET_DOMAIN);
    for (_, digest) in ordered_digests {
        bytes.extend_from_slice(&decode_hex::<32>("target_identity_sha256", digest)?);
    }
    Ok(sha256_hex(&bytes))
}

pub fn device_installation_binding_sha256(
    input: &DeviceInstallationInput,
) -> Result<String, Lab002Error> {
    let nonce = decode_hex::<32>("identity_nonce_hex", &input.identity_nonce_hex)?;
    let public_key = decode_hex::<32>(
        "enrollment_public_key_hex",
        &input.enrollment_public_key_hex,
    )?;
    let installation_nonce =
        decode_hex::<32>("installation_nonce_hex", &input.installation_nonce_hex)?;
    validate_identifier_for_vendor(&input.identifier_for_vendor)?;
    validate_device_environment(
        &input.hardware_model,
        &input.ios_product_version,
        &input.ios_build,
    )?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(DEVICE_INSTALLATION_DOMAIN);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&public_key);
    bytes.extend_from_slice(&installation_nonce);
    for (field, value) in [
        (
            "identifier_for_vendor",
            input.identifier_for_vendor.as_str(),
        ),
        ("hardware_model", input.hardware_model.as_str()),
        ("ios_product_version", input.ios_product_version.as_str()),
        ("ios_build", input.ios_build.as_str()),
    ] {
        append_framed(&mut bytes, field, value)?;
    }
    Ok(sha256_hex(&bytes))
}

fn utf16_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn validate_json_string(value: &str) -> Result<(), Lab002Error> {
    if value.nfc().ne(value.chars())
        || value
            .chars()
            .any(|scalar| scalar == '\0' || scalar.is_control())
    {
        return Err(Lab002Error::InvalidJsonText);
    }
    Ok(())
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), Lab002Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => {
            let safe = number
                .as_i64()
                .map(|value| value.unsigned_abs() <= MAX_JCS_SAFE_INTEGER)
                .or_else(|| number.as_u64().map(|value| value <= MAX_JCS_SAFE_INTEGER));
            if safe != Some(true) {
                return Err(Lab002Error::NonIntegerJsonNumber);
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(string) => {
            validate_json_string(string)?;
            output.extend_from_slice(
                serde_json::to_string(string)
                    .map_err(|_| Lab002Error::InvalidJson)?
                    .as_bytes(),
            );
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(item, output)?;
            }
            output.push(b']');
        }
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| utf16_order(left, right));
            output.push(b'{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                validate_json_string(key)?;
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|_| Lab002Error::InvalidJson)?
                        .as_bytes(),
                );
                output.push(b':');
                write_canonical(item, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub fn canonical_json_with_limit<T: Serialize>(
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, Lab002Error> {
    let value = serde_json::to_value(value).map_err(|_| Lab002Error::InvalidJson)?;
    let mut output = Vec::new();
    write_canonical(&value, &mut output)?;
    if output.len() > maximum {
        return Err(Lab002Error::CanonicalJsonTooLarge { maximum });
    }
    Ok(output)
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Lab002Error> {
    canonical_json_with_limit(value, MAX_INTERNAL_REPORT_BYTES)
}

fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), Lab002Error> {
    struct DuplicateVisitor;
    impl<'de> serde::de::Visitor<'de> for DuplicateVisitor {
        type Value = ();

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("duplicate-free JSON")
        }
        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_string<E>(self, _: String) -> Result<(), E> {
            Ok(())
        }
        fn visit_none<E>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_some<D>(self, deserializer: D) -> Result<(), D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(DuplicateVisitor)
        }
        fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            while sequence.next_element_seed(DuplicateSeed)?.is_some() {}
            Ok(())
        }
        fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut keys = HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key) {
                    return Err(serde::de::Error::custom("duplicate object key"));
                }
                map.next_value_seed(DuplicateSeed)?;
            }
            Ok(())
        }
    }
    struct DuplicateSeed;
    impl<'de> serde::de::DeserializeSeed<'de> for DuplicateSeed {
        type Value = ();
        fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(DuplicateVisitor)
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    serde::de::DeserializeSeed::deserialize(DuplicateSeed, &mut deserializer)
        .and_then(|_| deserializer.end())
        .map_err(|_| Lab002Error::InvalidJson)
}

pub fn decode_canonical_json_with_limit<T: DeserializeOwned>(
    bytes: &[u8],
    maximum: usize,
) -> Result<T, Lab002Error> {
    if bytes.len() > maximum {
        return Err(Lab002Error::CanonicalJsonTooLarge { maximum });
    }
    reject_duplicate_keys(bytes)?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| Lab002Error::InvalidJson)?;
    let mut encoded = Vec::new();
    write_canonical(&value, &mut encoded)?;
    if encoded != bytes {
        return Err(Lab002Error::NonCanonicalJson);
    }
    serde_json::from_value(value).map_err(|_| Lab002Error::InvalidJson)
}

pub fn decode_canonical_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Lab002Error> {
    decode_canonical_json_with_limit(bytes, MAX_INTERNAL_REPORT_BYTES)
}

fn authorized_operation_message(
    acknowledgement: &[u8],
    operation_core: &[u8],
) -> Result<Vec<u8>, Lab002Error> {
    let acknowledgement_size =
        u32::try_from(acknowledgement.len()).map_err(|_| Lab002Error::InvalidAuthorizationScope)?;
    let operation_size =
        u32::try_from(operation_core.len()).map_err(|_| Lab002Error::InvalidAuthorizationScope)?;
    let mut message = Vec::with_capacity(
        AUTHORIZED_OPERATION_DOMAIN.len() + 8 + acknowledgement.len() + operation_core.len(),
    );
    message.extend_from_slice(AUTHORIZED_OPERATION_DOMAIN);
    message.extend_from_slice(&acknowledgement_size.to_be_bytes());
    message.extend_from_slice(acknowledgement);
    message.extend_from_slice(&operation_size.to_be_bytes());
    message.extend_from_slice(operation_core);
    Ok(message)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationEnvelope {
    pub profile: String,
    pub authorization_key_id: String,
    pub acknowledgement_canonical: String,
    pub operation_core_canonical: String,
    pub signature_hex: String,
}

pub fn sign_authorized_operation(
    signing_key: &SigningKey,
    acknowledgement: &[u8],
    operation_core: &[u8],
) -> Result<AuthorizationEnvelope, Lab002Error> {
    decode_canonical_json_with_limit::<Value>(acknowledgement, MAX_AUTHORIZATION_OBJECT_BYTES)?;
    decode_canonical_json_with_limit::<Value>(operation_core, MAX_AUTHORIZATION_OBJECT_BYTES)?;
    let message = authorized_operation_message(acknowledgement, operation_core)?;
    let verifying_key = signing_key.verifying_key();
    if verifying_key.is_weak() {
        return Err(Lab002Error::InvalidSignatureEncoding);
    }
    let key_id = sha256_hex(verifying_key.as_bytes());
    let signature = signing_key.sign(&message);
    let envelope = AuthorizationEnvelope {
        profile: LAB002_PROFILE.to_owned(),
        authorization_key_id: key_id,
        acknowledgement_canonical: String::from_utf8(acknowledgement.to_vec())
            .map_err(|_| Lab002Error::InvalidJson)?,
        operation_core_canonical: String::from_utf8(operation_core.to_vec())
            .map_err(|_| Lab002Error::InvalidJson)?,
        signature_hex: lower_hex(&signature.to_bytes()),
    };
    canonical_json_with_limit(&envelope, MAX_AUTHORIZATION_ENVELOPE_BYTES)?;
    Ok(envelope)
}

pub fn verify_authorized_operation<A: DeserializeOwned, O: DeserializeOwned>(
    envelope_bytes: &[u8],
    public_key_hex: &str,
) -> Result<(A, O), Lab002Error> {
    let envelope = decode_canonical_json_with_limit::<AuthorizationEnvelope>(
        envelope_bytes,
        MAX_AUTHORIZATION_ENVELOPE_BYTES,
    )?;
    verify_authorized_operation_envelope(&envelope, public_key_hex)
}

fn verify_authorized_operation_envelope<A: DeserializeOwned, O: DeserializeOwned>(
    envelope: &AuthorizationEnvelope,
    public_key_hex: &str,
) -> Result<(A, O), Lab002Error> {
    if envelope.profile != LAB002_PROFILE {
        return Err(Lab002Error::InvalidAuthorizationScope);
    }
    let public_key = decode_hex::<32>("authorization_public_key", public_key_hex)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| Lab002Error::InvalidSignatureEncoding)?;
    if verifying_key.is_weak() {
        return Err(Lab002Error::InvalidSignatureEncoding);
    }
    if envelope.authorization_key_id != sha256_hex(&public_key) {
        return Err(Lab002Error::AuthorizationKeyIdMismatch);
    }
    let signature_bytes = decode_hex::<64>("authorization_signature", &envelope.signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let acknowledgement_bytes = envelope.acknowledgement_canonical.as_bytes();
    let operation_bytes = envelope.operation_core_canonical.as_bytes();
    let acknowledgement = decode_canonical_json_with_limit::<A>(
        acknowledgement_bytes,
        MAX_AUTHORIZATION_OBJECT_BYTES,
    )?;
    let operation =
        decode_canonical_json_with_limit::<O>(operation_bytes, MAX_AUTHORIZATION_OBJECT_BYTES)?;
    let message = authorized_operation_message(acknowledgement_bytes, operation_bytes)?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| Lab002Error::InvalidAuthorizationSignature)?;
    Ok((acknowledgement, operation))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAcknowledgement {
    pub profile: String,
    pub policy_version: String,
    pub acknowledgement_id: String,
    pub operation: AuthorizedOperation,
    pub experiment_id: String,
    pub not_before: i64,
    pub not_after: i64,
    pub owns_target: bool,
    pub owns_device: bool,
    pub no_third_party_data: bool,
    pub accepts_retention_policy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizedOperation {
    #[serde(rename = "install_and_enroll_exact_build")]
    InstallAndEnrollExactBuild,
    #[serde(rename = "collect_fixed_range_run")]
    CollectFixedRangeRun,
}

impl AuthorizationAcknowledgement {
    pub fn validate(&self, expected_operation: AuthorizedOperation) -> Result<(), Lab002Error> {
        if self.profile != LAB002_PROFILE
            || self.policy_version != AUTHORIZATION_POLICY_VERSION
            || self.operation != expected_operation
            || self.not_after.checked_sub(self.not_before) != Some(900)
            || !self.owns_target
            || !self.owns_device
            || !self.no_third_party_data
            || !self.accepts_retention_policy
        {
            return Err(Lab002Error::InvalidAuthorizationScope);
        }
        decode_hex::<32>("experiment_id", &self.experiment_id)?;
        decode_hex::<32>("acknowledgement_id", &self.acknowledgement_id)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabSignaturePresence {
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabSignatureKind {
    Cms,
    AdHoc,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabSignatureValidation {
    Valid,
    Invalid,
    NotChecked,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabSignature {
    pub presence: LabSignaturePresence,
    pub kind: LabSignatureKind,
    pub validation: LabSignatureValidation,
    pub validator_id: String,
    pub validator_revision: String,
    pub superblob_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleSlice {
    pub ordinal: u8,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub macho_uuid: String,
    pub slice_file_offset: u64,
    pub slice_file_size: u64,
    pub section_slice_offset: u64,
    pub section_file_offset: u64,
    pub section_vm_offset: u64,
    pub section_length: u64,
    pub expected_plaintext_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleRole {
    pub role: LabRole,
    pub fixture_relative_path: String,
    pub target_identity_binding_sha256: String,
    pub slices: Vec<OracleSlice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabOracle {
    pub profile: String,
    pub source_commit: String,
    pub marketing_version: String,
    pub build_number: String,
    pub observer_revision: String,
    pub build_binding_sha256: String,
    pub authorized_target_manifest_sha256: String,
    pub ipa_sha256: String,
    pub roles: Vec<OracleRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedSlice {
    pub ordinal: u8,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub macho_uuid: String,
    pub slice_file_offset: u64,
    pub slice_file_size: u64,
    pub section_slice_offset: u64,
    pub section_file_offset: u64,
    pub section_vm_offset: u64,
    pub section_length: u64,
    pub cryptoff: u64,
    pub cryptsize: u64,
    pub cryptid: u32,
    pub encryption_covers_section: bool,
    pub disk_sha256: String,
    pub mapped_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleReport {
    pub profile: String,
    pub collection_id: String,
    pub session_id: String,
    pub run_ordinal: u8,
    pub run_counter: String,
    pub challenge_sha256: String,
    pub authorization_policy_version: String,
    pub acknowledgement_sha256: String,
    pub authorization_envelope_sha256: String,
    pub enrollment_binding_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub hardware_model: String,
    pub ios_product_version: String,
    pub ios_build: String,
    pub source_commit: String,
    pub marketing_version: String,
    pub build_number: String,
    pub observer_revision: String,
    pub build_binding_sha256: String,
    pub role: LabRole,
    pub fixture_relative_path: String,
    pub target_identity_binding_sha256: String,
    pub signature: LabSignature,
    pub disk_phase_completed_at: i64,
    pub mapped_phase_completed_at: i64,
    pub slices: Vec<ObservedSlice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabRun {
    pub profile: String,
    pub collection_id: String,
    pub session_id: String,
    pub run_ordinal: u8,
    pub run_counter: String,
    pub challenge_sha256: String,
    pub authorization_policy_version: String,
    pub acknowledgement_sha256: String,
    pub authorization_envelope_sha256: String,
    pub enrollment_binding_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub hardware_model: String,
    pub ios_product_version: String,
    pub ios_build: String,
    pub source_commit: String,
    pub marketing_version: String,
    pub build_number: String,
    pub observer_revision: String,
    pub build_binding_sha256: String,
    pub authorization_not_before: i64,
    pub authorization_not_after: i64,
    pub created_at: i64,
    pub completed_at: i64,
    pub prior_collection_binding_sha256: Option<String>,
    pub collection_binding_sha256: String,
    pub reports: Vec<RoleReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFreeVerification {
    pub profile: String,
    pub status: DeviceFreeVerificationStatus,
    pub normalized_evidence_sha256: String,
}

/// A successful result proves only that closed synthetic/device-free evidence
/// obeyed the LAB-002 comparison contract. It is deliberately not named Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceFreeVerificationStatus {
    ConsistentSyntheticEvidence,
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    decode_hex::<32>(field, value).map(|_| ())
}

fn decode_counter(value: &str) -> Result<u64, Lab002Error> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Lab002Error::InvalidEvidence(
            "run counter is not fixed-width lowercase hex",
        ));
    }
    u64::from_str_radix(value, 16)
        .map_err(|_| Lab002Error::InvalidEvidence("run counter is invalid"))
}

fn validate_oracle(oracle: &LabOracle) -> Result<(), Lab002Error> {
    if oracle.profile != LAB002_PROFILE
        || oracle.roles.len() != LabRole::ALL.len()
        || oracle
            .roles
            .iter()
            .zip(LabRole::ALL)
            .any(|(role, expected)| role.role != expected)
    {
        return Err(Lab002Error::InvalidEvidence(
            "oracle profile or role inventory is invalid",
        ));
    }
    decode_hex::<20>("oracle_source_commit", &oracle.source_commit)?;
    validate_dotted_numeric_version("marketing_version", &oracle.marketing_version, 3)?;
    validate_dotted_numeric_version("build_number", &oracle.build_number, 3)?;
    validate_observer_revision(&oracle.observer_revision)?;
    for (field, digest) in [
        ("build_binding_sha256", &oracle.build_binding_sha256),
        (
            "authorized_target_manifest_sha256",
            &oracle.authorized_target_manifest_sha256,
        ),
        ("ipa_sha256", &oracle.ipa_sha256),
    ] {
        validate_digest(field, digest)?;
    }
    for (role, expected_role) in oracle.roles.iter().zip(LabRole::ALL) {
        if role.role != expected_role
            || role.fixture_relative_path != expected_role.fixture_relative_path()
            || role.slices.is_empty()
            || role.slices.len() > 4
        {
            return Err(Lab002Error::InvalidEvidence(
                "oracle role path or slice inventory is invalid",
            ));
        }
        validate_digest(
            "target_identity_binding_sha256",
            &role.target_identity_binding_sha256,
        )?;
        let mut previous_slice_end = 0_u64;
        for (index, slice) in role.slices.iter().enumerate() {
            if usize::from(slice.ordinal) != index || !(64..=1024).contains(&slice.section_length) {
                return Err(Lab002Error::InvalidEvidence(
                    "oracle slice ordinal or range length is invalid",
                ));
            }
            decode_hex::<16>("macho_uuid", &slice.macho_uuid)?;
            validate_digest(
                "expected_plaintext_sha256",
                &slice.expected_plaintext_sha256,
            )?;
            let slice_end = slice
                .slice_file_offset
                .checked_add(slice.slice_file_size)
                .ok_or(Lab002Error::InvalidEvidence(
                    "oracle slice file range overflows",
                ))?;
            let section_slice_end = slice
                .section_slice_offset
                .checked_add(slice.section_length)
                .ok_or(Lab002Error::InvalidEvidence(
                    "oracle section slice range overflows",
                ))?;
            let section_file_end = slice
                .section_file_offset
                .checked_add(slice.section_length)
                .ok_or(Lab002Error::InvalidEvidence(
                    "oracle section file range overflows",
                ))?;
            slice
                .section_vm_offset
                .checked_add(slice.section_length)
                .ok_or(Lab002Error::InvalidEvidence(
                    "oracle section VM range overflows",
                ))?;
            if slice.slice_file_size == 0
                || (index != 0 && slice.slice_file_offset < previous_slice_end)
                || slice.slice_file_offset > MAX_JCS_SAFE_INTEGER
                || slice.slice_file_size > MAX_JCS_SAFE_INTEGER
                || slice_end > MAX_JCS_SAFE_INTEGER
                || section_slice_end > slice.slice_file_size
                || slice
                    .slice_file_offset
                    .checked_add(slice.section_slice_offset)
                    != Some(slice.section_file_offset)
                || section_file_end > slice_end
            {
                return Err(Lab002Error::InvalidEvidence(
                    "oracle slice extent or section coordinate is invalid",
                ));
            }
            previous_slice_end = slice_end;
        }
    }
    Ok(())
}

fn validate_report_against_run(report: &RoleReport, run: &LabRun) -> Result<(), Lab002Error> {
    if report.profile != LAB002_PROFILE
        || report.collection_id != run.collection_id
        || report.session_id != run.session_id
        || report.run_ordinal != run.run_ordinal
        || report.run_counter != run.run_counter
        || report.challenge_sha256 != run.challenge_sha256
        || report.authorization_policy_version != run.authorization_policy_version
        || report.acknowledgement_sha256 != run.acknowledgement_sha256
        || report.authorization_envelope_sha256 != run.authorization_envelope_sha256
        || report.enrollment_binding_sha256 != run.enrollment_binding_sha256
        || report.enrollment_public_key != run.enrollment_public_key
        || report.device_installation_binding_sha256 != run.device_installation_binding_sha256
        || report.hardware_model != run.hardware_model
        || report.ios_product_version != run.ios_product_version
        || report.ios_build != run.ios_build
        || report.source_commit != run.source_commit
        || report.marketing_version != run.marketing_version
        || report.build_number != run.build_number
        || report.observer_revision != run.observer_revision
        || report.build_binding_sha256 != run.build_binding_sha256
    {
        return Err(Lab002Error::InvalidEvidence(
            "role report does not match its immutable session",
        ));
    }
    if report.disk_phase_completed_at < run.created_at
        || report.mapped_phase_completed_at < report.disk_phase_completed_at
        || report.mapped_phase_completed_at > run.completed_at
    {
        return Err(Lab002Error::InvalidEvidence(
            "disk and mapped phases are not ordered inside the session",
        ));
    }
    Ok(())
}

fn validate_run(oracle: &LabOracle, run: &LabRun, ordinal: u8) -> Result<(), Lab002Error> {
    let authorization_earliest =
        run.authorization_not_before
            .checked_sub(120)
            .ok_or(Lab002Error::InvalidEvidence(
                "authorization skew window underflows",
            ))?;
    let authorization_latest =
        run.authorization_not_after
            .checked_add(120)
            .ok_or(Lab002Error::InvalidEvidence(
                "authorization skew window overflows",
            ))?;
    if run.profile != LAB002_PROFILE
        || run.run_ordinal != ordinal
        || run.authorization_policy_version != AUTHORIZATION_POLICY_VERSION
        || decode_counter(&run.run_counter)? != u64::from(ordinal)
        || run
            .authorization_not_after
            .checked_sub(run.authorization_not_before)
            != Some(900)
        || run.created_at < authorization_earliest
        || run.completed_at > authorization_latest
        || run.created_at > run.completed_at
        || run.source_commit != oracle.source_commit
        || run.marketing_version != oracle.marketing_version
        || run.build_number != oracle.build_number
        || run.observer_revision != oracle.observer_revision
        || run.build_binding_sha256 != oracle.build_binding_sha256
        || run.reports.len() != LabRole::ALL.len()
    {
        return Err(Lab002Error::InvalidEvidence(
            "run control or build binding is invalid",
        ));
    }
    for (field, digest) in [
        ("collection_id", &run.collection_id),
        ("session_id", &run.session_id),
        ("challenge_sha256", &run.challenge_sha256),
        ("acknowledgement_sha256", &run.acknowledgement_sha256),
        (
            "authorization_envelope_sha256",
            &run.authorization_envelope_sha256,
        ),
        ("enrollment_binding_sha256", &run.enrollment_binding_sha256),
        (
            "device_installation_binding_sha256",
            &run.device_installation_binding_sha256,
        ),
        ("collection_binding_sha256", &run.collection_binding_sha256),
    ] {
        validate_digest(field, digest)?;
    }
    decode_hex::<32>("enrollment_public_key", &run.enrollment_public_key)?;
    validate_device_environment(
        &run.hardware_model,
        &run.ios_product_version,
        &run.ios_build,
    )?;

    for ((report, oracle_role), expected_role) in
        run.reports.iter().zip(&oracle.roles).zip(LabRole::ALL)
    {
        validate_report_against_run(report, run)?;
        if report.role != expected_role
            || report.role != oracle_role.role
            || report.fixture_relative_path != oracle_role.fixture_relative_path
            || report.target_identity_binding_sha256 != oracle_role.target_identity_binding_sha256
            || report.slices.len() != oracle_role.slices.len()
        {
            return Err(Lab002Error::InvalidEvidence(
                "role identity or complete slice inventory does not match the oracle",
            ));
        }
        valid_text("signature_validator_id", &report.signature.validator_id)?;
        valid_text(
            "signature_validator_revision",
            &report.signature.validator_revision,
        )?;
        if report.signature.presence != LabSignaturePresence::Present
            || report.signature.kind != LabSignatureKind::Cms
            || report.signature.validation != LabSignatureValidation::Valid
            || report.signature.validator_id.is_empty()
            || report.signature.validator_revision.is_empty()
            || report.signature.superblob_sha256.is_none()
        {
            return Err(Lab002Error::InvalidEvidence(
                "installed signature is absent, non-CMS, invalid, or unchecked",
            ));
        }
        validate_digest(
            "signature_superblob_sha256",
            report
                .signature
                .superblob_sha256
                .as_deref()
                .expect("checked as present"),
        )?;

        for (observed, expected) in report.slices.iter().zip(&oracle_role.slices) {
            let crypt_end = observed
                .cryptoff
                .checked_add(observed.cryptsize)
                .ok_or(Lab002Error::InvalidEvidence("encryption range overflows"))?;
            let section_end = observed
                .section_slice_offset
                .checked_add(observed.section_length)
                .ok_or(Lab002Error::InvalidEvidence("section range overflows"))?;
            if observed.ordinal != expected.ordinal
                || observed.cpu_type != expected.cpu_type
                || observed.cpu_subtype != expected.cpu_subtype
                || observed.macho_uuid != expected.macho_uuid
                || observed.slice_file_offset != expected.slice_file_offset
                || observed.slice_file_size != expected.slice_file_size
                || observed.section_slice_offset != expected.section_slice_offset
                || observed.section_file_offset != expected.section_file_offset
                || observed.section_vm_offset != expected.section_vm_offset
                || observed.section_length != expected.section_length
                || observed.cryptid != 1
                || observed.cryptsize == 0
                || crypt_end > observed.slice_file_size
                || !observed.encryption_covers_section
                || observed.cryptoff > observed.section_slice_offset
                || crypt_end < section_end
                || observed.disk_sha256 == expected.expected_plaintext_sha256
                || observed.mapped_sha256 != expected.expected_plaintext_sha256
            {
                return Err(Lab002Error::InvalidEvidence(
                    "slice identity, protection, or mapped plaintext evidence is invalid",
                ));
            }
            validate_digest("disk_sha256", &observed.disk_sha256)?;
            validate_digest("mapped_sha256", &observed.mapped_sha256)?;
        }
    }
    Ok(())
}

fn normalized_run(run: &LabRun) -> Result<Vec<u8>, Lab002Error> {
    #[derive(Serialize)]
    struct Projection<'a> {
        profile: &'a str,
        authorization_policy_version: &'a str,
        enrollment_binding_sha256: &'a str,
        enrollment_public_key: &'a str,
        device_installation_binding_sha256: &'a str,
        hardware_model: &'a str,
        ios_product_version: &'a str,
        ios_build: &'a str,
        source_commit: &'a str,
        marketing_version: &'a str,
        build_number: &'a str,
        observer_revision: &'a str,
        build_binding_sha256: &'a str,
        reports: Vec<ReportProjection<'a>>,
    }
    #[derive(Serialize)]
    struct ReportProjection<'a> {
        role: LabRole,
        fixture_relative_path: &'a str,
        target_identity_binding_sha256: &'a str,
        signature: &'a LabSignature,
        slices: &'a [ObservedSlice],
    }
    canonical_json(&Projection {
        profile: &run.profile,
        authorization_policy_version: &run.authorization_policy_version,
        enrollment_binding_sha256: &run.enrollment_binding_sha256,
        enrollment_public_key: &run.enrollment_public_key,
        device_installation_binding_sha256: &run.device_installation_binding_sha256,
        hardware_model: &run.hardware_model,
        ios_product_version: &run.ios_product_version,
        ios_build: &run.ios_build,
        source_commit: &run.source_commit,
        marketing_version: &run.marketing_version,
        build_number: &run.build_number,
        observer_revision: &run.observer_revision,
        build_binding_sha256: &run.build_binding_sha256,
        reports: run
            .reports
            .iter()
            .map(|report| ReportProjection {
                role: report.role,
                fixture_relative_path: &report.fixture_relative_path,
                target_identity_binding_sha256: &report.target_identity_binding_sha256,
                signature: &report.signature,
                slices: &report.slices,
            })
            .collect(),
    })
}

/// Validate the closed oracle and two synthetic or imported run sets.
///
/// Success never means that a phone was observed. Callers must separately
/// authenticate receipt/export signatures and record real-device provenance
/// before the final LAB-002 Go/No-Go gate can be evaluated.
pub fn verify_two_runs(
    oracle: &LabOracle,
    run1: &LabRun,
    run2: &LabRun,
) -> Result<DeviceFreeVerification, Lab002Error> {
    validate_oracle(oracle)?;
    validate_run(oracle, run1, 1)?;
    validate_run(oracle, run2, 2)?;
    if run1.prior_collection_binding_sha256.is_some()
        || run2.prior_collection_binding_sha256.as_deref()
            != Some(run1.collection_binding_sha256.as_str())
        || run1.collection_id == run2.collection_id
        || run1.session_id == run2.session_id
        || run1.challenge_sha256 == run2.challenge_sha256
        || run1.acknowledgement_sha256 == run2.acknowledgement_sha256
        || run1.authorization_envelope_sha256 == run2.authorization_envelope_sha256
        || run1.collection_binding_sha256 == run2.collection_binding_sha256
        || run1.enrollment_binding_sha256 != run2.enrollment_binding_sha256
        || run1.enrollment_public_key != run2.enrollment_public_key
        || run1.device_installation_binding_sha256 != run2.device_installation_binding_sha256
        || run1.hardware_model != run2.hardware_model
        || run1.ios_product_version != run2.ios_product_version
        || run1.ios_build != run2.ios_build
        || run1.authorization_not_after >= run2.authorization_not_before
        || run1.completed_at >= run2.created_at
    {
        return Err(Lab002Error::InvalidEvidence(
            "run freshness, chain, or physical environment does not match",
        ));
    }
    let normalized1 = normalized_run(run1)?;
    let normalized2 = normalized_run(run2)?;
    if normalized1 != normalized2 {
        return Err(Lab002Error::InvalidEvidence(
            "normalized observation evidence differs between runs",
        ));
    }
    Ok(DeviceFreeVerification {
        profile: LAB002_PROFILE.to_owned(),
        status: DeviceFreeVerificationStatus::ConsistentSyntheticEvidence,
        normalized_evidence_sha256: sha256_hex(&normalized1),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedSectionSlice {
    pub ordinal: u8,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub macho_uuid: String,
    pub slice_file_offset: u64,
    pub slice_file_size: u64,
    pub section_slice_offset: u64,
    pub section_file_offset: u64,
    pub section_vm_offset: u64,
    pub section_length: u64,
    pub section_sha256: String,
    pub fixup_layout_sha256: String,
    pub encryption: Option<EncryptionInfo>,
    pub signing: Option<PreuploadSigningMetadata>,
}

/// Bounded signed identity selected from one pre-upload Mach-O SuperBlob.
///
/// The complete SuperBlob digest is safe to retain in the private oracle. The
/// selected identifiers and entitlements are used only to recompute the
/// private target-identity binding and are not copied into that oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreuploadSigningMetadata {
    pub superblob_sha256: String,
    pub code_directory_identifier: String,
    pub code_directory_team_identifier: String,
    pub application_identifier: Option<String>,
    pub developer_team_identifier: Option<String>,
    pub application_groups: Option<Vec<String>>,
    pub is_ad_hoc: bool,
    pub has_cms: bool,
    #[serde(skip)]
    pub code_directory: Vec<u8>,
    #[serde(skip)]
    pub cms_signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedSectionReport {
    pub container: MachOContainer,
    pub file_size: u64,
    pub slices: Vec<FixedSectionSlice>,
}

fn read_u32_at(bytes: &[u8], offset: usize, endianness: Endianness) -> u32 {
    let value = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ];
    match endianness {
        Endianness::Little => u32::from_le_bytes(value),
        Endianness::Big => u32::from_be_bytes(value),
    }
}

fn read_u16_at(bytes: &[u8], offset: usize, endianness: Endianness) -> u16 {
    let value = [bytes[offset], bytes[offset + 1]];
    match endianness {
        Endianness::Little => u16::from_le_bytes(value),
        Endianness::Big => u16::from_be_bytes(value),
    }
}

fn read_u64_at(bytes: &[u8], offset: usize, endianness: Endianness) -> u64 {
    let value = [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ];
    match endianness {
        Endianness::Little => u64::from_le_bytes(value),
        Endianness::Big => u64::from_be_bytes(value),
    }
}

fn read_be_u32(bytes: &[u8], offset: usize, label: &'static str) -> Result<u32, Lab002Error> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Lab002Error::InvalidMachO(format!("{label} is truncated")))?;
    Ok(u32::from_be_bytes(value))
}

fn read_be_u64(bytes: &[u8], offset: usize, label: &'static str) -> Result<u64, Lab002Error> {
    let value = bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Lab002Error::InvalidMachO(format!("{label} is truncated")))?;
    Ok(u64::from_be_bytes(value))
}

fn code_signature_string(
    bytes: &[u8],
    offset: usize,
    upper_bound: usize,
) -> Result<String, Lab002Error> {
    if offset < 8 || offset >= upper_bound || upper_bound > bytes.len() {
        return Err(Lab002Error::InvalidMachO(
            "CodeDirectory string offset is invalid".into(),
        ));
    }
    let relative_end = bytes[offset..upper_bound]
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Lab002Error::InvalidMachO("CodeDirectory string is unterminated".into()))?;
    if relative_end == 0 {
        return Err(Lab002Error::InvalidMachO(
            "CodeDirectory string is empty".into(),
        ));
    }
    let value = std::str::from_utf8(&bytes[offset..offset + relative_end])
        .map_err(|_| Lab002Error::InvalidMachO("CodeDirectory string is not UTF-8".into()))?;
    if value
        .chars()
        .any(|scalar| scalar.is_control() || scalar == '\u{7f}')
    {
        return Err(Lab002Error::InvalidMachO(
            "CodeDirectory string contains a control scalar".into(),
        ));
    }
    Ok(value.to_owned())
}

struct SelectedCodeSigningEntitlements {
    application_identifier: Option<String>,
    developer_team_identifier: Option<String>,
    application_groups: Option<Vec<String>>,
}

fn parse_selected_entitlements(
    payload: &[u8],
) -> Result<SelectedCodeSigningEntitlements, Lab002Error> {
    let parsed = if payload.starts_with(b"bplist00") {
        preflight_binary_entitlements(payload)?;
        parse_selected_entitlement_events(PlistBinaryReader::new(Cursor::new(payload)))
    } else if entitlements_look_like_xml(payload) {
        parse_selected_entitlement_events(PlistXmlReader::new(BufReader::new(Cursor::new(payload))))
    } else {
        return Err(invalid_entitlements(
            "embedded code-signing entitlements have an unsupported encoding",
        ));
    }?;
    let application_identifier = parsed.application_identifier;
    let developer_team_identifier = parsed.developer_team_identifier;
    let application_groups = parsed.application_groups;
    if let Some(value) = &application_identifier {
        validate_bundle_identifier("application_identifier", value)?;
    }
    if let Some(value) = &developer_team_identifier {
        validate_team_identifier("developer_team_identifier", value)?;
    }
    Ok(SelectedCodeSigningEntitlements {
        application_identifier,
        developer_team_identifier,
        application_groups,
    })
}

fn preflight_binary_entitlements(payload: &[u8]) -> Result<(), Lab002Error> {
    let trailer_start = payload
        .len()
        .checked_sub(32)
        .filter(|offset| *offset >= 8)
        .ok_or_else(|| invalid_entitlements("binary entitlement plist trailer is truncated"))?;
    let offset_size = usize::from(payload[trailer_start + 6]);
    let reference_size = usize::from(payload[trailer_start + 7]);
    if !matches!(offset_size, 1 | 2 | 3 | 4 | 8) || !matches!(reference_size, 1 | 2 | 4 | 8) {
        return Err(invalid_entitlements(
            "binary entitlement plist trailer widths are invalid",
        ));
    }
    let object_count = read_be_u64(
        payload,
        trailer_start + 8,
        "binary entitlement object count",
    )?;
    let root_object = read_be_u64(
        payload,
        trailer_start + 16,
        "binary entitlement root object",
    )?;
    let offset_table = read_be_u64(
        payload,
        trailer_start + 24,
        "binary entitlement offset table",
    )
    .and_then(|offset| {
        usize::try_from(offset)
            .map_err(|_| invalid_entitlements("binary entitlement offset table overflows"))
    })?;
    if object_count == 0
        || object_count > MAX_ENTITLEMENTS_BINARY_OBJECTS
        || root_object >= object_count
        || !(8..trailer_start).contains(&offset_table)
    {
        return Err(invalid_entitlements(
            "binary entitlement plist object inventory is invalid or exceeds its limit",
        ));
    }
    let object_count = usize::try_from(object_count)
        .map_err(|_| invalid_entitlements("binary entitlement object count overflows"))?;
    let offset_table_bytes = object_count
        .checked_mul(offset_size)
        .and_then(|size| offset_table.checked_add(size))
        .filter(|end| *end <= trailer_start)
        .ok_or_else(|| invalid_entitlements("binary entitlement offset table is invalid"))?;

    for index in 0..object_count {
        let entry =
            offset_table
                .checked_add(index.checked_mul(offset_size).ok_or_else(|| {
                    invalid_entitlements("binary entitlement offset entry overflows")
                })?)
                .ok_or_else(|| invalid_entitlements("binary entitlement offset entry overflows"))?;
        let object_offset =
            read_binary_plist_uint(payload, entry, offset_size, offset_table_bytes)?;
        let object_offset = usize::try_from(object_offset)
            .map_err(|_| invalid_entitlements("binary entitlement object offset overflows"))?;
        if !(8..offset_table).contains(&object_offset) {
            return Err(invalid_entitlements(
                "binary entitlement object offset is outside the object table",
            ));
        }
        preflight_binary_entitlement_object(
            payload,
            object_offset,
            offset_table,
            reference_size,
            object_count as u64,
        )?;
    }
    Ok(())
}

fn preflight_binary_entitlement_object(
    payload: &[u8],
    object_offset: usize,
    object_table_end: usize,
    reference_size: usize,
    object_count: u64,
) -> Result<(), Lab002Error> {
    let token = *payload
        .get(object_offset)
        .ok_or_else(|| invalid_entitlements("binary entitlement object is truncated"))?;
    let kind = token >> 4;
    let inline_length = token & 0x0f;
    match kind {
        0x4..=0x6 => {
            let (length, body_start) =
                read_binary_plist_length(payload, object_offset, inline_length, object_table_end)?;
            let unit = if kind == 0x6 { 2 } else { 1 };
            let body_bytes = length.checked_mul(unit).ok_or_else(|| {
                invalid_entitlements("binary entitlement scalar length overflows")
            })?;
            enforce_entitlement_limit(
                "binary scalar bytes",
                body_bytes,
                MAX_ENTITLEMENTS_SCALAR_BYTES,
            )?;
            checked_binary_plist_extent(body_start, body_bytes, object_table_end)?;
        }
        0xa | 0xd => {
            let (length, references_start) =
                read_binary_plist_length(payload, object_offset, inline_length, object_table_end)?;
            enforce_entitlement_limit(
                "binary collection items",
                length,
                MAX_ENTITLEMENTS_COLLECTION_ITEMS,
            )?;
            let reference_count = if kind == 0xd {
                length.checked_mul(2).ok_or_else(|| {
                    invalid_entitlements("binary entitlement reference count overflows")
                })?
            } else {
                length
            };
            let reference_bytes = reference_count
                .checked_mul(reference_size as u64)
                .ok_or_else(|| {
                    invalid_entitlements("binary entitlement reference bytes overflow")
                })?;
            let references_end =
                checked_binary_plist_extent(references_start, reference_bytes, object_table_end)?;
            let mut cursor = references_start;
            while cursor < references_end {
                let reference =
                    read_binary_plist_uint(payload, cursor, reference_size, references_end)?;
                if reference >= object_count {
                    return Err(invalid_entitlements(
                        "binary entitlement object reference is out of range",
                    ));
                }
                cursor += reference_size;
            }
        }
        _ => {}
    }
    Ok(())
}

fn read_binary_plist_length(
    payload: &[u8],
    object_offset: usize,
    inline_length: u8,
    object_table_end: usize,
) -> Result<(u64, usize), Lab002Error> {
    let body_start = object_offset
        .checked_add(1)
        .ok_or_else(|| invalid_entitlements("binary entitlement object offset overflows"))?;
    if inline_length < 0x0f {
        return Ok((u64::from(inline_length), body_start));
    }
    let marker = *payload
        .get(body_start)
        .filter(|_| body_start < object_table_end)
        .ok_or_else(|| invalid_entitlements("binary entitlement length marker is truncated"))?;
    if marker >> 4 != 0x1 || marker & 0x0f > 3 {
        return Err(invalid_entitlements(
            "binary entitlement length marker is invalid",
        ));
    }
    let width = 1usize << (marker & 0x0f);
    let length_start = body_start
        .checked_add(1)
        .ok_or_else(|| invalid_entitlements("binary entitlement length offset overflows"))?;
    let length = read_binary_plist_uint(payload, length_start, width, object_table_end)?;
    let value_start = length_start
        .checked_add(width)
        .ok_or_else(|| invalid_entitlements("binary entitlement value offset overflows"))?;
    Ok((length, value_start))
}

fn read_binary_plist_uint(
    payload: &[u8],
    offset: usize,
    width: usize,
    upper_bound: usize,
) -> Result<u64, Lab002Error> {
    let end = offset
        .checked_add(width)
        .filter(|end| *end <= upper_bound)
        .ok_or_else(|| invalid_entitlements("binary entitlement integer is truncated"))?;
    payload
        .get(offset..end)
        .ok_or_else(|| invalid_entitlements("binary entitlement integer is truncated"))?
        .iter()
        .try_fold(0_u64, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(u64::from(*byte)))
                .ok_or_else(|| invalid_entitlements("binary entitlement integer overflows"))
        })
}

fn checked_binary_plist_extent(
    start: usize,
    byte_length: u64,
    upper_bound: usize,
) -> Result<usize, Lab002Error> {
    usize::try_from(byte_length)
        .ok()
        .and_then(|length| start.checked_add(length))
        .filter(|end| *end <= upper_bound)
        .ok_or_else(|| invalid_entitlements("binary entitlement object extent is invalid"))
}

#[derive(Default)]
struct EntitlementFields {
    application_identifier: Option<String>,
    developer_team_identifier: Option<String>,
    application_groups: Option<Vec<String>>,
}

#[derive(Default)]
struct EntitlementEventBudget {
    events: u64,
    scalar_bytes: u64,
}

fn parse_selected_entitlement_events<I>(
    events: I,
) -> Result<SelectedCodeSigningEntitlements, Lab002Error>
where
    I: IntoIterator<Item = Result<PlistEvent<'static>, plist::Error>>,
{
    let mut events = events.into_iter();
    let mut budget = EntitlementEventBudget::default();
    let first = next_entitlement_event(&mut events, &mut budget)?
        .ok_or_else(|| invalid_entitlements("embedded entitlement event stream is empty"))?;
    let declared_keys = match first {
        PlistEvent::StartDictionary(len) => len,
        other => {
            return Err(invalid_entitlements(format!(
                "embedded entitlements root must be a dictionary, found {}",
                entitlement_event_kind(&other)
            )));
        }
    };
    if let Some(actual) = declared_keys {
        enforce_entitlement_limit(
            "root dictionary key count",
            actual,
            MAX_ENTITLEMENTS_ROOT_KEYS,
        )?;
    }

    let mut parsed = EntitlementFields::default();
    let mut keys = HashSet::new();
    loop {
        let event =
            next_required_entitlement_event(&mut events, &mut budget, "root dictionary key")?;
        let key = match event {
            PlistEvent::EndCollection => break,
            PlistEvent::String(key) => key.into_owned(),
            other => {
                return Err(invalid_entitlements(format!(
                    "embedded entitlement key must be a string, found {}",
                    entitlement_event_kind(&other)
                )));
            }
        };
        enforce_entitlement_limit(
            "root dictionary key bytes",
            key.len() as u64,
            MAX_ENTITLEMENTS_KEY_BYTES,
        )?;
        enforce_entitlement_limit(
            "root dictionary key count",
            keys.len() as u64 + 1,
            MAX_ENTITLEMENTS_ROOT_KEYS,
        )?;
        if !keys.insert(key.clone()) {
            return Err(invalid_entitlements(format!(
                "embedded entitlements repeat root key `{key}`"
            )));
        }

        let value =
            next_required_entitlement_event(&mut events, &mut budget, "root dictionary value")?;
        match key.as_str() {
            "application-identifier" => {
                parsed.application_identifier =
                    Some(require_entitlement_string(value, "application-identifier")?);
            }
            "com.apple.developer.team-identifier" => {
                parsed.developer_team_identifier = Some(require_entitlement_string(
                    value,
                    "com.apple.developer.team-identifier",
                )?);
            }
            "com.apple.security.application-groups" => {
                parsed.application_groups =
                    Some(parse_application_groups(value, &mut events, &mut budget)?);
            }
            _ => skip_entitlement_value(value, &mut events, &mut budget, 2)?,
        }
    }
    if let Some(event) = next_entitlement_event(&mut events, &mut budget)? {
        return Err(invalid_entitlements(format!(
            "trailing event after embedded entitlements dictionary: {}",
            entitlement_event_kind(&event)
        )));
    }
    Ok(SelectedCodeSigningEntitlements {
        application_identifier: parsed.application_identifier,
        developer_team_identifier: parsed.developer_team_identifier,
        application_groups: parsed.application_groups,
    })
}

fn parse_application_groups<I>(
    first: PlistEvent<'static>,
    events: &mut I,
    budget: &mut EntitlementEventBudget,
) -> Result<Vec<String>, Lab002Error>
where
    I: Iterator<Item = Result<PlistEvent<'static>, plist::Error>>,
{
    let declared_items = match first {
        PlistEvent::StartArray(len) => len,
        other => {
            return Err(invalid_entitlements(format!(
                "selected application-groups entitlement is not an array, found {}",
                entitlement_event_kind(&other)
            )));
        }
    };
    if let Some(actual) = declared_items {
        enforce_entitlement_limit("application groups", actual, MAX_APPLICATION_GROUPS)?;
    }
    let mut groups = Vec::new();
    loop {
        let event =
            next_required_entitlement_event(events, budget, "application group or array end")?;
        if matches!(event, PlistEvent::EndCollection) {
            break;
        }
        enforce_entitlement_limit(
            "application groups",
            groups.len() as u64 + 1,
            MAX_APPLICATION_GROUPS,
        )?;
        groups.push(require_entitlement_string(
            event,
            "com.apple.security.application-groups entry",
        )?);
    }
    if groups.is_empty() || groups.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_entitlements(
            "selected application-groups entitlement is not nonempty, unique, and sorted",
        ));
    }
    for group in &groups {
        let identifier = group.strip_prefix("group.").ok_or_else(|| {
            invalid_entitlements("selected application group has an invalid prefix")
        })?;
        validate_bundle_identifier("application_group", identifier)?;
    }
    Ok(groups)
}

fn skip_entitlement_value<I>(
    first: PlistEvent<'static>,
    events: &mut I,
    budget: &mut EntitlementEventBudget,
    depth: u64,
) -> Result<(), Lab002Error>
where
    I: Iterator<Item = Result<PlistEvent<'static>, plist::Error>>,
{
    enforce_entitlement_limit("collection depth", depth, MAX_ENTITLEMENTS_DEPTH)?;
    match first {
        PlistEvent::StartArray(_) => {
            let mut items = 0u64;
            loop {
                let event = next_required_entitlement_event(events, budget, "array value or end")?;
                if matches!(event, PlistEvent::EndCollection) {
                    return Ok(());
                }
                items = items.checked_add(1).ok_or_else(|| {
                    invalid_entitlements("embedded entitlement collection item count overflowed")
                })?;
                enforce_entitlement_limit(
                    "collection items",
                    items,
                    MAX_ENTITLEMENTS_COLLECTION_ITEMS,
                )?;
                skip_entitlement_value(event, events, budget, depth + 1)?;
            }
        }
        PlistEvent::StartDictionary(_) => {
            let mut items = 0u64;
            loop {
                let event =
                    next_required_entitlement_event(events, budget, "dictionary key or end")?;
                if matches!(event, PlistEvent::EndCollection) {
                    return Ok(());
                }
                if !matches!(event, PlistEvent::String(_)) {
                    return Err(invalid_entitlements(format!(
                        "nested entitlement dictionary key must be a string, found {}",
                        entitlement_event_kind(&event)
                    )));
                }
                items = items.checked_add(1).ok_or_else(|| {
                    invalid_entitlements("embedded entitlement collection item count overflowed")
                })?;
                enforce_entitlement_limit(
                    "collection items",
                    items,
                    MAX_ENTITLEMENTS_COLLECTION_ITEMS,
                )?;
                let value =
                    next_required_entitlement_event(events, budget, "nested dictionary value")?;
                if matches!(value, PlistEvent::EndCollection) {
                    return Err(invalid_entitlements(
                        "nested entitlement dictionary key has no value",
                    ));
                }
                skip_entitlement_value(value, events, budget, depth + 1)?;
            }
        }
        PlistEvent::EndCollection => Err(invalid_entitlements(
            "unexpected entitlement collection end where a value was required",
        )),
        _ => Ok(()),
    }
}

fn require_entitlement_string(
    event: PlistEvent<'static>,
    field: &'static str,
) -> Result<String, Lab002Error> {
    match event {
        PlistEvent::String(value) => Ok(value.into_owned()),
        other => Err(invalid_entitlements(format!(
            "selected code-signing entitlement `{field}` is not a string, found {}",
            entitlement_event_kind(&other)
        ))),
    }
}

fn next_required_entitlement_event<I>(
    events: &mut I,
    budget: &mut EntitlementEventBudget,
    expected: &'static str,
) -> Result<PlistEvent<'static>, Lab002Error>
where
    I: Iterator<Item = Result<PlistEvent<'static>, plist::Error>>,
{
    next_entitlement_event(events, budget)?.ok_or_else(|| {
        invalid_entitlements(format!(
            "embedded entitlement event stream ended while reading {expected}"
        ))
    })
}

fn next_entitlement_event<I>(
    events: &mut I,
    budget: &mut EntitlementEventBudget,
) -> Result<Option<PlistEvent<'static>>, Lab002Error>
where
    I: Iterator<Item = Result<PlistEvent<'static>, plist::Error>>,
{
    let Some(event) = events.next() else {
        return Ok(None);
    };
    let event = event.map_err(|_| invalid_entitlements("embedded entitlement plist is invalid"))?;
    budget.events = budget
        .events
        .checked_add(1)
        .ok_or_else(|| invalid_entitlements("embedded entitlement event count overflowed"))?;
    enforce_entitlement_limit("event count", budget.events, MAX_ENTITLEMENTS_EVENTS)?;

    let scalar_bytes = match &event {
        PlistEvent::String(value) => value.len() as u64,
        PlistEvent::Data(value) => value.len() as u64,
        _ => 0,
    };
    budget.scalar_bytes = budget
        .scalar_bytes
        .checked_add(scalar_bytes)
        .ok_or_else(|| invalid_entitlements("embedded entitlement scalar byte count overflowed"))?;
    enforce_entitlement_limit(
        "cumulative scalar bytes",
        budget.scalar_bytes,
        MAX_ENTITLEMENTS_SCALAR_BYTES,
    )?;
    match &event {
        PlistEvent::StartArray(Some(actual)) | PlistEvent::StartDictionary(Some(actual)) => {
            enforce_entitlement_limit(
                "declared collection items",
                *actual,
                MAX_ENTITLEMENTS_COLLECTION_ITEMS,
            )?;
        }
        _ => {}
    }
    Ok(Some(event))
}

fn enforce_entitlement_limit(
    label: &'static str,
    actual: u64,
    maximum: u64,
) -> Result<(), Lab002Error> {
    if actual > maximum {
        return Err(invalid_entitlements(format!(
            "embedded entitlements exceeded the {label} limit: {actual} > {maximum}"
        )));
    }
    Ok(())
}

fn entitlements_look_like_xml(bytes: &[u8]) -> bool {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'<')
}

fn entitlement_event_kind(event: &PlistEvent<'_>) -> &'static str {
    match event {
        PlistEvent::StartArray(_) => "array",
        PlistEvent::StartDictionary(_) => "dictionary",
        PlistEvent::EndCollection => "collection end",
        PlistEvent::Boolean(_) => "boolean",
        PlistEvent::Data(_) => "data",
        PlistEvent::Date(_) => "date",
        PlistEvent::Integer(_) => "integer",
        PlistEvent::Real(_) => "real",
        PlistEvent::String(_) => "string",
        _ => "unsupported scalar",
    }
}

fn invalid_entitlements(reason: impl Into<String>) -> Lab002Error {
    Lab002Error::InvalidMachO(reason.into())
}

fn code_directory_hash_size(hash_type: u8) -> Option<usize> {
    match hash_type {
        1 => Some(20),
        2 => Some(32),
        3 => Some(20),
        4 => Some(48),
        _ => None,
    }
}

fn verify_code_directory_pages<R: Read + Seek>(
    reader: &mut R,
    slice_offset: u64,
    code_limit: u64,
    page_size: u64,
    code_directory: &[u8],
    hash_offset: usize,
    code_slot_count: usize,
) -> Result<(), Lab002Error> {
    let mut page = vec![
        0_u8;
        usize::try_from(page_size).map_err(|_| {
            Lab002Error::InvalidMachO("CodeDirectory page size does not fit memory".into())
        })?
    ];
    for slot in 0..code_slot_count {
        let relative_offset = u64::try_from(slot)
            .ok()
            .and_then(|slot| slot.checked_mul(page_size))
            .ok_or_else(|| {
                Lab002Error::InvalidMachO("CodeDirectory page offset overflows".into())
            })?;
        let remaining = code_limit.checked_sub(relative_offset).ok_or_else(|| {
            Lab002Error::InvalidMachO("CodeDirectory page exceeds code coverage".into())
        })?;
        let length = usize::try_from(remaining.min(page_size)).map_err(|_| {
            Lab002Error::InvalidMachO("CodeDirectory page length does not fit memory".into())
        })?;
        let absolute = slice_offset.checked_add(relative_offset).ok_or_else(|| {
            Lab002Error::InvalidMachO("CodeDirectory page file offset overflows".into())
        })?;
        reader
            .seek(SeekFrom::Start(absolute))
            .map_err(|error| Lab002Error::Io(error.to_string()))?;
        reader
            .read_exact(&mut page[..length])
            .map_err(|error| Lab002Error::Io(error.to_string()))?;
        let expected_start = hash_offset
            .checked_add(slot.checked_mul(32).ok_or_else(|| {
                Lab002Error::InvalidMachO("CodeDirectory page-hash offset overflows".into())
            })?)
            .ok_or_else(|| {
                Lab002Error::InvalidMachO("CodeDirectory page-hash offset overflows".into())
            })?;
        let expected_end = expected_start.checked_add(32).ok_or_else(|| {
            Lab002Error::InvalidMachO("CodeDirectory page-hash extent overflows".into())
        })?;
        let expected = code_directory
            .get(expected_start..expected_end)
            .ok_or_else(|| {
                Lab002Error::InvalidMachO("CodeDirectory page-hash extent is invalid".into())
            })?;
        if Sha256::digest(&page[..length]).as_slice() != expected {
            return Err(Lab002Error::InvalidMachO(
                "CodeDirectory page hash does not match the executable".into(),
            ));
        }
    }
    Ok(())
}

fn parse_preupload_code_signature<R: Read + Seek>(
    signature_bytes: &[u8],
    expected_code_limit: u64,
    reader: &mut R,
    slice_offset: u64,
) -> Result<PreuploadSigningMetadata, Lab002Error> {
    if signature_bytes.len() < 12
        || read_be_u32(signature_bytes, 0, "code-signature SuperBlob")? != 0xfade_0cc0
    {
        return Err(Lab002Error::InvalidMachO(
            "code-signature SuperBlob is invalid".into(),
        ));
    }
    let declared_length =
        usize::try_from(read_be_u32(signature_bytes, 4, "code-signature SuperBlob")?)
            .map_err(|_| Lab002Error::InvalidMachO("code-signature length overflows".into()))?;
    if !(12..=signature_bytes.len()).contains(&declared_length)
        || signature_bytes[declared_length..]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(Lab002Error::InvalidMachO(
            "code-signature SuperBlob length or padding is invalid".into(),
        ));
    }
    let blob = &signature_bytes[..declared_length];
    let count = usize::try_from(read_be_u32(blob, 8, "code-signature SuperBlob")?)
        .map_err(|_| Lab002Error::InvalidMachO("code-signature slot count overflows".into()))?;
    let index_end = count
        .checked_mul(8)
        .and_then(|bytes| 12_usize.checked_add(bytes))
        .ok_or_else(|| Lab002Error::InvalidMachO("code-signature slot index overflows".into()))?;
    if !(1..=64).contains(&count) || index_end > blob.len() {
        return Err(Lab002Error::InvalidMachO(
            "code-signature slot inventory is invalid".into(),
        ));
    }
    let mut slots = HashMap::with_capacity(count);
    let mut intervals = Vec::with_capacity(count);
    for index in 0..count {
        let entry = 12 + index * 8;
        let slot = read_be_u32(blob, entry, "code-signature slot index")?;
        let offset = usize::try_from(read_be_u32(blob, entry + 4, "code-signature slot index")?)
            .map_err(|_| {
                Lab002Error::InvalidMachO("code-signature slot offset overflows".into())
            })?;
        if slots.contains_key(&slot) || offset < index_end || offset > blob.len().saturating_sub(8)
        {
            return Err(Lab002Error::InvalidMachO(
                "code-signature slot identity or offset is invalid".into(),
            ));
        }
        let length = usize::try_from(read_be_u32(blob, offset + 4, "code-signature slot")?)
            .map_err(|_| {
                Lab002Error::InvalidMachO("code-signature slot length overflows".into())
            })?;
        let end = offset.checked_add(length).ok_or_else(|| {
            Lab002Error::InvalidMachO("code-signature slot extent overflows".into())
        })?;
        if length < 8 || end > blob.len() {
            return Err(Lab002Error::InvalidMachO(
                "code-signature slot extent is invalid".into(),
            ));
        }
        slots.insert(slot, &blob[offset..end]);
        intervals.push((offset, end));
    }
    intervals.sort_unstable();
    if intervals.first().map(|interval| interval.0) != Some(index_end)
        || intervals.windows(2).any(|pair| pair[0].1 != pair[1].0)
        || intervals.last().map(|interval| interval.1) != Some(blob.len())
    {
        return Err(Lab002Error::InvalidMachO(
            "code-signature slots do not exactly consume the SuperBlob".into(),
        ));
    }

    let code_directory = slots
        .get(&0)
        .ok_or_else(|| Lab002Error::InvalidMachO("primary CodeDirectory is missing".into()))?;
    if code_directory.len() < 44
        || read_be_u32(code_directory, 0, "CodeDirectory")? != 0xfade_0c02
        || usize::try_from(read_be_u32(code_directory, 4, "CodeDirectory")?).ok()
            != Some(code_directory.len())
    {
        return Err(Lab002Error::InvalidMachO(
            "primary CodeDirectory is invalid".into(),
        ));
    }
    let version = read_be_u32(code_directory, 8, "CodeDirectory")?;
    let flags = read_be_u32(code_directory, 12, "CodeDirectory")?;
    let hash_offset = usize::try_from(read_be_u32(code_directory, 16, "CodeDirectory")?)
        .map_err(|_| Lab002Error::InvalidMachO("CodeDirectory hash offset overflows".into()))?;
    let identifier_offset = usize::try_from(read_be_u32(code_directory, 20, "CodeDirectory")?)
        .map_err(|_| {
            Lab002Error::InvalidMachO("CodeDirectory identifier offset overflows".into())
        })?;
    let special_slot_count = usize::try_from(read_be_u32(code_directory, 24, "CodeDirectory")?)
        .map_err(|_| {
            Lab002Error::InvalidMachO("CodeDirectory special-slot count overflows".into())
        })?;
    let code_slot_count = usize::try_from(read_be_u32(code_directory, 28, "CodeDirectory")?)
        .map_err(|_| Lab002Error::InvalidMachO("CodeDirectory code-slot count overflows".into()))?;
    let code_limit_32 = u64::from(read_be_u32(code_directory, 32, "CodeDirectory")?);
    let hash_size = usize::from(code_directory[36]);
    let hash_type = code_directory[37];
    let page_size_power = code_directory[39];
    let minimum_length = match version {
        0x20200..=0x202ff => 52,
        0x20300..=0x203ff => 64,
        0x20400..=0x204ff => 88,
        0x20500..=0x205ff => 96,
        0x20600 => 108,
        _ => {
            return Err(Lab002Error::InvalidMachO(
                "CodeDirectory version is outside the closed profile".into(),
            ));
        }
    };
    if code_directory.len() < minimum_length
        || read_be_u32(code_directory, 40, "CodeDirectory")? != 0
        || !(12..=16).contains(&page_size_power)
        || hash_type != 2
        || hash_size != 32
        || code_directory_hash_size(hash_type) != Some(hash_size)
    {
        return Err(Lab002Error::InvalidMachO(
            "CodeDirectory layout is outside the closed profile".into(),
        ));
    }
    if version >= 0x20200 && read_be_u32(code_directory, 44, "CodeDirectory")? != 0 {
        return Err(Lab002Error::InvalidMachO(
            "CodeDirectory scatter table is outside the closed profile".into(),
        ));
    }
    let code_limit_64 = if version >= 0x20300 {
        read_be_u64(code_directory, 56, "CodeDirectory")?
    } else {
        0
    };
    let code_limit = if code_limit_64 == 0 {
        code_limit_32
    } else {
        code_limit_64
    };
    let page_size = 1_u64 << page_size_power;
    let expected_slots = code_limit
        .checked_add(page_size - 1)
        .map(|value| value / page_size)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| Lab002Error::InvalidMachO("CodeDirectory page count overflows".into()))?;
    let special_bytes = special_slot_count.checked_mul(hash_size).ok_or_else(|| {
        Lab002Error::InvalidMachO("CodeDirectory special-slot bytes overflow".into())
    })?;
    let code_bytes = code_slot_count.checked_mul(hash_size).ok_or_else(|| {
        Lab002Error::InvalidMachO("CodeDirectory code-slot bytes overflow".into())
    })?;
    let hash_end = hash_offset.checked_add(code_bytes).ok_or_else(|| {
        Lab002Error::InvalidMachO("CodeDirectory code-slot extent overflows".into())
    })?;
    if code_limit == 0
        || code_limit != expected_code_limit
        || code_limit > MAX_LAB002_EXECUTABLE_BYTES
        || code_slot_count != expected_slots
        || hash_offset < special_bytes
        || hash_end > code_directory.len()
    {
        return Err(Lab002Error::InvalidMachO(
            "CodeDirectory code coverage is invalid".into(),
        ));
    }
    let dynamic_data_start = hash_offset - special_bytes;
    if dynamic_data_start < minimum_length {
        return Err(Lab002Error::InvalidMachO(
            "CodeDirectory dynamic fields overlap its header".into(),
        ));
    }
    verify_code_directory_pages(
        reader,
        slice_offset,
        code_limit,
        page_size,
        code_directory,
        hash_offset,
        code_slot_count,
    )?;
    let team_offset = usize::try_from(read_be_u32(code_directory, 48, "CodeDirectory")?)
        .map_err(|_| Lab002Error::InvalidMachO("CodeDirectory team offset overflows".into()))?;
    let identifier = code_signature_string(code_directory, identifier_offset, dynamic_data_start)?;
    let is_linker_signed_ad_hoc = version == 0x20400 && flags == 0x0002_0002;
    let team_identifier = if is_linker_signed_ad_hoc {
        if team_offset != 0 || special_slot_count != 0 || slots.len() != 1 {
            return Err(Lab002Error::InvalidMachO(
                "linker-signed CodeDirectory has unexpected identity slots".into(),
            ));
        }
        validate_bundle_identifier("code_directory_identifier", &identifier)?;
        String::new()
    } else {
        let team_identifier =
            code_signature_string(code_directory, team_offset, dynamic_data_start)?;
        validate_bundle_identifier("code_directory_identifier", &identifier)?;
        validate_team_identifier("code_directory_team_identifier", &team_identifier)?;
        team_identifier
    };

    for (&slot, signed_blob) in &slots {
        if !(1..0x1000).contains(&slot) {
            continue;
        }
        let slot_index = usize::try_from(slot).map_err(|_| {
            Lab002Error::InvalidMachO("code-signing special-slot index overflows".into())
        })?;
        if slot_index > special_slot_count {
            return Err(Lab002Error::InvalidMachO(
                "code-signing special slot is not covered by the CodeDirectory".into(),
            ));
        }
        let signed_hash_bytes = slot_index.checked_mul(hash_size).ok_or_else(|| {
            Lab002Error::InvalidMachO("CodeDirectory special-slot offset overflows".into())
        })?;
        let signed_hash_start = hash_offset.checked_sub(signed_hash_bytes).ok_or_else(|| {
            Lab002Error::InvalidMachO("CodeDirectory special-slot hash underflows".into())
        })?;
        let signed_hash_end = signed_hash_start.checked_add(hash_size).ok_or_else(|| {
            Lab002Error::InvalidMachO("CodeDirectory special-slot hash overflows".into())
        })?;
        if code_directory.get(signed_hash_start..signed_hash_end)
            != Some(Sha256::digest(*signed_blob).as_slice())
        {
            return Err(Lab002Error::InvalidMachO(
                "code-signing blob does not match its signed special slot".into(),
            ));
        }
    }

    let entitlements = if let Some(entitlements) = slots.get(&5) {
        if read_be_u32(entitlements, 0, "code-signing entitlements")? != 0xfade_7171 {
            return Err(Lab002Error::InvalidMachO(
                "code-signing entitlements slot has an invalid magic".into(),
            ));
        }
        parse_selected_entitlements(&entitlements[8..])?
    } else {
        SelectedCodeSigningEntitlements {
            application_identifier: None,
            developer_team_identifier: None,
            application_groups: None,
        }
    };
    let cms = slots
        .get(&0x1_0000)
        .map(|cms| {
            if cms.len() <= 8 || read_be_u32(cms, 0, "CMS signature")? != 0xfade_0b01 {
                return Err(Lab002Error::InvalidMachO(
                    "detached CMS signature slot is invalid".into(),
                ));
            }
            Ok(cms[8..].to_vec())
        })
        .transpose()?;
    Ok(PreuploadSigningMetadata {
        superblob_sha256: sha256_hex(blob),
        code_directory_identifier: identifier,
        code_directory_team_identifier: team_identifier,
        application_identifier: entitlements.application_identifier,
        developer_team_identifier: entitlements.developer_team_identifier,
        application_groups: entitlements.application_groups,
        is_ad_hoc: flags & 0x2 != 0,
        has_cms: cms.is_some(),
        code_directory: code_directory.to_vec(),
        cms_signature: cms.unwrap_or_default(),
    })
}

fn macho_name(bytes: &[u8]) -> Result<&str, Lab002Error> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end < bytes.len() && bytes[end + 1..].iter().any(|byte| *byte != 0) {
        return Err(Lab002Error::InvalidMachO(
            "Mach-O name contains bytes after its NUL terminator".into(),
        ));
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| Lab002Error::InvalidMachO("Mach-O name is not ASCII/UTF-8".into()))
}

fn bounded_range(
    start: u64,
    length: u64,
    limit: u64,
    context: &'static str,
) -> Result<std::ops::Range<usize>, Lab002Error> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| Lab002Error::InvalidMachO(format!("{context} overflows")))?;
    if end > limit {
        return Err(Lab002Error::InvalidMachO(format!(
            "{context} exceeds its containing range"
        )));
    }
    let start = usize::try_from(start)
        .map_err(|_| Lab002Error::InvalidMachO(format!("{context} is too large")))?;
    let end = usize::try_from(end)
        .map_err(|_| Lab002Error::InvalidMachO(format!("{context} is too large")))?;
    Ok(start..end)
}

#[derive(Debug, Clone)]
struct FixupSegment {
    vmaddr: u64,
    vmsize: u64,
    filesize: u64,
    is_text: bool,
}

fn reject_overlapping_segment_vm_ranges(segments: &[FixupSegment]) -> Result<(), Lab002Error> {
    let mut ranges = Vec::with_capacity(segments.len());
    for segment in segments {
        if segment.vmsize == 0 {
            continue;
        }
        let end = segment
            .vmaddr
            .checked_add(segment.vmsize)
            .ok_or_else(|| Lab002Error::InvalidMachO("segment VM range overflows".into()))?;
        ranges.push((segment.vmaddr, end));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(Lab002Error::InvalidMachO(
            "Mach-O segment VM ranges overlap".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum FixupOpcodeKind {
    Rebase,
    Bind,
    LazyBind,
}

impl FixupOpcodeKind {
    fn binding_byte(self) -> u8 {
        match self {
            Self::Rebase => 0,
            Self::Bind => 1,
            Self::LazyBind => 2,
        }
    }
}

type ClassicFixupStreams = (u32, [(u32, u32, FixupOpcodeKind); 4]);

struct FixupLayout<'a> {
    slice_offset: u64,
    slice_size: u64,
    endianness: Endianness,
    is_64_bit: bool,
    segments: &'a [FixupSegment],
    classic: Option<ClassicFixupStreams>,
    chained: Option<(u32, u32)>,
    saw_dynamic_symbol_table: bool,
    image_text_vmaddr: u64,
}

fn supported_lab002_load_command(command: u32, is_64_bit: bool) -> bool {
    matches!(
        command,
        // Final linked-image metadata understood by this closed parser.
        0x02 // LC_SYMTAB
            | LC_DYSYMTAB
            | 0x0c // LC_LOAD_DYLIB
            | 0x0d // LC_ID_DYLIB
            | 0x0e // LC_LOAD_DYLINKER
            | 0x8000_0018 // LC_LOAD_WEAK_DYLIB
            | 0x1b // LC_UUID
            | 0x8000_001c // LC_RPATH
            | 0x1d // LC_CODE_SIGNATURE
            | 0x1e // LC_SEGMENT_SPLIT_INFO
            | 0x8000_001f // LC_REEXPORT_DYLIB
            | 0x21 // LC_ENCRYPTION_INFO
            | LC_DYLD_INFO
            | LC_DYLD_INFO_ONLY
            | 0x8000_0023 // LC_LOAD_UPWARD_DYLIB
            | 0x25 // LC_VERSION_MIN_IPHONEOS
            | 0x26 // LC_FUNCTION_STARTS
            | 0x8000_0028 // LC_MAIN
            | 0x29 // LC_DATA_IN_CODE
            | 0x2a // LC_SOURCE_VERSION
            | 0x2b // LC_DYLIB_CODE_SIGN_DRS
            | 0x2c // LC_ENCRYPTION_INFO_64
            | 0x2e // LC_LINKER_OPTIMIZATION_HINT
            | 0x32 // LC_BUILD_VERSION
            | 0x8000_0033 // LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | 0x36 // LC_ATOM_INFO
            | 0x37 // LC_FUNCTION_VARIANTS
            | 0x38 // LC_FUNCTION_VARIANT_FIXUPS
            | 0x39 // LC_TARGET_TRIPLE
    ) || (!is_64_bit && command == 0x01)
        || (is_64_bit && command == 0x19)
}

fn read_uleb128(bytes: &[u8], cursor: &mut usize) -> Result<u64, Lab002Error> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    for _ in 0..10 {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| Lab002Error::InvalidMachO("truncated ULEB128".into()))?;
        *cursor += 1;
        let payload = u64::from(byte & 0x7f);
        if shift == 63 && payload > 1 {
            return Err(Lab002Error::InvalidMachO("ULEB128 overflows".into()));
        }
        value |= payload
            .checked_shl(shift)
            .ok_or_else(|| Lab002Error::InvalidMachO("ULEB128 overflows".into()))?;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(Lab002Error::InvalidMachO("ULEB128 is too long".into()))
}

fn skip_sleb128(bytes: &[u8], cursor: &mut usize) -> Result<(), Lab002Error> {
    for _ in 0..10 {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| Lab002Error::InvalidMachO("truncated SLEB128".into()))?;
        *cursor += 1;
        if byte & 0x80 == 0 {
            return Ok(());
        }
    }
    Err(Lab002Error::InvalidMachO("SLEB128 is too long".into()))
}

fn set_fixup_segment(
    segments: &[FixupSegment],
    immediate: u8,
    offset: u64,
) -> Result<(usize, u64), Lab002Error> {
    let index = usize::from(immediate);
    let segment = segments
        .get(index)
        .ok_or_else(|| Lab002Error::InvalidMachO("fixup segment index is invalid".into()))?;
    if offset > segment.vmsize {
        return Err(Lab002Error::InvalidMachO(
            "fixup offset exceeds its segment".into(),
        ));
    }
    Ok((index, offset))
}

fn advance_fixups(
    segments: &[FixupSegment],
    state: &mut Option<(usize, u64)>,
    count: u64,
    stride: u64,
    width: u64,
) -> Result<(), Lab002Error> {
    let (segment_index, offset) = state
        .as_mut()
        .ok_or_else(|| Lab002Error::InvalidMachO("fixup opcode has no segment state".into()))?;
    if count == 0 {
        return Ok(());
    }
    let segment = &segments[*segment_index];
    if segment.is_text {
        return Err(Lab002Error::InvalidMachO(
            "dyld fixup targets executable __TEXT".into(),
        ));
    }
    let last_offset = stride
        .checked_mul(count - 1)
        .and_then(|delta| offset.checked_add(delta))
        .ok_or_else(|| Lab002Error::InvalidMachO("fixup sequence overflows".into()))?;
    if last_offset
        .checked_add(width)
        .is_none_or(|end| end > segment.vmsize)
    {
        return Err(Lab002Error::InvalidMachO(
            "fixup sequence exceeds its segment".into(),
        ));
    }
    *offset = stride
        .checked_mul(count)
        .and_then(|delta| offset.checked_add(delta))
        .ok_or_else(|| Lab002Error::InvalidMachO("fixup sequence overflows".into()))?;
    Ok(())
}

fn inspect_fixup_opcodes(
    bytes: &[u8],
    kind: FixupOpcodeKind,
    segments: &[FixupSegment],
    pointer_size: u64,
) -> Result<(), Lab002Error> {
    let mut cursor = 0_usize;
    let mut state = None;
    while cursor < bytes.len() {
        let byte = bytes[cursor];
        cursor += 1;
        if byte == 0 {
            if bytes[cursor..].iter().all(|trailing| *trailing == 0) {
                return Ok(());
            }
            if matches!(kind, FixupOpcodeKind::LazyBind) {
                state = None;
                continue;
            }
            return Err(Lab002Error::InvalidMachO(
                "dyld fixup stream has a non-padding opcode after DONE".into(),
            ));
        }
        let opcode = byte & 0xf0;
        let immediate = byte & 0x0f;
        match kind {
            FixupOpcodeKind::Rebase => match opcode {
                0x10 => {}
                0x20 => {
                    let offset = read_uleb128(bytes, &mut cursor)?;
                    state = Some(set_fixup_segment(segments, immediate, offset)?);
                }
                0x30 => {
                    let delta = read_uleb128(bytes, &mut cursor)?;
                    let (_, offset) = state.as_mut().ok_or_else(|| {
                        Lab002Error::InvalidMachO("rebase add has no segment state".into())
                    })?;
                    *offset = offset.checked_add(delta).ok_or_else(|| {
                        Lab002Error::InvalidMachO("rebase offset overflows".into())
                    })?;
                }
                0x40 => {
                    let delta =
                        u64::from(immediate)
                            .checked_mul(pointer_size)
                            .ok_or_else(|| {
                                Lab002Error::InvalidMachO("rebase offset overflows".into())
                            })?;
                    let (_, offset) = state.as_mut().ok_or_else(|| {
                        Lab002Error::InvalidMachO("rebase add has no segment state".into())
                    })?;
                    *offset = offset.checked_add(delta).ok_or_else(|| {
                        Lab002Error::InvalidMachO("rebase offset overflows".into())
                    })?;
                }
                0x50 => advance_fixups(
                    segments,
                    &mut state,
                    u64::from(immediate),
                    pointer_size,
                    pointer_size,
                )?,
                0x60 => {
                    let count = read_uleb128(bytes, &mut cursor)?;
                    advance_fixups(segments, &mut state, count, pointer_size, pointer_size)?;
                }
                0x70 => {
                    let skip = read_uleb128(bytes, &mut cursor)?;
                    let stride = pointer_size.checked_add(skip).ok_or_else(|| {
                        Lab002Error::InvalidMachO("rebase stride overflows".into())
                    })?;
                    advance_fixups(segments, &mut state, 1, stride, pointer_size)?;
                }
                0x80 => {
                    let count = read_uleb128(bytes, &mut cursor)?;
                    let skip = read_uleb128(bytes, &mut cursor)?;
                    let stride = pointer_size.checked_add(skip).ok_or_else(|| {
                        Lab002Error::InvalidMachO("rebase stride overflows".into())
                    })?;
                    advance_fixups(segments, &mut state, count, stride, pointer_size)?;
                }
                _ => {
                    return Err(Lab002Error::InvalidMachO("unknown rebase opcode".into()));
                }
            },
            FixupOpcodeKind::Bind | FixupOpcodeKind::LazyBind => match opcode {
                0x10 | 0x30 | 0x50 => {}
                0x20 => {
                    read_uleb128(bytes, &mut cursor)?;
                }
                0x40 => {
                    let terminator = bytes[cursor..]
                        .iter()
                        .position(|byte| *byte == 0)
                        .ok_or_else(|| {
                            Lab002Error::InvalidMachO("bind symbol is unterminated".into())
                        })?;
                    cursor = cursor
                        .checked_add(terminator + 1)
                        .ok_or_else(|| Lab002Error::InvalidMachO("bind cursor overflows".into()))?;
                }
                0x60 => skip_sleb128(bytes, &mut cursor)?,
                0x70 => {
                    let offset = read_uleb128(bytes, &mut cursor)?;
                    state = Some(set_fixup_segment(segments, immediate, offset)?);
                }
                0x80 => {
                    let delta = read_uleb128(bytes, &mut cursor)?;
                    let (_, offset) = state.as_mut().ok_or_else(|| {
                        Lab002Error::InvalidMachO("bind add has no segment state".into())
                    })?;
                    *offset = offset
                        .checked_add(delta)
                        .ok_or_else(|| Lab002Error::InvalidMachO("bind offset overflows".into()))?;
                }
                0x90 => {
                    advance_fixups(segments, &mut state, 1, pointer_size, pointer_size)?;
                }
                0xa0 => {
                    let skip = read_uleb128(bytes, &mut cursor)?;
                    let stride = pointer_size
                        .checked_add(skip)
                        .ok_or_else(|| Lab002Error::InvalidMachO("bind stride overflows".into()))?;
                    advance_fixups(segments, &mut state, 1, stride, pointer_size)?;
                }
                0xb0 => {
                    let skip = u64::from(immediate)
                        .checked_mul(pointer_size)
                        .and_then(|value| value.checked_add(pointer_size))
                        .ok_or_else(|| Lab002Error::InvalidMachO("bind stride overflows".into()))?;
                    advance_fixups(segments, &mut state, 1, skip, pointer_size)?;
                }
                // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                0xc0 => {
                    let count = read_uleb128(bytes, &mut cursor)?;
                    let skip = read_uleb128(bytes, &mut cursor)?;
                    let stride = pointer_size
                        .checked_add(skip)
                        .ok_or_else(|| Lab002Error::InvalidMachO("bind stride overflows".into()))?;
                    advance_fixups(segments, &mut state, count, stride, pointer_size)?;
                }
                // BIND_OPCODE_THREADED:
                //   0 = SET_BIND_ORDINAL_TABLE_SIZE_ULEB
                //   1 = APPLY at the current segment/offset
                0xd0 if immediate == 0 => {
                    read_uleb128(bytes, &mut cursor)?;
                }
                0xd0 if immediate == 1 => {
                    advance_fixups(segments, &mut state, 1, pointer_size, pointer_size)?;
                }
                _ => {
                    return Err(Lab002Error::InvalidMachO("unknown bind opcode".into()));
                }
            },
        }
    }
    Err(Lab002Error::InvalidMachO(
        "dyld fixup stream has no terminal DONE opcode".into(),
    ))
}

fn read_slice_payload<R: Read + Seek>(
    reader: &mut R,
    slice_offset: u64,
    slice_size: u64,
    data_offset: u32,
    data_size: u32,
    context: &'static str,
) -> Result<Vec<u8>, Lab002Error> {
    if data_size > MAX_FIXUP_PAYLOAD_BYTES {
        return Err(Lab002Error::InvalidMachO(format!(
            "{context} exceeds the 16 MiB limit"
        )));
    }
    bounded_range(
        u64::from(data_offset),
        u64::from(data_size),
        slice_size,
        context,
    )?;
    let absolute = slice_offset
        .checked_add(u64::from(data_offset))
        .ok_or_else(|| Lab002Error::InvalidMachO(format!("{context} offset overflows")))?;
    let mut bytes = vec![0_u8; data_size as usize];
    reader
        .seek(SeekFrom::Start(absolute))
        .map_err(|error| Lab002Error::Io(error.to_string()))?;
    reader
        .read_exact(&mut bytes)
        .map_err(|error| Lab002Error::Io(error.to_string()))?;
    Ok(bytes)
}

fn inspect_chained_fixups(
    payload: &[u8],
    endianness: Endianness,
    segments: &[FixupSegment],
    image_vmaddr: u64,
) -> Result<(), Lab002Error> {
    if payload.len() < 28 || read_u32_at(payload, 0, endianness) != 0 {
        return Err(Lab002Error::InvalidMachO(
            "chained-fixups header is invalid".into(),
        ));
    }
    let starts_offset = read_u32_at(payload, 4, endianness) as usize;
    let imports_offset = read_u32_at(payload, 8, endianness) as usize;
    let symbols_offset = read_u32_at(payload, 12, endianness) as usize;
    let imports_count = read_u32_at(payload, 16, endianness) as usize;
    let imports_format = read_u32_at(payload, 20, endianness);
    let symbols_format = read_u32_at(payload, 24, endianness);
    if starts_offset < 28
        || starts_offset
            .checked_add(4)
            .is_none_or(|end| end > payload.len())
    {
        return Err(Lab002Error::InvalidMachO(
            "chained-fixups starts offset is invalid".into(),
        ));
    }
    let starts = &payload[starts_offset..];
    let segment_count = read_u32_at(starts, 0, endianness) as usize;
    let offsets_end = 4_usize
        .checked_add(segment_count.checked_mul(4).ok_or_else(|| {
            Lab002Error::InvalidMachO("chained-fixups segment table overflows".into())
        })?)
        .ok_or_else(|| {
            Lab002Error::InvalidMachO("chained-fixups segment table overflows".into())
        })?;
    if segment_count != segments.len() || offsets_end > starts.len() {
        return Err(Lab002Error::InvalidMachO(
            "chained-fixups segment inventory is invalid".into(),
        ));
    }
    let mut record_intervals = Vec::new();
    for (index, segment) in segments.iter().enumerate() {
        let info_offset = read_u32_at(starts, 4 + index * 4, endianness) as usize;
        if info_offset == 0 {
            continue;
        }
        if info_offset < offsets_end
            || info_offset
                .checked_add(22)
                .is_none_or(|end| end > starts.len())
        {
            return Err(Lab002Error::InvalidMachO(
                "chained-fixups segment record is misplaced or truncated".into(),
            ));
        }
        let info = &starts[info_offset..];
        let record_size = read_u32_at(info, 0, endianness) as usize;
        let page_size = read_u16_at(info, 4, endianness);
        let pointer_format = read_u16_at(info, 6, endianness);
        let segment_offset = read_u64_at(info, 8, endianness);
        let page_count = read_u16_at(info, 20, endianness) as usize;
        let pages_end = 22_usize
            .checked_add(page_count.checked_mul(2).ok_or_else(|| {
                Lab002Error::InvalidMachO("chained-fixups page table overflows".into())
            })?)
            .ok_or_else(|| {
                Lab002Error::InvalidMachO("chained-fixups page table overflows".into())
            })?;
        let expected_segment_offset =
            segment.vmaddr.checked_sub(image_vmaddr).ok_or_else(|| {
                Lab002Error::InvalidMachO("chained-fixups segment precedes the image header".into())
            })?;
        // Chained starts cover the serialized prefix through the last page
        // containing a fixup. Xcode 26 can emit one page entry for a two-page
        // file-backed __DATA segment when only its first page has a start, so
        // equality with the file-backed page count would reject valid output.
        // The prefix still cannot exceed the file-backed segment extent, while
        // the VM extent may additionally include trailing __bss/__common pages.
        let maximum_page_count = if matches!(page_size, 0x1000 | 0x4000) {
            segment
                .filesize
                .checked_add(u64::from(page_size) - 1)
                .map(|size| size / u64::from(page_size))
                .and_then(|count| usize::try_from(count).ok())
        } else {
            None
        };
        if record_size < pages_end
            || record_size > info.len()
            || !matches!(page_size, 0x1000 | 0x4000)
            || !(1..=14).contains(&pointer_format)
            || segment_offset != expected_segment_offset
            || page_count == 0
            || maximum_page_count.is_none_or(|maximum| page_count > maximum)
        {
            return Err(Lab002Error::InvalidMachO(
                "chained-fixups segment record is invalid".into(),
            ));
        }
        let record_end = info_offset.checked_add(record_size).ok_or_else(|| {
            Lab002Error::InvalidMachO("chained-fixups segment record overflows".into())
        })?;
        record_intervals.push((info_offset, record_end));
        if segment.is_text {
            for page in 0..page_count {
                let offset = 22 + page * 2;
                let start = read_u16_at(info, offset, endianness);
                if start != 0xffff {
                    return Err(Lab002Error::InvalidMachO(
                        "chained fixup targets executable __TEXT".into(),
                    ));
                }
            }
        } else {
            for page in 0..page_count {
                let offset = 22 + page * 2;
                let start = read_u16_at(info, offset, endianness);
                if start == 0xffff {
                    continue;
                }
                let page_start = u64::from(page_size)
                    .checked_mul(page as u64)
                    .and_then(|base| base.checked_add(u64::from(start)));
                if start & 0x8000 != 0
                    || u64::from(start) >= u64::from(page_size)
                    || page_start.is_none_or(|value| value >= segment.filesize)
                {
                    return Err(Lab002Error::InvalidMachO(
                        "chained-fixups page start is invalid".into(),
                    ));
                }
            }
        }
    }
    record_intervals.sort_unstable();
    if record_intervals
        .windows(2)
        .any(|pair| pair[0].1 > pair[1].0)
    {
        return Err(Lab002Error::InvalidMachO(
            "chained-fixups segment records overlap".into(),
        ));
    }
    let starts_extent = record_intervals
        .last()
        .map_or(offsets_end, |(_, end)| offsets_end.max(*end));
    let starts_end = starts_offset.checked_add(starts_extent).ok_or_else(|| {
        Lab002Error::InvalidMachO("chained-fixups starts structure overflows".into())
    })?;
    if symbols_format != 0 || !(1..=3).contains(&imports_format) {
        return Err(Lab002Error::InvalidMachO(
            "chained-fixups import or symbol format is invalid".into(),
        ));
    }
    if imports_count == 0 {
        if (imports_offset != 0 || symbols_offset != 0)
            && (imports_offset < starts_end
                || imports_offset > payload.len()
                || symbols_offset < imports_offset
                || symbols_offset > payload.len())
        {
            return Err(Lab002Error::InvalidMachO(
                "empty chained-fixups tables are outside their bounded layout".into(),
            ));
        }
    } else {
        let import_record_size = match imports_format {
            1 => 4_usize,
            2 => 8_usize,
            3 => 16_usize,
            _ => unreachable!("validated import format"),
        };
        let imports_end = imports_offset
            .checked_add(
                imports_count
                    .checked_mul(import_record_size)
                    .ok_or_else(|| {
                        Lab002Error::InvalidMachO("chained-fixups imports table overflows".into())
                    })?,
            )
            .ok_or_else(|| {
                Lab002Error::InvalidMachO("chained-fixups imports table overflows".into())
            })?;
        if imports_offset < starts_end
            || imports_end > payload.len()
            || symbols_offset < imports_end
            || symbols_offset >= payload.len()
        {
            return Err(Lab002Error::InvalidMachO(
                "chained-fixups starts, imports, or symbols layout overlaps".into(),
            ));
        }
        let symbols = &payload[symbols_offset..];
        for import_index in 0..imports_count {
            let record_offset = imports_offset + import_index * import_record_size;
            let name_offset = match imports_format {
                1 | 2 => usize::try_from(read_u32_at(payload, record_offset, endianness) >> 9)
                    .expect("23-bit name offset fits usize"),
                3 => {
                    let record = read_u64_at(payload, record_offset, endianness);
                    if record & 0x0000_0000_fffe_0000 != 0 {
                        return Err(Lab002Error::InvalidMachO(
                            "chained-fixups 64-bit import has nonzero reserved bits".into(),
                        ));
                    }
                    usize::try_from(record >> 32).map_err(|_| {
                        Lab002Error::InvalidMachO(
                            "chained-fixups import name offset is too large".into(),
                        )
                    })?
                }
                _ => unreachable!("validated import format"),
            };
            let name = symbols.get(name_offset..).ok_or_else(|| {
                Lab002Error::InvalidMachO(
                    "chained-fixups import name is outside the symbol pool".into(),
                )
            })?;
            if name.first() == Some(&0) || !name.contains(&0) {
                return Err(Lab002Error::InvalidMachO(
                    "chained-fixups import name is empty or unterminated".into(),
                ));
            }
        }
    }
    Ok(())
}

fn measure_fixup_layout<R: Read + Seek>(
    reader: &mut R,
    layout: FixupLayout<'_>,
) -> Result<String, Lab002Error> {
    if layout.classic.is_some() && layout.chained.is_some() {
        return Err(Lab002Error::InvalidMachO(
            "classic and chained fixup layouts cannot coexist".into(),
        ));
    }

    let mut digest = Sha256::new();
    digest.update(FIXUP_LAYOUT_DOMAIN);
    digest.update([match layout.endianness {
        Endianness::Little => 0,
        Endianness::Big => 1,
    }]);
    digest.update([
        u8::from(layout.is_64_bit),
        u8::from(layout.saw_dynamic_symbol_table),
    ]);
    digest.update(
        u32::try_from(layout.segments.len())
            .map_err(|_| Lab002Error::InvalidMachO("segment inventory overflows".into()))?
            .to_be_bytes(),
    );
    for segment in layout.segments {
        digest.update(segment.vmaddr.to_be_bytes());
        digest.update(segment.vmsize.to_be_bytes());
        digest.update(segment.filesize.to_be_bytes());
        digest.update([u8::from(segment.is_text)]);
    }

    match (layout.classic, layout.chained) {
        (Some((command, streams)), None) => {
            digest.update([1]);
            digest.update(command.to_be_bytes());
            for (data_offset, data_size, kind) in streams {
                digest.update([kind.binding_byte()]);
                digest.update(data_offset.to_be_bytes());
                digest.update(data_size.to_be_bytes());
                if (data_offset == 0) != (data_size == 0) {
                    return Err(Lab002Error::InvalidMachO(
                        "dyld-info offset/size pair is contradictory".into(),
                    ));
                }
                if data_size == 0 {
                    continue;
                }
                let stream = read_slice_payload(
                    reader,
                    layout.slice_offset,
                    layout.slice_size,
                    data_offset,
                    data_size,
                    "dyld-info fixup stream",
                )?;
                inspect_fixup_opcodes(
                    &stream,
                    kind,
                    layout.segments,
                    if layout.is_64_bit { 8 } else { 4 },
                )?;
                digest.update(&stream);
            }
        }
        (None, Some((data_offset, data_size))) => {
            digest.update([2]);
            digest.update(data_offset.to_be_bytes());
            digest.update(data_size.to_be_bytes());
            if (data_offset == 0) != (data_size == 0) || data_size == 0 {
                return Err(Lab002Error::InvalidMachO(
                    "chained-fixups offset/size pair is invalid".into(),
                ));
            }
            let payload = read_slice_payload(
                reader,
                layout.slice_offset,
                layout.slice_size,
                data_offset,
                data_size,
                "chained-fixups payload",
            )?;
            inspect_chained_fixups(
                &payload,
                layout.endianness,
                layout.segments,
                layout.image_text_vmaddr,
            )?;
            digest.update(&payload);
        }
        (None, None) => digest.update([0]),
        (Some(_), Some(_)) => unreachable!("coexistence rejected above"),
    }
    Ok(lower_hex(&digest.finalize()))
}

/// Parse exactly one `__TEXT,__oprobe` pure-instruction section per slice.
///
/// The parser first reuses the bounded general Mach-O parser, then independently
/// validates segment/section structure, UUID uniqueness, section relocations,
/// file/VM delta equality, and the exact section bytes. It never modifies the
/// input or treats simulator plaintext as device evidence.
pub fn parse_fixed_sections<R: Read + Seek>(
    reader: &mut R,
) -> Result<FixedSectionReport, Lab002Error> {
    let report =
        parse_macho(reader).map_err(|error| Lab002Error::InvalidMachO(error.to_string()))?;
    if report.file_size > MAX_LAB002_EXECUTABLE_BYTES {
        return Err(Lab002Error::InvalidMachO(
            "LAB-002 executable exceeds 100 MiB".into(),
        ));
    }
    let mut fixed_slices = Vec::with_capacity(report.slices.len());
    let mut seen_uuids = HashSet::with_capacity(report.slices.len());

    for (ordinal, slice) in report.slices.iter().enumerate() {
        if slice.load_command_bytes > MAX_LAB002_LOAD_COMMAND_BYTES {
            return Err(Lab002Error::InvalidMachO(
                "LAB-002 load-command table exceeds 4 MiB".into(),
            ));
        }
        let header_size = if slice.is_64_bit { 32_u64 } else { 28_u64 };
        let load_commands_end = header_size
            .checked_add(u64::from(slice.load_command_bytes))
            .ok_or_else(|| Lab002Error::InvalidMachO("load-command table overflows".into()))?;
        let command_start = slice
            .offset
            .checked_add(header_size)
            .ok_or_else(|| Lab002Error::InvalidMachO("load-command offset overflows".into()))?;
        let mut commands = vec![0_u8; slice.load_command_bytes as usize];
        reader
            .seek(SeekFrom::Start(command_start))
            .map_err(|error| Lab002Error::Io(error.to_string()))?;
        reader
            .read_exact(&mut commands)
            .map_err(|error| Lab002Error::Io(error.to_string()))?;

        let mut cursor = 0_usize;
        let mut uuid = None;
        let mut fixed = None;
        let mut fixed_section_index = None;
        let mut section_index_in_image = 0_usize;
        let mut file_backed_sections = Vec::new();
        let mut vm_sections = Vec::new();
        let mut fixup_segments = Vec::new();
        let mut classic_fixup_streams = None;
        let mut chained_fixups = None;
        let mut saw_dynamic_symbol_table = false;
        let mut image_text_vmaddr = None;
        let mut code_signature = None;
        for _ in 0..slice.load_command_count {
            if cursor.checked_add(8).is_none_or(|end| end > commands.len()) {
                return Err(Lab002Error::InvalidMachO(
                    "load-command header exceeds declared table".into(),
                ));
            }
            let command = read_u32_at(&commands, cursor, slice.endianness);
            let size = read_u32_at(&commands, cursor + 4, slice.endianness) as usize;
            let command_end = cursor
                .checked_add(size)
                .ok_or_else(|| Lab002Error::InvalidMachO("load-command size overflows".into()))?;
            if size < 8 || command_end > commands.len() {
                return Err(Lab002Error::InvalidMachO(
                    "load command exceeds declared table".into(),
                ));
            }
            if !supported_lab002_load_command(command, slice.is_64_bit) {
                return Err(Lab002Error::InvalidMachO(format!(
                    "load command 0x{command:08x} is outside the closed LAB-002 profile"
                )));
            }
            let bytes = &commands[cursor..command_end];
            if command == 0x1b {
                if size != 24 || uuid.is_some() {
                    return Err(Lab002Error::InvalidMachO(
                        "Mach-O must contain exactly one well-formed LC_UUID".into(),
                    ));
                }
                uuid = Some(bytes[8..24].to_vec());
            }
            if command == LC_DYLD_INFO || command == LC_DYLD_INFO_ONLY {
                if size != 48 || classic_fixup_streams.is_some() {
                    return Err(Lab002Error::InvalidMachO(
                        "Mach-O has malformed or duplicate dyld-info commands".into(),
                    ));
                }
                classic_fixup_streams = Some((
                    command,
                    [
                        (
                            read_u32_at(bytes, 8, slice.endianness),
                            read_u32_at(bytes, 12, slice.endianness),
                            FixupOpcodeKind::Rebase,
                        ),
                        (
                            read_u32_at(bytes, 16, slice.endianness),
                            read_u32_at(bytes, 20, slice.endianness),
                            FixupOpcodeKind::Bind,
                        ),
                        (
                            read_u32_at(bytes, 24, slice.endianness),
                            read_u32_at(bytes, 28, slice.endianness),
                            FixupOpcodeKind::Bind,
                        ),
                        (
                            read_u32_at(bytes, 32, slice.endianness),
                            read_u32_at(bytes, 36, slice.endianness),
                            FixupOpcodeKind::LazyBind,
                        ),
                    ],
                ));
            }
            if command == LC_DYLD_CHAINED_FIXUPS {
                if size != 16 || chained_fixups.is_some() {
                    return Err(Lab002Error::InvalidMachO(
                        "Mach-O has malformed or duplicate chained-fixups commands".into(),
                    ));
                }
                chained_fixups = Some((
                    read_u32_at(bytes, 8, slice.endianness),
                    read_u32_at(bytes, 12, slice.endianness),
                ));
            }
            if command == LC_DYSYMTAB {
                if size != 80 || saw_dynamic_symbol_table {
                    return Err(Lab002Error::InvalidMachO(
                        "Mach-O has malformed or duplicate dynamic-symbol-table commands".into(),
                    ));
                }
                saw_dynamic_symbol_table = true;
                let external_relocation_count = read_u32_at(bytes, 68, slice.endianness);
                let local_relocation_count = read_u32_at(bytes, 76, slice.endianness);
                if external_relocation_count != 0 || local_relocation_count != 0 {
                    return Err(Lab002Error::InvalidMachO(
                        "Mach-O dynamic relocation tables are outside the LAB-002 fixed-range profile"
                            .into(),
                    ));
                }
            }
            if command == 0x1d {
                if size != 16 || code_signature.is_some() {
                    return Err(Lab002Error::InvalidMachO(
                        "Mach-O has malformed or duplicate code-signature commands".into(),
                    ));
                }
                code_signature = Some((
                    read_u32_at(bytes, 8, slice.endianness),
                    read_u32_at(bytes, 12, slice.endianness),
                ));
            }

            let is_segment =
                (!slice.is_64_bit && command == 0x1) || (slice.is_64_bit && command == 0x19);
            if is_segment {
                let (
                    segment_header_size,
                    section_size,
                    vmaddr,
                    vmsize,
                    fileoff,
                    filesize,
                    initprot,
                    nsects,
                ) = if slice.is_64_bit {
                    if size < 72 {
                        return Err(Lab002Error::InvalidMachO(
                            "LC_SEGMENT_64 is truncated".into(),
                        ));
                    }
                    (
                        72_usize,
                        80_usize,
                        read_u64_at(bytes, 24, slice.endianness),
                        read_u64_at(bytes, 32, slice.endianness),
                        read_u64_at(bytes, 40, slice.endianness),
                        read_u64_at(bytes, 48, slice.endianness),
                        read_u32_at(bytes, 60, slice.endianness),
                        read_u32_at(bytes, 64, slice.endianness),
                    )
                } else {
                    if size < 56 {
                        return Err(Lab002Error::InvalidMachO("LC_SEGMENT is truncated".into()));
                    }
                    (
                        56_usize,
                        68_usize,
                        u64::from(read_u32_at(bytes, 24, slice.endianness)),
                        u64::from(read_u32_at(bytes, 28, slice.endianness)),
                        u64::from(read_u32_at(bytes, 32, slice.endianness)),
                        u64::from(read_u32_at(bytes, 36, slice.endianness)),
                        read_u32_at(bytes, 44, slice.endianness),
                        read_u32_at(bytes, 48, slice.endianness),
                    )
                };
                let expected_size = section_size
                    .checked_mul(nsects as usize)
                    .and_then(|sections| segment_header_size.checked_add(sections))
                    .ok_or_else(|| {
                        Lab002Error::InvalidMachO("segment section table overflows".into())
                    })?;
                if expected_size != size {
                    return Err(Lab002Error::InvalidMachO(
                        "segment command size does not match its section count".into(),
                    ));
                }
                let segment_file_end = fileoff.checked_add(filesize).ok_or_else(|| {
                    Lab002Error::InvalidMachO("segment file range overflows".into())
                })?;
                if filesize > vmsize || segment_file_end > slice.size {
                    return Err(Lab002Error::InvalidMachO(
                        "segment file extent is invalid".into(),
                    ));
                }
                let segment_name = macho_name(&bytes[8..24])?;
                if segment_name == "__TEXT" && image_text_vmaddr.replace(vmaddr).is_some() {
                    return Err(Lab002Error::InvalidMachO(
                        "Mach-O has duplicate __TEXT segments".into(),
                    ));
                }
                fixup_segments.push(FixupSegment {
                    vmaddr,
                    vmsize,
                    filesize,
                    is_text: segment_name == "__TEXT",
                });
                for section_index in 0..nsects as usize {
                    let section_start = segment_header_size + section_index * section_size;
                    let section = &bytes[section_start..section_start + section_size];
                    let current_section_index = section_index_in_image;
                    section_index_in_image =
                        section_index_in_image.checked_add(1).ok_or_else(|| {
                            Lab002Error::InvalidMachO("section inventory overflows".into())
                        })?;
                    let section_name = macho_name(&section[0..16])?;
                    let section_segment_name = macho_name(&section[16..32])?;
                    let (address, length, offset, relocation_offset, relocation_count, flags) =
                        if slice.is_64_bit {
                            (
                                read_u64_at(section, 32, slice.endianness),
                                read_u64_at(section, 40, slice.endianness),
                                u64::from(read_u32_at(section, 48, slice.endianness)),
                                read_u32_at(section, 56, slice.endianness),
                                read_u32_at(section, 60, slice.endianness),
                                read_u32_at(section, 64, slice.endianness),
                            )
                        } else {
                            (
                                u64::from(read_u32_at(section, 32, slice.endianness)),
                                u64::from(read_u32_at(section, 36, slice.endianness)),
                                u64::from(read_u32_at(section, 40, slice.endianness)),
                                read_u32_at(section, 48, slice.endianness),
                                read_u32_at(section, 52, slice.endianness),
                                read_u32_at(section, 56, slice.endianness),
                            )
                        };
                    if length != 0 {
                        let vm_end = address.checked_add(length).ok_or_else(|| {
                            Lab002Error::InvalidMachO("section VM range overflows".into())
                        })?;
                        vm_sections.push((current_section_index, address, vm_end));
                    }
                    if length != 0 && !is_zero_fill_section(flags) {
                        let end = offset.checked_add(length).ok_or_else(|| {
                            Lab002Error::InvalidMachO("section file range overflows".into())
                        })?;
                        if end > slice.size {
                            return Err(Lab002Error::InvalidMachO(
                                "section file range exceeds its slice".into(),
                            ));
                        }
                        file_backed_sections.push((current_section_index, offset, end));
                    }
                    if section_name != "__oprobe" || section_segment_name != "__TEXT" {
                        continue;
                    }
                    if fixed.is_some() {
                        return Err(Lab002Error::InvalidMachO(
                            "slice has duplicate __TEXT,__oprobe sections".into(),
                        ));
                    }
                    if segment_name != "__TEXT" || initprot & 0x4 == 0 {
                        return Err(Lab002Error::InvalidMachO(
                            "fixed section is not in executable __TEXT".into(),
                        ));
                    }
                    if !(64..=1024).contains(&length)
                        || flags & 0xff != 0
                        || flags & 0x8000_0000 == 0
                        || flags & 0x0000_0400 == 0
                        || relocation_offset != 0
                        || relocation_count != 0
                    {
                        return Err(Lab002Error::InvalidMachO(
                            "fixed section is not relocation-free pure instructions".into(),
                        ));
                    }
                    let segment_vm_end = vmaddr.checked_add(vmsize).ok_or_else(|| {
                        Lab002Error::InvalidMachO("segment VM range overflows".into())
                    })?;
                    let section_end = offset.checked_add(length).ok_or_else(|| {
                        Lab002Error::InvalidMachO("section file range overflows".into())
                    })?;
                    let section_vm_end = address.checked_add(length).ok_or_else(|| {
                        Lab002Error::InvalidMachO("section VM range overflows".into())
                    })?;
                    if offset < load_commands_end
                        || offset < fileoff
                        || section_end > segment_file_end
                        || address < vmaddr
                        || section_vm_end > segment_vm_end
                    {
                        return Err(Lab002Error::InvalidMachO(
                            "fixed section overlaps metadata or exceeds its file-backed/VM segment"
                                .into(),
                        ));
                    }
                    let file_delta = offset.checked_sub(fileoff).ok_or_else(|| {
                        Lab002Error::InvalidMachO("section file delta underflows".into())
                    })?;
                    let vm_delta = address.checked_sub(vmaddr).ok_or_else(|| {
                        Lab002Error::InvalidMachO("section VM delta underflows".into())
                    })?;
                    if file_delta != vm_delta {
                        return Err(Lab002Error::InvalidMachO(
                            "fixed section file/VM segment deltas differ".into(),
                        ));
                    }
                    fixed = Some((offset, address, length));
                    fixed_section_index = Some(current_section_index);
                }
            }
            cursor = command_end;
        }
        if cursor != commands.len() {
            return Err(Lab002Error::InvalidMachO(
                "load commands do not consume the declared table".into(),
            ));
        }
        reject_overlapping_segment_vm_ranges(&fixup_segments)?;
        let image_text_vmaddr = image_text_vmaddr
            .ok_or_else(|| Lab002Error::InvalidMachO("slice has no __TEXT segment".into()))?;
        let fixup_layout_sha256 = measure_fixup_layout(
            reader,
            FixupLayout {
                slice_offset: slice.offset,
                slice_size: slice.size,
                endianness: slice.endianness,
                is_64_bit: slice.is_64_bit,
                segments: &fixup_segments,
                classic: classic_fixup_streams,
                chained: chained_fixups,
                saw_dynamic_symbol_table,
                image_text_vmaddr,
            },
        )?;
        let uuid =
            uuid.ok_or_else(|| Lab002Error::InvalidMachO("Mach-O slice has no LC_UUID".into()))?;
        if !seen_uuids.insert(uuid.clone()) {
            return Err(Lab002Error::InvalidMachO(
                "Mach-O slices have duplicate LC_UUID values".into(),
            ));
        }
        let (section_slice_offset, section_address, section_length) = fixed.ok_or_else(|| {
            Lab002Error::InvalidMachO("slice has no __TEXT,__oprobe section".into())
        })?;
        let fixed_section_index = fixed_section_index.expect("fixed section index is paired");
        let fixed_end = section_slice_offset
            .checked_add(section_length)
            .ok_or_else(|| Lab002Error::InvalidMachO("fixed section range overflows".into()))?;
        if file_backed_sections.iter().any(|(index, start, end)| {
            *index != fixed_section_index && *start < fixed_end && section_slice_offset < *end
        }) {
            return Err(Lab002Error::InvalidMachO(
                "fixed section overlaps another section".into(),
            ));
        }
        let fixed_vm_end = section_address
            .checked_add(section_length)
            .ok_or_else(|| Lab002Error::InvalidMachO("fixed section VM range overflows".into()))?;
        if vm_sections.iter().any(|(index, start, end)| {
            *index != fixed_section_index && *start < fixed_vm_end && section_address < *end
        }) {
            return Err(Lab002Error::InvalidMachO(
                "fixed section overlaps another section in VM".into(),
            ));
        }
        let section_vm_offset = section_address
            .checked_sub(image_text_vmaddr)
            .ok_or_else(|| Lab002Error::InvalidMachO("section VM offset underflows".into()))?;
        let section_file_offset = slice
            .offset
            .checked_add(section_slice_offset)
            .ok_or_else(|| Lab002Error::InvalidMachO("absolute section offset overflows".into()))?;
        let section_range = bounded_range(
            section_slice_offset,
            section_length,
            slice.size,
            "fixed section",
        )?;
        let mut section_bytes = vec![0_u8; section_range.len()];
        reader
            .seek(SeekFrom::Start(section_file_offset))
            .map_err(|error| Lab002Error::Io(error.to_string()))?;
        reader
            .read_exact(&mut section_bytes)
            .map_err(|error| Lab002Error::Io(error.to_string()))?;
        let signing = if let Some((data_offset, data_size)) = code_signature {
            if !(12..=MAX_FIXUP_PAYLOAD_BYTES).contains(&data_size)
                || u64::from(data_offset) < fixed_end
            {
                return Err(Lab002Error::InvalidMachO(
                    "code-signature range is invalid or overlaps the fixed section".into(),
                ));
            }
            let signature = read_slice_payload(
                reader,
                slice.offset,
                slice.size,
                data_offset,
                data_size,
                "code-signature SuperBlob",
            )?;
            Some(parse_preupload_code_signature(
                &signature,
                u64::from(data_offset),
                reader,
                slice.offset,
            )?)
        } else {
            None
        };
        fixed_slices.push(FixedSectionSlice {
            ordinal: u8::try_from(ordinal).map_err(|_| {
                Lab002Error::InvalidMachO("slice ordinal exceeds the LAB-002 limit".into())
            })?,
            cpu_type: slice.cpu_type,
            cpu_subtype: slice.cpu_subtype,
            macho_uuid: lower_hex(&uuid),
            slice_file_offset: slice.offset,
            slice_file_size: slice.size,
            section_slice_offset,
            section_file_offset,
            section_vm_offset,
            section_length,
            section_sha256: sha256_hex(&section_bytes),
            fixup_layout_sha256,
            encryption: slice.encryption.clone(),
            signing,
        });
    }
    Ok(FixedSectionReport {
        container: report.container,
        file_size: report.file_size,
        slices: fixed_slices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Cursor, SeekFrom, Write};

    fn build_input() -> BuildBindingInput {
        BuildBindingInput {
            source_commit: "11".repeat(20),
            marketing_version: "1.1".into(),
            build_number: "3".into(),
            configuration: "Release".into(),
            observer_revision: "lab002-observer-v1".into(),
            authorized_target_manifest_sha256: "22".repeat(32),
            xcode_version: "26.0".into(),
            xcode_build: "17A100".into(),
            iphoneos_sdk_version: "26.0".into(),
            iphoneos_sdk_build: "23A100".into(),
            xcodegen_version: "2.44.1".into(),
            xcodegen_architecture: "arm64".into(),
            xcodegen_executable_sha256: "33".repeat(32),
            fastlane_version: "2.228.0".into(),
            gemfile_lock_sha256: "44".repeat(32),
        }
    }

    #[test]
    fn selected_entitlements_accept_bounded_binary_plist() {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert(
            "application-identifier".into(),
            plist::Value::String("TEAM123456.com.example.demolab".into()),
        );
        dictionary.insert(
            "com.apple.developer.team-identifier".into(),
            plist::Value::String("TEAM123456".into()),
        );
        dictionary.insert(
            "com.apple.security.application-groups".into(),
            plist::Value::Array(vec![plist::Value::String(
                "group.com.example.demolab".into(),
            )]),
        );
        let mut encoded = Vec::new();
        plist::Value::Dictionary(dictionary)
            .to_writer_binary(&mut encoded)
            .unwrap();

        let parsed = parse_selected_entitlements(&encoded).unwrap();
        assert_eq!(
            parsed.application_identifier.as_deref(),
            Some("TEAM123456.com.example.demolab")
        );
        assert_eq!(
            parsed.developer_team_identifier.as_deref(),
            Some("TEAM123456")
        );
        assert_eq!(
            parsed.application_groups.as_deref(),
            Some(["group.com.example.demolab".to_owned()].as_slice())
        );
    }

    #[test]
    fn selected_entitlements_reject_binary_allocation_amplification() {
        let mut oversized_collection = b"bplist00".to_vec();
        oversized_collection.extend_from_slice(&[
            0xaf, // Array with an extended length.
            0x13, // Eight-byte integer length.
        ]);
        oversized_collection
            .extend_from_slice(&(MAX_ENTITLEMENTS_COLLECTION_ITEMS + 1).to_be_bytes());
        let offset_table = oversized_collection.len() as u64;
        oversized_collection.push(8);
        let mut trailer = [0_u8; 32];
        trailer[6] = 1;
        trailer[7] = 1;
        trailer[15] = 1;
        trailer[24..].copy_from_slice(&offset_table.to_be_bytes());
        oversized_collection.extend_from_slice(&trailer);
        assert!(matches!(
            parse_selected_entitlements(&oversized_collection),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("binary collection items")
        ));

        let mut excessive_objects = b"bplist00\xd0\x08".to_vec();
        let offset_table = 9_u64;
        let mut trailer = [0_u8; 32];
        trailer[6] = 1;
        trailer[7] = 1;
        trailer[8..16].copy_from_slice(&(MAX_ENTITLEMENTS_BINARY_OBJECTS + 1).to_be_bytes());
        trailer[24..].copy_from_slice(&offset_table.to_be_bytes());
        excessive_objects.extend_from_slice(&trailer);
        assert!(matches!(
            parse_selected_entitlements(&excessive_objects),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("object inventory")
        ));
    }

    #[test]
    fn selected_entitlements_reject_duplicate_root_keys() {
        let encoded = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>application-identifier</key><string>TEAM123456.com.example.demolab</string>
<key>application-identifier</key><string>TEAM123456.com.example.replacement</string>
</dict></plist>"#;
        assert!(matches!(
            parse_selected_entitlements(encoded),
            Err(Lab002Error::InvalidMachO(message)) if message.contains("repeat root key")
        ));
    }

    #[test]
    fn selected_entitlements_reject_excessive_unknown_structure() {
        let too_many_items = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>unknown</key><array>{}</array></dict></plist>"#,
            "<true/>".repeat(MAX_ENTITLEMENTS_COLLECTION_ITEMS as usize + 1)
        );
        assert!(matches!(
            parse_selected_entitlements(too_many_items.as_bytes()),
            Err(Lab002Error::InvalidMachO(message)) if message.contains("collection items")
        ));

        let nested = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>unknown</key>{}<true/>{}</dict></plist>"#,
            "<array>".repeat(MAX_ENTITLEMENTS_DEPTH as usize),
            "</array>".repeat(MAX_ENTITLEMENTS_DEPTH as usize)
        );
        assert!(matches!(
            parse_selected_entitlements(nested.as_bytes()),
            Err(Lab002Error::InvalidMachO(message)) if message.contains("collection depth")
        ));
    }

    #[test]
    fn build_binding_is_domain_separated_and_field_order_sensitive() {
        let input = build_input();
        let digest = build_binding_sha256(&input).unwrap();
        assert_eq!(digest.len(), 64);
        let mut changed = input.clone();
        changed.xcode_build = "17A101".into();
        assert_ne!(digest, build_binding_sha256(&changed).unwrap());
        changed.configuration = "Debug".into();
        assert_eq!(
            build_binding_sha256(&changed),
            Err(Lab002Error::InvalidConfiguration)
        );
        for (field, changed) in [
            (
                "marketing version",
                BuildBindingInput {
                    marketing_version: "1.beta".into(),
                    ..input.clone()
                },
            ),
            (
                "observer revision",
                BuildBindingInput {
                    observer_revision: "../observer".into(),
                    ..input.clone()
                },
            ),
            (
                "Xcode build",
                BuildBindingInput {
                    xcode_build: "17a100".into(),
                    ..input.clone()
                },
            ),
            (
                "XcodeGen architecture",
                BuildBindingInput {
                    xcodegen_architecture: "arm64e".into(),
                    ..input.clone()
                },
            ),
        ] {
            assert!(
                matches!(
                    build_binding_sha256(&changed),
                    Err(Lab002Error::InvalidFieldGrammar { .. })
                ),
                "{field} grammar must fail closed"
            );
        }
    }

    #[test]
    fn target_identity_rejects_group_reordering_and_duplicates() {
        let base = TargetIdentityInput {
            identity_nonce_hex: "55".repeat(32),
            role: LabRole::MainApp,
            bundle_id: "com.example.demolab".into(),
            code_directory_identifier: "com.example.demolab".into(),
            code_directory_team_identifier: "TEAM123456".into(),
            application_identifier: EntitlementValue::Present(
                "TEAM123456.com.example.demolab".into(),
            ),
            developer_team_identifier: EntitlementValue::Present("TEAM123456".into()),
            app_groups: AppGroups::Present(vec![
                "group.com.example.demolab".into(),
                "group.com.example.demolab.shared".into(),
            ]),
        };
        let digest = target_identity_binding_sha256(&base).unwrap();
        let mut changed = base.clone();
        changed.role = LabRole::Framework;
        assert_ne!(digest, target_identity_binding_sha256(&changed).unwrap());
        changed.app_groups = AppGroups::Present(vec!["same".into(), "same".into()]);
        assert_eq!(
            target_identity_binding_sha256(&changed),
            Err(Lab002Error::InvalidAppGroups)
        );
        for (label, changed) in [
            (
                "malformed bundle identifier",
                TargetIdentityInput {
                    bundle_id: "com..example".into(),
                    ..base.clone()
                },
            ),
            (
                "malformed team identifier",
                TargetIdentityInput {
                    code_directory_team_identifier: "team123456".into(),
                    ..base.clone()
                },
            ),
            (
                "mismatched application identifier",
                TargetIdentityInput {
                    application_identifier: EntitlementValue::Present(
                        "TEAM123456.com.example.other".into(),
                    ),
                    ..base.clone()
                },
            ),
            (
                "malformed application group",
                TargetIdentityInput {
                    app_groups: AppGroups::Present(vec!["../group".into()]),
                    ..base.clone()
                },
            ),
        ] {
            assert!(
                matches!(
                    target_identity_binding_sha256(&changed),
                    Err(Lab002Error::InvalidFieldGrammar { .. })
                ),
                "{label} must fail closed"
            );
        }
    }

    #[test]
    fn device_binding_changes_with_device_installation_or_os() {
        let base = DeviceInstallationInput {
            identity_nonce_hex: "11".repeat(32),
            enrollment_public_key_hex: "22".repeat(32),
            installation_nonce_hex: "33".repeat(32),
            identifier_for_vendor: "123e4567-e89b-12d3-a456-426614174000".into(),
            hardware_model: "iPhone17,1".into(),
            ios_product_version: "26.0".into(),
            ios_build: "23A100".into(),
        };
        let digest = device_installation_binding_sha256(&base).unwrap();
        for changed in [
            DeviceInstallationInput {
                installation_nonce_hex: "44".repeat(32),
                ..base.clone()
            },
            DeviceInstallationInput {
                hardware_model: "iPhone17,2".into(),
                ..base.clone()
            },
            DeviceInstallationInput {
                ios_build: "23A101".into(),
                ..base.clone()
            },
        ] {
            assert_ne!(
                digest,
                device_installation_binding_sha256(&changed).unwrap()
            );
        }
        let mut uppercase_uuid = base.clone();
        uppercase_uuid.identifier_for_vendor = "123E4567-E89B-12D3-A456-426614174000".into();
        assert!(matches!(
            device_installation_binding_sha256(&uppercase_uuid),
            Err(Lab002Error::InvalidFieldGrammar {
                field: "identifier_for_vendor"
            })
        ));
        let mut nil_uuid = base.clone();
        nil_uuid.identifier_for_vendor = "00000000-0000-0000-0000-000000000000".into();
        assert!(matches!(
            device_installation_binding_sha256(&nil_uuid),
            Err(Lab002Error::InvalidFieldGrammar {
                field: "identifier_for_vendor"
            })
        ));
        let mut oversized_hardware = base.clone();
        oversized_hardware.hardware_model = format!("iPhone{},1", "1".repeat(30));
        assert!(matches!(
            device_installation_binding_sha256(&oversized_hardware),
            Err(Lab002Error::InvalidFieldGrammar {
                field: "hardware_model"
            })
        ));
    }

    #[test]
    fn canonical_json_sorts_utf16_keys_and_rejects_alternate_encodings() {
        let value = json!({"z": 1, "a": "quoted\"value", "array": [true, null]});
        let bytes = canonical_json(&value).unwrap();
        assert_eq!(bytes, br#"{"a":"quoted\"value","array":[true,null],"z":1}"#);
        assert_eq!(decode_canonical_json::<Value>(&bytes).unwrap(), value);
        assert_eq!(
            decode_canonical_json::<Value>(br#"{ "a":1}"#),
            Err(Lab002Error::NonCanonicalJson)
        );
        assert_eq!(
            decode_canonical_json::<Value>(br#"{"a":1,"a":1}"#),
            Err(Lab002Error::InvalidJson)
        );
        assert_eq!(
            decode_canonical_json::<Value>(br#"{"a":1.0}"#),
            Err(Lab002Error::NonIntegerJsonNumber)
        );
        assert_eq!(
            canonical_json(&json!({"unsafe": MAX_JCS_SAFE_INTEGER + 1})),
            Err(Lab002Error::NonIntegerJsonNumber)
        );
        assert_eq!(
            canonical_json(&json!({"unsafe": -(MAX_JCS_SAFE_INTEGER as i64) - 1})),
            Err(Lab002Error::NonIntegerJsonNumber)
        );
        let oversized = "a".repeat(MAX_AUTHORIZATION_OBJECT_BYTES);
        assert!(matches!(
            canonical_json_with_limit(&json!({"value": oversized}), MAX_AUTHORIZATION_OBJECT_BYTES),
            Err(Lab002Error::CanonicalJsonTooLarge {
                maximum: MAX_AUTHORIZATION_OBJECT_BYTES
            })
        ));
    }

    #[test]
    fn authorization_signature_binds_both_exact_canonical_objects() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let public_key_hex = lower_hex(&signing_key.verifying_key().to_bytes());
        let acknowledgement = AuthorizationAcknowledgement {
            profile: LAB002_PROFILE.into(),
            policy_version: AUTHORIZATION_POLICY_VERSION.into(),
            acknowledgement_id: "11".repeat(32),
            operation: AuthorizedOperation::CollectFixedRangeRun,
            experiment_id: "22".repeat(32),
            not_before: 1000,
            not_after: 1900,
            owns_target: true,
            owns_device: true,
            no_third_party_data: true,
            accepts_retention_policy: true,
        };
        let acknowledgement_bytes = canonical_json(&acknowledgement).unwrap();
        let operation = json!({
            "collection_id": "33".repeat(32),
            "expected_counter": "0000000000000001",
            "profile": LAB002_PROFILE
        });
        let operation_bytes = canonical_json(&operation).unwrap();
        let envelope =
            sign_authorized_operation(&signing_key, &acknowledgement_bytes, &operation_bytes)
                .unwrap();
        let envelope_bytes =
            canonical_json_with_limit(&envelope, MAX_AUTHORIZATION_ENVELOPE_BYTES).unwrap();
        let (decoded, _): (AuthorizationAcknowledgement, Value) =
            verify_authorized_operation(&envelope_bytes, &public_key_hex).unwrap();
        decoded
            .validate(AuthorizedOperation::CollectFixedRangeRun)
            .unwrap();
        let mut wrong_policy = decoded.clone();
        wrong_policy.policy_version = "orchardprobe.authorized-use.v2".into();
        assert_eq!(
            wrong_policy.validate(AuthorizedOperation::CollectFixedRangeRun),
            Err(Lab002Error::InvalidAuthorizationScope)
        );

        let mut forged = envelope.clone();
        forged.operation_core_canonical =
            r#"{"collection_id":"replayed","expected_counter":"0000000000000001","profile":"orchardprobe.demolab.lab002.observation.v1"}"#.into();
        let forged_bytes =
            canonical_json_with_limit(&forged, MAX_AUTHORIZATION_ENVELOPE_BYTES).unwrap();
        assert_eq!(
            verify_authorized_operation::<AuthorizationAcknowledgement, Value>(
                &forged_bytes,
                &public_key_hex
            ),
            Err(Lab002Error::InvalidAuthorizationSignature)
        );
        let mut noncanonical_outer = vec![b' '];
        noncanonical_outer.extend_from_slice(&envelope_bytes);
        assert_eq!(
            verify_authorized_operation::<AuthorizationAcknowledgement, Value>(
                &noncanonical_outer,
                &public_key_hex
            ),
            Err(Lab002Error::NonCanonicalJson)
        );
    }

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn oracle_fixture() -> LabOracle {
        LabOracle {
            profile: LAB002_PROFILE.into(),
            source_commit: "12".repeat(20),
            marketing_version: "1.1".into(),
            build_number: "3".into(),
            observer_revision: "lab002-observer-v1".into(),
            build_binding_sha256: digest(0x13),
            authorized_target_manifest_sha256: digest(0x14),
            ipa_sha256: digest(0x15),
            roles: LabRole::ALL
                .into_iter()
                .enumerate()
                .map(|(index, role)| OracleRole {
                    role,
                    fixture_relative_path: role.fixture_relative_path().into(),
                    target_identity_binding_sha256: digest(0x20 + index as u8),
                    slices: vec![OracleSlice {
                        ordinal: 0,
                        cpu_type: 0x0100_000c,
                        cpu_subtype: index as i32,
                        macho_uuid: format!("{:02x}", 0x30 + index as u8).repeat(16),
                        slice_file_offset: 0,
                        slice_file_size: 8192,
                        section_slice_offset: 4096,
                        section_file_offset: 4096,
                        section_vm_offset: 4096,
                        section_length: 256,
                        expected_plaintext_sha256: digest(0x40 + index as u8),
                    }],
                })
                .collect(),
        }
    }

    fn run_fixture(oracle: &LabOracle, ordinal: u8) -> LabRun {
        let base = if ordinal == 1 { 1_000 } else { 2_000 };
        let collection_id = digest(0x50 + ordinal);
        let session_id = digest(0x60 + ordinal);
        let challenge_sha256 = digest(0x70 + ordinal);
        let acknowledgement_sha256 = digest(0x80 + ordinal);
        let authorization_envelope_sha256 = digest(0x90 + ordinal);
        let collection_binding_sha256 = digest(0xa0 + ordinal);
        let run_counter = format!("{ordinal:016x}");
        let reports = oracle
            .roles
            .iter()
            .enumerate()
            .map(|(index, role)| RoleReport {
                profile: LAB002_PROFILE.into(),
                collection_id: collection_id.clone(),
                session_id: session_id.clone(),
                run_ordinal: ordinal,
                run_counter: run_counter.clone(),
                challenge_sha256: challenge_sha256.clone(),
                authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
                acknowledgement_sha256: acknowledgement_sha256.clone(),
                authorization_envelope_sha256: authorization_envelope_sha256.clone(),
                enrollment_binding_sha256: digest(0xb0),
                enrollment_public_key: digest(0xb1),
                device_installation_binding_sha256: digest(0xb2),
                hardware_model: "iPhone17,1".into(),
                ios_product_version: "26.0".into(),
                ios_build: "23A100".into(),
                source_commit: oracle.source_commit.clone(),
                marketing_version: oracle.marketing_version.clone(),
                build_number: oracle.build_number.clone(),
                observer_revision: oracle.observer_revision.clone(),
                build_binding_sha256: oracle.build_binding_sha256.clone(),
                role: role.role,
                fixture_relative_path: role.fixture_relative_path.clone(),
                target_identity_binding_sha256: role.target_identity_binding_sha256.clone(),
                signature: LabSignature {
                    presence: LabSignaturePresence::Present,
                    kind: LabSignatureKind::Cms,
                    validation: LabSignatureValidation::Valid,
                    validator_id: "bounded-cms-v1".into(),
                    validator_revision: "1".into(),
                    superblob_sha256: Some(digest(0xc0 + index as u8)),
                },
                disk_phase_completed_at: base + 10 + index as i64,
                mapped_phase_completed_at: base + 20 + index as i64,
                slices: role
                    .slices
                    .iter()
                    .enumerate()
                    .map(|(slice_index, slice)| ObservedSlice {
                        ordinal: slice.ordinal,
                        cpu_type: slice.cpu_type,
                        cpu_subtype: slice.cpu_subtype,
                        macho_uuid: slice.macho_uuid.clone(),
                        slice_file_offset: slice.slice_file_offset,
                        slice_file_size: slice.slice_file_size,
                        section_slice_offset: slice.section_slice_offset,
                        section_file_offset: slice.section_file_offset,
                        section_vm_offset: slice.section_vm_offset,
                        section_length: slice.section_length,
                        cryptoff: 0,
                        cryptsize: 8192,
                        cryptid: 1,
                        encryption_covers_section: true,
                        disk_sha256: digest(0xd0 + slice_index as u8 + index as u8),
                        mapped_sha256: slice.expected_plaintext_sha256.clone(),
                    })
                    .collect(),
            })
            .collect();
        LabRun {
            profile: LAB002_PROFILE.into(),
            collection_id,
            session_id,
            run_ordinal: ordinal,
            run_counter,
            challenge_sha256,
            authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
            acknowledgement_sha256,
            authorization_envelope_sha256,
            enrollment_binding_sha256: digest(0xb0),
            enrollment_public_key: digest(0xb1),
            device_installation_binding_sha256: digest(0xb2),
            hardware_model: "iPhone17,1".into(),
            ios_product_version: "26.0".into(),
            ios_build: "23A100".into(),
            source_commit: oracle.source_commit.clone(),
            marketing_version: oracle.marketing_version.clone(),
            build_number: oracle.build_number.clone(),
            observer_revision: oracle.observer_revision.clone(),
            build_binding_sha256: oracle.build_binding_sha256.clone(),
            authorization_not_before: base - 100,
            authorization_not_after: base + 800,
            created_at: base,
            completed_at: base + 100,
            prior_collection_binding_sha256: None,
            collection_binding_sha256,
            reports,
        }
    }

    fn two_run_fixture() -> (LabOracle, LabRun, LabRun) {
        let oracle = oracle_fixture();
        let run1 = run_fixture(&oracle, 1);
        let mut run2 = run_fixture(&oracle, 2);
        run2.prior_collection_binding_sha256 = Some(run1.collection_binding_sha256.clone());
        (oracle, run1, run2)
    }

    #[test]
    fn two_run_verifier_accepts_only_consistent_synthetic_evidence() {
        let (oracle, run1, run2) = two_run_fixture();
        let verified = verify_two_runs(&oracle, &run1, &run2).unwrap();
        assert_eq!(
            verified.status,
            DeviceFreeVerificationStatus::ConsistentSyntheticEvidence
        );
        assert_eq!(verified.normalized_evidence_sha256.len(), 64);
    }

    #[test]
    fn two_run_verifier_rejects_protection_plaintext_and_signature_failures() {
        let (oracle, run1, run2) = two_run_fixture();
        let mut mutations: Vec<(&str, LabRun)> = Vec::new();

        let mut cryptid_zero = run1.clone();
        cryptid_zero.reports[0].slices[0].cryptid = 0;
        mutations.push(("cryptid zero", cryptid_zero));

        let mut uncovered = run1.clone();
        uncovered.reports[0].slices[0].cryptsize = 64;
        mutations.push(("uncovered section", uncovered));

        let mut encryption_beyond_slice = run1.clone();
        encryption_beyond_slice.reports[0].slices[0].cryptsize =
            encryption_beyond_slice.reports[0].slices[0].slice_file_size + 1;
        mutations.push(("encryption beyond slice", encryption_beyond_slice));

        let mut disk_plaintext = run1.clone();
        disk_plaintext.reports[0].slices[0].disk_sha256 =
            oracle.roles[0].slices[0].expected_plaintext_sha256.clone();
        mutations.push(("disk already equals plaintext", disk_plaintext));

        let mut mapped_mismatch = run1.clone();
        mapped_mismatch.reports[0].slices[0].mapped_sha256 = digest(0xee);
        mutations.push(("mapped digest mismatch", mapped_mismatch));

        let mut unchecked = run1.clone();
        unchecked.reports[0].signature.validation = LabSignatureValidation::NotChecked;
        mutations.push(("signature unchecked", unchecked));

        let mut phase_reordered = run1.clone();
        phase_reordered.reports[0].mapped_phase_completed_at =
            phase_reordered.reports[0].disk_phase_completed_at - 1;
        mutations.push(("phase order", phase_reordered));

        for (label, changed_run1) in mutations {
            assert!(
                verify_two_runs(&oracle, &changed_run1, &run2).is_err(),
                "{label} must fail closed"
            );
        }
    }

    #[test]
    fn two_run_verifier_rejects_replay_environment_drift_and_inventory_changes() {
        let (oracle, run1, run2) = two_run_fixture();

        let mut replay = run2.clone();
        replay.challenge_sha256 = run1.challenge_sha256.clone();
        replay.reports.iter_mut().for_each(|report| {
            report.challenge_sha256 = replay.challenge_sha256.clone();
        });
        assert!(verify_two_runs(&oracle, &run1, &replay).is_err());

        let mut wrong_chain = run2.clone();
        wrong_chain.prior_collection_binding_sha256 = Some(digest(0xef));
        assert!(verify_two_runs(&oracle, &run1, &wrong_chain).is_err());

        let mut changed_os = run2.clone();
        changed_os.ios_build = "23A101".into();
        changed_os.reports.iter_mut().for_each(|report| {
            report.ios_build = changed_os.ios_build.clone();
        });
        assert!(verify_two_runs(&oracle, &run1, &changed_os).is_err());

        let mut skipped_counter = run2.clone();
        skipped_counter.run_counter = "0000000000000003".into();
        skipped_counter.reports.iter_mut().for_each(|report| {
            report.run_counter = skipped_counter.run_counter.clone();
        });
        assert!(verify_two_runs(&oracle, &run1, &skipped_counter).is_err());

        let mut extra_slice = run1.clone();
        let duplicated_slice = extra_slice.reports[0].slices[0].clone();
        extra_slice.reports[0].slices.push(duplicated_slice);
        assert!(verify_two_runs(&oracle, &extra_slice, &run2).is_err());

        let mut changed_slice_extent = run1.clone();
        changed_slice_extent.reports[0].slices[0].slice_file_size += 1;
        assert!(verify_two_runs(&oracle, &changed_slice_extent, &run2).is_err());

        let mut out_of_scope_oracle = oracle.clone();
        out_of_scope_oracle.roles[0].fixture_relative_path = "../Other.app/Other".into();
        assert!(verify_two_runs(&out_of_scope_oracle, &run1, &run2).is_err());

        let mut changed_validator = run2.clone();
        changed_validator.reports[1].signature.validator_revision = "2".into();
        assert!(verify_two_runs(&oracle, &run1, &changed_validator).is_err());

        let mut stale = run1.clone();
        stale.authorization_not_before = stale.created_at - 1_100;
        stale.authorization_not_after = stale.created_at - 200;
        assert!(verify_two_runs(&oracle, &stale, &run2).is_err());

        let mut overlapping_window = run2.clone();
        overlapping_window.authorization_not_before = run1.authorization_not_after;
        overlapping_window.authorization_not_after =
            overlapping_window.authorization_not_before + 900;
        assert!(verify_two_runs(&oracle, &run1, &overlapping_window).is_err());

        let mut oversized_validator_run1 = run1.clone();
        let mut oversized_validator_run2 = run2.clone();
        for run in [&mut oversized_validator_run1, &mut oversized_validator_run2] {
            run.reports[0].signature.validator_id = "v".repeat(MAX_FIELD_SCALARS + 1);
        }
        assert!(
            verify_two_runs(
                &oracle,
                &oversized_validator_run1,
                &oversized_validator_run2
            )
            .is_err()
        );
    }

    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(output: &mut Vec<u8>, value: u64) {
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn name16(value: &str) -> [u8; 16] {
        let mut output = [0_u8; 16];
        output[..value.len()].copy_from_slice(value.as_bytes());
        output
    }

    fn synthetic_fixed_macho(
        section_count: u32,
        vm_delta_mismatch: bool,
        relocation_count: u32,
        include_uuid: bool,
    ) -> Vec<u8> {
        let segment_size = 72 + section_count * 80;
        let command_count = 1 + u32::from(include_uuid) + 1;
        let command_bytes = segment_size + u32::from(include_uuid) * 24 + 24;
        let mut output = Vec::with_capacity(4096);
        push_u32(&mut output, 0xfeed_facf);
        push_u32(&mut output, 0x0100_000c);
        push_u32(&mut output, 0);
        push_u32(&mut output, 2);
        push_u32(&mut output, command_count);
        push_u32(&mut output, command_bytes);
        push_u32(&mut output, 0);
        push_u32(&mut output, 0);

        push_u32(&mut output, 0x19);
        push_u32(&mut output, segment_size);
        output.extend_from_slice(&name16("__TEXT"));
        push_u64(&mut output, 0x1_0000_0000);
        push_u64(&mut output, 4096);
        push_u64(&mut output, 0);
        push_u64(&mut output, 4096);
        push_u32(&mut output, 5);
        push_u32(&mut output, 5);
        push_u32(&mut output, section_count);
        push_u32(&mut output, 0);
        for index in 0..section_count {
            output.extend_from_slice(&name16("__oprobe"));
            output.extend_from_slice(&name16("__TEXT"));
            push_u64(
                &mut output,
                0x1_0000_0200 + if vm_delta_mismatch { 4 } else { 0 },
            );
            push_u64(&mut output, 256);
            push_u32(&mut output, 0x200 + index * 0x100);
            push_u32(&mut output, 2);
            push_u32(&mut output, if relocation_count == 0 { 0 } else { 0x300 });
            push_u32(&mut output, relocation_count);
            push_u32(&mut output, 0x8000_0400);
            push_u32(&mut output, 0);
            push_u32(&mut output, 0);
            push_u32(&mut output, 0);
        }
        if include_uuid {
            push_u32(&mut output, 0x1b);
            push_u32(&mut output, 24);
            output.extend(0_u8..16);
        }
        push_u32(&mut output, 0x2c);
        push_u32(&mut output, 24);
        push_u32(&mut output, 0);
        push_u32(&mut output, 2048);
        push_u32(&mut output, 0);
        push_u32(&mut output, 0);
        output.resize(4096, 0x90);
        output[0x200..0x300].fill(0x1f);
        output
    }

    fn append_be_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_be_bytes());
    }

    fn synthetic_code_signature_version(
        covered_code: &[u8],
        include_cms: bool,
        ad_hoc: bool,
        version: u32,
    ) -> Vec<u8> {
        let code_limit = u32::try_from(covered_code.len()).unwrap();
        let identifier = b"com.example.demolab\0";
        let team = b"TEAM123456\0";
        let entitlement_payload = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>application-identifier</key><string>TEAM123456.com.example.demolab</string>
<key>com.apple.developer.team-identifier</key><string>TEAM123456</string>
<key>com.apple.security.application-groups</key><array><string>group.com.example.demolab</string></array>
</dict></plist>"#;

        let header_length = match version {
            0x20200 => 52,
            0x20300 => 64,
            _ => panic!("unsupported synthetic CodeDirectory version"),
        };
        let dynamic_start = header_length + identifier.len() + team.len();
        let hash_offset = dynamic_start + 5 * 32;
        let code_slot_count = covered_code.len().div_ceil(4096);
        let mut code_directory = vec![0_u8; hash_offset + code_slot_count * 32];
        code_directory[0..4].copy_from_slice(&0xfade_0c02_u32.to_be_bytes());
        let code_directory_length = code_directory.len() as u32;
        code_directory[4..8].copy_from_slice(&code_directory_length.to_be_bytes());
        code_directory[8..12].copy_from_slice(&version.to_be_bytes());
        code_directory[12..16].copy_from_slice(&(if ad_hoc { 0x2_u32 } else { 0 }).to_be_bytes());
        code_directory[16..20].copy_from_slice(&(hash_offset as u32).to_be_bytes());
        code_directory[20..24].copy_from_slice(&(header_length as u32).to_be_bytes());
        code_directory[24..28].copy_from_slice(&5_u32.to_be_bytes());
        code_directory[28..32]
            .copy_from_slice(&u32::try_from(code_slot_count).unwrap().to_be_bytes());
        code_directory[32..36].copy_from_slice(&code_limit.to_be_bytes());
        code_directory[36] = 32;
        code_directory[37] = 2;
        code_directory[39] = 12;
        code_directory[40..44].copy_from_slice(&0_u32.to_be_bytes());
        code_directory[44..48].copy_from_slice(&0_u32.to_be_bytes());
        code_directory[48..52]
            .copy_from_slice(&(header_length as u32 + identifier.len() as u32).to_be_bytes());
        if version >= 0x20300 {
            code_directory[52..56].copy_from_slice(&0_u32.to_be_bytes());
            code_directory[56..64].copy_from_slice(&0_u64.to_be_bytes());
        }
        code_directory[header_length..header_length + identifier.len()].copy_from_slice(identifier);
        code_directory[header_length + identifier.len()..dynamic_start].copy_from_slice(team);
        for (index, page) in covered_code.chunks(4096).enumerate() {
            let start = hash_offset + index * 32;
            code_directory[start..start + 32].copy_from_slice(&Sha256::digest(page));
        }

        let mut entitlements = Vec::new();
        append_be_u32(&mut entitlements, 0xfade_7171);
        append_be_u32(&mut entitlements, (8 + entitlement_payload.len()) as u32);
        entitlements.extend_from_slice(entitlement_payload);
        let entitlement_hash_start = hash_offset - 5 * 32;
        code_directory[entitlement_hash_start..entitlement_hash_start + 32]
            .copy_from_slice(&Sha256::digest(&entitlements));
        let mut requirements = Vec::new();
        append_be_u32(&mut requirements, 0xfade_0c01);
        append_be_u32(&mut requirements, 12);
        append_be_u32(&mut requirements, 0);
        let requirements_hash_start = hash_offset - 2 * 32;
        code_directory[requirements_hash_start..requirements_hash_start + 32]
            .copy_from_slice(&Sha256::digest(&requirements));
        let mut cms = Vec::new();
        append_be_u32(&mut cms, 0xfade_0b01);
        append_be_u32(&mut cms, 12);
        append_be_u32(&mut cms, 0);

        let index_count = if include_cms { 4 } else { 3 };
        let index_end = 12 + index_count * 8;
        let code_directory_offset = index_end;
        let requirements_offset = code_directory_offset + code_directory.len();
        let entitlements_offset = requirements_offset + requirements.len();
        let cms_offset = entitlements_offset + entitlements.len();
        let length = cms_offset + if include_cms { cms.len() } else { 0 };
        let mut superblob = Vec::with_capacity(length);
        append_be_u32(&mut superblob, 0xfade_0cc0);
        append_be_u32(&mut superblob, length as u32);
        append_be_u32(&mut superblob, index_count as u32);
        let mut entries = vec![
            (0_u32, code_directory_offset),
            (2_u32, requirements_offset),
            (5_u32, entitlements_offset),
        ];
        if include_cms {
            entries.push((0x1_0000_u32, cms_offset));
        }
        for (slot, offset) in entries {
            append_be_u32(&mut superblob, slot);
            append_be_u32(&mut superblob, offset as u32);
        }
        superblob.extend_from_slice(&code_directory);
        superblob.extend_from_slice(&requirements);
        superblob.extend_from_slice(&entitlements);
        if include_cms {
            superblob.extend_from_slice(&cms);
        }
        superblob
    }

    fn synthetic_linker_signed_code_signature(covered_code: &[u8]) -> Vec<u8> {
        let code_limit = u32::try_from(covered_code.len()).unwrap();
        let identifier = b"DemoLab.debug.dylib\0";
        let header_length = 88_usize;
        let hash_offset = header_length + identifier.len();
        let code_slot_count = covered_code.len().div_ceil(4096);
        let mut code_directory = vec![0_u8; hash_offset + code_slot_count * 32];
        code_directory[0..4].copy_from_slice(&0xfade_0c02_u32.to_be_bytes());
        let code_directory_length = code_directory.len() as u32;
        code_directory[4..8].copy_from_slice(&code_directory_length.to_be_bytes());
        code_directory[8..12].copy_from_slice(&0x20400_u32.to_be_bytes());
        code_directory[12..16].copy_from_slice(&0x0002_0002_u32.to_be_bytes());
        code_directory[16..20].copy_from_slice(&(hash_offset as u32).to_be_bytes());
        code_directory[20..24].copy_from_slice(&(header_length as u32).to_be_bytes());
        code_directory[24..28].copy_from_slice(&0_u32.to_be_bytes());
        code_directory[28..32]
            .copy_from_slice(&u32::try_from(code_slot_count).unwrap().to_be_bytes());
        code_directory[32..36].copy_from_slice(&code_limit.to_be_bytes());
        code_directory[36] = 32;
        code_directory[37] = 2;
        code_directory[39] = 12;
        code_directory[header_length..header_length + identifier.len()].copy_from_slice(identifier);
        for (index, page) in covered_code.chunks(4096).enumerate() {
            let start = hash_offset + index * 32;
            code_directory[start..start + 32].copy_from_slice(&Sha256::digest(page));
        }

        let code_directory_offset = 20_usize;
        let length = code_directory_offset + code_directory.len();
        let mut superblob = Vec::with_capacity(length);
        append_be_u32(&mut superblob, 0xfade_0cc0);
        append_be_u32(&mut superblob, length as u32);
        append_be_u32(&mut superblob, 1);
        append_be_u32(&mut superblob, 0);
        append_be_u32(&mut superblob, code_directory_offset as u32);
        superblob.extend_from_slice(&code_directory);
        superblob
    }

    fn add_linker_signed_superblob_slot(signature: &[u8]) -> Vec<u8> {
        let code_directory_offset =
            u32::from_be_bytes(signature[16..20].try_into().unwrap()) as usize;
        let code_directory = &signature[code_directory_offset..];
        let extra_blob = [0xfa, 0xde, 0x0c, 0x01, 0, 0, 0, 8];
        let new_code_directory_offset = 28_usize;
        let extra_offset = new_code_directory_offset + code_directory.len();
        let length = extra_offset + extra_blob.len();
        let mut superblob = Vec::with_capacity(length);
        append_be_u32(&mut superblob, 0xfade_0cc0);
        append_be_u32(&mut superblob, length as u32);
        append_be_u32(&mut superblob, 2);
        append_be_u32(&mut superblob, 0);
        append_be_u32(&mut superblob, new_code_directory_offset as u32);
        append_be_u32(&mut superblob, 2);
        append_be_u32(&mut superblob, extra_offset as u32);
        superblob.extend_from_slice(code_directory);
        superblob.extend_from_slice(&extra_blob);
        superblob
    }

    fn add_linker_signed_special_slot_count(signature: &[u8]) -> Vec<u8> {
        let code_directory_offset =
            u32::from_be_bytes(signature[16..20].try_into().unwrap()) as usize;
        let old_hash_offset = u32::from_be_bytes(
            signature[code_directory_offset + 16..code_directory_offset + 20]
                .try_into()
                .unwrap(),
        ) as usize;
        let insertion = code_directory_offset + old_hash_offset;
        let mut superblob = signature.to_vec();
        superblob.splice(insertion..insertion, [0_u8; 32]);
        let code_directory_length = u32::from_be_bytes(
            superblob[code_directory_offset + 4..code_directory_offset + 8]
                .try_into()
                .unwrap(),
        ) + 32;
        superblob[code_directory_offset + 4..code_directory_offset + 8]
            .copy_from_slice(&code_directory_length.to_be_bytes());
        superblob[code_directory_offset + 16..code_directory_offset + 20]
            .copy_from_slice(&((old_hash_offset + 32) as u32).to_be_bytes());
        superblob[code_directory_offset + 24..code_directory_offset + 28]
            .copy_from_slice(&1_u32.to_be_bytes());
        let superblob_length = superblob.len() as u32;
        superblob[4..8].copy_from_slice(&superblob_length.to_be_bytes());
        superblob
    }

    fn add_code_signature(thin: Vec<u8>) -> Vec<u8> {
        add_code_signature_profile(thin, true, false)
    }

    fn add_linker_signed_code_signature(mut thin: Vec<u8>) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        let signature_offset = 0x800_u32;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 16).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&0x1d_u32.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&16_u32.to_le_bytes());
        thin[command_at + 8..command_at + 12].copy_from_slice(&signature_offset.to_le_bytes());
        let initial_signature =
            synthetic_linker_signed_code_signature(&thin[..signature_offset as usize]);
        thin[command_at + 12..command_at + 16]
            .copy_from_slice(&(initial_signature.len() as u32).to_le_bytes());
        let signature = synthetic_linker_signed_code_signature(&thin[..signature_offset as usize]);
        assert_eq!(signature.len(), initial_signature.len());
        thin[signature_offset as usize..signature_offset as usize + signature.len()]
            .copy_from_slice(&signature);
        thin
    }

    fn add_code_signature_profile(thin: Vec<u8>, include_cms: bool, ad_hoc: bool) -> Vec<u8> {
        add_code_signature_profile_version(thin, include_cms, ad_hoc, 0x20200)
    }

    fn add_code_signature_profile_version(
        mut thin: Vec<u8>,
        include_cms: bool,
        ad_hoc: bool,
        version: u32,
    ) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        let signature_offset = 0x800_u32;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 16).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&0x1d_u32.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&16_u32.to_le_bytes());
        thin[command_at + 8..command_at + 12].copy_from_slice(&signature_offset.to_le_bytes());
        let initial_signature = synthetic_code_signature_version(
            &thin[..signature_offset as usize],
            include_cms,
            ad_hoc,
            version,
        );
        thin[command_at + 12..command_at + 16]
            .copy_from_slice(&(initial_signature.len() as u32).to_le_bytes());
        let signature = synthetic_code_signature_version(
            &thin[..signature_offset as usize],
            include_cms,
            ad_hoc,
            version,
        );
        assert_eq!(signature.len(), initial_signature.len());
        thin[signature_offset as usize..signature_offset as usize + signature.len()]
            .copy_from_slice(&signature);
        thin
    }

    fn add_unknown_load_command(mut thin: Vec<u8>) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 8).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&0x7fff_fffe_u32.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&8_u32.to_le_bytes());
        thin
    }

    fn fat_wrap(thin: &[u8]) -> Vec<u8> {
        let offset = 4096_u32;
        let mut output = Vec::with_capacity(offset as usize + thin.len());
        output.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
        output.extend_from_slice(&1_u32.to_be_bytes());
        output.extend_from_slice(&0x0100_000c_u32.to_be_bytes());
        output.extend_from_slice(&0_u32.to_be_bytes());
        output.extend_from_slice(&offset.to_be_bytes());
        output.extend_from_slice(&(thin.len() as u32).to_be_bytes());
        output.extend_from_slice(&12_u32.to_be_bytes());
        output.resize(offset as usize, 0);
        output.extend_from_slice(thin);
        output
    }

    fn fat_wrap_duplicate_uuid() -> Vec<u8> {
        let arm64 = synthetic_fixed_macho(1, false, 0, true);
        let mut x86_64 = arm64.clone();
        x86_64[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
        let mut output = Vec::new();
        output.extend_from_slice(&0xcafe_babe_u32.to_be_bytes());
        output.extend_from_slice(&2_u32.to_be_bytes());
        for (cpu_type, offset) in [(0x0100_000c_u32, 4096_u32), (0x0100_0007, 8192)] {
            output.extend_from_slice(&cpu_type.to_be_bytes());
            output.extend_from_slice(&0_u32.to_be_bytes());
            output.extend_from_slice(&offset.to_be_bytes());
            output.extend_from_slice(&4096_u32.to_be_bytes());
            output.extend_from_slice(&12_u32.to_be_bytes());
        }
        output.resize(4096, 0);
        output.extend_from_slice(&arm64);
        output.extend_from_slice(&x86_64);
        output
    }

    fn add_chained_text_fixup(mut thin: Vec<u8>) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 16).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&LC_DYLD_CHAINED_FIXUPS.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&16_u32.to_le_bytes());
        thin[command_at + 8..command_at + 12].copy_from_slice(&0x400_u32.to_le_bytes());
        thin[command_at + 12..command_at + 16].copy_from_slice(&60_u32.to_le_bytes());

        let mut payload = Vec::new();
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 28);
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 1);
        push_u32(&mut payload, 0);
        push_u32(&mut payload, 1);
        push_u32(&mut payload, 8);
        push_u32(&mut payload, 24);
        payload.extend_from_slice(&0x1000_u16.to_le_bytes());
        payload.extend_from_slice(&2_u16.to_le_bytes());
        push_u64(&mut payload, 0);
        push_u32(&mut payload, 0);
        payload.extend_from_slice(&1_u16.to_le_bytes());
        payload.extend_from_slice(&0x200_u16.to_le_bytes());
        assert_eq!(payload.len(), 60);
        thin[0x400..0x400 + payload.len()].copy_from_slice(&payload);
        thin
    }

    fn add_chained_header_alias(mut thin: Vec<u8>) -> Vec<u8> {
        thin = add_chained_text_fixup(thin);
        // Point starts_offset at imports_format inside the 28-byte header.
        // The old parser interpreted the header words as an empty starts table.
        thin[0x404..0x408].copy_from_slice(&20_u32.to_le_bytes());
        thin
    }

    fn add_chained_overlapping_imports(mut thin: Vec<u8>) -> Vec<u8> {
        thin = add_chained_text_fixup(thin);
        thin[0x408..0x40c].copy_from_slice(&28_u32.to_le_bytes());
        thin[0x40c..0x410].copy_from_slice(&32_u32.to_le_bytes());
        thin[0x410..0x414].copy_from_slice(&1_u32.to_le_bytes());
        thin[0x43a..0x43c].copy_from_slice(&0xffff_u16.to_le_bytes());
        thin
    }

    fn chained_import_payload(imports_format: u32) -> Vec<u8> {
        let record_size = match imports_format {
            1 => 4_u32,
            2 => 8_u32,
            3 => 16_u32,
            _ => panic!("unsupported test import format"),
        };
        let symbols_offset = 32 + record_size;
        let mut payload = Vec::new();
        for value in [0, 28, 32, symbols_offset, 1, imports_format, 0, 0] {
            push_u32(&mut payload, value);
        }
        match imports_format {
            1 => push_u32(&mut payload, 0),
            2 => {
                push_u32(&mut payload, 0);
                push_u32(&mut payload, 0);
            }
            3 => {
                push_u64(&mut payload, 0);
                push_u64(&mut payload, 0);
            }
            _ => unreachable!("validated test import format"),
        }
        payload.extend_from_slice(b"_symbol\0");
        payload
    }

    fn add_overlapping_data_segment(mut thin: Vec<u8>) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 72).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&0x19_u32.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&72_u32.to_le_bytes());
        thin[command_at + 8..command_at + 24].copy_from_slice(&name16("__DATA"));
        thin[command_at + 24..command_at + 32].copy_from_slice(&0x1_0000_0100_u64.to_le_bytes());
        thin[command_at + 32..command_at + 40].copy_from_slice(&0x100_u64.to_le_bytes());
        thin[command_at + 56..command_at + 60].copy_from_slice(&3_u32.to_le_bytes());
        thin[command_at + 60..command_at + 64].copy_from_slice(&3_u32.to_le_bytes());
        thin
    }

    fn add_dynamic_relocation_table(mut thin: Vec<u8>, external: bool) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 80).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&LC_DYSYMTAB.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&80_u32.to_le_bytes());
        let (offset_field, count_field) = if external {
            (command_at + 64, command_at + 68)
        } else {
            (command_at + 72, command_at + 76)
        };
        thin[offset_field..offset_field + 4].copy_from_slice(&0x500_u32.to_le_bytes());
        thin[count_field..count_field + 4].copy_from_slice(&1_u32.to_le_bytes());
        thin
    }

    fn add_classic_text_rebase(mut thin: Vec<u8>) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 48).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&LC_DYLD_INFO_ONLY.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&48_u32.to_le_bytes());
        thin[command_at + 8..command_at + 12].copy_from_slice(&0x400_u32.to_le_bytes());
        thin[command_at + 12..command_at + 16].copy_from_slice(&5_u32.to_le_bytes());
        thin[0x400..0x405].copy_from_slice(&[0x20, 0x80, 0x04, 0x51, 0x00]);
        thin
    }

    fn add_classic_text_bind_with_skip(mut thin: Vec<u8>) -> Vec<u8> {
        let command_count = u32::from_le_bytes(thin[16..20].try_into().unwrap());
        let command_bytes = u32::from_le_bytes(thin[20..24].try_into().unwrap());
        let command_at = 32 + command_bytes as usize;
        thin[16..20].copy_from_slice(&(command_count + 1).to_le_bytes());
        thin[20..24].copy_from_slice(&(command_bytes + 48).to_le_bytes());
        thin[command_at..command_at + 4].copy_from_slice(&LC_DYLD_INFO_ONLY.to_le_bytes());
        thin[command_at + 4..command_at + 8].copy_from_slice(&48_u32.to_le_bytes());
        thin[command_at + 16..command_at + 20].copy_from_slice(&0x400_u32.to_le_bytes());
        thin[command_at + 20..command_at + 24].copy_from_slice(&7_u32.to_le_bytes());
        thin[0x400..0x407].copy_from_slice(&[0x70, 0x80, 0x04, 0xc0, 0x01, 0x00, 0x00]);
        thin
    }

    fn add_nonzero_after_section_name_terminator(mut thin: Vec<u8>) -> Vec<u8> {
        let section_name_start = 32 + 72;
        thin[section_name_start + "__oprobe".len() + 1] = b'X';
        thin
    }

    fn move_fixed_section_into_load_commands(mut thin: Vec<u8>) -> Vec<u8> {
        thin[136..144].copy_from_slice(&0x1_0000_0020_u64.to_le_bytes());
        thin[152..156].copy_from_slice(&32_u32.to_le_bytes());
        thin
    }

    fn rename_second_section_with_overlapping_vm(mut thin: Vec<u8>) -> Vec<u8> {
        let second_section_name = 32 + 72 + 80;
        thin[second_section_name..second_section_name + 16].copy_from_slice(&name16("__other"));
        thin
    }

    fn replace_second_section_with_zero_fill(mut thin: Vec<u8>, section_type: u32) -> Vec<u8> {
        let second_section = 32 + 72 + 80;
        thin[second_section..second_section + 16].copy_from_slice(&name16("__zerofill"));
        thin[second_section + 32..second_section + 40]
            .copy_from_slice(&0x1_0000_0400_u64.to_le_bytes());
        thin[second_section + 48..second_section + 52].copy_from_slice(&u32::MAX.to_le_bytes());
        thin[second_section + 64..second_section + 68].copy_from_slice(&section_type.to_le_bytes());
        thin
    }

    #[test]
    fn fixed_section_parser_normalizes_nonzero_fat_slice_offsets() {
        let thin = synthetic_fixed_macho(1, false, 0, true);
        let report = parse_fixed_sections(&mut Cursor::new(fat_wrap(&thin))).unwrap();
        assert_eq!(report.container, MachOContainer::Fat32);
        assert_eq!(report.slices.len(), 1);
        assert_eq!(report.slices[0].slice_file_offset, 4096);
        assert_eq!(report.slices[0].section_slice_offset, 0x200);
        assert_eq!(report.slices[0].section_file_offset, 4096 + 0x200);
        assert_eq!(report.slices[0].section_vm_offset, 0x200);
        assert_eq!(report.slices[0].section_length, 256);
        assert_eq!(
            report.slices[0].macho_uuid,
            "000102030405060708090a0b0c0d0e0f"
        );
    }

    #[test]
    fn fixed_section_parser_rejects_executable_over_100_mib() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&synthetic_fixed_macho(1, false, 0, true))
            .unwrap();
        file.set_len(MAX_LAB002_EXECUTABLE_BYTES + 1).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        assert!(matches!(
            parse_fixed_sections(&mut file),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("exceeds 100 MiB")
        ));
    }

    #[test]
    fn fixed_section_parser_rejects_file_extent_beyond_segment_vm() {
        let mut thin = synthetic_fixed_macho(1, false, 0, true);
        thin[80..88].copy_from_slice(&0x1001_u64.to_le_bytes());
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(thin)),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("segment file extent is invalid")
        ));
    }

    #[test]
    fn fixed_section_parser_treats_every_zero_fill_type_as_non_file_backed() {
        for section_type in [S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL] {
            let bytes = replace_second_section_with_zero_fill(
                synthetic_fixed_macho(2, false, 0, true),
                section_type,
            );
            parse_fixed_sections(&mut Cursor::new(bytes))
                .expect("zero-fill sections must not contribute a file range");
        }
    }

    #[test]
    fn chained_fixups_reject_nontext_record_pointing_into_text() {
        let image_vmaddr = 0x1_0000_0000;
        let segments = [
            FixupSegment {
                vmaddr: image_vmaddr,
                vmsize: 0x1000,
                filesize: 0x1000,
                is_text: true,
            },
            FixupSegment {
                vmaddr: image_vmaddr + 0x1000,
                vmsize: 0x1000,
                filesize: 0x1000,
                is_text: false,
            },
        ];
        let mut payload = Vec::new();
        for value in [0, 28, 0, 0, 0, 1, 0, 2, 0, 12, 24] {
            push_u32(&mut payload, value);
        }
        payload.extend_from_slice(&0x1000_u16.to_le_bytes());
        payload.extend_from_slice(&2_u16.to_le_bytes());
        push_u64(&mut payload, 0);
        push_u32(&mut payload, 0);
        payload.extend_from_slice(&1_u16.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());

        assert!(matches!(
            inspect_chained_fixups(
                &payload,
                Endianness::Little,
                &segments,
                image_vmaddr
            ),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("segment record is invalid")
        ));
    }

    #[test]
    fn chained_fixups_accept_xcode_short_page_table_prefix() {
        let image_vmaddr = 0x1_0000_0000;
        let file_backed_page_count = 2_usize;
        let serialized_prefix_page_count = 1_usize;
        assert!(serialized_prefix_page_count < file_backed_page_count);
        let segments = [FixupSegment {
            vmaddr: image_vmaddr,
            vmsize: 0x3000,
            filesize: 0x1000 * file_backed_page_count as u64,
            is_text: false,
        }];
        let mut payload = Vec::new();
        for value in [0, 28, 0, 0, 0, 1, 0, 1, 8, 24] {
            push_u32(&mut payload, value);
        }
        payload.extend_from_slice(&0x1000_u16.to_le_bytes());
        payload.extend_from_slice(&2_u16.to_le_bytes());
        push_u64(&mut payload, 0);
        push_u32(&mut payload, 0);
        payload.extend_from_slice(&1_u16.to_le_bytes());
        payload.extend_from_slice(&0_u16.to_le_bytes());

        inspect_chained_fixups(&payload, Endianness::Little, &segments, image_vmaddr).unwrap();
    }

    #[test]
    fn chained_fixups_reject_page_start_outside_file_backed_extent() {
        let image_vmaddr = 0x1_0000_0000;
        let short_file_segments = [FixupSegment {
            vmaddr: image_vmaddr,
            vmsize: 0x2000,
            filesize: 0x1800,
            is_text: false,
        }];
        let mut outside_file = Vec::new();
        for value in [0, 28, 0, 0, 0, 1, 0, 1, 8, 26] {
            push_u32(&mut outside_file, value);
        }
        outside_file.extend_from_slice(&0x1000_u16.to_le_bytes());
        outside_file.extend_from_slice(&2_u16.to_le_bytes());
        push_u64(&mut outside_file, 0);
        push_u32(&mut outside_file, 0);
        outside_file.extend_from_slice(&2_u16.to_le_bytes());
        outside_file.extend_from_slice(&0xffff_u16.to_le_bytes());
        outside_file.extend_from_slice(&0x900_u16.to_le_bytes());
        assert!(matches!(
            inspect_chained_fixups(
                &outside_file,
                Endianness::Little,
                &short_file_segments,
                image_vmaddr
            ),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("page start is invalid")
        ));
    }

    #[test]
    fn chained_imports_validate_empty_intervals_and_every_name_reference() {
        let mut empty = Vec::new();
        for value in [0, 28, 32, 32, 0, 1, 0, 0] {
            push_u32(&mut empty, value);
        }
        inspect_chained_fixups(&empty, Endianness::Little, &[], 0).unwrap();

        for imports_format in 1..=3 {
            inspect_chained_fixups(
                &chained_import_payload(imports_format),
                Endianness::Little,
                &[],
                0,
            )
            .unwrap();
        }

        let mut outside = chained_import_payload(1);
        outside[32..36].copy_from_slice(&(100_u32 << 9).to_le_bytes());
        assert!(matches!(
            inspect_chained_fixups(&outside, Endianness::Little, &[], 0),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("outside the symbol pool")
        ));

        let mut unterminated = chained_import_payload(2);
        unterminated.pop();
        assert!(matches!(
            inspect_chained_fixups(&unterminated, Endianness::Little, &[], 0),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("unterminated")
        ));
    }

    #[test]
    fn classic_fixup_streams_require_one_terminal_done_opcode() {
        for kind in [FixupOpcodeKind::Rebase, FixupOpcodeKind::Bind] {
            inspect_fixup_opcodes(&[0x10, 0x00, 0x00, 0x00], kind, &[], 8).unwrap();

            assert!(matches!(
                inspect_fixup_opcodes(&[0x10], kind, &[], 8),
                Err(Lab002Error::InvalidMachO(message))
                    if message.contains("no terminal DONE")
            ));
            assert!(matches!(
                inspect_fixup_opcodes(&[0x00, 0x10], kind, &[], 8),
                Err(Lab002Error::InvalidMachO(message))
                    if message.contains("after DONE")
            ));
        }

        inspect_fixup_opcodes(&[0x10, 0x00, 0x10, 0x00], FixupOpcodeKind::LazyBind, &[], 8)
            .unwrap();
        assert!(matches!(
            inspect_fixup_opcodes(&[0x10, 0x00, 0x10], FixupOpcodeKind::LazyBind, &[], 8),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("no terminal DONE")
        ));
    }

    #[test]
    fn fixed_section_parser_rejects_duplicates_fixups_delta_drift_and_missing_uuid() {
        for (label, bytes) in [
            (
                "duplicate section",
                synthetic_fixed_macho(2, false, 0, true),
            ),
            (
                "section relocation",
                synthetic_fixed_macho(1, false, 1, true),
            ),
            (
                "file VM delta mismatch",
                synthetic_fixed_macho(1, true, 0, true),
            ),
            ("missing UUID", synthetic_fixed_macho(1, false, 0, false)),
            (
                "chained fixup in text",
                add_chained_text_fixup(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "chained starts alias the header",
                add_chained_header_alias(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "chained starts overlap imports",
                add_chained_overlapping_imports(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "overlapping segment VM ranges",
                add_overlapping_data_segment(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "external dynamic relocation table",
                add_dynamic_relocation_table(synthetic_fixed_macho(1, false, 0, true), true),
            ),
            (
                "local dynamic relocation table",
                add_dynamic_relocation_table(synthetic_fixed_macho(1, false, 0, true), false),
            ),
            (
                "classic rebase in text",
                add_classic_text_rebase(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "classic bind-with-skip in text",
                add_classic_text_bind_with_skip(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "nonzero bytes after section-name terminator",
                add_nonzero_after_section_name_terminator(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "fixed section overlaps load commands",
                move_fixed_section_into_load_commands(synthetic_fixed_macho(1, false, 0, true)),
            ),
            (
                "fixed section overlaps another section in VM",
                rename_second_section_with_overlapping_vm(synthetic_fixed_macho(2, false, 0, true)),
            ),
            (
                "unknown load command",
                add_unknown_load_command(synthetic_fixed_macho(1, false, 0, true)),
            ),
        ] {
            assert!(
                parse_fixed_sections(&mut Cursor::new(bytes)).is_err(),
                "{label} must fail closed"
            );
        }
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(fat_wrap_duplicate_uuid())),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("duplicate LC_UUID")
        ));
    }

    #[test]
    fn fixed_section_parser_closes_preupload_code_signature_identity() {
        let bytes = add_code_signature(synthetic_fixed_macho(1, false, 0, true));
        let report = parse_fixed_sections(&mut Cursor::new(bytes)).unwrap();
        let signing = report.slices[0].signing.as_ref().unwrap();
        assert_eq!(signing.code_directory_identifier, "com.example.demolab");
        assert_eq!(signing.code_directory_team_identifier, "TEAM123456");
        assert_eq!(
            signing.application_identifier.as_deref(),
            Some("TEAM123456.com.example.demolab")
        );
        assert_eq!(
            signing.developer_team_identifier.as_deref(),
            Some("TEAM123456")
        );
        assert_eq!(
            signing.application_groups.as_deref(),
            Some(["group.com.example.demolab".to_owned()].as_slice())
        );
        assert!(!signing.is_ad_hoc);
        assert!(signing.has_cms);
        assert!(!signing.code_directory.is_empty());
        assert!(!signing.cms_signature.is_empty());
        assert_eq!(signing.superblob_sha256.len(), 64);
        assert_eq!(report.slices[0].fixup_layout_sha256.len(), 64);
    }

    #[test]
    fn fixed_section_parser_preserves_ad_hoc_without_cms_classification() {
        let bytes =
            add_code_signature_profile(synthetic_fixed_macho(1, false, 0, true), false, true);
        let report = parse_fixed_sections(&mut Cursor::new(bytes)).unwrap();
        let signing = report.slices[0].signing.as_ref().unwrap();
        assert!(signing.is_ad_hoc);
        assert!(!signing.has_cms);
        assert!(signing.cms_signature.is_empty());
        assert!(!signing.code_directory.is_empty());
    }

    #[test]
    fn fixed_section_parser_accepts_only_exact_linker_signed_identity_omission() {
        let bytes = add_linker_signed_code_signature(synthetic_fixed_macho(1, false, 0, true));
        let report = parse_fixed_sections(&mut Cursor::new(bytes.clone())).unwrap();
        let signing = report.slices[0].signing.as_ref().unwrap();
        assert_eq!(signing.code_directory_identifier, "DemoLab.debug.dylib");
        assert!(signing.code_directory_team_identifier.is_empty());
        assert!(signing.application_identifier.is_none());
        assert!(signing.developer_team_identifier.is_none());
        assert!(signing.application_groups.is_none());
        assert!(signing.is_ad_hoc);
        assert!(!signing.has_cms);

        let signature_offset = 0x800_usize;
        let code_directory_offset = signature_offset + 20;
        let mut invalid_identifier = bytes.clone();
        invalid_identifier[code_directory_offset + 88 + 7] = b'/';
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(invalid_identifier)),
            Err(Lab002Error::InvalidFieldGrammar {
                field: "code_directory_identifier"
            })
        ));

        let mut ordinary_ad_hoc = bytes;
        ordinary_ad_hoc[code_directory_offset + 12..code_directory_offset + 16]
            .copy_from_slice(&0x2_u32.to_be_bytes());
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(ordinary_ad_hoc)),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("string offset")
        ));

        let covered_code = synthetic_fixed_macho(1, false, 0, true);
        let linker_signature = synthetic_linker_signed_code_signature(&covered_code);
        for changed_signature in [
            add_linker_signed_superblob_slot(&linker_signature),
            add_linker_signed_special_slot_count(&linker_signature),
        ] {
            assert!(matches!(
                parse_preupload_code_signature(
                    &changed_signature,
                    covered_code.len() as u64,
                    &mut Cursor::new(&covered_code),
                    0,
                ),
                Err(Lab002Error::InvalidMachO(message))
                    if message.contains("unexpected identity slots")
            ));
        }
    }

    #[test]
    fn fixed_section_parser_rejects_unconsumed_cms_wrapper_bytes() {
        let mut bytes = add_code_signature(synthetic_fixed_macho(1, false, 0, true));
        let signature_offset = 0x800_usize;
        let slot_count = u32::from_be_bytes(
            bytes[signature_offset + 8..signature_offset + 12]
                .try_into()
                .unwrap(),
        ) as usize;
        let cms_offset = (0..slot_count)
            .find_map(|index| {
                let entry = signature_offset + 12 + index * 8;
                let slot = u32::from_be_bytes(bytes[entry..entry + 4].try_into().unwrap());
                (slot == 0x1_0000).then(|| {
                    u32::from_be_bytes(bytes[entry + 4..entry + 8].try_into().unwrap()) as usize
                })
            })
            .unwrap();
        let cms = signature_offset + cms_offset;
        let cms_length = u32::from_be_bytes(bytes[cms + 4..cms + 8].try_into().unwrap());
        bytes[cms + 4..cms + 8].copy_from_slice(&(cms_length - 1).to_be_bytes());

        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(bytes)),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("exactly consume")
        ));
    }

    #[test]
    fn fixed_section_parser_accepts_only_zero_code_signature_padding() {
        let mut padded = add_code_signature(synthetic_fixed_macho(1, false, 0, true));
        let command_count = u32::from_le_bytes(padded[16..20].try_into().unwrap());
        let mut cursor = 32_usize;
        let command = (0..command_count)
            .find_map(|_| {
                let command = u32::from_le_bytes(padded[cursor..cursor + 4].try_into().unwrap());
                let size =
                    u32::from_le_bytes(padded[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
                let current = cursor;
                cursor += size;
                (command == 0x1d).then_some(current)
            })
            .unwrap();
        let signature_offset =
            u32::from_le_bytes(padded[command + 8..command + 12].try_into().unwrap()) as usize;
        let signature_size =
            u32::from_le_bytes(padded[command + 12..command + 16].try_into().unwrap());
        padded[command + 12..command + 16].copy_from_slice(&(signature_size + 16).to_le_bytes());
        padded[signature_offset + signature_size as usize
            ..signature_offset + signature_size as usize + 16]
            .fill(0);
        let code_directory_offset = u32::from_be_bytes(
            padded[signature_offset + 16..signature_offset + 20]
                .try_into()
                .unwrap(),
        ) as usize;
        let code_directory = signature_offset + code_directory_offset;
        let hash_offset = u32::from_be_bytes(
            padded[code_directory + 16..code_directory + 20]
                .try_into()
                .unwrap(),
        ) as usize;
        let page_hash = Sha256::digest(&padded[..signature_offset]);
        padded[code_directory + hash_offset..code_directory + hash_offset + 32]
            .copy_from_slice(&page_hash);
        parse_fixed_sections(&mut Cursor::new(padded.clone())).unwrap();

        padded[signature_offset + signature_size as usize + 15] = 1;
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(padded)),
            Err(Lab002Error::InvalidMachO(message)) if message.contains("padding")
        ));
    }

    #[test]
    fn fixed_section_parser_rejects_page_hash_drift_and_scatter_tables() {
        let mut changed_page = add_code_signature(synthetic_fixed_macho(1, false, 0, true));
        changed_page[0x600] ^= 1;
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(changed_page)),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("page hash")
        ));

        let mut changed_entitlement = add_code_signature(synthetic_fixed_macho(1, false, 0, true));
        let entitlement = b"TEAM123456.com.example.demolab";
        let entitlement_offset = changed_entitlement
            .windows(entitlement.len())
            .position(|window| window == entitlement)
            .unwrap();
        changed_entitlement[entitlement_offset] ^= 1;
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(changed_entitlement)),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("signed special slot")
        ));

        let mut changed_requirements = add_code_signature(synthetic_fixed_macho(1, false, 0, true));
        let signature_offset = 0x800_usize;
        let slot_count = u32::from_be_bytes(
            changed_requirements[signature_offset + 8..signature_offset + 12]
                .try_into()
                .unwrap(),
        ) as usize;
        let requirements_offset = (0..slot_count)
            .find_map(|index| {
                let entry = signature_offset + 12 + index * 8;
                let slot =
                    u32::from_be_bytes(changed_requirements[entry..entry + 4].try_into().unwrap());
                (slot == 2).then(|| {
                    u32::from_be_bytes(
                        changed_requirements[entry + 4..entry + 8]
                            .try_into()
                            .unwrap(),
                    ) as usize
                })
            })
            .unwrap();
        changed_requirements[signature_offset + requirements_offset + 8] ^= 1;
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(changed_requirements)),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("signed special slot")
        ));

        let mut scatter = add_code_signature(synthetic_fixed_macho(1, false, 0, true));
        let signature_offset = 0x800;
        let code_directory_offset = signature_offset + 12 + 4 * 8;
        scatter[code_directory_offset + 44..code_directory_offset + 48]
            .copy_from_slice(&1_u32.to_be_bytes());
        assert!(matches!(
            parse_fixed_sections(&mut Cursor::new(scatter)),
            Err(Lab002Error::InvalidMachO(message))
                if message.contains("scatter table")
        ));

        let version_20300 = add_code_signature_profile_version(
            synthetic_fixed_macho(1, false, 0, true),
            true,
            false,
            0x20300,
        );
        let report = parse_fixed_sections(&mut Cursor::new(version_20300)).unwrap();
        assert_eq!(
            report.slices[0]
                .signing
                .as_ref()
                .unwrap()
                .code_directory_identifier,
            "com.example.demolab"
        );
    }
}
