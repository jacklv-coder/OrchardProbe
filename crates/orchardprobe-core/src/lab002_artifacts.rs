//! Closed wire types and bounded canonical codecs for every LAB-002 artifact.
//!
//! These types deliberately contain no filesystem, device, transport, signing,
//! or target-selection operation. Cross-artifact verification is assembled by
//! the host chain in checkpoint 2B.3.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{
    AUTHORIZATION_POLICY_VERSION, Lab002Error, LabRole, MAX_AUTHORIZATION_ENVELOPE_BYTES,
    MAX_AUTHORIZATION_OBJECT_BYTES, MAX_INTERNAL_REPORT_BYTES, MAX_JCS_SAFE_INTEGER,
    MAX_LAB002_EXECUTABLE_BYTES, MAX_SESSION_EXPORT_BYTES, canonical_json_with_limit,
    decode_canonical_json_with_limit, decode_counter, decode_hex, sha256_hex,
};

pub const MAX_STATE_BYTES: usize = 1024;
pub const MAX_HOST_CONTROL_BYTES: usize = 16 * 1024;

pub trait ClosedArtifact: Serialize + DeserializeOwned + Sized {
    const SCHEMA: &'static str;
    const MAX_BYTES: usize;

    fn schema(&self) -> &str;
    fn validate(&self) -> Result<(), Lab002Error>;

    fn to_canonical_bytes(&self) -> Result<Vec<u8>, Lab002Error> {
        self.validate()?;
        canonical_json_with_limit(self, Self::MAX_BYTES)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Lab002Error> {
        let artifact: Self = decode_canonical_json_with_limit(bytes, Self::MAX_BYTES)?;
        artifact.validate()?;
        Ok(artifact)
    }
}

fn deserialize_required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

enum OptionalField<T> {
    Missing,
    Present(Option<T>),
}

impl<T> Default for OptionalField<T> {
    fn default() -> Self {
        Self::Missing
    }
}

fn deserialize_optional_field<'de, D, T>(deserializer: D) -> Result<OptionalField<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(OptionalField::Present)
}

fn validate_schema(value: &str, expected: &'static str) -> Result<(), Lab002Error> {
    if value == expected {
        Ok(())
    } else {
        Err(Lab002Error::InvalidEvidence(
            "artifact schema identifier is invalid",
        ))
    }
}

fn validate_profile(value: &str) -> Result<(), Lab002Error> {
    if value == super::LAB002_PROFILE {
        Ok(())
    } else {
        Err(Lab002Error::InvalidEvidence(
            "artifact profile is not the fixed LAB-002 profile",
        ))
    }
}

fn validate_policy(value: &str) -> Result<(), Lab002Error> {
    if value == AUTHORIZATION_POLICY_VERSION {
        Ok(())
    } else {
        Err(Lab002Error::InvalidAuthorizationScope)
    }
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    decode_hex::<32>(field, value).map(|_| ())
}

fn validate_signature(value: &str) -> Result<(), Lab002Error> {
    decode_hex::<64>("signature", value).map(|_| ())
}

fn validate_embedded_canonical_value(value: &str, maximum: usize) -> Result<(), Lab002Error> {
    if value.chars().count() < 2 {
        return Err(Lab002Error::InvalidJson);
    }
    decode_canonical_json_with_limit::<serde_json::Value>(value.as_bytes(), maximum).map(|_| ())
}

fn validate_source_commit(value: &str) -> Result<(), Lab002Error> {
    decode_hex::<20>("source_commit", value).map(|_| ())
}

fn validate_uuid(value: &str) -> Result<(), Lab002Error> {
    decode_hex::<16>("macho_uuid", value).map(|_| ())
}

fn validate_run_counter(run_ordinal: u8, value: &str) -> Result<(), Lab002Error> {
    if matches!(run_ordinal, 1 | 2) && decode_counter(value)? == u64::from(run_ordinal) {
        Ok(())
    } else {
        Err(Lab002Error::InvalidEvidence(
            "run ordinal and counter do not match",
        ))
    }
}

fn validate_window(not_before: i64, not_after: i64) -> Result<(), Lab002Error> {
    validate_unix_time("not_before", not_before)?;
    validate_unix_time("not_after", not_after)?;
    if not_after.checked_sub(not_before) == Some(900) {
        Ok(())
    } else {
        Err(Lab002Error::InvalidAuthorizationScope)
    }
}

fn invalid_grammar(field: &'static str) -> Lab002Error {
    Lab002Error::InvalidFieldGrammar { field }
}

fn validate_unix_time(field: &'static str, value: i64) -> Result<(), Lab002Error> {
    if value < 0 || value.unsigned_abs() > MAX_JCS_SAFE_INTEGER {
        return Err(invalid_grammar(field));
    }
    Ok(())
}

fn validate_version(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    if value.is_empty()
        || value.len() > 32
        || value.split('.').count() > 4
        || value
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid_grammar(field));
    }
    Ok(())
}

fn validate_apple_build(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    if value.len() < 3 || value.len() > 32 || !value.is_ascii() {
        return Err(invalid_grammar(field));
    }
    let bytes = value.as_bytes();
    let letter = bytes
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .ok_or_else(|| invalid_grammar(field))?;
    if letter == 0
        || !bytes[letter].is_ascii_uppercase()
        || letter + 1 == bytes.len()
        || !bytes[letter + 1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(invalid_grammar(field));
    }
    Ok(())
}

fn validate_observer(value: &str) -> Result<(), Lab002Error> {
    const FIELD: &str = "observer_revision";
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return Err(invalid_grammar(FIELD));
    }
    let mut previous_separator = true;
    for byte in value.bytes() {
        let separator = matches!(byte, b'.' | b'_' | b'-');
        if !(separator || byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || (separator && previous_separator)
        {
            return Err(invalid_grammar(FIELD));
        }
        previous_separator = separator;
    }
    if previous_separator {
        return Err(invalid_grammar(FIELD));
    }
    Ok(())
}

fn validate_bundle_identifier(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    if value.len() < 3
        || value.len() > 255
        || !value.is_ascii()
        || value.split('.').count() < 2
        || value.split('.').any(|component| {
            component.is_empty()
                || !component
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphanumeric())
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid_grammar(field));
    }
    Ok(())
}

fn validate_team_identifier(field: &'static str, value: &str) -> Result<(), Lab002Error> {
    if value.len() != 10
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(invalid_grammar(field));
    }
    Ok(())
}

fn validate_entitlement_value(value: &str) -> Result<(), Lab002Error> {
    const FIELD: &str = "entitlement";
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(invalid_grammar(FIELD));
    }
    Ok(())
}

fn validate_version_fields(marketing_version: &str, build_number: &str) -> Result<(), Lab002Error> {
    validate_version("marketing_version", marketing_version)?;
    validate_version("build_number", build_number)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    pub hardware_model: String,
    pub ios_product_version: String,
    pub ios_build: String,
}

impl Environment {
    fn validate(&self) -> Result<(), Lab002Error> {
        let hardware_suffix = self
            .hardware_model
            .strip_prefix("iPhone")
            .ok_or_else(|| invalid_grammar("hardware_model"))?;
        let (family, model) = hardware_suffix
            .split_once(',')
            .ok_or_else(|| invalid_grammar("hardware_model"))?;
        if self.hardware_model.len() > 32
            || family.is_empty()
            || model.is_empty()
            || !family.bytes().all(|byte| byte.is_ascii_digit())
            || !model.bytes().all(|byte| byte.is_ascii_digit())
            || model.contains(',')
        {
            return Err(invalid_grammar("hardware_model"));
        }
        validate_version("ios_product_version", &self.ios_product_version)?;
        validate_apple_build("ios_build", &self.ios_build)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Toolchain {
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

impl Toolchain {
    fn validate(&self) -> Result<(), Lab002Error> {
        for (field, value) in [
            ("xcode_version", &self.xcode_version),
            ("iphoneos_sdk_version", &self.iphoneos_sdk_version),
            ("xcodegen_version", &self.xcodegen_version),
            ("fastlane_version", &self.fastlane_version),
        ] {
            validate_version(field, value)?;
        }
        validate_apple_build("xcode_build", &self.xcode_build)?;
        validate_apple_build("iphoneos_sdk_build", &self.iphoneos_sdk_build)?;
        if !matches!(self.xcodegen_architecture.as_str(), "arm64" | "x86_64") {
            return Err(invalid_grammar("xcodegen_architecture"));
        }
        validate_digest(
            "xcodegen_executable_sha256",
            &self.xcodegen_executable_sha256,
        )?;
        validate_digest("gemfile_lock_sha256", &self.gemfile_lock_sha256)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    RequiredAbsent,
    Present,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredEntitlement {
    pub presence: Presence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredEntitlementWire {
    presence: Presence,
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    value: OptionalField<String>,
}

impl<'de> Deserialize<'de> for RequiredEntitlement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RequiredEntitlementWire::deserialize(deserializer)?;
        match (wire.presence, wire.value) {
            (Presence::RequiredAbsent, OptionalField::Missing) => Ok(Self {
                presence: Presence::RequiredAbsent,
                value: None,
            }),
            (Presence::Present, OptionalField::Present(Some(value))) => Ok(Self {
                presence: Presence::Present,
                value: Some(value),
            }),
            _ => Err(serde::de::Error::custom(
                "entitlement field presence is invalid",
            )),
        }
    }
}

impl RequiredEntitlement {
    fn validate(&self) -> Result<(), Lab002Error> {
        match (&self.presence, &self.value) {
            (Presence::RequiredAbsent, None) => Ok(()),
            (Presence::Present, Some(value)) => validate_entitlement_value(value),
            _ => Err(Lab002Error::InvalidEvidence(
                "entitlement presence and value are contradictory",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredAppGroups {
    pub presence: Presence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredAppGroupsWire {
    presence: Presence,
    #[serde(default, deserialize_with = "deserialize_optional_field")]
    values: OptionalField<Vec<String>>,
}

impl<'de> Deserialize<'de> for RequiredAppGroups {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RequiredAppGroupsWire::deserialize(deserializer)?;
        match (wire.presence, wire.values) {
            (Presence::RequiredAbsent, OptionalField::Missing) => Ok(Self {
                presence: Presence::RequiredAbsent,
                values: None,
            }),
            (Presence::Present, OptionalField::Present(Some(values))) => Ok(Self {
                presence: Presence::Present,
                values: Some(values),
            }),
            _ => Err(serde::de::Error::custom(
                "application-group field presence is invalid",
            )),
        }
    }
}

impl RequiredAppGroups {
    fn validate(&self) -> Result<(), Lab002Error> {
        match (&self.presence, &self.values) {
            (Presence::RequiredAbsent, None) => Ok(()),
            (Presence::Present, Some(values))
                if !values.is_empty()
                    && values.len() <= 16
                    && values
                        .iter()
                        .enumerate()
                        .all(|(index, value)| !values[..index].contains(value)) =>
            {
                for value in values {
                    let identifier = value
                        .strip_prefix("group.")
                        .ok_or_else(|| invalid_grammar("application_group"))?;
                    validate_bundle_identifier("application_group", identifier)?;
                    if value.len() > 255 {
                        return Err(invalid_grammar("application_group"));
                    }
                }
                Ok(())
            }
            _ => Err(Lab002Error::InvalidEvidence(
                "application-group presence and values are contradictory",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedTarget {
    pub role: LabRole,
    pub bundle_id: String,
    pub code_directory_identifier: String,
    pub code_directory_team_identifier: String,
    pub application_identifier: RequiredEntitlement,
    pub developer_team_identifier: RequiredEntitlement,
    pub application_groups: RequiredAppGroups,
}

impl AuthorizedTarget {
    fn validate(&self) -> Result<(), Lab002Error> {
        validate_bundle_identifier("bundle_id", &self.bundle_id)?;
        validate_bundle_identifier("code_directory_identifier", &self.code_directory_identifier)?;
        validate_team_identifier(
            "code_directory_team_identifier",
            &self.code_directory_team_identifier,
        )?;
        self.application_identifier.validate()?;
        self.developer_team_identifier.validate()?;
        self.application_groups.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedTargetManifest {
    pub schema: String,
    pub profile: String,
    pub identity_nonce: String,
    pub authorization_public_key: String,
    pub authorization_key_id: String,
    pub targets: Vec<AuthorizedTarget>,
}

impl ClosedArtifact for AuthorizedTargetManifest {
    const SCHEMA: &'static str = "orchardprobe.lab002.authorized-targets.v1";
    const MAX_BYTES: usize = MAX_HOST_CONTROL_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        for (field, value) in [
            ("identity_nonce", &self.identity_nonce),
            ("authorization_public_key", &self.authorization_public_key),
            ("authorization_key_id", &self.authorization_key_id),
        ] {
            validate_digest(field, value)?;
        }
        if self.targets.len() != LabRole::ALL.len() {
            return Err(Lab002Error::InvalidTargetIdentitySet);
        }
        for (target, role) in self.targets.iter().zip(LabRole::ALL) {
            if target.role != role {
                return Err(Lab002Error::InvalidTargetIdentitySet);
            }
            target.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizedOperation {
    InstallAndEnrollExactBuild,
    CollectFixedRangeRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    AuthorizationControlMetadata,
    SanitizedDeviceEnvironment,
    CodeSignatureMetadata,
    FixedRangeSha256,
    ClosedOutcomes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizedAction {
    InstallExactBuild,
    ImportInstallationEnrollment,
    ConfirmDeviceEnrollment,
    ExportEnrollmentReceipt,
    ImportCollectionChallenge,
    StartCleanRun,
    ObserveMainApp,
    ObserveFramework,
    InvokeShareExtension,
    ExportSessionEvidence,
    ConfirmExportReceived,
    CleanupReportSubtree,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationAcknowledgement {
    pub schema: String,
    pub profile: String,
    pub authorization_policy_version: String,
    pub acknowledgement_id: String,
    pub experiment_id: String,
    pub operation: AuthorizedOperation,
    pub build_binding_sha256: String,
    pub authorized_target_manifest_sha256: String,
    pub technique_profile: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub run_ordinal: Option<u8>,
    pub data_categories: Vec<DataCategory>,
    pub retention_profile: String,
    pub authorized_actions: Vec<AuthorizedAction>,
    pub device_selection_nonce: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub expected_environment: Option<Environment>,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub expected_enrollment_binding_sha256: Option<String>,
    pub acknowledged_at: i64,
    pub not_before: i64,
    pub not_after: i64,
    pub confirmed: bool,
    pub owns_or_explicitly_authorized_target: bool,
    pub within_authorized_scope: bool,
    pub understands_legal_limits: bool,
    pub will_protect_output_and_not_resign_install_or_redistribute: bool,
}

impl ClosedArtifact for AuthorizationAcknowledgement {
    const SCHEMA: &'static str = "orchardprobe.lab002.authorized-use-ack.v1";
    const MAX_BYTES: usize = MAX_AUTHORIZATION_OBJECT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        validate_window(self.not_before, self.not_after)?;
        validate_unix_time("acknowledged_at", self.acknowledged_at)?;
        if self.acknowledged_at != self.not_before
            || self.technique_profile != "first_party_fixed_range_disk_and_mapped_sha256"
            || self.retention_profile != "owner_only_lab002_experiment_v1"
            || !self.confirmed
            || !self.owns_or_explicitly_authorized_target
            || !self.within_authorized_scope
            || !self.understands_legal_limits
            || !self.will_protect_output_and_not_resign_install_or_redistribute
        {
            return Err(Lab002Error::InvalidAuthorizationScope);
        }
        for (field, value) in [
            ("acknowledgement_id", &self.acknowledgement_id),
            ("experiment_id", &self.experiment_id),
            ("build_binding_sha256", &self.build_binding_sha256),
            (
                "authorized_target_manifest_sha256",
                &self.authorized_target_manifest_sha256,
            ),
            ("device_selection_nonce", &self.device_selection_nonce),
        ] {
            validate_digest(field, value)?;
        }
        let expected_categories = [
            DataCategory::AuthorizationControlMetadata,
            DataCategory::SanitizedDeviceEnvironment,
            DataCategory::CodeSignatureMetadata,
            DataCategory::FixedRangeSha256,
            DataCategory::ClosedOutcomes,
        ];
        if self.data_categories != expected_categories {
            return Err(Lab002Error::InvalidAuthorizationScope);
        }
        let install_actions = [
            AuthorizedAction::InstallExactBuild,
            AuthorizedAction::ImportInstallationEnrollment,
            AuthorizedAction::ConfirmDeviceEnrollment,
            AuthorizedAction::ExportEnrollmentReceipt,
        ];
        let run_actions = [
            AuthorizedAction::ImportCollectionChallenge,
            AuthorizedAction::StartCleanRun,
            AuthorizedAction::ObserveMainApp,
            AuthorizedAction::ObserveFramework,
            AuthorizedAction::InvokeShareExtension,
            AuthorizedAction::ExportSessionEvidence,
            AuthorizedAction::ConfirmExportReceived,
            AuthorizedAction::CleanupReportSubtree,
        ];
        match self.operation {
            AuthorizedOperation::InstallAndEnrollExactBuild
                if self.run_ordinal.is_none()
                    && self.expected_enrollment_binding_sha256.is_none()
                    && self.authorized_actions == install_actions
                    && self.expected_environment.is_some() =>
            {
                self.expected_environment
                    .as_ref()
                    .expect("checked as present")
                    .validate()
            }
            AuthorizedOperation::CollectFixedRangeRun
                if matches!(self.run_ordinal, Some(1 | 2))
                    && self.expected_environment.is_none()
                    && self.expected_enrollment_binding_sha256.is_some()
                    && self.authorized_actions == run_actions =>
            {
                validate_digest(
                    "expected_enrollment_binding_sha256",
                    self.expected_enrollment_binding_sha256
                        .as_deref()
                        .expect("checked as present"),
                )
            }
            _ => Err(Lab002Error::InvalidAuthorizationScope),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEnrollmentCore {
    pub schema: String,
    pub profile: String,
    pub operation: AuthorizedOperation,
    pub experiment_id: String,
    pub enrollment_challenge: String,
    pub build_binding_sha256: String,
    pub authorized_target_manifest_sha256: String,
    pub authorization_policy_version: String,
    pub device_selection_nonce: String,
    pub expected_environment: Environment,
    pub not_before: i64,
    pub not_after: i64,
}

impl ClosedArtifact for InstallationEnrollmentCore {
    const SCHEMA: &'static str = "orchardprobe.lab002.installation-enrollment-core.v1";
    const MAX_BYTES: usize = MAX_AUTHORIZATION_OBJECT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        validate_window(self.not_before, self.not_after)?;
        if self.operation != AuthorizedOperation::InstallAndEnrollExactBuild {
            return Err(Lab002Error::InvalidAuthorizationScope);
        }
        for (field, value) in [
            ("experiment_id", &self.experiment_id),
            ("enrollment_challenge", &self.enrollment_challenge),
            ("build_binding_sha256", &self.build_binding_sha256),
            (
                "authorized_target_manifest_sha256",
                &self.authorized_target_manifest_sha256,
            ),
            ("device_selection_nonce", &self.device_selection_nonce),
        ] {
            validate_digest(field, value)?;
        }
        self.expected_environment.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionChallengeCore {
    pub schema: String,
    pub profile: String,
    pub operation: AuthorizedOperation,
    pub challenge: String,
    pub collection_id: String,
    pub run_ordinal: u8,
    pub expected_run_counter: String,
    pub build_binding_sha256: String,
    pub authorization_policy_version: String,
    pub expected_enrollment_binding_sha256: String,
    pub enrollment_public_key: String,
    pub expected_device_installation_binding_sha256: String,
    pub not_before: i64,
    pub not_after: i64,
}

impl ClosedArtifact for CollectionChallengeCore {
    const SCHEMA: &'static str = "orchardprobe.lab002.collection-challenge-core.v1";
    const MAX_BYTES: usize = MAX_AUTHORIZATION_OBJECT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        validate_window(self.not_before, self.not_after)?;
        validate_run_counter(self.run_ordinal, &self.expected_run_counter)?;
        if self.operation != AuthorizedOperation::CollectFixedRangeRun {
            return Err(Lab002Error::InvalidAuthorizationScope);
        }
        for (field, value) in [
            ("challenge", &self.challenge),
            ("collection_id", &self.collection_id),
            ("build_binding_sha256", &self.build_binding_sha256),
            (
                "expected_enrollment_binding_sha256",
                &self.expected_enrollment_binding_sha256,
            ),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "expected_device_installation_binding_sha256",
                &self.expected_device_installation_binding_sha256,
            ),
        ] {
            validate_digest(field, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedOperationEnvelope {
    pub schema: String,
    pub profile: String,
    pub authorization_key_id: String,
    pub acknowledgement_canonical: String,
    pub operation_core_canonical: String,
    pub signature: String,
}

impl ClosedArtifact for AuthorizedOperationEnvelope {
    const SCHEMA: &'static str = "orchardprobe.lab002.authorized-operation-envelope.v1";
    const MAX_BYTES: usize = MAX_AUTHORIZATION_ENVELOPE_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_digest("authorization_key_id", &self.authorization_key_id)?;
        validate_signature(&self.signature)?;
        validate_embedded_canonical_value(
            &self.acknowledgement_canonical,
            MAX_AUTHORIZATION_OBJECT_BYTES,
        )?;
        validate_embedded_canonical_value(
            &self.operation_core_canonical,
            MAX_AUTHORIZATION_OBJECT_BYTES,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedEnrollmentReceipt {
    pub schema: String,
    pub profile: String,
    pub authorization_envelope_sha256: String,
    pub acknowledgement_sha256: String,
    pub authorization_policy_version: String,
    pub enrollment_challenge_response: String,
    pub experiment_id: String,
    pub build_binding_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub environment: Environment,
    pub created_at: i64,
}

impl ClosedArtifact for UnsignedEnrollmentReceipt {
    const SCHEMA: &'static str = "orchardprobe.lab002.device-enrollment-receipt-core.v1";
    const MAX_BYTES: usize = MAX_AUTHORIZATION_ENVELOPE_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        for (field, value) in [
            (
                "authorization_envelope_sha256",
                &self.authorization_envelope_sha256,
            ),
            ("acknowledgement_sha256", &self.acknowledgement_sha256),
            (
                "enrollment_challenge_response",
                &self.enrollment_challenge_response,
            ),
            ("experiment_id", &self.experiment_id),
            ("build_binding_sha256", &self.build_binding_sha256),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "device_installation_binding_sha256",
                &self.device_installation_binding_sha256,
            ),
        ] {
            validate_digest(field, value)?;
        }
        validate_unix_time("created_at", self.created_at)?;
        self.environment.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnrollmentReceipt {
    pub schema: String,
    pub profile: String,
    pub unsigned_receipt_canonical: String,
    pub enrollment_public_key: String,
    pub signature: String,
}

impl ClosedArtifact for SignedEnrollmentReceipt {
    const SCHEMA: &'static str = "orchardprobe.lab002.device-enrollment-receipt.v1";
    const MAX_BYTES: usize = MAX_AUTHORIZATION_ENVELOPE_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_digest("enrollment_public_key", &self.enrollment_public_key)?;
        validate_signature(&self.signature)?;
        UnsignedEnrollmentReceipt::from_canonical_bytes(self.unsigned_receipt_canonical.as_bytes())
            .map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSelectionConfirmation {
    pub schema: String,
    pub profile: String,
    pub experiment_id: String,
    pub authorization_envelope_sha256: String,
    pub receipt_sha256: String,
    pub device_selection_fingerprint_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub confirmed_at: i64,
    pub confirmed: bool,
}

impl ClosedArtifact for DeviceSelectionConfirmation {
    const SCHEMA: &'static str = "orchardprobe.lab002.device-selection-confirmation.v1";
    const MAX_BYTES: usize = MAX_HOST_CONTROL_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_unix_time("confirmed_at", self.confirmed_at)?;
        if !self.confirmed {
            return Err(Lab002Error::InvalidAuthorizationScope);
        }
        for (field, value) in [
            ("experiment_id", &self.experiment_id),
            (
                "authorization_envelope_sha256",
                &self.authorization_envelope_sha256,
            ),
            ("receipt_sha256", &self.receipt_sha256),
            (
                "device_selection_fingerprint_sha256",
                &self.device_selection_fingerprint_sha256,
            ),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "device_installation_binding_sha256",
                &self.device_installation_binding_sha256,
            ),
        ] {
            validate_digest(field, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceEnrollmentBinding {
    pub schema: String,
    pub profile: String,
    pub experiment_id: String,
    pub installation_acknowledgement_sha256: String,
    pub authorization_envelope_sha256: String,
    pub receipt_sha256: String,
    pub selection_confirmation_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub environment: Environment,
    pub completed_at: i64,
}

impl ClosedArtifact for DeviceEnrollmentBinding {
    const SCHEMA: &'static str = "orchardprobe.lab002.device-enrollment-binding.v1";
    const MAX_BYTES: usize = MAX_HOST_CONTROL_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        for (field, value) in [
            ("experiment_id", &self.experiment_id),
            (
                "installation_acknowledgement_sha256",
                &self.installation_acknowledgement_sha256,
            ),
            (
                "authorization_envelope_sha256",
                &self.authorization_envelope_sha256,
            ),
            ("receipt_sha256", &self.receipt_sha256),
            (
                "selection_confirmation_sha256",
                &self.selection_confirmation_sha256,
            ),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "device_installation_binding_sha256",
                &self.device_installation_binding_sha256,
            ),
        ] {
            validate_digest(field, value)?;
        }
        validate_unix_time("completed_at", self.completed_at)?;
        self.environment.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunCounterState {
    pub schema: String,
    pub build_binding_sha256: String,
    pub counter: String,
}

impl ClosedArtifact for RunCounterState {
    const SCHEMA: &'static str = "orchardprobe.lab002.run-counter-state.v1";
    const MAX_BYTES: usize = MAX_STATE_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_digest("build_binding_sha256", &self.build_binding_sha256)?;
        decode_counter(&self.counter).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationNonceState {
    pub schema: String,
    pub profile: String,
    pub build_binding_sha256: String,
    pub enrollment_public_key: String,
    pub installation_nonce: String,
}

impl ClosedArtifact for InstallationNonceState {
    const SCHEMA: &'static str = "orchardprobe.lab002.installation-nonce-state.v1";
    const MAX_BYTES: usize = MAX_STATE_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        for (field, value) in [
            ("build_binding_sha256", &self.build_binding_sha256),
            ("enrollment_public_key", &self.enrollment_public_key),
            ("installation_nonce", &self.installation_nonce),
        ] {
            validate_digest(field, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePresence {
    Present,
    Absent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureKind {
    Cms,
    AdHoc,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureValidation {
    Valid,
    Invalid,
    NotChecked,
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEvidence {
    pub presence: SignaturePresence,
    pub kind: SignatureKind,
    pub validation: SignatureValidation,
    pub validator_id: String,
    pub validator_revision: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub superblob_sha256: Option<String>,
}

impl SignatureEvidence {
    fn validate(&self) -> Result<(), Lab002Error> {
        validate_observer(&self.validator_id)?;
        validate_observer(&self.validator_revision)?;
        if let Some(digest) = &self.superblob_sha256 {
            validate_digest("superblob_sha256", digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionCommand {
    #[serde(rename = "lc_encryption_info")]
    LcEncryptionInfo,
    #[serde(rename = "lc_encryption_info_64")]
    LcEncryptionInfo64,
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
    pub segment_name: String,
    pub section_name: String,
    pub section_length: u64,
    pub encryption_command: EncryptionCommand,
    pub cryptoff: u64,
    pub cryptsize: u64,
    pub crypt_file_start: u64,
    pub crypt_file_end: u64,
    pub cryptid: u32,
    pub encryption_covers_section: bool,
    pub disk_sha256: String,
    pub mapped_sha256: String,
}

impl ObservedSlice {
    fn validate(&self, expected_ordinal: usize) -> Result<(), Lab002Error> {
        if self.ordinal > 3
            || usize::from(self.ordinal) != expected_ordinal
            || self.segment_name != "__TEXT"
            || self.section_name != "__oprobe"
            || !(64..=1024).contains(&self.section_length)
        {
            return Err(Lab002Error::InvalidEvidence(
                "observed slice ordinal or fixed section is invalid",
            ));
        }
        validate_uuid(&self.macho_uuid)?;
        validate_digest("disk_sha256", &self.disk_sha256)?;
        validate_digest("mapped_sha256", &self.mapped_sha256)?;
        for value in [
            self.slice_file_offset,
            self.slice_file_size,
            self.section_slice_offset,
            self.section_file_offset,
            self.section_vm_offset,
            self.cryptoff,
            self.cryptsize,
            self.crypt_file_start,
            self.crypt_file_end,
        ] {
            if value > MAX_LAB002_EXECUTABLE_BYTES {
                return Err(Lab002Error::InvalidEvidence(
                    "observed executable coordinate exceeds 100 MiB",
                ));
            }
        }
        let slice_end = self
            .slice_file_offset
            .checked_add(self.slice_file_size)
            .ok_or(Lab002Error::InvalidEvidence("slice extent overflows"))?;
        let section_end = self
            .section_slice_offset
            .checked_add(self.section_length)
            .ok_or(Lab002Error::InvalidEvidence("section extent overflows"))?;
        let calculated_encryption_coverage = self.cryptoff <= self.section_slice_offset
            && self
                .cryptoff
                .checked_add(self.cryptsize)
                .is_some_and(|crypt_end| crypt_end >= section_end);
        if self.slice_file_size == 0
            || self.cryptsize == 0
            || slice_end > MAX_LAB002_EXECUTABLE_BYTES
            || section_end > self.slice_file_size
            || self
                .slice_file_offset
                .checked_add(self.section_slice_offset)
                != Some(self.section_file_offset)
            || self.crypt_file_start
                != self
                    .slice_file_offset
                    .checked_add(self.cryptoff)
                    .unwrap_or(u64::MAX)
            || self.crypt_file_end
                != self
                    .crypt_file_start
                    .checked_add(self.cryptsize)
                    .unwrap_or(u64::MAX)
            || self.crypt_file_end > slice_end
            || self.encryption_covers_section != calculated_encryption_coverage
        {
            return Err(Lab002Error::InvalidEvidence(
                "observed slice coordinates are contradictory",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleSlice {
    pub ordinal: u8,
    pub cpu_type: i32,
    pub cpu_subtype: i32,
    pub macho_uuid: String,
    pub code_signature_sha256: String,
    pub slice_file_offset: u64,
    pub slice_file_size: u64,
    pub archive_cryptid: u32,
    pub ipa_cryptid: u32,
    pub section_slice_offset: u64,
    pub section_file_offset: u64,
    pub section_vm_offset: u64,
    pub section_length: u64,
    pub expected_plaintext_sha256: String,
    pub ipa_section_sha256: String,
}

impl OracleSlice {
    fn validate(&self, expected_ordinal: usize) -> Result<(), Lab002Error> {
        if self.ordinal > 3
            || usize::from(self.ordinal) != expected_ordinal
            || self.archive_cryptid != 0
            || self.ipa_cryptid != 0
            || !(64..=1024).contains(&self.section_length)
        {
            return Err(Lab002Error::InvalidEvidence(
                "oracle slice ordinal, cryptid, or range length is invalid",
            ));
        }
        validate_uuid(&self.macho_uuid)?;
        for (field, value) in [
            ("code_signature_sha256", &self.code_signature_sha256),
            ("expected_plaintext_sha256", &self.expected_plaintext_sha256),
            ("ipa_section_sha256", &self.ipa_section_sha256),
        ] {
            validate_digest(field, value)?;
        }
        for value in [
            self.slice_file_offset,
            self.slice_file_size,
            self.section_slice_offset,
            self.section_file_offset,
            self.section_vm_offset,
        ] {
            if value > MAX_LAB002_EXECUTABLE_BYTES {
                return Err(Lab002Error::InvalidEvidence(
                    "oracle executable coordinate exceeds 100 MiB",
                ));
            }
        }
        let slice_end = self
            .slice_file_offset
            .checked_add(self.slice_file_size)
            .ok_or(Lab002Error::InvalidEvidence("oracle slice overflows"))?;
        let section_end = self
            .section_slice_offset
            .checked_add(self.section_length)
            .ok_or(Lab002Error::InvalidEvidence("oracle section overflows"))?;
        if self.slice_file_size == 0
            || slice_end > MAX_LAB002_EXECUTABLE_BYTES
            || section_end > self.slice_file_size
            || self
                .slice_file_offset
                .checked_add(self.section_slice_offset)
                != Some(self.section_file_offset)
        {
            return Err(Lab002Error::InvalidEvidence(
                "oracle slice coordinates are contradictory",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleRole {
    pub role: LabRole,
    pub fixture_relative_path: String,
    pub target_identity_binding_sha256: String,
    pub container_kind: ContainerKind,
    pub slices: Vec<OracleSlice>,
}

impl OracleRole {
    fn validate(&self, expected_role: LabRole) -> Result<(), Lab002Error> {
        if self.role != expected_role
            || self.fixture_relative_path != expected_role.fixture_relative_path()
            || self.slices.is_empty()
            || self.slices.len() > 4
        {
            return Err(Lab002Error::InvalidEvidence(
                "oracle role inventory or path is invalid",
            ));
        }
        validate_digest(
            "target_identity_binding_sha256",
            &self.target_identity_binding_sha256,
        )?;
        for (index, slice) in self.slices.iter().enumerate() {
            slice.validate(index)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LabOracle {
    pub schema: String,
    pub profile: String,
    pub source_commit: String,
    pub fixture_source_root: String,
    pub marketing_version: String,
    pub build_number: String,
    pub configuration: String,
    pub observer_revision: String,
    pub generator_revision: String,
    pub build_binding_sha256: String,
    pub authorized_target_manifest_sha256: String,
    pub authorization_public_key: String,
    pub authorization_key_id: String,
    pub target_identity_set_sha256: String,
    pub toolchain: Toolchain,
    pub ipa_size: u64,
    pub ipa_sha256: String,
    pub roles: Vec<OracleRole>,
}

impl ClosedArtifact for LabOracle {
    const SCHEMA: &'static str = "orchardprobe.lab002.oracle.v1";
    const MAX_BYTES: usize = MAX_HOST_CONTROL_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_source_commit(&self.source_commit)?;
        validate_source_commit(&self.generator_revision)?;
        validate_version_fields(&self.marketing_version, &self.build_number)?;
        validate_observer(&self.observer_revision)?;
        if self.fixture_source_root != "fixtures/DemoLab"
            || self.configuration != "Release"
            || self.generator_revision != self.source_commit
            || self.ipa_size == 0
            || self.ipa_size > MAX_JCS_SAFE_INTEGER
            || self.roles.len() != LabRole::ALL.len()
        {
            return Err(Lab002Error::InvalidEvidence(
                "oracle fixed build identity or role count is invalid",
            ));
        }
        for (field, value) in [
            ("build_binding_sha256", &self.build_binding_sha256),
            (
                "authorized_target_manifest_sha256",
                &self.authorized_target_manifest_sha256,
            ),
            ("authorization_public_key", &self.authorization_public_key),
            ("authorization_key_id", &self.authorization_key_id),
            (
                "target_identity_set_sha256",
                &self.target_identity_set_sha256,
            ),
            ("ipa_sha256", &self.ipa_sha256),
        ] {
            validate_digest(field, value)?;
        }
        self.toolchain.validate()?;
        for (role, expected) in self.roles.iter().zip(LabRole::ALL) {
            role.validate(expected)?;
        }
        Ok(())
    }
}

const CHECKPOINT_3_LEGACY_ORACLE_SHA256: &str =
    "326d7a3260600f13dd65c518fdbeafebbfb119deb31dced15eb4745ced5f9472";

fn has_legacy_oracle_digest(bytes: &[u8], legacy_sha256: &str) -> bool {
    bytes.len() <= LabOracle::MAX_BYTES && sha256_hex(bytes) == legacy_sha256
}

/// Return whether bytes are the sole published checkpoint-3 legacy Oracle.
///
/// This is used by the closed operator chain to scope compatibility behavior
/// to the exact immutable DemoLab 1.0 (3) tuple.
pub fn is_checkpoint_3_legacy_oracle(bytes: &[u8]) -> bool {
    has_legacy_oracle_digest(bytes, CHECKPOINT_3_LEGACY_ORACLE_SHA256)
}

fn decode_frozen_oracle_with_legacy_digest(
    bytes: &[u8],
    legacy_sha256: &str,
) -> Result<LabOracle, Lab002Error> {
    let strict_error = match LabOracle::from_canonical_bytes(bytes) {
        Ok(oracle) => return Ok(oracle),
        Err(error) => error,
    };
    if !has_legacy_oracle_digest(bytes, legacy_sha256) {
        return Err(strict_error);
    }

    let mut value: serde_json::Value =
        decode_canonical_json_with_limit(bytes, LabOracle::MAX_BYTES)?;
    let roles = value
        .get_mut("roles")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or(Lab002Error::InvalidJson)?;
    if roles.len() != LabRole::ALL.len() {
        return Err(Lab002Error::InvalidJson);
    }
    for role in roles {
        let object = role.as_object_mut().ok_or(Lab002Error::InvalidJson)?;
        if object
            .insert(
                "container_kind".into(),
                serde_json::Value::String("thin".into()),
            )
            .is_some()
        {
            return Err(strict_error);
        }
    }
    let upgraded = canonical_json_with_limit(&value, LabOracle::MAX_BYTES)?;
    LabOracle::from_canonical_bytes(&upgraded)
}

/// Decode the frozen Oracle used by the closed Host chain.
///
/// Current artifacts remain strict. The sole compatibility path is pinned to
/// the already published checkpoint-3 DemoLab `1.0 (3)` Oracle bytes. That
/// artifact predates the required `container_kind` field; its three frozen
/// Archive/IPA executables are independently re-derived as thin Mach-O files
/// by the operator before any control artifact can be published.
pub fn decode_frozen_oracle(bytes: &[u8]) -> Result<LabOracle, Lab002Error> {
    decode_frozen_oracle_with_legacy_digest(bytes, CHECKPOINT_3_LEGACY_ORACLE_SHA256)
}

#[cfg(test)]
pub(crate) fn decode_frozen_oracle_with_test_digest(
    bytes: &[u8],
    legacy_sha256: &str,
) -> Result<LabOracle, Lab002Error> {
    decode_frozen_oracle_with_legacy_digest(bytes, legacy_sha256)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Collecting,
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionReport {
    pub schema: String,
    pub profile: String,
    pub observer_revision: String,
    pub build_binding_sha256: String,
    pub collection_id: String,
    pub run_ordinal: u8,
    pub challenge_sha256: String,
    pub authorization_policy_version: String,
    pub acknowledgement_sha256: String,
    pub authorization_envelope_sha256: String,
    pub authorization_not_after: i64,
    pub device_enrollment_binding_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub environment: Environment,
    pub session_id: String,
    pub run_counter: String,
    pub created_at: i64,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub completed_at: Option<i64>,
    pub source_commit: String,
    pub marketing_version: String,
    pub build_number: String,
    pub state: SessionState,
}

impl ClosedArtifact for SessionReport {
    const SCHEMA: &'static str = "orchardprobe.lab002.session-report.v1";
    const MAX_BYTES: usize = MAX_INTERNAL_REPORT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        validate_observer(&self.observer_revision)?;
        validate_source_commit(&self.source_commit)?;
        validate_version_fields(&self.marketing_version, &self.build_number)?;
        validate_run_counter(self.run_ordinal, &self.run_counter)?;
        validate_unix_time("created_at", self.created_at)?;
        validate_unix_time("authorization_not_after", self.authorization_not_after)?;
        let authorization_latest =
            self.authorization_not_after
                .checked_add(120)
                .ok_or(Lab002Error::InvalidEvidence(
                    "session authorization skew window overflows",
                ))?;
        if let Some(completed_at) = self.completed_at {
            validate_unix_time("completed_at", completed_at)?;
        }
        if self.created_at > authorization_latest
            || self
                .completed_at
                .is_some_and(|completed_at| completed_at > authorization_latest)
        {
            return Err(Lab002Error::InvalidEvidence(
                "session lies outside its authorization window",
            ));
        }
        for (field, value) in [
            ("build_binding_sha256", &self.build_binding_sha256),
            ("collection_id", &self.collection_id),
            ("challenge_sha256", &self.challenge_sha256),
            ("acknowledgement_sha256", &self.acknowledgement_sha256),
            (
                "authorization_envelope_sha256",
                &self.authorization_envelope_sha256,
            ),
            (
                "device_enrollment_binding_sha256",
                &self.device_enrollment_binding_sha256,
            ),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "device_installation_binding_sha256",
                &self.device_installation_binding_sha256,
            ),
            ("session_id", &self.session_id),
        ] {
            validate_digest(field, value)?;
        }
        self.environment.validate()?;
        match (self.state, self.completed_at) {
            (SessionState::Collecting, None) => Ok(()),
            (SessionState::Complete | SessionState::Failed, Some(completed_at))
                if completed_at >= self.created_at =>
            {
                Ok(())
            }
            _ => Err(Lab002Error::InvalidEvidence(
                "session state and completion time are contradictory",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseKind {
    DiskInspection,
    MappedHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    pub phase: PhaseKind,
    pub completed_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    Thin,
    Fat32,
    Fat64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    IdentityMismatch,
    SignatureInvalidOrUnchecked,
    InventoryMismatch,
    MissingOrDuplicateFixedSection,
    FixedSectionOutOfBounds,
    FixedSectionHasFixups,
    EncryptionCommandInvalid,
    EncryptionDoesNotCoverRange,
    DiskDigestEqualsPlaintext,
    MappedDigestMismatch,
    StaleOrConflictingSession,
    DuplicateRoleReport,
    UnexpectedInstalledSlice,
    ReportLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleReport {
    pub schema: String,
    pub profile: String,
    pub collection_id: String,
    pub session_id: String,
    pub run_ordinal: u8,
    pub run_counter: String,
    pub challenge_sha256: String,
    pub authorization_policy_version: String,
    pub acknowledgement_sha256: String,
    pub authorization_envelope_sha256: String,
    pub authorization_not_after: i64,
    pub device_enrollment_binding_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub environment: Environment,
    pub source_commit: String,
    pub marketing_version: String,
    pub build_number: String,
    pub observer_revision: String,
    pub build_binding_sha256: String,
    pub role: LabRole,
    pub fixture_relative_path: String,
    pub target_identity_binding_sha256: String,
    pub installed_file_size: u64,
    pub container_kind: ContainerKind,
    pub active_slice_ordinal: u8,
    pub active_cpu_type: i32,
    pub active_cpu_subtype: i32,
    pub active_macho_uuid: String,
    pub signature: SignatureEvidence,
    pub phases: Vec<Phase>,
    pub slices: Vec<ObservedSlice>,
    pub outcome: Outcome,
    pub reasons: Vec<ReasonCode>,
}

impl ClosedArtifact for RoleReport {
    const SCHEMA: &'static str = "orchardprobe.lab002.role-report.v1";
    const MAX_BYTES: usize = MAX_INTERNAL_REPORT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        validate_source_commit(&self.source_commit)?;
        validate_version_fields(&self.marketing_version, &self.build_number)?;
        validate_observer(&self.observer_revision)?;
        validate_run_counter(self.run_ordinal, &self.run_counter)?;
        validate_unix_time("authorization_not_after", self.authorization_not_after)?;
        let authorization_latest =
            self.authorization_not_after
                .checked_add(120)
                .ok_or(Lab002Error::InvalidEvidence(
                    "role authorization skew window overflows",
                ))?;
        for phase in &self.phases {
            validate_unix_time("phase.completed_at", phase.completed_at)?;
        }
        if self.fixture_relative_path != self.role.fixture_relative_path()
            || self.installed_file_size == 0
            || self.installed_file_size > MAX_LAB002_EXECUTABLE_BYTES
            || self.slices.is_empty()
            || self.slices.len() > 4
            || usize::from(self.active_slice_ordinal) >= self.slices.len()
            || self.phases.len() != 2
            || self.phases[0].phase != PhaseKind::DiskInspection
            || self.phases[1].phase != PhaseKind::MappedHash
            || self.phases[1].completed_at < self.phases[0].completed_at
            || self.phases[1].completed_at > authorization_latest
            || self.reasons.len() > 8
            || matches!(self.outcome, Outcome::Pass) != self.reasons.is_empty()
        {
            return Err(Lab002Error::InvalidEvidence(
                "role report inventory, phases, or outcome is invalid",
            ));
        }
        let mut unique_reasons = self.reasons.clone();
        unique_reasons.sort_by_key(|reason| *reason as u8);
        unique_reasons.dedup();
        if unique_reasons.len() != self.reasons.len() {
            return Err(Lab002Error::InvalidEvidence(
                "role report contains duplicate reasons",
            ));
        }
        for (field, value) in [
            ("collection_id", &self.collection_id),
            ("session_id", &self.session_id),
            ("challenge_sha256", &self.challenge_sha256),
            ("acknowledgement_sha256", &self.acknowledgement_sha256),
            (
                "authorization_envelope_sha256",
                &self.authorization_envelope_sha256,
            ),
            (
                "device_enrollment_binding_sha256",
                &self.device_enrollment_binding_sha256,
            ),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "device_installation_binding_sha256",
                &self.device_installation_binding_sha256,
            ),
            ("build_binding_sha256", &self.build_binding_sha256),
            (
                "target_identity_binding_sha256",
                &self.target_identity_binding_sha256,
            ),
        ] {
            validate_digest(field, value)?;
        }
        validate_uuid(&self.active_macho_uuid)?;
        self.environment.validate()?;
        self.signature.validate()?;
        for (index, slice) in self.slices.iter().enumerate() {
            slice.validate(index)?;
        }
        let active = &self.slices[usize::from(self.active_slice_ordinal)];
        if active.cpu_type != self.active_cpu_type
            || active.cpu_subtype != self.active_cpu_subtype
            || active.macho_uuid != self.active_macho_uuid
        {
            return Err(Lab002Error::InvalidEvidence(
                "active slice identity is contradictory",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionIntent {
    pub schema: String,
    pub profile: String,
    pub challenge_file_sha256: String,
    pub collection_id: String,
    pub run_ordinal: u8,
    pub expected_run_counter: String,
    #[serde(deserialize_with = "deserialize_required_option")]
    pub prior_collection_binding_sha256: Option<String>,
    pub not_before: i64,
    pub not_after: i64,
    pub source_commit: String,
    pub marketing_version: String,
    pub build_number: String,
    pub observer_revision: String,
    pub build_binding_sha256: String,
    pub installation_acknowledgement_sha256: String,
    pub device_enrollment_binding_sha256: String,
    pub run_acknowledgement_sha256: String,
    pub authorization_policy_version: String,
    pub authorization_envelope_signature: String,
    pub authorization_envelope_sha256: String,
    pub authorized_target_manifest_sha256: String,
    pub expected_target_identity_set_sha256: String,
    pub enrollment_public_key: String,
    pub expected_device_installation_binding_sha256: String,
    pub toolchain: Toolchain,
    pub preupload_evidence_sha256: String,
    pub ipa_sha256: String,
    pub oracle_sha256: String,
    pub expected_inventory_sha256: String,
}

impl ClosedArtifact for CollectionIntent {
    const SCHEMA: &'static str = "orchardprobe.lab002.collection-intent.v1";
    const MAX_BYTES: usize = MAX_HOST_CONTROL_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        validate_window(self.not_before, self.not_after)?;
        validate_run_counter(self.run_ordinal, &self.expected_run_counter)?;
        validate_source_commit(&self.source_commit)?;
        validate_version_fields(&self.marketing_version, &self.build_number)?;
        validate_observer(&self.observer_revision)?;
        match (self.run_ordinal, &self.prior_collection_binding_sha256) {
            (1, None) => {}
            (2, Some(value)) => validate_digest("prior_collection_binding_sha256", value)?,
            _ => {
                return Err(Lab002Error::InvalidEvidence(
                    "intent prior binding does not match its run ordinal",
                ));
            }
        }
        for (field, value) in [
            ("challenge_file_sha256", &self.challenge_file_sha256),
            ("collection_id", &self.collection_id),
            ("build_binding_sha256", &self.build_binding_sha256),
            (
                "installation_acknowledgement_sha256",
                &self.installation_acknowledgement_sha256,
            ),
            (
                "device_enrollment_binding_sha256",
                &self.device_enrollment_binding_sha256,
            ),
            (
                "run_acknowledgement_sha256",
                &self.run_acknowledgement_sha256,
            ),
            (
                "authorization_envelope_sha256",
                &self.authorization_envelope_sha256,
            ),
            (
                "authorized_target_manifest_sha256",
                &self.authorized_target_manifest_sha256,
            ),
            (
                "expected_target_identity_set_sha256",
                &self.expected_target_identity_set_sha256,
            ),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "expected_device_installation_binding_sha256",
                &self.expected_device_installation_binding_sha256,
            ),
            ("preupload_evidence_sha256", &self.preupload_evidence_sha256),
            ("ipa_sha256", &self.ipa_sha256),
            ("oracle_sha256", &self.oracle_sha256),
            ("expected_inventory_sha256", &self.expected_inventory_sha256),
        ] {
            validate_digest(field, value)?;
        }
        validate_signature(&self.authorization_envelope_signature)?;
        self.toolchain.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicalFilename {
    #[serde(rename = "session.json")]
    Session,
    #[serde(rename = "main-app.json")]
    MainApp,
    #[serde(rename = "framework.json")]
    Framework,
    #[serde(rename = "share-extension.json")]
    ShareExtension,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportEntry {
    pub logical_filename: LogicalFilename,
    pub sha256: String,
    pub canonical_document: String,
}

impl ExportEntry {
    fn validate(&self, expected: LogicalFilename) -> Result<(), Lab002Error> {
        if self.logical_filename != expected {
            return Err(Lab002Error::InvalidEvidence(
                "session export entry order is invalid",
            ));
        }
        validate_digest("export_entry_sha256", &self.sha256)?;
        validate_embedded_canonical_value(&self.canonical_document, MAX_INTERNAL_REPORT_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedSessionExport {
    pub schema: String,
    pub profile: String,
    pub collection_id: String,
    pub session_id: String,
    pub run_ordinal: u8,
    pub run_counter: String,
    pub challenge_sha256: String,
    pub build_binding_sha256: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub entries: Vec<ExportEntry>,
}

impl ClosedArtifact for UnsignedSessionExport {
    const SCHEMA: &'static str = "orchardprobe.lab002.session-export-core.v1";
    const MAX_BYTES: usize = MAX_SESSION_EXPORT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_run_counter(self.run_ordinal, &self.run_counter)?;
        for (field, value) in [
            ("collection_id", &self.collection_id),
            ("session_id", &self.session_id),
            ("challenge_sha256", &self.challenge_sha256),
            ("build_binding_sha256", &self.build_binding_sha256),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "device_installation_binding_sha256",
                &self.device_installation_binding_sha256,
            ),
        ] {
            validate_digest(field, value)?;
        }
        let expected = [
            LogicalFilename::Session,
            LogicalFilename::MainApp,
            LogicalFilename::Framework,
            LogicalFilename::ShareExtension,
        ];
        if self.entries.len() != expected.len() {
            return Err(Lab002Error::InvalidEvidence(
                "session export must contain exactly four entries",
            ));
        }
        for (entry, filename) in self.entries.iter().zip(expected) {
            entry.validate(filename)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSessionExport {
    pub schema: String,
    pub profile: String,
    pub unsigned_export_canonical: String,
    pub enrollment_public_key: String,
    pub signature: String,
}

impl ClosedArtifact for SignedSessionExport {
    const SCHEMA: &'static str = "orchardprobe.lab002.session-export.v1";
    const MAX_BYTES: usize = MAX_SESSION_EXPORT_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_digest("enrollment_public_key", &self.enrollment_public_key)?;
        validate_signature(&self.signature)?;
        UnsignedSessionExport::from_canonical_bytes(self.unsigned_export_canonical.as_bytes())
            .map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleFileHashes {
    pub main_app_sha256: String,
    pub framework_sha256: String,
    pub share_extension_sha256: String,
}

impl RoleFileHashes {
    fn validate(&self) -> Result<(), Lab002Error> {
        for (field, value) in [
            ("main_app_sha256", &self.main_app_sha256),
            ("framework_sha256", &self.framework_sha256),
            ("share_extension_sha256", &self.share_extension_sha256),
        ] {
            validate_digest(field, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionBinding {
    pub schema: String,
    pub profile: String,
    pub installation_acknowledgement_sha256: String,
    pub run_acknowledgement_sha256: String,
    pub authorization_policy_version: String,
    pub intent_sha256: String,
    pub device_enrollment_binding_sha256: String,
    pub authorization_envelope_signature: String,
    pub authorization_envelope_sha256: String,
    pub challenge_file_sha256: String,
    pub signed_session_export_sha256: String,
    pub collection_id: String,
    pub run_ordinal: u8,
    pub signed_run_counter: String,
    pub collected_run_counter: String,
    pub session_id: String,
    pub enrollment_public_key: String,
    pub device_installation_binding_sha256: String,
    pub environment: Environment,
    pub session_sha256: String,
    pub role_file_hashes: RoleFileHashes,
    pub completed_at: i64,
}

impl ClosedArtifact for CollectionBinding {
    const SCHEMA: &'static str = "orchardprobe.lab002.collection-binding.v1";
    const MAX_BYTES: usize = MAX_HOST_CONTROL_BYTES;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn validate(&self) -> Result<(), Lab002Error> {
        validate_schema(&self.schema, Self::SCHEMA)?;
        validate_profile(&self.profile)?;
        validate_policy(&self.authorization_policy_version)?;
        validate_run_counter(self.run_ordinal, &self.signed_run_counter)?;
        validate_run_counter(self.run_ordinal, &self.collected_run_counter)?;
        validate_unix_time("completed_at", self.completed_at)?;
        for (field, value) in [
            (
                "installation_acknowledgement_sha256",
                &self.installation_acknowledgement_sha256,
            ),
            (
                "run_acknowledgement_sha256",
                &self.run_acknowledgement_sha256,
            ),
            ("intent_sha256", &self.intent_sha256),
            (
                "device_enrollment_binding_sha256",
                &self.device_enrollment_binding_sha256,
            ),
            (
                "authorization_envelope_sha256",
                &self.authorization_envelope_sha256,
            ),
            ("challenge_file_sha256", &self.challenge_file_sha256),
            (
                "signed_session_export_sha256",
                &self.signed_session_export_sha256,
            ),
            ("collection_id", &self.collection_id),
            ("session_id", &self.session_id),
            ("enrollment_public_key", &self.enrollment_public_key),
            (
                "device_installation_binding_sha256",
                &self.device_installation_binding_sha256,
            ),
            ("session_sha256", &self.session_sha256),
        ] {
            validate_digest(field, value)?;
        }
        validate_signature(&self.authorization_envelope_signature)?;
        self.environment.validate()?;
        self.role_file_hashes.validate()
    }
}
