//! Bounded, device-independent wire contracts used before a backend exists.
//!
//! These types model public protocol facts only. They intentionally have no
//! fields for device identifiers, addresses, credentials, pairing material,
//! process identifiers, or arbitrary log text.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    EvidenceLevel, MAX_BINARY_RANGES, MAX_PATH_UTF8_BYTES, MAX_RANGE_BYTES, MAX_SAFE_JSON_INTEGER,
    MAX_TOTAL_RANGES, Outcome, is_safe_relative_path,
};

pub const CAPABILITY_SCHEMA_VERSION: u32 = 1;
pub const ERROR_SCHEMA_VERSION: u32 = 1;
pub const PROTOCOL_MAJOR_VERSION: u16 = 0;
/// Pre-negotiation ceiling that future wire parsers must enforce before JSON parsing.
pub const MAX_WIRE_MESSAGE_BYTES: u64 = 64 * 1024;
pub const CAPABILITY_MESSAGE_TYPE: &str = "capability_report";
pub const ERROR_MESSAGE_TYPE: &str = "error";

const CAPABILITY_REVISION: u32 = 1;
const MAX_CAPABILITIES: usize = 16;
const MAX_ERROR_CONTEXTS: usize = 8;

pub const KNOWN_CAPABILITY_IDS: [&str; 6] = [
    "transport.framed_json",
    "target.catalog",
    "bundle.enumerate",
    "bundle.entry_stream",
    "binary.code_range_stream",
    "session.cancel",
];

pub const KNOWN_REASON_CODES: [&str; 12] = [
    "backend.not_implemented",
    "binary.unsupported",
    "binary.skipped",
    "collection.incomplete",
    "evidence.metadata_only",
    "evidence.structure_only",
    "evidence.range_hash_match",
    "evidence.oracle_not_evaluated",
    "evidence.oracle_missing",
    "evidence.known_plaintext_match",
    "evidence.known_plaintext_mismatch",
    "signature.not_checked",
];

#[must_use]
pub fn is_known_capability_id(value: &str) -> bool {
    KNOWN_CAPABILITY_IDS.contains(&value)
}

#[must_use]
pub fn is_known_reason_code(value: &str) -> bool {
    KNOWN_REASON_CODES.contains(&value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityReport {
    pub schema_version: u32,
    pub message_type: String,
    pub protocol_version: ProtocolVersion,
    pub backend_id: String,
    pub capabilities: Vec<Capability>,
    pub disabled_capabilities: Vec<DisabledCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "id", deny_unknown_fields)]
pub enum Capability {
    #[serde(rename = "transport.framed_json")]
    FramedJson {
        revision: u32,
        limits: FramedJsonLimits,
    },
    #[serde(rename = "target.catalog")]
    TargetCatalog {
        revision: u32,
        limits: TargetCatalogLimits,
    },
    #[serde(rename = "bundle.enumerate")]
    BundleEnumerate {
        revision: u32,
        limits: BundleEnumerateLimits,
    },
    #[serde(rename = "bundle.entry_stream")]
    BundleEntryStream {
        revision: u32,
        limits: BundleEntryStreamLimits,
    },
    #[serde(rename = "binary.code_range_stream")]
    CodeRangeStream {
        revision: u32,
        limits: CodeRangeStreamLimits,
    },
    #[serde(rename = "session.cancel")]
    Cancel { revision: u32 },
}

impl Capability {
    #[must_use]
    pub fn id(&self) -> &'static str {
        match self {
            Self::FramedJson { .. } => "transport.framed_json",
            Self::TargetCatalog { .. } => "target.catalog",
            Self::BundleEnumerate { .. } => "bundle.enumerate",
            Self::BundleEntryStream { .. } => "bundle.entry_stream",
            Self::CodeRangeStream { .. } => "binary.code_range_stream",
            Self::Cancel { .. } => "session.cancel",
        }
    }

    fn revision(&self) -> u32 {
        match self {
            Self::FramedJson { revision, .. }
            | Self::TargetCatalog { revision, .. }
            | Self::BundleEnumerate { revision, .. }
            | Self::BundleEntryStream { revision, .. }
            | Self::CodeRangeStream { revision, .. }
            | Self::Cancel { revision } => *revision,
        }
    }

    fn limits_are_valid(&self) -> bool {
        match self {
            Self::FramedJson { limits, .. } => {
                (1_024..=1_048_576).contains(&limits.max_frame_bytes)
            }
            Self::TargetCatalog { limits, .. } => (1..=64).contains(&limits.max_targets),
            Self::BundleEnumerate { limits, .. } => {
                (1..=16_384).contains(&limits.max_entries)
                    && (1..=MAX_PATH_UTF8_BYTES as u32)
                        .contains(&limits.max_relative_path_utf8_bytes)
            }
            Self::BundleEntryStream { limits, .. } => {
                (1..=8_589_934_592).contains(&limits.max_entry_bytes)
                    && (1_024..=1_048_576).contains(&limits.max_chunk_bytes)
                    && u64::from(limits.max_chunk_bytes) <= limits.max_entry_bytes
            }
            Self::CodeRangeStream { limits, .. } => {
                (1..=MAX_BINARY_RANGES as u32).contains(&limits.max_ranges_per_binary)
                    && (1..=MAX_TOTAL_RANGES as u32).contains(&limits.max_total_ranges)
                    && (1..=MAX_RANGE_BYTES).contains(&limits.max_range_bytes)
                    && (1..=68_719_476_736).contains(&limits.max_total_bytes)
                    && (1_024..=1_048_576).contains(&limits.max_chunk_bytes)
                    && limits.max_ranges_per_binary <= limits.max_total_ranges
                    && u64::from(limits.max_chunk_bytes) <= limits.max_range_bytes
                    && limits.max_range_bytes <= limits.max_total_bytes
            }
            Self::Cancel { .. } => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FramedJsonLimits {
    pub max_frame_bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetCatalogLimits {
    pub max_targets: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEnumerateLimits {
    pub max_entries: u32,
    pub max_relative_path_utf8_bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleEntryStreamLimits {
    pub max_entry_bytes: u64,
    pub max_chunk_bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRangeStreamLimits {
    pub max_ranges_per_binary: u32,
    pub max_total_ranges: u32,
    pub max_range_bytes: u64,
    pub max_total_bytes: u64,
    pub max_chunk_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisabledCapability {
    pub id: String,
    pub revision: u32,
    pub reason: DisabledCapabilityReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisabledCapabilityReason {
    UnknownOptional,
    PolicyBlocked,
    LimitOutOfBounds,
    VersionUnsupported,
    BackendNotImplemented,
    NotExercised,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityValidationError {
    #[error("unsupported capability schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion { expected: u32, actual: u32 },
    #[error("unexpected capability message type")]
    UnexpectedMessageType,
    #[error("unsupported protocol major version {actual}; expected {expected}")]
    UnsupportedProtocolMajor { expected: u16, actual: u16 },
    #[error("backend_id is not a bounded public identifier")]
    InvalidBackendId,
    #[error("capability collection exceeds {maximum} items")]
    TooManyCapabilities { maximum: usize },
    #[error("capability `{id}` is offered more than once")]
    DuplicateCapability { id: String },
    #[error("disabled capability `{id}` is reported more than once")]
    DuplicateDisabledCapability { id: String },
    #[error("capability `{id}` is both offered and disabled")]
    OfferedAndDisabled { id: String },
    #[error("capability `{id}` has an unsupported revision")]
    UnsupportedRevision { id: String },
    #[error("capability `{id}` advertises a limit outside the hard bounds")]
    LimitOutOfBounds { id: String },
    #[error("disabled capability `{id}` is not a bounded public identifier")]
    InvalidDisabledCapabilityId { id: String },
    #[error("disabled capability `{id}` uses an inconsistent reason")]
    InconsistentDisabledReason { id: String },
}

impl CapabilityReport {
    pub fn validate(&self) -> Result<(), CapabilityValidationError> {
        if self.schema_version != CAPABILITY_SCHEMA_VERSION {
            return Err(CapabilityValidationError::UnsupportedSchemaVersion {
                expected: CAPABILITY_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if self.message_type != CAPABILITY_MESSAGE_TYPE {
            return Err(CapabilityValidationError::UnexpectedMessageType);
        }
        if self.protocol_version.major != PROTOCOL_MAJOR_VERSION {
            return Err(CapabilityValidationError::UnsupportedProtocolMajor {
                expected: PROTOCOL_MAJOR_VERSION,
                actual: self.protocol_version.major,
            });
        }
        if !is_public_wire_id(&self.backend_id) {
            return Err(CapabilityValidationError::InvalidBackendId);
        }
        if self.capabilities.len() > MAX_CAPABILITIES
            || self.disabled_capabilities.len() > MAX_CAPABILITIES
        {
            return Err(CapabilityValidationError::TooManyCapabilities {
                maximum: MAX_CAPABILITIES,
            });
        }

        let mut offered = HashSet::with_capacity(self.capabilities.len());
        for capability in &self.capabilities {
            let id = capability.id();
            if !offered.insert(id) {
                return Err(CapabilityValidationError::DuplicateCapability { id: id.to_owned() });
            }
            if capability.revision() != CAPABILITY_REVISION {
                return Err(CapabilityValidationError::UnsupportedRevision { id: id.to_owned() });
            }
            if !capability.limits_are_valid() {
                return Err(CapabilityValidationError::LimitOutOfBounds { id: id.to_owned() });
            }
        }

        let mut disabled = HashSet::with_capacity(self.disabled_capabilities.len());
        for capability in &self.disabled_capabilities {
            if !is_public_wire_id(&capability.id) {
                return Err(CapabilityValidationError::InvalidDisabledCapabilityId {
                    id: capability.id.clone(),
                });
            }
            if !disabled.insert(capability.id.as_str()) {
                return Err(CapabilityValidationError::DuplicateDisabledCapability {
                    id: capability.id.clone(),
                });
            }
            if offered.contains(capability.id.as_str()) {
                return Err(CapabilityValidationError::OfferedAndDisabled {
                    id: capability.id.clone(),
                });
            }

            let known = is_known_capability_id(&capability.id);
            let inconsistent = if known {
                capability.revision != CAPABILITY_REVISION
                    || capability.reason == DisabledCapabilityReason::UnknownOptional
            } else {
                capability.reason != DisabledCapabilityReason::UnknownOptional
            };
            if inconsistent {
                return Err(CapabilityValidationError::InconsistentDisabledReason {
                    id: capability.id.clone(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Policy,
    Capability,
    Transport,
    Protocol,
    Collection,
    Reconstruction,
    Verification,
    Reporting,
    Internal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AuthorizationRequired,
    AcknowledgementRequired,
    TargetNotAllowed,
    IncompatibleSchemaVersion,
    IncompatibleProtocolVersion,
    RequiredCapabilityMissing,
    TransportUnavailable,
    TransportInterrupted,
    MalformedMessage,
    InvalidState,
    LimitExceeded,
    TargetChanged,
    UnsafeRelativePath,
    InvalidRange,
    ResourceChanged,
    UnsupportedBinary,
    ReconstructionFailed,
    InsufficientEvidence,
    HashMismatch,
    SignatureStateInconsistent,
    ManifestInvalid,
    OutputFailed,
    InvariantFailed,
}

impl ErrorCode {
    #[must_use]
    pub fn category(self) -> ErrorCategory {
        match self {
            Self::AuthorizationRequired
            | Self::AcknowledgementRequired
            | Self::TargetNotAllowed => ErrorCategory::Policy,
            Self::IncompatibleSchemaVersion
            | Self::IncompatibleProtocolVersion
            | Self::RequiredCapabilityMissing => ErrorCategory::Capability,
            Self::TransportUnavailable | Self::TransportInterrupted => ErrorCategory::Transport,
            Self::MalformedMessage | Self::InvalidState | Self::LimitExceeded => {
                ErrorCategory::Protocol
            }
            Self::TargetChanged
            | Self::UnsafeRelativePath
            | Self::InvalidRange
            | Self::ResourceChanged => ErrorCategory::Collection,
            Self::UnsupportedBinary | Self::ReconstructionFailed => ErrorCategory::Reconstruction,
            Self::InsufficientEvidence | Self::HashMismatch | Self::SignatureStateInconsistent => {
                ErrorCategory::Verification
            }
            Self::ManifestInvalid | Self::OutputFailed => ErrorCategory::Reporting,
            Self::InvariantFailed => ErrorCategory::Internal,
        }
    }

    #[must_use]
    pub fn disposition(self) -> (bool, bool) {
        match self {
            Self::TransportUnavailable | Self::TransportInterrupted | Self::ResourceChanged => {
                (true, true)
            }
            Self::LimitExceeded
            | Self::UnsupportedBinary
            | Self::InsufficientEvidence
            | Self::SignatureStateInconsistent
            | Self::ManifestInvalid => (false, false),
            Self::AuthorizationRequired
            | Self::AcknowledgementRequired
            | Self::TargetNotAllowed
            | Self::IncompatibleSchemaVersion
            | Self::IncompatibleProtocolVersion
            | Self::RequiredCapabilityMissing
            | Self::MalformedMessage
            | Self::InvalidState
            | Self::TargetChanged
            | Self::UnsafeRelativePath
            | Self::InvalidRange
            | Self::ReconstructionFailed
            | Self::HashMismatch
            | Self::InvariantFailed => (true, false),
            Self::OutputFailed => (true, true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Authorization,
    Handshake,
    CapabilityReport,
    TargetCatalog,
    TargetSelect,
    BundleEnumerate,
    BundleEntryStream,
    CodeRangeStream,
    Cancel,
    Teardown,
    Reconstruct,
    ManifestValidate,
    EvidenceVerify,
    ReportWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    HostLocal,
    Negotiating,
    TargetSelected,
    Collecting,
    Reconstructing,
    Verifying,
    Reporting,
    TearingDown,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireContract {
    Capability,
    Error,
    ExportManifest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    FrameBytes,
    MessageBytes,
    TargetCount,
    EntryCount,
    RelativePathUtf8Bytes,
    EntryBytes,
    RangeCount,
    RangeBytes,
    TotalBytes,
    DiagnosticContextCount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ErrorContext {
    Version {
        contract: WireContract,
        received: u32,
        supported: Vec<u32>,
    },
    ProtocolVersion {
        received_major: u16,
        received_minor: u16,
        supported_major: u16,
        minimum_minor: u16,
        maximum_minor: u16,
    },
    Capability {
        capability_id: String,
    },
    Limit {
        limit: LimitKind,
        observed: u64,
        allowed: u64,
    },
    RelativePath {
        relative_path: String,
    },
    Range {
        relative_path: String,
        file_offset: u64,
        requested_size: u64,
    },
    Evidence {
        evidence_level: EvidenceLevel,
        outcome: Outcome,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorEnvelope {
    pub schema_version: u32,
    pub message_type: String,
    pub category: ErrorCategory,
    pub code: ErrorCode,
    pub terminal: bool,
    pub retryable: bool,
    pub operation: Operation,
    pub state: SessionState,
    pub context: Vec<ErrorContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ErrorEnvelopeValidationError {
    #[error("unsupported error schema version {actual}; expected {expected}")]
    UnsupportedSchemaVersion { expected: u32, actual: u32 },
    #[error("unexpected error message type")]
    UnexpectedMessageType,
    #[error("error category does not match its code")]
    CategoryCodeMismatch,
    #[error("error terminal/retryable disposition does not match its code")]
    DispositionMismatch,
    #[error("error operation is inconsistent with its session state")]
    OperationStateMismatch,
    #[error("error context exceeds {maximum} items")]
    TooManyContexts { maximum: usize },
    #[error("error context appears more than once")]
    DuplicateContext,
    #[error("error context is invalid or outside its bounds")]
    InvalidContext,
    #[error("error code is missing its required typed context")]
    MissingRequiredContext,
}

impl ErrorEnvelope {
    pub fn validate(&self) -> Result<(), ErrorEnvelopeValidationError> {
        if self.schema_version != ERROR_SCHEMA_VERSION {
            return Err(ErrorEnvelopeValidationError::UnsupportedSchemaVersion {
                expected: ERROR_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if self.message_type != ERROR_MESSAGE_TYPE {
            return Err(ErrorEnvelopeValidationError::UnexpectedMessageType);
        }
        if self.category != self.code.category() {
            return Err(ErrorEnvelopeValidationError::CategoryCodeMismatch);
        }
        if (self.terminal, self.retryable) != self.code.disposition() {
            return Err(ErrorEnvelopeValidationError::DispositionMismatch);
        }
        if !operation_state_is_valid(self.code, self.operation, self.state) {
            return Err(ErrorEnvelopeValidationError::OperationStateMismatch);
        }
        if self.context.len() > MAX_ERROR_CONTEXTS {
            return Err(ErrorEnvelopeValidationError::TooManyContexts {
                maximum: MAX_ERROR_CONTEXTS,
            });
        }
        for (index, context) in self.context.iter().enumerate() {
            if self.context[..index].contains(context) || !context_is_valid(context) {
                return Err(if self.context[..index].contains(context) {
                    ErrorEnvelopeValidationError::DuplicateContext
                } else {
                    ErrorEnvelopeValidationError::InvalidContext
                });
            }
        }
        if !has_required_context(self.code, &self.context) {
            return Err(ErrorEnvelopeValidationError::MissingRequiredContext);
        }
        Ok(())
    }
}

fn context_is_valid(context: &ErrorContext) -> bool {
    match context {
        ErrorContext::Version {
            contract,
            supported,
            ..
        } => {
            let expected = match contract {
                WireContract::Capability => CAPABILITY_SCHEMA_VERSION,
                WireContract::Error => ERROR_SCHEMA_VERSION,
                WireContract::ExportManifest => crate::MANIFEST_SCHEMA_VERSION,
            };
            supported.as_slice() == [expected]
        }
        ErrorContext::ProtocolVersion {
            supported_major,
            minimum_minor,
            maximum_minor,
            ..
        } => *supported_major == PROTOCOL_MAJOR_VERSION && minimum_minor <= maximum_minor,
        ErrorContext::Capability { capability_id } => is_public_wire_id(capability_id),
        ErrorContext::Limit {
            observed, allowed, ..
        } => *observed <= MAX_SAFE_JSON_INTEGER && *allowed <= MAX_SAFE_JSON_INTEGER,
        ErrorContext::RelativePath { relative_path } => is_safe_relative_path(relative_path),
        ErrorContext::Range {
            relative_path,
            file_offset,
            requested_size,
        } => {
            is_safe_relative_path(relative_path)
                && *requested_size > 0
                && *requested_size <= MAX_RANGE_BYTES
                && file_offset
                    .checked_add(*requested_size)
                    .is_some_and(|end| end <= MAX_SAFE_JSON_INTEGER)
        }
        ErrorContext::Evidence { .. } => true,
    }
}

fn operation_state_is_valid(code: ErrorCode, operation: Operation, state: SessionState) -> bool {
    if code == ErrorCode::InvalidState {
        return true;
    }
    if matches!(operation, Operation::Cancel | Operation::Teardown) {
        return state != SessionState::Closed;
    }

    match operation {
        Operation::Authorization => {
            matches!(state, SessionState::HostLocal | SessionState::Negotiating)
        }
        Operation::Handshake | Operation::CapabilityReport => state == SessionState::Negotiating,
        Operation::TargetCatalog | Operation::TargetSelect => matches!(
            state,
            SessionState::Negotiating | SessionState::TargetSelected
        ),
        Operation::BundleEnumerate => matches!(
            state,
            SessionState::TargetSelected | SessionState::Collecting
        ),
        Operation::BundleEntryStream | Operation::CodeRangeStream => {
            state == SessionState::Collecting
        }
        Operation::Reconstruct => state == SessionState::Reconstructing,
        Operation::ManifestValidate | Operation::ReportWrite => {
            matches!(state, SessionState::HostLocal | SessionState::Reporting)
        }
        Operation::EvidenceVerify => {
            matches!(state, SessionState::HostLocal | SessionState::Verifying)
        }
        Operation::Cancel | Operation::Teardown => unreachable!("handled above"),
    }
}

fn has_required_context(code: ErrorCode, contexts: &[ErrorContext]) -> bool {
    let matches_required = |context: &ErrorContext| match code {
        ErrorCode::IncompatibleSchemaVersion => matches!(context, ErrorContext::Version { .. }),
        ErrorCode::IncompatibleProtocolVersion => {
            matches!(context, ErrorContext::ProtocolVersion { .. })
        }
        ErrorCode::RequiredCapabilityMissing => {
            matches!(context, ErrorContext::Capability { .. })
        }
        ErrorCode::LimitExceeded => matches!(
            context,
            ErrorContext::Limit {
                observed,
                allowed,
                ..
            } if observed > allowed
        ),
        ErrorCode::UnsafeRelativePath => matches!(context, ErrorContext::RelativePath { .. }),
        ErrorCode::InvalidRange => matches!(context, ErrorContext::Range { .. }),
        ErrorCode::InsufficientEvidence
        | ErrorCode::HashMismatch
        | ErrorCode::SignatureStateInconsistent => {
            matches!(context, ErrorContext::Evidence { .. })
        }
        _ => true,
    };

    contexts.iter().any(matches_required)
        || !matches!(
            code,
            ErrorCode::IncompatibleSchemaVersion
                | ErrorCode::IncompatibleProtocolVersion
                | ErrorCode::RequiredCapabilityMissing
                | ErrorCode::LimitExceeded
                | ErrorCode::UnsafeRelativePath
                | ErrorCode::InvalidRange
                | ErrorCode::InsufficientEvidence
                | ErrorCode::HashMismatch
                | ErrorCode::SignatureStateInconsistent
        )
}

fn is_public_wire_id(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disabled(id: &str, reason: DisabledCapabilityReason) -> DisabledCapability {
        DisabledCapability {
            id: id.to_owned(),
            revision: CAPABILITY_REVISION,
            reason,
        }
    }

    fn report() -> CapabilityReport {
        CapabilityReport {
            schema_version: CAPABILITY_SCHEMA_VERSION,
            message_type: CAPABILITY_MESSAGE_TYPE.to_owned(),
            protocol_version: ProtocolVersion { major: 0, minor: 1 },
            backend_id: "device_free_demo".to_owned(),
            capabilities: Vec::new(),
            disabled_capabilities: KNOWN_CAPABILITY_IDS
                .iter()
                .map(|id| disabled(id, DisabledCapabilityReason::BackendNotImplemented))
                .collect(),
        }
    }

    #[test]
    fn device_free_report_offers_nothing_and_is_valid() {
        report().validate().expect("bounded report is valid");
    }

    #[test]
    fn rejects_duplicate_ids_even_when_limits_differ() {
        let mut report = report();
        report.disabled_capabilities.clear();
        report.capabilities = vec![
            Capability::FramedJson {
                revision: 1,
                limits: FramedJsonLimits {
                    max_frame_bytes: 1_024,
                },
            },
            Capability::FramedJson {
                revision: 1,
                limits: FramedJsonLimits {
                    max_frame_bytes: 2_048,
                },
            },
        ];
        assert!(matches!(
            report.validate(),
            Err(CapabilityValidationError::DuplicateCapability { .. })
        ));
    }

    #[test]
    fn unknown_optional_capabilities_can_only_be_disabled() {
        let mut report = report();
        report.disabled_capabilities.push(disabled(
            "future.optional",
            DisabledCapabilityReason::UnknownOptional,
        ));
        report
            .validate()
            .expect("bounded unknown optional ID is safe");

        report.disabled_capabilities.last_mut().unwrap().reason =
            DisabledCapabilityReason::PolicyBlocked;
        assert!(matches!(
            report.validate(),
            Err(CapabilityValidationError::InconsistentDisabledReason { .. })
        ));
    }

    #[test]
    fn rejects_offered_and_disabled_overlap() {
        let mut report = report();
        report.capabilities.push(Capability::Cancel { revision: 1 });
        assert!(matches!(
            report.validate(),
            Err(CapabilityValidationError::OfferedAndDisabled { .. })
        ));
    }

    #[test]
    fn rejects_limits_that_are_individually_bounded_but_internally_inconsistent() {
        let mut report = report();
        report.disabled_capabilities.clear();
        report.capabilities = vec![Capability::BundleEntryStream {
            revision: 1,
            limits: BundleEntryStreamLimits {
                max_entry_bytes: 1,
                max_chunk_bytes: 1_024,
            },
        }];
        assert!(matches!(
            report.validate(),
            Err(CapabilityValidationError::LimitOutOfBounds { .. })
        ));

        report.capabilities = vec![Capability::CodeRangeStream {
            revision: 1,
            limits: CodeRangeStreamLimits {
                max_ranges_per_binary: 2,
                max_total_ranges: 1,
                max_range_bytes: 1,
                max_total_bytes: 1,
                max_chunk_bytes: 1_024,
            },
        }];
        assert!(matches!(
            report.validate(),
            Err(CapabilityValidationError::LimitOutOfBounds { .. })
        ));
    }

    fn limit_error() -> ErrorEnvelope {
        ErrorEnvelope {
            schema_version: ERROR_SCHEMA_VERSION,
            message_type: ERROR_MESSAGE_TYPE.to_owned(),
            category: ErrorCategory::Protocol,
            code: ErrorCode::LimitExceeded,
            terminal: false,
            retryable: false,
            operation: Operation::CodeRangeStream,
            state: SessionState::Collecting,
            context: vec![ErrorContext::Limit {
                limit: LimitKind::RangeBytes,
                observed: MAX_RANGE_BYTES + 1,
                allowed: MAX_RANGE_BYTES,
            }],
        }
    }

    #[test]
    fn validates_category_disposition_and_required_context_together() {
        limit_error().validate().expect("typed error is valid");

        let mut error = limit_error();
        error.retryable = true;
        assert_eq!(
            error.validate(),
            Err(ErrorEnvelopeValidationError::DispositionMismatch)
        );

        let mut error = limit_error();
        error.context.clear();
        assert_eq!(
            error.validate(),
            Err(ErrorEnvelopeValidationError::MissingRequiredContext)
        );
    }

    #[test]
    fn rejects_unsafe_range_context_without_opening_a_path() {
        let mut error = limit_error();
        error.category = ErrorCategory::Collection;
        error.code = ErrorCode::InvalidRange;
        error.terminal = true;
        error.context = vec![ErrorContext::Range {
            relative_path: "Payload/../outside".to_owned(),
            file_offset: 0,
            requested_size: 1,
        }];
        assert_eq!(
            error.validate(),
            Err(ErrorEnvelopeValidationError::InvalidContext)
        );
    }

    #[test]
    fn rejects_operation_state_pairs_outside_the_protocol_phase() {
        let mut error = limit_error();
        error.state = SessionState::Negotiating;
        assert_eq!(
            error.validate(),
            Err(ErrorEnvelopeValidationError::OperationStateMismatch)
        );

        error.code = ErrorCode::InvalidState;
        error.context.clear();
        error.terminal = true;
        error
            .validate()
            .expect("invalid_state can describe the rejected operation-state pair");
    }

    #[test]
    fn authorization_errors_are_valid_before_or_during_negotiation() {
        for state in [SessionState::HostLocal, SessionState::Negotiating] {
            let error = ErrorEnvelope {
                schema_version: ERROR_SCHEMA_VERSION,
                message_type: ERROR_MESSAGE_TYPE.to_owned(),
                category: ErrorCategory::Policy,
                code: ErrorCode::AuthorizationRequired,
                terminal: true,
                retryable: false,
                operation: Operation::Authorization,
                state,
                context: Vec::new(),
            };
            error
                .validate()
                .expect("authorization gate is valid before device work");
        }
    }
}
