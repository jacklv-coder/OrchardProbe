//! Device-free host cryptographic bindings for the closed LAB-002 artifacts.
//!
//! This module signs or verifies exact canonical artifact bytes. It has no
//! device transport, filesystem traversal, target selection, or signing-build
//! capability.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use super::{
    AUTHORIZED_OPERATION_DOMAIN, Lab002Error,
    artifacts::{
        AuthorizationAcknowledgement, AuthorizedOperationEnvelope, AuthorizedTargetManifest,
        ClosedArtifact, CollectionBinding, CollectionChallengeCore, CollectionIntent,
        DeviceEnrollmentBinding, DeviceSelectionConfirmation, ExportEntry,
        InstallationEnrollmentCore, LogicalFilename, RoleReport, SessionReport, SessionState,
        SignedEnrollmentReceipt, SignedSessionExport, UnsignedEnrollmentReceipt,
        UnsignedSessionExport,
    },
    decode_hex, lower_hex, sha256_hex,
};

const ENROLLMENT_RECEIPT_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.enrollment-receipt.v1\0";
const SESSION_EXPORT_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.session-export.v1\0";
const DEVICE_SELECTION_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.device-selection.v1\0";

fn framed_message(domain: &[u8], canonical: &[u8]) -> Result<Vec<u8>, Lab002Error> {
    let size =
        u32::try_from(canonical.len()).map_err(|_| Lab002Error::InvalidAuthorizationScope)?;
    let mut message = Vec::with_capacity(domain.len() + 4 + canonical.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&size.to_be_bytes());
    message.extend_from_slice(canonical);
    Ok(message)
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

fn public_key_hex(signing_key: &SigningKey) -> String {
    lower_hex(signing_key.verifying_key().as_bytes())
}

fn ensure_strong_signing_key(signing_key: &SigningKey) -> Result<VerifyingKey, Lab002Error> {
    let key = signing_key.verifying_key();
    if key.is_weak() {
        return Err(Lab002Error::InvalidSignatureEncoding);
    }
    Ok(key)
}

fn verifying_key(public_key_hex: &str) -> Result<VerifyingKey, Lab002Error> {
    let bytes = decode_hex::<32>("ed25519_public_key", public_key_hex)?;
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| Lab002Error::InvalidSignatureEncoding)?;
    if key.is_weak() {
        return Err(Lab002Error::InvalidSignatureEncoding);
    }
    Ok(key)
}

fn verify_signature(
    public_key_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<(), Lab002Error> {
    let key = verifying_key(public_key_hex)?;
    let signature_bytes = decode_hex::<64>("ed25519_signature", signature_hex)?;
    key.verify_strict(message, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| Lab002Error::InvalidAuthorizationSignature)
}

/// SHA-256 of exact canonical artifact bytes after exact typed decoding.
pub fn verified_artifact_sha256<T: ClosedArtifact>(
    canonical: &[u8],
) -> Result<(T, String), Lab002Error> {
    let artifact = T::from_canonical_bytes(canonical)?;
    Ok((artifact, sha256_hex(canonical)))
}

/// Sign one exact acknowledgement and one exact operation core.
pub fn sign_authorized_operation<A: ClosedArtifact, O: ClosedArtifact>(
    signing_key: &SigningKey,
    acknowledgement: &A,
    operation_core: &O,
) -> Result<AuthorizedOperationEnvelope, Lab002Error> {
    let acknowledgement_canonical = acknowledgement.to_canonical_bytes()?;
    let operation_core_canonical = operation_core.to_canonical_bytes()?;
    let message =
        authorized_operation_message(&acknowledgement_canonical, &operation_core_canonical)?;
    let public_key = ensure_strong_signing_key(signing_key)?;
    let envelope = AuthorizedOperationEnvelope {
        schema: AuthorizedOperationEnvelope::SCHEMA.to_owned(),
        profile: super::LAB002_PROFILE.to_owned(),
        authorization_key_id: sha256_hex(public_key.as_bytes()),
        acknowledgement_canonical: String::from_utf8(acknowledgement_canonical)
            .map_err(|_| Lab002Error::InvalidJson)?,
        operation_core_canonical: String::from_utf8(operation_core_canonical)
            .map_err(|_| Lab002Error::InvalidJson)?,
        signature: lower_hex(&signing_key.sign(&message).to_bytes()),
    };
    envelope.to_canonical_bytes()?;
    Ok(envelope)
}

/// Verify the exact embedded acknowledgement/core bytes and Host signature.
pub fn verify_authorized_operation<A: ClosedArtifact, O: ClosedArtifact>(
    envelope: &AuthorizedOperationEnvelope,
    authorization_public_key: &str,
) -> Result<(A, O), Lab002Error> {
    envelope.validate()?;
    let public_key = decode_hex::<32>("authorization_public_key", authorization_public_key)?;
    if envelope.authorization_key_id != sha256_hex(&public_key) {
        return Err(Lab002Error::AuthorizationKeyIdMismatch);
    }
    let acknowledgement = A::from_canonical_bytes(envelope.acknowledgement_canonical.as_bytes())?;
    let operation_core = O::from_canonical_bytes(envelope.operation_core_canonical.as_bytes())?;
    let message = authorized_operation_message(
        envelope.acknowledgement_canonical.as_bytes(),
        envelope.operation_core_canonical.as_bytes(),
    )?;
    verify_signature(authorization_public_key, &envelope.signature, &message)?;
    Ok((acknowledgement, operation_core))
}

/// Create a signed enrollment receipt with a domain distinct from exports.
pub fn sign_enrollment_receipt(
    enrollment_key: &SigningKey,
    unsigned_receipt: &UnsignedEnrollmentReceipt,
) -> Result<SignedEnrollmentReceipt, Lab002Error> {
    ensure_strong_signing_key(enrollment_key)?;
    let enrollment_public_key = public_key_hex(enrollment_key);
    if unsigned_receipt.enrollment_public_key != enrollment_public_key {
        return Err(Lab002Error::InvalidEvidence(
            "unsigned enrollment receipt public key does not match signing key",
        ));
    }
    let canonical = unsigned_receipt.to_canonical_bytes()?;
    let message = framed_message(ENROLLMENT_RECEIPT_DOMAIN, &canonical)?;
    let receipt = SignedEnrollmentReceipt {
        schema: SignedEnrollmentReceipt::SCHEMA.to_owned(),
        profile: super::LAB002_PROFILE.to_owned(),
        unsigned_receipt_canonical: String::from_utf8(canonical)
            .map_err(|_| Lab002Error::InvalidJson)?,
        enrollment_public_key,
        signature: lower_hex(&enrollment_key.sign(&message).to_bytes()),
    };
    receipt.to_canonical_bytes()?;
    Ok(receipt)
}

/// Verify a signed enrollment receipt against the expected enrollment key.
pub fn verify_enrollment_receipt(
    receipt: &SignedEnrollmentReceipt,
    expected_enrollment_public_key: &str,
) -> Result<UnsignedEnrollmentReceipt, Lab002Error> {
    receipt.validate()?;
    if receipt.enrollment_public_key != expected_enrollment_public_key {
        return Err(Lab002Error::InvalidEvidence(
            "enrollment receipt public key does not match",
        ));
    }
    let unsigned = UnsignedEnrollmentReceipt::from_canonical_bytes(
        receipt.unsigned_receipt_canonical.as_bytes(),
    )?;
    if unsigned.enrollment_public_key != receipt.enrollment_public_key {
        return Err(Lab002Error::InvalidEvidence(
            "enrollment receipt core and envelope keys do not match",
        ));
    }
    let message = framed_message(
        ENROLLMENT_RECEIPT_DOMAIN,
        receipt.unsigned_receipt_canonical.as_bytes(),
    )?;
    verify_signature(expected_enrollment_public_key, &receipt.signature, &message)?;
    Ok(unsigned)
}

/// Create a signed session export under its dedicated domain.
pub fn sign_session_export(
    enrollment_key: &SigningKey,
    unsigned_export: &UnsignedSessionExport,
) -> Result<SignedSessionExport, Lab002Error> {
    ensure_strong_signing_key(enrollment_key)?;
    let enrollment_public_key = public_key_hex(enrollment_key);
    if unsigned_export.enrollment_public_key != enrollment_public_key {
        return Err(Lab002Error::InvalidEvidence(
            "unsigned session export public key does not match signing key",
        ));
    }
    let canonical = unsigned_export.to_canonical_bytes()?;
    let message = framed_message(SESSION_EXPORT_DOMAIN, &canonical)?;
    let export = SignedSessionExport {
        schema: SignedSessionExport::SCHEMA.to_owned(),
        profile: super::LAB002_PROFILE.to_owned(),
        unsigned_export_canonical: String::from_utf8(canonical)
            .map_err(|_| Lab002Error::InvalidJson)?,
        enrollment_public_key,
        signature: lower_hex(&enrollment_key.sign(&message).to_bytes()),
    };
    export.to_canonical_bytes()?;
    Ok(export)
}

/// Verify a signed session export against the enrolled public key.
pub fn verify_session_export(
    export: &SignedSessionExport,
    expected_enrollment_public_key: &str,
) -> Result<UnsignedSessionExport, Lab002Error> {
    export.validate()?;
    if export.enrollment_public_key != expected_enrollment_public_key {
        return Err(Lab002Error::InvalidEvidence(
            "session export public key does not match",
        ));
    }
    let unsigned =
        UnsignedSessionExport::from_canonical_bytes(export.unsigned_export_canonical.as_bytes())?;
    if unsigned.enrollment_public_key != export.enrollment_public_key {
        return Err(Lab002Error::InvalidEvidence(
            "session export core and envelope keys do not match",
        ));
    }
    let message = framed_message(
        SESSION_EXPORT_DOMAIN,
        export.unsigned_export_canonical.as_bytes(),
    )?;
    verify_signature(expected_enrollment_public_key, &export.signature, &message)?;
    Ok(unsigned)
}

/// Full, unshortened fingerprint used by the physical device-selection ceremony.
pub fn device_selection_fingerprint_sha256(
    authorization_envelope_sha256: &str,
    enrollment_public_key: &str,
    device_installation_binding_sha256: &str,
    device_selection_nonce: &str,
) -> Result<String, Lab002Error> {
    let mut message = Vec::with_capacity(DEVICE_SELECTION_DOMAIN.len() + 4 * 32);
    message.extend_from_slice(DEVICE_SELECTION_DOMAIN);
    for (field, value) in [
        (
            "authorization_envelope_sha256",
            authorization_envelope_sha256,
        ),
        ("enrollment_public_key", enrollment_public_key),
        (
            "device_installation_binding_sha256",
            device_installation_binding_sha256,
        ),
        ("device_selection_nonce", device_selection_nonce),
    ] {
        message.extend_from_slice(&decode_hex::<32>(field, value)?);
    }
    Ok(sha256_hex(&message))
}

/// Exact canonical files required to close one device enrollment.
#[derive(Debug, Clone, Copy)]
pub struct EnrollmentArtifactBytes<'a> {
    pub authorized_target_manifest: &'a [u8],
    pub installation_acknowledgement: &'a [u8],
    pub authorization_envelope: &'a [u8],
    pub signed_enrollment_receipt: &'a [u8],
    pub device_selection_confirmation: &'a [u8],
    pub device_enrollment_binding: &'a [u8],
}

/// Closed enrollment facts carried into both collection runs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedEnrollment {
    pub(crate) authorized_target_manifest_sha256: String,
    pub(crate) installation_acknowledgement_sha256: String,
    pub(crate) authorization_envelope_sha256: String,
    pub(crate) signed_enrollment_receipt_sha256: String,
    pub(crate) device_selection_confirmation_sha256: String,
    pub(crate) device_enrollment_binding_sha256: String,
    pub(crate) experiment_id: String,
    pub(crate) build_binding_sha256: String,
    pub(crate) authorization_public_key: String,
    pub(crate) enrollment_public_key: String,
    pub(crate) device_installation_binding_sha256: String,
    pub(crate) environment: super::artifacts::Environment,
    pub(crate) authorization_not_before: i64,
    pub(crate) authorization_not_after: i64,
    pub(crate) completed_at: i64,
}

/// Verify the complete manifest-to-binding enrollment chain without device I/O.
pub fn verify_enrollment_chain(
    files: EnrollmentArtifactBytes<'_>,
) -> Result<VerifiedEnrollment, Lab002Error> {
    let (manifest, manifest_sha256) =
        verified_artifact_sha256::<AuthorizedTargetManifest>(files.authorized_target_manifest)?;
    let authorization_public_key = decode_hex::<32>(
        "authorization_public_key",
        &manifest.authorization_public_key,
    )?;
    verifying_key(&manifest.authorization_public_key)?;
    if manifest.authorization_key_id != sha256_hex(&authorization_public_key) {
        return Err(Lab002Error::AuthorizationKeyIdMismatch);
    }

    let (acknowledgement, acknowledgement_sha256) = verified_artifact_sha256::<
        AuthorizationAcknowledgement,
    >(files.installation_acknowledgement)?;
    if acknowledgement.authorized_target_manifest_sha256 != manifest_sha256 {
        return Err(Lab002Error::InvalidEvidence(
            "installation acknowledgement does not bind the manifest",
        ));
    }

    let (envelope, envelope_sha256) =
        verified_artifact_sha256::<AuthorizedOperationEnvelope>(files.authorization_envelope)?;
    if envelope.acknowledgement_canonical.as_bytes() != files.installation_acknowledgement {
        return Err(Lab002Error::InvalidEvidence(
            "authorization envelope does not contain the selected acknowledgement bytes",
        ));
    }
    let (embedded_acknowledgement, core) = verify_authorized_operation::<
        AuthorizationAcknowledgement,
        InstallationEnrollmentCore,
    >(&envelope, &manifest.authorization_public_key)?;
    if embedded_acknowledgement != acknowledgement
        || core.experiment_id != acknowledgement.experiment_id
        || core.build_binding_sha256 != acknowledgement.build_binding_sha256
        || core.authorized_target_manifest_sha256 != manifest_sha256
        || core.authorization_policy_version != acknowledgement.authorization_policy_version
        || core.device_selection_nonce != acknowledgement.device_selection_nonce
        || core.expected_environment
            != acknowledgement
                .expected_environment
                .clone()
                .ok_or(Lab002Error::InvalidEvidence(
                    "installation acknowledgement environment is absent",
                ))?
        || core.not_before != acknowledgement.not_before
        || core.not_after != acknowledgement.not_after
    {
        return Err(Lab002Error::InvalidEvidence(
            "installation acknowledgement and core are inconsistent",
        ));
    }

    let (signed_receipt, signed_receipt_sha256) =
        verified_artifact_sha256::<SignedEnrollmentReceipt>(files.signed_enrollment_receipt)?;
    let receipt =
        verify_enrollment_receipt(&signed_receipt, &signed_receipt.enrollment_public_key)?;
    if receipt.authorization_envelope_sha256 != envelope_sha256
        || receipt.acknowledgement_sha256 != acknowledgement_sha256
        || receipt.authorization_policy_version != acknowledgement.authorization_policy_version
        || receipt.enrollment_challenge_response != core.enrollment_challenge
        || receipt.experiment_id != acknowledgement.experiment_id
        || receipt.build_binding_sha256 != acknowledgement.build_binding_sha256
        || receipt.environment != core.expected_environment
        || receipt.created_at < acknowledgement.not_before
        || receipt.created_at > acknowledgement.not_after
    {
        return Err(Lab002Error::InvalidEvidence(
            "enrollment receipt does not match the authorized installation",
        ));
    }

    let (selection, selection_sha256) = verified_artifact_sha256::<DeviceSelectionConfirmation>(
        files.device_selection_confirmation,
    )?;
    let expected_fingerprint = device_selection_fingerprint_sha256(
        &envelope_sha256,
        &receipt.enrollment_public_key,
        &receipt.device_installation_binding_sha256,
        &acknowledgement.device_selection_nonce,
    )?;
    if selection.experiment_id != acknowledgement.experiment_id
        || selection.authorization_envelope_sha256 != envelope_sha256
        || selection.receipt_sha256 != signed_receipt_sha256
        || selection.device_selection_fingerprint_sha256 != expected_fingerprint
        || selection.enrollment_public_key != receipt.enrollment_public_key
        || selection.device_installation_binding_sha256
            != receipt.device_installation_binding_sha256
        || selection.confirmed_at < receipt.created_at
        || selection.confirmed_at > acknowledgement.not_after
    {
        return Err(Lab002Error::InvalidEvidence(
            "device selection confirmation is inconsistent",
        ));
    }

    let (binding, binding_sha256) =
        verified_artifact_sha256::<DeviceEnrollmentBinding>(files.device_enrollment_binding)?;
    if binding.experiment_id != acknowledgement.experiment_id
        || binding.installation_acknowledgement_sha256 != acknowledgement_sha256
        || binding.authorization_envelope_sha256 != envelope_sha256
        || binding.receipt_sha256 != signed_receipt_sha256
        || binding.selection_confirmation_sha256 != selection_sha256
        || binding.enrollment_public_key != receipt.enrollment_public_key
        || binding.device_installation_binding_sha256 != receipt.device_installation_binding_sha256
        || binding.environment != receipt.environment
        || binding.completed_at < selection.confirmed_at
        || binding.completed_at > acknowledgement.not_after
    {
        return Err(Lab002Error::InvalidEvidence(
            "device enrollment binding is inconsistent",
        ));
    }

    Ok(VerifiedEnrollment {
        authorized_target_manifest_sha256: manifest_sha256,
        installation_acknowledgement_sha256: acknowledgement_sha256,
        authorization_envelope_sha256: envelope_sha256,
        signed_enrollment_receipt_sha256: signed_receipt_sha256,
        device_selection_confirmation_sha256: selection_sha256,
        device_enrollment_binding_sha256: binding_sha256,
        experiment_id: acknowledgement.experiment_id,
        build_binding_sha256: acknowledgement.build_binding_sha256,
        authorization_public_key: manifest.authorization_public_key,
        enrollment_public_key: receipt.enrollment_public_key,
        device_installation_binding_sha256: receipt.device_installation_binding_sha256,
        environment: receipt.environment,
        authorization_not_before: acknowledgement.not_before,
        authorization_not_after: acknowledgement.not_after,
        completed_at: binding.completed_at,
    })
}

/// Exact canonical files required to close one collection run.
#[derive(Debug, Clone, Copy)]
pub struct RunArtifactBytes<'a> {
    pub run_acknowledgement: &'a [u8],
    pub authorization_envelope: &'a [u8],
    pub collection_intent: &'a [u8],
    pub signed_session_export: &'a [u8],
    pub collection_binding: &'a [u8],
}

/// Closed per-run facts used by the final two-run verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedRun {
    pub(crate) run_acknowledgement_sha256: String,
    pub(crate) authorization_envelope_sha256: String,
    pub(crate) collection_intent_sha256: String,
    pub(crate) signed_session_export_sha256: String,
    pub(crate) collection_binding_sha256: String,
    pub(crate) collection_id: String,
    pub(crate) session_id: String,
    pub(crate) acknowledgement_id: String,
    pub(crate) challenge_id: String,
    pub(crate) run_ordinal: u8,
    pub(crate) run_counter: String,
    pub(crate) challenge_sha256: String,
    pub(crate) prior_collection_binding_sha256: Option<String>,
    pub(crate) experiment_id: String,
    pub(crate) build_binding_sha256: String,
    pub(crate) device_enrollment_binding_sha256: String,
    pub(crate) enrollment_public_key: String,
    pub(crate) device_installation_binding_sha256: String,
    pub(crate) environment: super::artifacts::Environment,
    pub(crate) authorization_not_before: i64,
    pub(crate) authorization_not_after: i64,
    pub(crate) created_at: i64,
    pub(crate) completed_at: i64,
}

fn verified_export_entry<T: ClosedArtifact>(
    entry: &ExportEntry,
    expected_filename: LogicalFilename,
) -> Result<(T, String), Lab002Error> {
    if entry.logical_filename != expected_filename {
        return Err(Lab002Error::InvalidEvidence(
            "session export entry order is invalid",
        ));
    }
    let canonical = entry.canonical_document.as_bytes();
    let sha256 = sha256_hex(canonical);
    if entry.sha256 != sha256 {
        return Err(Lab002Error::InvalidEvidence(
            "session export entry digest does not match its exact bytes",
        ));
    }
    Ok((T::from_canonical_bytes(canonical)?, sha256))
}

/// Verify one acknowledgement-to-binding collection chain without device I/O.
pub fn verify_run_chain(
    enrollment: &VerifiedEnrollment,
    files: RunArtifactBytes<'_>,
) -> Result<VerifiedRun, Lab002Error> {
    let (acknowledgement, acknowledgement_sha256) =
        verified_artifact_sha256::<AuthorizationAcknowledgement>(files.run_acknowledgement)?;
    if acknowledgement.experiment_id != enrollment.experiment_id
        || acknowledgement.not_before < enrollment.completed_at
        || acknowledgement.build_binding_sha256 != enrollment.build_binding_sha256
        || acknowledgement.authorized_target_manifest_sha256
            != enrollment.authorized_target_manifest_sha256
        || acknowledgement
            .expected_enrollment_binding_sha256
            .as_deref()
            != Some(enrollment.device_enrollment_binding_sha256.as_str())
    {
        return Err(Lab002Error::InvalidEvidence(
            "run acknowledgement does not match enrollment",
        ));
    }

    let (envelope, envelope_sha256) =
        verified_artifact_sha256::<AuthorizedOperationEnvelope>(files.authorization_envelope)?;
    if envelope.acknowledgement_canonical.as_bytes() != files.run_acknowledgement {
        return Err(Lab002Error::InvalidEvidence(
            "run envelope does not contain the selected acknowledgement bytes",
        ));
    }
    let (embedded_acknowledgement, core) = verify_authorized_operation::<
        AuthorizationAcknowledgement,
        CollectionChallengeCore,
    >(&envelope, &enrollment.authorization_public_key)?;
    if embedded_acknowledgement != acknowledgement
        || acknowledgement.run_ordinal != Some(core.run_ordinal)
        || acknowledgement.build_binding_sha256 != core.build_binding_sha256
        || acknowledgement.authorization_policy_version != core.authorization_policy_version
        || acknowledgement
            .expected_enrollment_binding_sha256
            .as_deref()
            != Some(core.expected_enrollment_binding_sha256.as_str())
        || acknowledgement.not_before != core.not_before
        || acknowledgement.not_after != core.not_after
        || core.expected_enrollment_binding_sha256 != enrollment.device_enrollment_binding_sha256
        || core.enrollment_public_key != enrollment.enrollment_public_key
        || core.expected_device_installation_binding_sha256
            != enrollment.device_installation_binding_sha256
    {
        return Err(Lab002Error::InvalidEvidence(
            "run acknowledgement and challenge core are inconsistent",
        ));
    }

    let (intent, intent_sha256) =
        verified_artifact_sha256::<CollectionIntent>(files.collection_intent)?;
    if intent.challenge_file_sha256 != envelope_sha256
        || intent.collection_id != core.collection_id
        || intent.run_ordinal != core.run_ordinal
        || intent.expected_run_counter != core.expected_run_counter
        || intent.not_before != core.not_before
        || intent.not_after != core.not_after
        || intent.build_binding_sha256 != enrollment.build_binding_sha256
        || intent.installation_acknowledgement_sha256
            != enrollment.installation_acknowledgement_sha256
        || intent.device_enrollment_binding_sha256 != enrollment.device_enrollment_binding_sha256
        || intent.run_acknowledgement_sha256 != acknowledgement_sha256
        || intent.authorization_policy_version != core.authorization_policy_version
        || intent.authorization_envelope_signature != envelope.signature
        || intent.authorization_envelope_sha256 != envelope_sha256
        || intent.authorized_target_manifest_sha256 != enrollment.authorized_target_manifest_sha256
        || intent.enrollment_public_key != enrollment.enrollment_public_key
        || intent.expected_device_installation_binding_sha256
            != enrollment.device_installation_binding_sha256
    {
        return Err(Lab002Error::InvalidEvidence(
            "collection intent does not match its challenge or enrollment",
        ));
    }

    let (signed_export, signed_export_sha256) =
        verified_artifact_sha256::<SignedSessionExport>(files.signed_session_export)?;
    let export = verify_session_export(&signed_export, &enrollment.enrollment_public_key)?;
    if export.collection_id != core.collection_id
        || export.run_ordinal != core.run_ordinal
        || export.run_counter != core.expected_run_counter
        || export.challenge_sha256 != envelope_sha256
        || export.build_binding_sha256 != enrollment.build_binding_sha256
        || export.enrollment_public_key != enrollment.enrollment_public_key
        || export.device_installation_binding_sha256
            != enrollment.device_installation_binding_sha256
    {
        return Err(Lab002Error::InvalidEvidence(
            "signed session export does not match its challenge or enrollment",
        ));
    }

    let (session, session_sha256) =
        verified_export_entry::<SessionReport>(&export.entries[0], LogicalFilename::Session)?;
    let (main_app, main_app_sha256) =
        verified_export_entry::<RoleReport>(&export.entries[1], LogicalFilename::MainApp)?;
    let (framework, framework_sha256) =
        verified_export_entry::<RoleReport>(&export.entries[2], LogicalFilename::Framework)?;
    let (share_extension, share_extension_sha256) =
        verified_export_entry::<RoleReport>(&export.entries[3], LogicalFilename::ShareExtension)?;

    let completed_at = session.completed_at.ok_or(Lab002Error::InvalidEvidence(
        "exported session is not complete",
    ))?;
    let authorization_earliest =
        core.not_before
            .checked_sub(120)
            .ok_or(Lab002Error::InvalidEvidence(
                "authorization skew window underflows",
            ))?;
    let authorization_latest =
        core.not_after
            .checked_add(120)
            .ok_or(Lab002Error::InvalidEvidence(
                "authorization skew window overflows",
            ))?;
    if session.state != SessionState::Complete
        || session.collection_id != core.collection_id
        || session.session_id != export.session_id
        || session.run_ordinal != core.run_ordinal
        || session.run_counter != core.expected_run_counter
        || session.challenge_sha256 != envelope_sha256
        || session.authorization_policy_version != core.authorization_policy_version
        || session.acknowledgement_sha256 != acknowledgement_sha256
        || session.authorization_envelope_sha256 != envelope_sha256
        || session.authorization_not_after != core.not_after
        || session.device_enrollment_binding_sha256 != enrollment.device_enrollment_binding_sha256
        || session.enrollment_public_key != enrollment.enrollment_public_key
        || session.device_installation_binding_sha256
            != enrollment.device_installation_binding_sha256
        || session.environment != enrollment.environment
        || session.source_commit != intent.source_commit
        || session.marketing_version != intent.marketing_version
        || session.build_number != intent.build_number
        || session.observer_revision != intent.observer_revision
        || session.build_binding_sha256 != enrollment.build_binding_sha256
        || session.created_at < authorization_earliest
        || session.created_at < enrollment.completed_at
        || completed_at > authorization_latest
        || session.created_at > completed_at
    {
        return Err(Lab002Error::InvalidEvidence(
            "exported session does not match immutable run control",
        ));
    }

    for (report, expected_role) in [
        (&main_app, super::LabRole::MainApp),
        (&framework, super::LabRole::Framework),
        (&share_extension, super::LabRole::ShareExtension),
    ] {
        if report.role != expected_role
            || report.collection_id != session.collection_id
            || report.session_id != session.session_id
            || report.run_ordinal != session.run_ordinal
            || report.run_counter != session.run_counter
            || report.challenge_sha256 != session.challenge_sha256
            || report.authorization_policy_version != session.authorization_policy_version
            || report.acknowledgement_sha256 != session.acknowledgement_sha256
            || report.authorization_envelope_sha256 != session.authorization_envelope_sha256
            || report.authorization_not_after != session.authorization_not_after
            || report.device_enrollment_binding_sha256 != session.device_enrollment_binding_sha256
            || report.enrollment_public_key != session.enrollment_public_key
            || report.device_installation_binding_sha256
                != session.device_installation_binding_sha256
            || report.environment != session.environment
            || report.source_commit != session.source_commit
            || report.marketing_version != session.marketing_version
            || report.build_number != session.build_number
            || report.observer_revision != session.observer_revision
            || report.build_binding_sha256 != session.build_binding_sha256
            || report.phases[0].completed_at < session.created_at
            || report.phases[1].completed_at > completed_at
        {
            return Err(Lab002Error::InvalidEvidence(
                "role report does not match its immutable session",
            ));
        }
    }
    if main_app.phases[1].completed_at > framework.phases[0].completed_at
        || framework.phases[1].completed_at > share_extension.phases[0].completed_at
    {
        return Err(Lab002Error::InvalidEvidence(
            "role report phases contain a backward clock step",
        ));
    }

    let (binding, binding_sha256) =
        verified_artifact_sha256::<CollectionBinding>(files.collection_binding)?;
    if binding.installation_acknowledgement_sha256 != enrollment.installation_acknowledgement_sha256
        || binding.run_acknowledgement_sha256 != acknowledgement_sha256
        || binding.authorization_policy_version != core.authorization_policy_version
        || binding.intent_sha256 != intent_sha256
        || binding.device_enrollment_binding_sha256 != enrollment.device_enrollment_binding_sha256
        || binding.authorization_envelope_signature != envelope.signature
        || binding.authorization_envelope_sha256 != envelope_sha256
        || binding.challenge_file_sha256 != envelope_sha256
        || binding.signed_session_export_sha256 != signed_export_sha256
        || binding.collection_id != session.collection_id
        || binding.run_ordinal != session.run_ordinal
        || binding.signed_run_counter != core.expected_run_counter
        || binding.collected_run_counter != session.run_counter
        || binding.session_id != session.session_id
        || binding.enrollment_public_key != enrollment.enrollment_public_key
        || binding.device_installation_binding_sha256
            != enrollment.device_installation_binding_sha256
        || binding.environment != enrollment.environment
        || binding.session_sha256 != session_sha256
        || binding.role_file_hashes.main_app_sha256 != main_app_sha256
        || binding.role_file_hashes.framework_sha256 != framework_sha256
        || binding.role_file_hashes.share_extension_sha256 != share_extension_sha256
        || binding.completed_at < completed_at
        || binding.completed_at > authorization_latest
    {
        return Err(Lab002Error::InvalidEvidence(
            "collection binding does not close the exact run",
        ));
    }

    Ok(VerifiedRun {
        run_acknowledgement_sha256: acknowledgement_sha256,
        authorization_envelope_sha256: envelope_sha256.clone(),
        collection_intent_sha256: intent_sha256,
        signed_session_export_sha256: signed_export_sha256,
        collection_binding_sha256: binding_sha256,
        collection_id: session.collection_id,
        session_id: session.session_id,
        acknowledgement_id: acknowledgement.acknowledgement_id,
        challenge_id: core.challenge,
        run_ordinal: session.run_ordinal,
        run_counter: session.run_counter,
        challenge_sha256: envelope_sha256,
        prior_collection_binding_sha256: intent.prior_collection_binding_sha256,
        experiment_id: enrollment.experiment_id.clone(),
        build_binding_sha256: enrollment.build_binding_sha256.clone(),
        device_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
        enrollment_public_key: enrollment.enrollment_public_key.clone(),
        device_installation_binding_sha256: enrollment.device_installation_binding_sha256.clone(),
        environment: session.environment,
        authorization_not_before: core.not_before,
        authorization_not_after: core.not_after,
        created_at: session.created_at,
        completed_at: binding.completed_at,
    })
}

/// A sealed enrollment plus the two distinct, ordered collection bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedTwoRunChain {
    enrollment_binding_sha256: String,
    run_one_binding_sha256: String,
    run_two_binding_sha256: String,
}

/// Close the cross-run replay, ordering, and enrollment-continuity boundary.
pub fn verify_two_run_chain(
    enrollment: &VerifiedEnrollment,
    run_one: &VerifiedRun,
    run_two: &VerifiedRun,
) -> Result<VerifiedTwoRunChain, Lab002Error> {
    let all_artifact_hashes = [
        &run_one.run_acknowledgement_sha256,
        &run_one.authorization_envelope_sha256,
        &run_one.collection_intent_sha256,
        &run_one.signed_session_export_sha256,
        &run_one.collection_binding_sha256,
        &run_two.run_acknowledgement_sha256,
        &run_two.authorization_envelope_sha256,
        &run_two.collection_intent_sha256,
        &run_two.signed_session_export_sha256,
        &run_two.collection_binding_sha256,
    ];
    let unique_artifact_hashes: HashSet<&str> = all_artifact_hashes
        .iter()
        .map(|value| value.as_str())
        .collect();
    if run_one.run_ordinal != 1
        || run_one.run_counter != "0000000000000001"
        || run_two.run_ordinal != 2
        || run_two.run_counter != "0000000000000002"
        || run_one.prior_collection_binding_sha256.is_some()
        || run_two.prior_collection_binding_sha256.as_deref()
            != Some(run_one.collection_binding_sha256.as_str())
        || run_one.authorization_not_after >= run_two.authorization_not_before
        || run_one.completed_at > run_two.authorization_not_before
        || run_one.completed_at >= run_two.created_at
        || run_one.collection_id == run_two.collection_id
        || run_one.session_id == run_two.session_id
        || run_one.acknowledgement_id == run_two.acknowledgement_id
        || run_one.challenge_id == run_two.challenge_id
        || run_one.challenge_sha256 == run_two.challenge_sha256
        || unique_artifact_hashes.len() != all_artifact_hashes.len()
        || run_one.experiment_id != enrollment.experiment_id
        || run_two.experiment_id != enrollment.experiment_id
        || run_one.build_binding_sha256 != enrollment.build_binding_sha256
        || run_two.build_binding_sha256 != enrollment.build_binding_sha256
        || run_one.device_enrollment_binding_sha256 != enrollment.device_enrollment_binding_sha256
        || run_two.device_enrollment_binding_sha256 != enrollment.device_enrollment_binding_sha256
        || run_one.enrollment_public_key != enrollment.enrollment_public_key
        || run_two.enrollment_public_key != enrollment.enrollment_public_key
        || run_one.device_installation_binding_sha256
            != enrollment.device_installation_binding_sha256
        || run_two.device_installation_binding_sha256
            != enrollment.device_installation_binding_sha256
        || run_one.environment != enrollment.environment
        || run_two.environment != enrollment.environment
    {
        return Err(Lab002Error::InvalidEvidence(
            "two collection runs are replayed, unordered, or enrollment-inconsistent",
        ));
    }

    Ok(VerifiedTwoRunChain {
        enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
        run_one_binding_sha256: run_one.collection_binding_sha256.clone(),
        run_two_binding_sha256: run_two.collection_binding_sha256.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab002::LabRole;
    use crate::lab002::artifacts::{
        AuthorizationAcknowledgement, AuthorizedAction, AuthorizedOperation, AuthorizedTarget,
        AuthorizedTargetManifest, CollectionBinding, CollectionChallengeCore, CollectionIntent,
        ContainerKind, DataCategory, DeviceEnrollmentBinding, DeviceSelectionConfirmation,
        EncryptionCommand, Environment, ExportEntry, InstallationEnrollmentCore, LogicalFilename,
        ObservedSlice, Outcome, Phase, PhaseKind, Presence, RequiredAppGroups, RequiredEntitlement,
        RoleFileHashes, RoleReport, SessionReport, SessionState, SignatureEvidence, SignatureKind,
        SignaturePresence, SignatureValidation, Toolchain,
    };

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn environment() -> Environment {
        Environment {
            hardware_model: "iPhone17,1".into(),
            ios_product_version: "26.0".into(),
            ios_build: "23A100".into(),
        }
    }

    fn installation_acknowledgement() -> AuthorizationAcknowledgement {
        AuthorizationAcknowledgement {
            schema: AuthorizationAcknowledgement::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            acknowledgement_id: digest(0x01),
            experiment_id: digest(0x02),
            operation: AuthorizedOperation::InstallAndEnrollExactBuild,
            build_binding_sha256: digest(0x03),
            authorized_target_manifest_sha256: digest(0x04),
            technique_profile: "first_party_fixed_range_disk_and_mapped_sha256".into(),
            run_ordinal: None,
            data_categories: vec![
                DataCategory::AuthorizationControlMetadata,
                DataCategory::SanitizedDeviceEnvironment,
                DataCategory::CodeSignatureMetadata,
                DataCategory::FixedRangeSha256,
                DataCategory::ClosedOutcomes,
            ],
            retention_profile: "owner_only_lab002_experiment_v1".into(),
            authorized_actions: vec![
                AuthorizedAction::InstallExactBuild,
                AuthorizedAction::ImportInstallationEnrollment,
                AuthorizedAction::ConfirmDeviceEnrollment,
                AuthorizedAction::ExportEnrollmentReceipt,
            ],
            device_selection_nonce: digest(0x05),
            expected_environment: Some(environment()),
            expected_enrollment_binding_sha256: None,
            acknowledged_at: 1_000,
            not_before: 1_000,
            not_after: 1_900,
            confirmed: true,
            owns_or_explicitly_authorized_target: true,
            within_authorized_scope: true,
            understands_legal_limits: true,
            will_protect_output_and_not_resign_install_or_redistribute: true,
        }
    }

    fn installation_core() -> InstallationEnrollmentCore {
        InstallationEnrollmentCore {
            schema: InstallationEnrollmentCore::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            operation: AuthorizedOperation::InstallAndEnrollExactBuild,
            experiment_id: digest(0x02),
            enrollment_challenge: digest(0x06),
            build_binding_sha256: digest(0x03),
            authorized_target_manifest_sha256: digest(0x04),
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            device_selection_nonce: digest(0x05),
            expected_environment: environment(),
            not_before: 1_000,
            not_after: 1_900,
        }
    }

    fn unsigned_receipt(public_key: String) -> UnsignedEnrollmentReceipt {
        UnsignedEnrollmentReceipt {
            schema: UnsignedEnrollmentReceipt::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            authorization_envelope_sha256: digest(0x07),
            acknowledgement_sha256: digest(0x01),
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            enrollment_challenge_response: digest(0x06),
            experiment_id: digest(0x02),
            build_binding_sha256: digest(0x03),
            enrollment_public_key: public_key,
            device_installation_binding_sha256: digest(0x08),
            environment: environment(),
            created_at: 1_800,
        }
    }

    fn unsigned_export(public_key: String) -> UnsignedSessionExport {
        let document = "{}";
        let document_sha256 = sha256_hex(document.as_bytes());
        UnsignedSessionExport {
            schema: UnsignedSessionExport::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            collection_id: digest(0x10),
            session_id: digest(0x11),
            run_ordinal: 1,
            run_counter: "0000000000000001".into(),
            challenge_sha256: digest(0x12),
            build_binding_sha256: digest(0x03),
            enrollment_public_key: public_key,
            device_installation_binding_sha256: digest(0x08),
            entries: [
                LogicalFilename::Session,
                LogicalFilename::MainApp,
                LogicalFilename::Framework,
                LogicalFilename::ShareExtension,
            ]
            .into_iter()
            .map(|logical_filename| ExportEntry {
                logical_filename,
                sha256: document_sha256.clone(),
                canonical_document: document.into(),
            })
            .collect(),
        }
    }

    struct OwnedEnrollmentChain {
        manifest: Vec<u8>,
        acknowledgement: Vec<u8>,
        envelope: Vec<u8>,
        receipt: Vec<u8>,
        selection: Vec<u8>,
        binding: Vec<u8>,
    }

    impl OwnedEnrollmentChain {
        fn files(&self) -> EnrollmentArtifactBytes<'_> {
            EnrollmentArtifactBytes {
                authorized_target_manifest: &self.manifest,
                installation_acknowledgement: &self.acknowledgement,
                authorization_envelope: &self.envelope,
                signed_enrollment_receipt: &self.receipt,
                device_selection_confirmation: &self.selection,
                device_enrollment_binding: &self.binding,
            }
        }
    }

    fn required_absent_entitlement() -> RequiredEntitlement {
        RequiredEntitlement {
            presence: Presence::RequiredAbsent,
            value: None,
        }
    }

    fn authorized_target(role: LabRole, bundle_id: &str) -> AuthorizedTarget {
        AuthorizedTarget {
            role,
            bundle_id: bundle_id.into(),
            code_directory_identifier: bundle_id.into(),
            code_directory_team_identifier: "36XNX296J9".into(),
            application_identifier: required_absent_entitlement(),
            developer_team_identifier: required_absent_entitlement(),
            application_groups: RequiredAppGroups {
                presence: Presence::RequiredAbsent,
                values: None,
            },
        }
    }

    fn owned_enrollment_chain() -> OwnedEnrollmentChain {
        let host_key = SigningKey::from_bytes(&[0x81; 32]);
        let enrollment_key = SigningKey::from_bytes(&[0x82; 32]);
        let manifest = AuthorizedTargetManifest {
            schema: AuthorizedTargetManifest::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            identity_nonce: digest(0x83),
            authorization_public_key: public_key_hex(&host_key),
            authorization_key_id: sha256_hex(host_key.verifying_key().as_bytes()),
            targets: vec![
                authorized_target(LabRole::MainApp, "com.orchardprobe.demolab"),
                authorized_target(LabRole::Framework, "com.orchardprobe.demolab.framework"),
                authorized_target(LabRole::ShareExtension, "com.orchardprobe.demolab.share"),
            ],
        }
        .to_canonical_bytes()
        .unwrap();
        let manifest_sha256 = sha256_hex(&manifest);

        let mut acknowledgement_value = installation_acknowledgement();
        acknowledgement_value.authorized_target_manifest_sha256 = manifest_sha256.clone();
        let acknowledgement = acknowledgement_value.to_canonical_bytes().unwrap();
        let acknowledgement_sha256 = sha256_hex(&acknowledgement);

        let mut core = installation_core();
        core.authorized_target_manifest_sha256 = manifest_sha256;
        let envelope = sign_authorized_operation(&host_key, &acknowledgement_value, &core)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        let envelope_sha256 = sha256_hex(&envelope);

        let enrollment_public_key = public_key_hex(&enrollment_key);
        let receipt = sign_enrollment_receipt(
            &enrollment_key,
            &UnsignedEnrollmentReceipt {
                schema: UnsignedEnrollmentReceipt::SCHEMA.into(),
                profile: super::super::LAB002_PROFILE.into(),
                authorization_envelope_sha256: envelope_sha256.clone(),
                acknowledgement_sha256,
                authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
                enrollment_challenge_response: core.enrollment_challenge,
                experiment_id: core.experiment_id.clone(),
                build_binding_sha256: core.build_binding_sha256.clone(),
                enrollment_public_key: enrollment_public_key.clone(),
                device_installation_binding_sha256: digest(0x84),
                environment: core.expected_environment.clone(),
                created_at: 1_800,
            },
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
        let receipt_sha256 = sha256_hex(&receipt);

        let selection = DeviceSelectionConfirmation {
            schema: DeviceSelectionConfirmation::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            experiment_id: core.experiment_id.clone(),
            authorization_envelope_sha256: envelope_sha256.clone(),
            receipt_sha256: receipt_sha256.clone(),
            device_selection_fingerprint_sha256: device_selection_fingerprint_sha256(
                &envelope_sha256,
                &enrollment_public_key,
                &digest(0x84),
                &core.device_selection_nonce,
            )
            .unwrap(),
            enrollment_public_key: enrollment_public_key.clone(),
            device_installation_binding_sha256: digest(0x84),
            confirmed_at: 1_820,
            confirmed: true,
        }
        .to_canonical_bytes()
        .unwrap();
        let selection_sha256 = sha256_hex(&selection);

        let binding = DeviceEnrollmentBinding {
            schema: DeviceEnrollmentBinding::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            experiment_id: core.experiment_id,
            installation_acknowledgement_sha256: sha256_hex(&acknowledgement),
            authorization_envelope_sha256: envelope_sha256,
            receipt_sha256,
            selection_confirmation_sha256: selection_sha256,
            enrollment_public_key,
            device_installation_binding_sha256: digest(0x84),
            environment: core.expected_environment,
            completed_at: 1_890,
        }
        .to_canonical_bytes()
        .unwrap();

        OwnedEnrollmentChain {
            manifest,
            acknowledgement,
            envelope,
            receipt,
            selection,
            binding,
        }
    }

    #[derive(Clone)]
    struct RunFixtureSpec {
        ordinal: u8,
        not_before: i64,
        acknowledgement_byte: u8,
        challenge_byte: u8,
        collection_byte: u8,
        session_byte: u8,
        binding_completed_offset: i64,
        prior_collection_binding_sha256: Option<String>,
    }

    impl RunFixtureSpec {
        fn counter(&self) -> String {
            format!("{:016x}", self.ordinal)
        }
    }

    fn run_one_spec() -> RunFixtureSpec {
        RunFixtureSpec {
            ordinal: 1,
            not_before: 2_000,
            acknowledgement_byte: 0xa0,
            challenge_byte: 0xa5,
            collection_byte: 0xa3,
            session_byte: 0xa4,
            binding_completed_offset: 800,
            prior_collection_binding_sha256: None,
        }
    }

    fn run_two_spec(prior_collection_binding_sha256: String) -> RunFixtureSpec {
        RunFixtureSpec {
            ordinal: 2,
            not_before: 3_000,
            acknowledgement_byte: 0xd0,
            challenge_byte: 0xd1,
            collection_byte: 0xd2,
            session_byte: 0xd3,
            binding_completed_offset: 800,
            prior_collection_binding_sha256: Some(prior_collection_binding_sha256),
        }
    }

    fn run_acknowledgement(
        enrollment: &VerifiedEnrollment,
        spec: &RunFixtureSpec,
    ) -> AuthorizationAcknowledgement {
        let mut acknowledgement = installation_acknowledgement();
        acknowledgement.acknowledgement_id = digest(spec.acknowledgement_byte);
        acknowledgement.operation = AuthorizedOperation::CollectFixedRangeRun;
        acknowledgement.build_binding_sha256 = enrollment.build_binding_sha256.clone();
        acknowledgement.authorized_target_manifest_sha256 =
            enrollment.authorized_target_manifest_sha256.clone();
        acknowledgement.run_ordinal = Some(spec.ordinal);
        acknowledgement.authorized_actions = vec![
            AuthorizedAction::ImportCollectionChallenge,
            AuthorizedAction::StartCleanRun,
            AuthorizedAction::ObserveMainApp,
            AuthorizedAction::ObserveFramework,
            AuthorizedAction::InvokeShareExtension,
            AuthorizedAction::ExportSessionEvidence,
            AuthorizedAction::ConfirmExportReceived,
            AuthorizedAction::CleanupReportSubtree,
        ];
        acknowledgement.expected_environment = None;
        acknowledgement.expected_enrollment_binding_sha256 =
            Some(enrollment.device_enrollment_binding_sha256.clone());
        acknowledgement.acknowledged_at = spec.not_before;
        acknowledgement.not_before = spec.not_before;
        acknowledgement.not_after = spec.not_before + 900;
        acknowledgement
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            xcode_version: "26.0".into(),
            xcode_build: "17A100".into(),
            iphoneos_sdk_version: "26.0".into(),
            iphoneos_sdk_build: "23A100".into(),
            xcodegen_version: "2.44.1".into(),
            xcodegen_architecture: "arm64".into(),
            xcodegen_executable_sha256: digest(0xa1),
            fastlane_version: "2.228.0".into(),
            gemfile_lock_sha256: digest(0xa2),
        }
    }

    fn session_report(
        enrollment: &VerifiedEnrollment,
        spec: &RunFixtureSpec,
        acknowledgement_sha256: &str,
        challenge_sha256: &str,
    ) -> SessionReport {
        SessionReport {
            schema: SessionReport::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            observer_revision: "lab002-observer-v1".into(),
            build_binding_sha256: enrollment.build_binding_sha256.clone(),
            collection_id: digest(spec.collection_byte),
            run_ordinal: spec.ordinal,
            challenge_sha256: challenge_sha256.into(),
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            acknowledgement_sha256: acknowledgement_sha256.into(),
            authorization_envelope_sha256: challenge_sha256.into(),
            authorization_not_after: spec.not_before + 900,
            device_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
            enrollment_public_key: enrollment.enrollment_public_key.clone(),
            device_installation_binding_sha256: enrollment
                .device_installation_binding_sha256
                .clone(),
            environment: enrollment.environment.clone(),
            session_id: digest(spec.session_byte),
            run_counter: spec.counter(),
            created_at: spec.not_before + 100,
            completed_at: Some(spec.not_before + 700),
            source_commit: "11".repeat(20),
            marketing_version: "1.0".into(),
            build_number: "1".into(),
            state: SessionState::Complete,
        }
    }

    fn role_report(
        session: &SessionReport,
        role: LabRole,
        target_byte: u8,
        phase_offset: i64,
    ) -> RoleReport {
        RoleReport {
            schema: RoleReport::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            collection_id: session.collection_id.clone(),
            session_id: session.session_id.clone(),
            run_ordinal: session.run_ordinal,
            run_counter: session.run_counter.clone(),
            challenge_sha256: session.challenge_sha256.clone(),
            authorization_policy_version: session.authorization_policy_version.clone(),
            acknowledgement_sha256: session.acknowledgement_sha256.clone(),
            authorization_envelope_sha256: session.authorization_envelope_sha256.clone(),
            authorization_not_after: session.authorization_not_after,
            device_enrollment_binding_sha256: session.device_enrollment_binding_sha256.clone(),
            enrollment_public_key: session.enrollment_public_key.clone(),
            device_installation_binding_sha256: session.device_installation_binding_sha256.clone(),
            environment: session.environment.clone(),
            source_commit: session.source_commit.clone(),
            marketing_version: session.marketing_version.clone(),
            build_number: session.build_number.clone(),
            observer_revision: session.observer_revision.clone(),
            build_binding_sha256: session.build_binding_sha256.clone(),
            role,
            fixture_relative_path: role.fixture_relative_path().into(),
            target_identity_binding_sha256: digest(target_byte),
            installed_file_size: 4_096,
            container_kind: ContainerKind::Thin,
            active_slice_ordinal: 0,
            active_cpu_type: 16_777_228,
            active_cpu_subtype: 0,
            active_macho_uuid: "00112233445566778899aabbccddeeff".into(),
            signature: SignatureEvidence {
                presence: SignaturePresence::Present,
                kind: SignatureKind::Cms,
                validation: SignatureValidation::Valid,
                validator_id: "security-framework".into(),
                validator_revision: "lab002-observer-v1".into(),
                superblob_sha256: Some(digest(target_byte.wrapping_add(1))),
            },
            phases: vec![
                Phase {
                    phase: PhaseKind::DiskInspection,
                    completed_at: session.created_at + 100 + phase_offset,
                },
                Phase {
                    phase: PhaseKind::MappedHash,
                    completed_at: session.created_at + 200 + phase_offset,
                },
            ],
            slices: vec![ObservedSlice {
                ordinal: 0,
                cpu_type: 16_777_228,
                cpu_subtype: 0,
                macho_uuid: "00112233445566778899aabbccddeeff".into(),
                slice_file_offset: 0,
                slice_file_size: 4_096,
                section_slice_offset: 512,
                section_file_offset: 512,
                section_vm_offset: 512,
                segment_name: "__TEXT".into(),
                section_name: "__oprobe".into(),
                section_length: 256,
                encryption_command: EncryptionCommand::LcEncryptionInfo64,
                cryptoff: 0,
                cryptsize: 4_096,
                crypt_file_start: 0,
                crypt_file_end: 4_096,
                cryptid: 1,
                encryption_covers_section: true,
                disk_sha256: digest(target_byte.wrapping_add(2)),
                mapped_sha256: digest(target_byte.wrapping_add(3)),
            }],
            outcome: Outcome::Pass,
            reasons: vec![],
        }
    }

    struct OwnedRunChain {
        acknowledgement: Vec<u8>,
        envelope: Vec<u8>,
        intent: Vec<u8>,
        export: Vec<u8>,
        binding: Vec<u8>,
    }

    impl OwnedRunChain {
        fn files(&self) -> RunArtifactBytes<'_> {
            RunArtifactBytes {
                run_acknowledgement: &self.acknowledgement,
                authorization_envelope: &self.envelope,
                collection_intent: &self.intent,
                signed_session_export: &self.export,
                collection_binding: &self.binding,
            }
        }
    }

    fn owned_run_chain_for(
        enrollment: &VerifiedEnrollment,
        spec: &RunFixtureSpec,
    ) -> OwnedRunChain {
        let host_key = SigningKey::from_bytes(&[0x81; 32]);
        let enrollment_key = SigningKey::from_bytes(&[0x82; 32]);
        let acknowledgement_value = run_acknowledgement(enrollment, spec);
        let acknowledgement = acknowledgement_value.to_canonical_bytes().unwrap();
        let acknowledgement_sha256 = sha256_hex(&acknowledgement);
        let core = CollectionChallengeCore {
            schema: CollectionChallengeCore::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            operation: AuthorizedOperation::CollectFixedRangeRun,
            challenge: digest(spec.challenge_byte),
            collection_id: digest(spec.collection_byte),
            run_ordinal: spec.ordinal,
            expected_run_counter: spec.counter(),
            build_binding_sha256: enrollment.build_binding_sha256.clone(),
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            expected_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
            enrollment_public_key: enrollment.enrollment_public_key.clone(),
            expected_device_installation_binding_sha256: enrollment
                .device_installation_binding_sha256
                .clone(),
            not_before: spec.not_before,
            not_after: spec.not_before + 900,
        };
        let envelope_value =
            sign_authorized_operation(&host_key, &acknowledgement_value, &core).unwrap();
        let envelope = envelope_value.to_canonical_bytes().unwrap();
        let envelope_sha256 = sha256_hex(&envelope);

        let intent_value = CollectionIntent {
            schema: CollectionIntent::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            challenge_file_sha256: envelope_sha256.clone(),
            collection_id: core.collection_id.clone(),
            run_ordinal: spec.ordinal,
            expected_run_counter: core.expected_run_counter.clone(),
            prior_collection_binding_sha256: spec.prior_collection_binding_sha256.clone(),
            not_before: spec.not_before,
            not_after: spec.not_before + 900,
            source_commit: "11".repeat(20),
            marketing_version: "1.0".into(),
            build_number: "1".into(),
            observer_revision: "lab002-observer-v1".into(),
            build_binding_sha256: enrollment.build_binding_sha256.clone(),
            installation_acknowledgement_sha256: enrollment
                .installation_acknowledgement_sha256
                .clone(),
            device_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
            run_acknowledgement_sha256: acknowledgement_sha256.clone(),
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            authorization_envelope_signature: envelope_value.signature.clone(),
            authorization_envelope_sha256: envelope_sha256.clone(),
            authorized_target_manifest_sha256: enrollment.authorized_target_manifest_sha256.clone(),
            expected_target_identity_set_sha256: digest(0xa6),
            enrollment_public_key: enrollment.enrollment_public_key.clone(),
            expected_device_installation_binding_sha256: enrollment
                .device_installation_binding_sha256
                .clone(),
            toolchain: toolchain(),
            preupload_evidence_sha256: digest(0xa7),
            ipa_sha256: digest(0xa8),
            oracle_sha256: digest(0xa9),
            expected_inventory_sha256: digest(0xaa),
        };
        let intent = intent_value.to_canonical_bytes().unwrap();
        let intent_sha256 = sha256_hex(&intent);

        let session = session_report(enrollment, spec, &acknowledgement_sha256, &envelope_sha256);
        let main_app = role_report(&session, LabRole::MainApp, 0xb0, 0);
        let framework = role_report(&session, LabRole::Framework, 0xb1, 110);
        let share_extension = role_report(&session, LabRole::ShareExtension, 0xb2, 220);
        let documents = [
            session.to_canonical_bytes().unwrap(),
            main_app.to_canonical_bytes().unwrap(),
            framework.to_canonical_bytes().unwrap(),
            share_extension.to_canonical_bytes().unwrap(),
        ];
        let entries = [
            LogicalFilename::Session,
            LogicalFilename::MainApp,
            LogicalFilename::Framework,
            LogicalFilename::ShareExtension,
        ]
        .into_iter()
        .zip(documents.iter())
        .map(|(logical_filename, document)| ExportEntry {
            logical_filename,
            sha256: sha256_hex(document),
            canonical_document: String::from_utf8(document.clone()).unwrap(),
        })
        .collect();
        let export = sign_session_export(
            &enrollment_key,
            &UnsignedSessionExport {
                schema: UnsignedSessionExport::SCHEMA.into(),
                profile: super::super::LAB002_PROFILE.into(),
                collection_id: session.collection_id.clone(),
                session_id: session.session_id.clone(),
                run_ordinal: spec.ordinal,
                run_counter: spec.counter(),
                challenge_sha256: envelope_sha256.clone(),
                build_binding_sha256: enrollment.build_binding_sha256.clone(),
                enrollment_public_key: enrollment.enrollment_public_key.clone(),
                device_installation_binding_sha256: enrollment
                    .device_installation_binding_sha256
                    .clone(),
                entries,
            },
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
        let export_sha256 = sha256_hex(&export);

        let binding = CollectionBinding {
            schema: CollectionBinding::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            installation_acknowledgement_sha256: enrollment
                .installation_acknowledgement_sha256
                .clone(),
            run_acknowledgement_sha256: acknowledgement_sha256,
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            intent_sha256,
            device_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
            authorization_envelope_signature: envelope_value.signature,
            authorization_envelope_sha256: envelope_sha256.clone(),
            challenge_file_sha256: envelope_sha256,
            signed_session_export_sha256: export_sha256,
            collection_id: session.collection_id,
            run_ordinal: spec.ordinal,
            signed_run_counter: spec.counter(),
            collected_run_counter: session.run_counter,
            session_id: session.session_id,
            enrollment_public_key: enrollment.enrollment_public_key.clone(),
            device_installation_binding_sha256: enrollment
                .device_installation_binding_sha256
                .clone(),
            environment: enrollment.environment.clone(),
            session_sha256: sha256_hex(&documents[0]),
            role_file_hashes: RoleFileHashes {
                main_app_sha256: sha256_hex(&documents[1]),
                framework_sha256: sha256_hex(&documents[2]),
                share_extension_sha256: sha256_hex(&documents[3]),
            },
            completed_at: spec.not_before + spec.binding_completed_offset,
        }
        .to_canonical_bytes()
        .unwrap();

        OwnedRunChain {
            acknowledgement,
            envelope,
            intent,
            export,
            binding,
        }
    }

    fn owned_run_chain(enrollment: &VerifiedEnrollment) -> OwnedRunChain {
        owned_run_chain_for(enrollment, &run_one_spec())
    }

    #[test]
    fn complete_enrollment_chain_closes_all_six_artifacts() {
        let chain = owned_enrollment_chain();
        let verified = verify_enrollment_chain(chain.files()).unwrap();

        assert_eq!(
            verified.authorized_target_manifest_sha256,
            sha256_hex(&chain.manifest)
        );
        assert_eq!(
            verified.installation_acknowledgement_sha256,
            sha256_hex(&chain.acknowledgement)
        );
        assert_eq!(
            verified.authorization_envelope_sha256,
            sha256_hex(&chain.envelope)
        );
        assert_eq!(
            verified.signed_enrollment_receipt_sha256,
            sha256_hex(&chain.receipt)
        );
        assert_eq!(
            verified.device_selection_confirmation_sha256,
            sha256_hex(&chain.selection)
        );
        assert_eq!(
            verified.device_enrollment_binding_sha256,
            sha256_hex(&chain.binding)
        );
        assert_eq!(verified.experiment_id, digest(0x02));
        assert_eq!(verified.build_binding_sha256, digest(0x03));
        assert_eq!(
            verified.enrollment_public_key,
            public_key_hex(&SigningKey::from_bytes(&[0x82; 32]))
        );
        assert_eq!(verified.device_installation_binding_sha256, digest(0x84));
        assert_eq!(verified.environment, environment());
        assert_eq!(verified.authorization_not_before, 1_000);
        assert_eq!(verified.authorization_not_after, 1_900);
        assert_eq!(verified.completed_at, 1_890);
    }

    #[test]
    fn enrollment_chain_rejects_acknowledgement_byte_substitution() {
        let chain = owned_enrollment_chain();
        let mut acknowledgement =
            AuthorizationAcknowledgement::from_canonical_bytes(&chain.acknowledgement).unwrap();
        acknowledgement.acknowledgement_id = digest(0x91);
        let substituted_acknowledgement = acknowledgement.to_canonical_bytes().unwrap();

        assert!(
            verify_enrollment_chain(EnrollmentArtifactBytes {
                installation_acknowledgement: &substituted_acknowledgement,
                ..chain.files()
            })
            .is_err()
        );
    }

    #[test]
    fn enrollment_chain_rejects_receipt_signature_substitution() {
        let chain = owned_enrollment_chain();
        let mut receipt = SignedEnrollmentReceipt::from_canonical_bytes(&chain.receipt).unwrap();
        let replacement = if receipt.signature.starts_with('0') {
            "1"
        } else {
            "0"
        };
        receipt.signature.replace_range(0..1, replacement);
        let substituted_receipt = receipt.to_canonical_bytes().unwrap();

        assert!(
            verify_enrollment_chain(EnrollmentArtifactBytes {
                signed_enrollment_receipt: &substituted_receipt,
                ..chain.files()
            })
            .is_err()
        );
    }

    #[test]
    fn enrollment_chain_rejects_selection_fingerprint_substitution() {
        let chain = owned_enrollment_chain();
        let mut selection =
            DeviceSelectionConfirmation::from_canonical_bytes(&chain.selection).unwrap();
        selection.device_selection_fingerprint_sha256 = digest(0x92);
        let substituted_selection = selection.to_canonical_bytes().unwrap();

        assert!(
            verify_enrollment_chain(EnrollmentArtifactBytes {
                device_selection_confirmation: &substituted_selection,
                ..chain.files()
            })
            .is_err()
        );
    }

    #[test]
    fn enrollment_chain_rejects_final_binding_substitution_and_time_reordering() {
        let chain = owned_enrollment_chain();
        let mut binding = DeviceEnrollmentBinding::from_canonical_bytes(&chain.binding).unwrap();
        binding.selection_confirmation_sha256 = digest(0x93);
        let substituted_binding = binding.to_canonical_bytes().unwrap();
        assert!(
            verify_enrollment_chain(EnrollmentArtifactBytes {
                device_enrollment_binding: &substituted_binding,
                ..chain.files()
            })
            .is_err()
        );

        let mut reordered = DeviceEnrollmentBinding::from_canonical_bytes(&chain.binding).unwrap();
        reordered.completed_at = 1_810;
        let reordered_binding = reordered.to_canonical_bytes().unwrap();
        assert!(
            verify_enrollment_chain(EnrollmentArtifactBytes {
                device_enrollment_binding: &reordered_binding,
                ..chain.files()
            })
            .is_err()
        );
    }

    fn enrollment_fixture() -> VerifiedEnrollment {
        let chain = owned_enrollment_chain();
        verify_enrollment_chain(chain.files()).unwrap()
    }

    #[test]
    fn complete_run_chain_closes_control_export_reports_and_binding() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let verified = verify_run_chain(&enrollment, chain.files()).unwrap();

        assert_eq!(
            verified.run_acknowledgement_sha256,
            sha256_hex(&chain.acknowledgement)
        );
        assert_eq!(
            verified.authorization_envelope_sha256,
            sha256_hex(&chain.envelope)
        );
        assert_eq!(verified.collection_intent_sha256, sha256_hex(&chain.intent));
        assert_eq!(
            verified.signed_session_export_sha256,
            sha256_hex(&chain.export)
        );
        assert_eq!(
            verified.collection_binding_sha256,
            sha256_hex(&chain.binding)
        );
        assert_eq!(verified.collection_id, digest(0xa3));
        assert_eq!(verified.session_id, digest(0xa4));
        assert_eq!(verified.run_ordinal, 1);
        assert_eq!(verified.run_counter, "0000000000000001");
        assert_eq!(verified.prior_collection_binding_sha256, None);
        assert_eq!(verified.environment, environment());
        assert_eq!(verified.created_at, 2_100);
        assert_eq!(verified.completed_at, 2_800);
    }

    fn verified_two_run_fixture() -> (VerifiedEnrollment, VerifiedRun, VerifiedRun) {
        let enrollment = enrollment_fixture();
        let run_one_chain = owned_run_chain(&enrollment);
        let run_one = verify_run_chain(&enrollment, run_one_chain.files()).unwrap();
        let run_two_chain = owned_run_chain_for(
            &enrollment,
            &run_two_spec(run_one.collection_binding_sha256.clone()),
        );
        let run_two = verify_run_chain(&enrollment, run_two_chain.files()).unwrap();
        (enrollment, run_one, run_two)
    }

    #[test]
    fn complete_two_run_chain_is_distinct_ordered_and_chained() {
        let (enrollment, run_one, run_two) = verified_two_run_fixture();
        let verified = verify_two_run_chain(&enrollment, &run_one, &run_two).unwrap();

        assert_eq!(
            verified.enrollment_binding_sha256,
            enrollment.device_enrollment_binding_sha256
        );
        assert_eq!(
            verified.run_one_binding_sha256,
            run_one.collection_binding_sha256
        );
        assert_eq!(
            verified.run_two_binding_sha256,
            run_two.collection_binding_sha256
        );
    }

    #[test]
    fn two_run_chain_rejects_replay_and_swapped_order() {
        let (enrollment, run_one, run_two) = verified_two_run_fixture();

        assert!(verify_two_run_chain(&enrollment, &run_one, &run_one).is_err());
        assert!(verify_two_run_chain(&enrollment, &run_two, &run_one).is_err());
    }

    #[test]
    fn two_run_chain_rejects_broken_prior_binding_and_overlapping_windows() {
        let enrollment = enrollment_fixture();
        let run_one_chain = owned_run_chain(&enrollment);
        let run_one = verify_run_chain(&enrollment, run_one_chain.files()).unwrap();

        let wrong_prior_chain = owned_run_chain_for(&enrollment, &run_two_spec(digest(0xd4)));
        let wrong_prior = verify_run_chain(&enrollment, wrong_prior_chain.files()).unwrap();
        assert!(verify_two_run_chain(&enrollment, &run_one, &wrong_prior).is_err());

        let mut overlapping_spec = run_two_spec(run_one.collection_binding_sha256.clone());
        overlapping_spec.not_before = 2_900;
        let overlapping_chain = owned_run_chain_for(&enrollment, &overlapping_spec);
        let overlapping = verify_run_chain(&enrollment, overlapping_chain.files()).unwrap();
        assert!(verify_two_run_chain(&enrollment, &run_one, &overlapping).is_err());
    }

    #[test]
    fn two_run_chain_rejects_reused_collection_challenge_and_session_ids() {
        let enrollment = enrollment_fixture();
        let run_one_chain = owned_run_chain(&enrollment);
        let run_one = verify_run_chain(&enrollment, run_one_chain.files()).unwrap();
        let mut reused = run_two_spec(run_one.collection_binding_sha256.clone());
        reused.collection_byte = 0xa3;
        reused.challenge_byte = 0xa5;
        reused.session_byte = 0xa4;
        let reused_chain = owned_run_chain_for(&enrollment, &reused);
        let run_two = verify_run_chain(&enrollment, reused_chain.files()).unwrap();

        assert!(verify_two_run_chain(&enrollment, &run_one, &run_two).is_err());
    }

    #[test]
    fn two_run_chain_rejects_acknowledgement_or_challenge_id_only_replay() {
        let enrollment = enrollment_fixture();
        let run_one_chain = owned_run_chain(&enrollment);
        let run_one = verify_run_chain(&enrollment, run_one_chain.files()).unwrap();

        let mut repeated_ack = run_two_spec(run_one.collection_binding_sha256.clone());
        repeated_ack.acknowledgement_byte = 0xa0;
        let repeated_ack_chain = owned_run_chain_for(&enrollment, &repeated_ack);
        let run_two_repeated_ack =
            verify_run_chain(&enrollment, repeated_ack_chain.files()).unwrap();
        assert!(verify_two_run_chain(&enrollment, &run_one, &run_two_repeated_ack).is_err());

        let mut repeated_challenge = run_two_spec(run_one.collection_binding_sha256.clone());
        repeated_challenge.challenge_byte = 0xa5;
        let repeated_challenge_chain = owned_run_chain_for(&enrollment, &repeated_challenge);
        let run_two_repeated_challenge =
            verify_run_chain(&enrollment, repeated_challenge_chain.files()).unwrap();
        assert!(verify_two_run_chain(&enrollment, &run_one, &run_two_repeated_challenge).is_err());
    }

    #[test]
    fn two_run_chain_rejects_run_two_authorized_before_run_one_binding_exists() {
        let enrollment = enrollment_fixture();
        let mut late_binding_spec = run_one_spec();
        late_binding_spec.binding_completed_offset = 950;
        let run_one_chain = owned_run_chain_for(&enrollment, &late_binding_spec);
        let run_one = verify_run_chain(&enrollment, run_one_chain.files()).unwrap();

        let mut premature_run_two = run_two_spec(run_one.collection_binding_sha256.clone());
        premature_run_two.not_before = 2_901;
        let run_two_chain = owned_run_chain_for(&enrollment, &premature_run_two);
        let run_two = verify_run_chain(&enrollment, run_two_chain.files()).unwrap();

        assert!(run_one.completed_at < run_two.created_at);
        assert!(run_one.authorization_not_after < run_two.authorization_not_before);
        assert!(verify_two_run_chain(&enrollment, &run_one, &run_two).is_err());
    }

    #[test]
    fn run_chain_rejects_export_entry_digest_substitution() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let signed = SignedSessionExport::from_canonical_bytes(&chain.export).unwrap();
        let mut export = UnsignedSessionExport::from_canonical_bytes(
            signed.unsigned_export_canonical.as_bytes(),
        )
        .unwrap();
        export.entries[1].sha256 = digest(0xc1);
        let substituted_export = sign_session_export(&SigningKey::from_bytes(&[0x82; 32]), &export)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();

        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    signed_session_export: &substituted_export,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn run_chain_rejects_role_document_substitution_under_a_valid_export_signature() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let signed = SignedSessionExport::from_canonical_bytes(&chain.export).unwrap();
        let mut export = UnsignedSessionExport::from_canonical_bytes(
            signed.unsigned_export_canonical.as_bytes(),
        )
        .unwrap();
        export.entries[2].canonical_document = export.entries[1].canonical_document.clone();
        export.entries[2].sha256 = sha256_hex(export.entries[2].canonical_document.as_bytes());
        let substituted_export = sign_session_export(&SigningKey::from_bytes(&[0x82; 32]), &export)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();

        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    signed_session_export: &substituted_export,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn run_chain_rejects_report_environment_drift_and_clock_skew() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let signed = SignedSessionExport::from_canonical_bytes(&chain.export).unwrap();
        let export = UnsignedSessionExport::from_canonical_bytes(
            signed.unsigned_export_canonical.as_bytes(),
        )
        .unwrap();

        let mut drifted = export.clone();
        let mut main =
            RoleReport::from_canonical_bytes(drifted.entries[1].canonical_document.as_bytes())
                .unwrap();
        main.environment.ios_build = "23A101".into();
        let main_bytes = main.to_canonical_bytes().unwrap();
        drifted.entries[1].sha256 = sha256_hex(&main_bytes);
        drifted.entries[1].canonical_document = String::from_utf8(main_bytes).unwrap();
        let drifted_export = sign_session_export(&SigningKey::from_bytes(&[0x82; 32]), &drifted)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    signed_session_export: &drifted_export,
                    ..chain.files()
                }
            )
            .is_err()
        );

        let mut stale = export;
        let mut session =
            SessionReport::from_canonical_bytes(stale.entries[0].canonical_document.as_bytes())
                .unwrap();
        session.created_at = 1_879;
        let session_bytes = session.to_canonical_bytes().unwrap();
        stale.entries[0].sha256 = sha256_hex(&session_bytes);
        stale.entries[0].canonical_document = String::from_utf8(session_bytes).unwrap();
        let stale_export = sign_session_export(&SigningKey::from_bytes(&[0x82; 32]), &stale)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();
        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    signed_session_export: &stale_export,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn run_chain_rejects_cross_role_backward_clock_step() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let signed = SignedSessionExport::from_canonical_bytes(&chain.export).unwrap();
        let mut export = UnsignedSessionExport::from_canonical_bytes(
            signed.unsigned_export_canonical.as_bytes(),
        )
        .unwrap();
        let mut framework =
            RoleReport::from_canonical_bytes(export.entries[2].canonical_document.as_bytes())
                .unwrap();
        framework.phases[0].completed_at = 2_250;
        framework.phases[1].completed_at = 2_260;
        let framework_bytes = framework.to_canonical_bytes().unwrap();
        export.entries[2].sha256 = sha256_hex(&framework_bytes);
        export.entries[2].canonical_document = String::from_utf8(framework_bytes).unwrap();
        let reordered_export = sign_session_export(&SigningKey::from_bytes(&[0x82; 32]), &export)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();

        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    signed_session_export: &reordered_export,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn run_chain_rejects_session_authorization_deadline_substitution() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let signed = SignedSessionExport::from_canonical_bytes(&chain.export).unwrap();
        let mut export = UnsignedSessionExport::from_canonical_bytes(
            signed.unsigned_export_canonical.as_bytes(),
        )
        .unwrap();
        let mut session =
            SessionReport::from_canonical_bytes(export.entries[0].canonical_document.as_bytes())
                .unwrap();
        session.authorization_not_after -= 1;
        let session_bytes = session.to_canonical_bytes().unwrap();
        export.entries[0].sha256 = sha256_hex(&session_bytes);
        export.entries[0].canonical_document = String::from_utf8(session_bytes).unwrap();
        let substituted_export = sign_session_export(&SigningKey::from_bytes(&[0x82; 32]), &export)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();

        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    signed_session_export: &substituted_export,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn run_chain_rejects_a_window_before_enrollment_completed() {
        let mut enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        enrollment.completed_at = 2_001;

        assert!(verify_run_chain(&enrollment, chain.files()).is_err());
    }

    #[test]
    fn run_chain_rejects_a_skew_tolerated_session_before_enrollment_completed() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let signed = SignedSessionExport::from_canonical_bytes(&chain.export).unwrap();
        let mut export = UnsignedSessionExport::from_canonical_bytes(
            signed.unsigned_export_canonical.as_bytes(),
        )
        .unwrap();
        let mut session =
            SessionReport::from_canonical_bytes(export.entries[0].canonical_document.as_bytes())
                .unwrap();
        session.created_at = 1_885;
        let session_bytes = session.to_canonical_bytes().unwrap();
        export.entries[0].sha256 = sha256_hex(&session_bytes);
        export.entries[0].canonical_document = String::from_utf8(session_bytes).unwrap();
        let substituted_export = sign_session_export(&SigningKey::from_bytes(&[0x82; 32]), &export)
            .unwrap()
            .to_canonical_bytes()
            .unwrap();

        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    signed_session_export: &substituted_export,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn run_chain_rejects_final_binding_substitution() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let mut binding = CollectionBinding::from_canonical_bytes(&chain.binding).unwrap();
        binding.intent_sha256 = digest(0xc2);
        let substituted_binding = binding.to_canonical_bytes().unwrap();

        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    collection_binding: &substituted_binding,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn run_chain_rejects_a_validly_signed_acknowledgement_for_another_experiment() {
        let enrollment = enrollment_fixture();
        let chain = owned_run_chain(&enrollment);
        let mut acknowledgement =
            AuthorizationAcknowledgement::from_canonical_bytes(&chain.acknowledgement).unwrap();
        acknowledgement.experiment_id = digest(0xc3);
        let envelope = AuthorizedOperationEnvelope::from_canonical_bytes(&chain.envelope).unwrap();
        let core = CollectionChallengeCore::from_canonical_bytes(
            envelope.operation_core_canonical.as_bytes(),
        )
        .unwrap();
        let substituted_acknowledgement = acknowledgement.to_canonical_bytes().unwrap();
        let substituted_envelope = sign_authorized_operation(
            &SigningKey::from_bytes(&[0x81; 32]),
            &acknowledgement,
            &core,
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();

        assert!(
            verify_run_chain(
                &enrollment,
                RunArtifactBytes {
                    run_acknowledgement: &substituted_acknowledgement,
                    authorization_envelope: &substituted_envelope,
                    ..chain.files()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn host_authorization_binds_exact_types_key_and_bytes() {
        let signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let public_key = public_key_hex(&signing_key);
        let acknowledgement = installation_acknowledgement();
        let core = installation_core();
        let envelope = sign_authorized_operation(&signing_key, &acknowledgement, &core).unwrap();

        let (decoded_acknowledgement, decoded_core) = verify_authorized_operation::<
            AuthorizationAcknowledgement,
            InstallationEnrollmentCore,
        >(&envelope, &public_key)
        .unwrap();
        assert_eq!(decoded_acknowledgement, acknowledgement);
        assert_eq!(decoded_core, core);

        let other_key = SigningKey::from_bytes(&[0x32; 32]);
        assert!(verify_authorized_operation::<
            AuthorizationAcknowledgement,
            InstallationEnrollmentCore,
        >(&envelope, &public_key_hex(&other_key))
        .is_err());

        let mut substituted = envelope;
        substituted.operation_core_canonical = installation_core()
            .to_canonical_bytes()
            .map(String::from_utf8)
            .unwrap()
            .unwrap();
        substituted.operation_core_canonical = substituted
            .operation_core_canonical
            .replace(&digest(0x06), &digest(0x16));
        assert!(verify_authorized_operation::<
            AuthorizationAcknowledgement,
            InstallationEnrollmentCore,
        >(&substituted, &public_key)
        .is_err());
    }

    #[test]
    fn enrollment_and_export_domains_reject_key_byte_and_domain_substitution() {
        let enrollment_key = SigningKey::from_bytes(&[0x41; 32]);
        let enrollment_public_key = public_key_hex(&enrollment_key);
        let receipt_core = unsigned_receipt(enrollment_public_key.clone());
        let receipt = sign_enrollment_receipt(&enrollment_key, &receipt_core).unwrap();
        assert_eq!(
            verify_enrollment_receipt(&receipt, &enrollment_public_key).unwrap(),
            receipt_core
        );

        let export_core = unsigned_export(enrollment_public_key.clone());
        let export = sign_session_export(&enrollment_key, &export_core).unwrap();
        assert_eq!(
            verify_session_export(&export, &enrollment_public_key).unwrap(),
            export_core
        );

        let mut wrong_domain = export.clone();
        wrong_domain.signature = receipt.signature.clone();
        assert!(verify_session_export(&wrong_domain, &enrollment_public_key).is_err());

        let mut substituted_receipt = receipt;
        let mut changed_core = unsigned_receipt(enrollment_public_key.clone());
        changed_core.created_at += 1;
        substituted_receipt.unsigned_receipt_canonical =
            String::from_utf8(changed_core.to_canonical_bytes().unwrap()).unwrap();
        assert!(verify_enrollment_receipt(&substituted_receipt, &enrollment_public_key).is_err());

        let other_key = SigningKey::from_bytes(&[0x42; 32]);
        assert!(verify_session_export(&export, &public_key_hex(&other_key)).is_err());
        assert!(
            sign_enrollment_receipt(
                &enrollment_key,
                &unsigned_receipt(public_key_hex(&other_key))
            )
            .is_err()
        );
        assert!(
            sign_session_export(
                &enrollment_key,
                &unsigned_export(public_key_hex(&other_key))
            )
            .is_err()
        );
    }

    #[test]
    fn selection_fingerprint_is_full_length_and_binds_all_four_inputs() {
        let values = [digest(0x51), digest(0x52), digest(0x53), digest(0x54)];
        let fingerprint =
            device_selection_fingerprint_sha256(&values[0], &values[1], &values[2], &values[3])
                .unwrap();
        assert_eq!(fingerprint.len(), 64);
        for index in 0..values.len() {
            let mut changed = values.clone();
            changed[index] = digest(0x60 + index as u8);
            assert_ne!(
                device_selection_fingerprint_sha256(
                    &changed[0],
                    &changed[1],
                    &changed[2],
                    &changed[3]
                )
                .unwrap(),
                fingerprint
            );
        }
    }

    #[test]
    fn authorization_domain_cannot_decode_a_run_core_as_installation() {
        let signing_key = SigningKey::from_bytes(&[0x71; 32]);
        let acknowledgement = installation_acknowledgement();
        let run_core = CollectionChallengeCore {
            schema: CollectionChallengeCore::SCHEMA.into(),
            profile: super::super::LAB002_PROFILE.into(),
            operation: AuthorizedOperation::CollectFixedRangeRun,
            challenge: digest(0x72),
            collection_id: digest(0x73),
            run_ordinal: 1,
            expected_run_counter: "0000000000000001".into(),
            build_binding_sha256: digest(0x03),
            authorization_policy_version: super::super::AUTHORIZATION_POLICY_VERSION.into(),
            expected_enrollment_binding_sha256: digest(0x74),
            enrollment_public_key: digest(0x75),
            expected_device_installation_binding_sha256: digest(0x76),
            not_before: 2_000,
            not_after: 2_900,
        };
        let envelope =
            sign_authorized_operation(&signing_key, &acknowledgement, &run_core).unwrap();
        assert!(verify_authorized_operation::<
            AuthorizationAcknowledgement,
            InstallationEnrollmentCore,
        >(&envelope, &public_key_hex(&signing_key))
        .is_err());
    }

    #[test]
    fn weak_ed25519_public_keys_are_rejected_before_verification() {
        let mut identity_encoding = [0_u8; 32];
        identity_encoding[0] = 1;
        assert!(verifying_key(&lower_hex(&identity_encoding)).is_err());
    }
}
