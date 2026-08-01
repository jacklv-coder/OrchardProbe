//! Closed Host authoring primitives for the LAB-002 enrollment and run chain.
//!
//! These functions create only the fixed first-party control artifacts. They
//! perform no device I/O, installation, upload, target selection, path access,
//! memory access, or decryption.

use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;

use super::{
    AUTHORIZATION_POLICY_VERSION, LAB002_PROFILE, Lab002Error,
    artifacts::{
        AuthorizationAcknowledgement, AuthorizedAction, AuthorizedOperation,
        AuthorizedOperationEnvelope, AuthorizedTargetManifest, ClosedArtifact, CollectionBinding,
        CollectionChallengeCore, CollectionIntent, DataCategory, DeviceEnrollmentBinding,
        DeviceSelectionConfirmation, Environment, LabOracle, LogicalFilename, RoleFileHashes,
        RoleReport, SessionReport, SignedEnrollmentReceipt, SignedSessionExport,
    },
    canonical_json,
    host::{
        EnrollmentArtifactBytes, RunArtifactBytes, VerifiedEnrollment, VerifiedRun,
        device_selection_fingerprint_sha256, sign_authorized_operation, verified_artifact_sha256,
        verify_authorized_operation, verify_enrollment_chain, verify_enrollment_receipt,
        verify_run_chain, verify_session_export,
    },
    lower_hex, sha256_hex,
};

const EXPECTED_INVENTORY_DOMAIN: &[u8] = b"orchardprobe.demolab.lab002.expected-inventory.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationAssertions {
    pub confirmed: bool,
    pub owns_or_explicitly_authorized_target: bool,
    pub within_authorized_scope: bool,
    pub understands_legal_limits: bool,
    pub will_protect_output_and_not_resign_install_or_redistribute: bool,
}

impl AuthorizationAssertions {
    fn validate(self) -> Result<(), Lab002Error> {
        if self.confirmed
            && self.owns_or_explicitly_authorized_target
            && self.within_authorized_scope
            && self.understands_legal_limits
            && self.will_protect_output_and_not_resign_install_or_redistribute
        {
            Ok(())
        } else {
            Err(Lab002Error::InvalidAuthorizationScope)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationControl {
    pub acknowledgement: Vec<u8>,
    pub authorization_envelope: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentClosure {
    pub device_selection_confirmation: Vec<u8>,
    pub device_enrollment_binding: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunControl {
    pub acknowledgement: Vec<u8>,
    pub authorization_envelope: Vec<u8>,
    pub collection_intent: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunClosure {
    pub collection_binding: Vec<u8>,
}

fn random_digest(rng: &mut (impl RngCore + CryptoRng)) -> String {
    let mut bytes = [0_u8; 32];
    rng.fill_bytes(&mut bytes);
    lower_hex(&bytes)
}

fn authorization_public_key(signing_key: &SigningKey) -> String {
    lower_hex(signing_key.verifying_key().as_bytes())
}

fn ensure_host_key(
    signing_key: &SigningKey,
    manifest: &AuthorizedTargetManifest,
) -> Result<(), Lab002Error> {
    let public_key = authorization_public_key(signing_key);
    if manifest.authorization_public_key != public_key
        || manifest.authorization_key_id != sha256_hex(signing_key.verifying_key().as_bytes())
        || signing_key.verifying_key().is_weak()
    {
        return Err(Lab002Error::AuthorizationKeyIdMismatch);
    }
    Ok(())
}

fn not_after(not_before: i64) -> Result<i64, Lab002Error> {
    not_before
        .checked_add(900)
        .ok_or(Lab002Error::InvalidAuthorizationScope)
}

fn categories() -> Vec<DataCategory> {
    vec![
        DataCategory::AuthorizationControlMetadata,
        DataCategory::SanitizedDeviceEnvironment,
        DataCategory::CodeSignatureMetadata,
        DataCategory::FixedRangeSha256,
        DataCategory::ClosedOutcomes,
    ]
}

struct AcknowledgementInput {
    acknowledgement_id: String,
    experiment_id: String,
    operation: AuthorizedOperation,
    build_binding_sha256: String,
    authorized_target_manifest_sha256: String,
    run_ordinal: Option<u8>,
    authorized_actions: Vec<AuthorizedAction>,
    device_selection_nonce: String,
    expected_environment: Option<Environment>,
    expected_enrollment_binding_sha256: Option<String>,
    acknowledged_at: i64,
}

fn acknowledgement(
    assertions: AuthorizationAssertions,
    input: AcknowledgementInput,
) -> Result<AuthorizationAcknowledgement, Lab002Error> {
    assertions.validate()?;
    let acknowledgement = AuthorizationAcknowledgement {
        schema: AuthorizationAcknowledgement::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
        acknowledgement_id: input.acknowledgement_id,
        experiment_id: input.experiment_id,
        operation: input.operation,
        build_binding_sha256: input.build_binding_sha256,
        authorized_target_manifest_sha256: input.authorized_target_manifest_sha256,
        technique_profile: "first_party_fixed_range_disk_and_mapped_sha256".into(),
        run_ordinal: input.run_ordinal,
        data_categories: categories(),
        retention_profile: "owner_only_lab002_experiment_v1".into(),
        authorized_actions: input.authorized_actions,
        device_selection_nonce: input.device_selection_nonce,
        expected_environment: input.expected_environment,
        expected_enrollment_binding_sha256: input.expected_enrollment_binding_sha256,
        acknowledged_at: input.acknowledged_at,
        not_before: input.acknowledged_at,
        not_after: not_after(input.acknowledged_at)?,
        confirmed: assertions.confirmed,
        owns_or_explicitly_authorized_target: assertions.owns_or_explicitly_authorized_target,
        within_authorized_scope: assertions.within_authorized_scope,
        understands_legal_limits: assertions.understands_legal_limits,
        will_protect_output_and_not_resign_install_or_redistribute: assertions
            .will_protect_output_and_not_resign_install_or_redistribute,
    };
    acknowledgement.to_canonical_bytes()?;
    Ok(acknowledgement)
}

pub fn create_installation_control(
    signing_key: &SigningKey,
    authorized_target_manifest: &[u8],
    build_binding_sha256: &str,
    expected_environment: Environment,
    assertions: AuthorizationAssertions,
    acknowledged_at: i64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<InstallationControl, Lab002Error> {
    let (manifest, manifest_sha256) =
        verified_artifact_sha256::<AuthorizedTargetManifest>(authorized_target_manifest)?;
    ensure_host_key(signing_key, &manifest)?;

    let experiment_id = random_digest(rng);
    let device_selection_nonce = random_digest(rng);
    let acknowledgement = acknowledgement(
        assertions,
        AcknowledgementInput {
            acknowledgement_id: random_digest(rng),
            experiment_id: experiment_id.clone(),
            operation: AuthorizedOperation::InstallAndEnrollExactBuild,
            build_binding_sha256: build_binding_sha256.into(),
            authorized_target_manifest_sha256: manifest_sha256.clone(),
            run_ordinal: None,
            authorized_actions: vec![
                AuthorizedAction::InstallExactBuild,
                AuthorizedAction::ImportInstallationEnrollment,
                AuthorizedAction::ConfirmDeviceEnrollment,
                AuthorizedAction::ExportEnrollmentReceipt,
            ],
            device_selection_nonce: device_selection_nonce.clone(),
            expected_environment: Some(expected_environment.clone()),
            expected_enrollment_binding_sha256: None,
            acknowledged_at,
        },
    )?;
    let core = super::artifacts::InstallationEnrollmentCore {
        schema: super::artifacts::InstallationEnrollmentCore::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        operation: AuthorizedOperation::InstallAndEnrollExactBuild,
        experiment_id,
        enrollment_challenge: random_digest(rng),
        build_binding_sha256: build_binding_sha256.into(),
        authorized_target_manifest_sha256: manifest_sha256,
        authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
        device_selection_nonce,
        expected_environment,
        not_before: acknowledged_at,
        not_after: not_after(acknowledged_at)?,
    };
    let envelope = sign_authorized_operation(signing_key, &acknowledgement, &core)?;
    Ok(InstallationControl {
        acknowledgement: acknowledgement.to_canonical_bytes()?,
        authorization_envelope: envelope.to_canonical_bytes()?,
    })
}

pub fn close_enrollment(
    authorized_target_manifest: &[u8],
    installation_acknowledgement: &[u8],
    authorization_envelope: &[u8],
    signed_enrollment_receipt: &[u8],
    displayed_fingerprint: &str,
    confirmed_at: i64,
) -> Result<(EnrollmentClosure, VerifiedEnrollment), Lab002Error> {
    let (manifest, _) =
        verified_artifact_sha256::<AuthorizedTargetManifest>(authorized_target_manifest)?;
    let (acknowledgement, acknowledgement_sha256) =
        verified_artifact_sha256::<AuthorizationAcknowledgement>(installation_acknowledgement)?;
    let (envelope, envelope_sha256) =
        verified_artifact_sha256::<AuthorizedOperationEnvelope>(authorization_envelope)?;
    let (_, core) = verify_authorized_operation::<
        AuthorizationAcknowledgement,
        super::artifacts::InstallationEnrollmentCore,
    >(&envelope, &manifest.authorization_public_key)?;
    let (signed_receipt, receipt_sha256) =
        verified_artifact_sha256::<SignedEnrollmentReceipt>(signed_enrollment_receipt)?;
    let receipt =
        verify_enrollment_receipt(&signed_receipt, &signed_receipt.enrollment_public_key)?;
    let expected_fingerprint = device_selection_fingerprint_sha256(
        &envelope_sha256,
        &receipt.enrollment_public_key,
        &receipt.device_installation_binding_sha256,
        &core.device_selection_nonce,
    )?;
    if displayed_fingerprint != expected_fingerprint {
        return Err(Lab002Error::InvalidEvidence(
            "device selection fingerprint does not match all 64 hex characters",
        ));
    }

    let selection = DeviceSelectionConfirmation {
        schema: DeviceSelectionConfirmation::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        experiment_id: acknowledgement.experiment_id.clone(),
        authorization_envelope_sha256: envelope_sha256.clone(),
        receipt_sha256: receipt_sha256.clone(),
        device_selection_fingerprint_sha256: expected_fingerprint,
        enrollment_public_key: receipt.enrollment_public_key.clone(),
        device_installation_binding_sha256: receipt.device_installation_binding_sha256.clone(),
        confirmed_at,
        confirmed: true,
    }
    .to_canonical_bytes()?;
    let binding = DeviceEnrollmentBinding {
        schema: DeviceEnrollmentBinding::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        experiment_id: acknowledgement.experiment_id,
        installation_acknowledgement_sha256: acknowledgement_sha256,
        authorization_envelope_sha256: envelope_sha256,
        receipt_sha256,
        selection_confirmation_sha256: sha256_hex(&selection),
        enrollment_public_key: receipt.enrollment_public_key,
        device_installation_binding_sha256: receipt.device_installation_binding_sha256,
        environment: receipt.environment,
        completed_at: confirmed_at,
    }
    .to_canonical_bytes()?;
    let verified = verify_enrollment_chain(EnrollmentArtifactBytes {
        authorized_target_manifest,
        installation_acknowledgement,
        authorization_envelope,
        signed_enrollment_receipt,
        device_selection_confirmation: &selection,
        device_enrollment_binding: &binding,
    })?;
    Ok((
        EnrollmentClosure {
            device_selection_confirmation: selection,
            device_enrollment_binding: binding,
        },
        verified,
    ))
}

#[derive(Serialize)]
struct InventoryProjection<'a> {
    roles: &'a [super::artifacts::OracleRole],
}

pub fn expected_inventory_sha256(oracle: &LabOracle) -> Result<String, Lab002Error> {
    oracle.validate()?;
    let canonical = canonical_json(&InventoryProjection {
        roles: &oracle.roles,
    })?;
    let size = u32::try_from(canonical.len())
        .map_err(|_| Lab002Error::InvalidEvidence("expected inventory projection is too large"))?;
    let mut input = Vec::with_capacity(EXPECTED_INVENTORY_DOMAIN.len() + 4 + canonical.len());
    input.extend_from_slice(EXPECTED_INVENTORY_DOMAIN);
    input.extend_from_slice(&size.to_be_bytes());
    input.extend_from_slice(&canonical);
    Ok(sha256_hex(&input))
}

pub struct RunControlRequest {
    pub preupload_evidence_sha256: String,
    pub run_ordinal: u8,
    pub prior_collection_binding_sha256: Option<String>,
    pub assertions: AuthorizationAssertions,
    pub acknowledged_at: i64,
}

pub fn create_run_control(
    signing_key: &SigningKey,
    enrollment: &VerifiedEnrollment,
    oracle_canonical: &[u8],
    request: RunControlRequest,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<RunControl, Lab002Error> {
    let run_ordinal = request.run_ordinal;
    let acknowledged_at = request.acknowledged_at;
    let (oracle, oracle_sha256) = verified_artifact_sha256::<LabOracle>(oracle_canonical)?;
    if authorization_public_key(signing_key) != enrollment.authorization_public_key
        || oracle.authorization_public_key != enrollment.authorization_public_key
        || oracle.authorized_target_manifest_sha256 != enrollment.authorized_target_manifest_sha256
        || oracle.build_binding_sha256 != enrollment.build_binding_sha256
        || !matches!(run_ordinal, 1 | 2)
        || (run_ordinal == 1 && request.prior_collection_binding_sha256.is_some())
        || (run_ordinal == 2 && request.prior_collection_binding_sha256.is_none())
        || acknowledged_at <= enrollment.completed_at
    {
        return Err(Lab002Error::InvalidEvidence(
            "run control does not match the closed enrollment and oracle",
        ));
    }

    let acknowledgement = acknowledgement(
        request.assertions,
        AcknowledgementInput {
            acknowledgement_id: random_digest(rng),
            experiment_id: enrollment.experiment_id.clone(),
            operation: AuthorizedOperation::CollectFixedRangeRun,
            build_binding_sha256: enrollment.build_binding_sha256.clone(),
            authorized_target_manifest_sha256: enrollment.authorized_target_manifest_sha256.clone(),
            run_ordinal: Some(run_ordinal),
            authorized_actions: vec![
                AuthorizedAction::ImportCollectionChallenge,
                AuthorizedAction::StartCleanRun,
                AuthorizedAction::ObserveMainApp,
                AuthorizedAction::ObserveFramework,
                AuthorizedAction::InvokeShareExtension,
                AuthorizedAction::ExportSessionEvidence,
                AuthorizedAction::ConfirmExportReceived,
                AuthorizedAction::CleanupReportSubtree,
            ],
            device_selection_nonce: random_digest(rng),
            expected_environment: None,
            expected_enrollment_binding_sha256: Some(
                enrollment.device_enrollment_binding_sha256.clone(),
            ),
            acknowledged_at,
        },
    )?;
    let counter = format!("{run_ordinal:016x}");
    let core = CollectionChallengeCore {
        schema: CollectionChallengeCore::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        operation: AuthorizedOperation::CollectFixedRangeRun,
        challenge: random_digest(rng),
        collection_id: random_digest(rng),
        run_ordinal,
        expected_run_counter: counter.clone(),
        build_binding_sha256: enrollment.build_binding_sha256.clone(),
        authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
        expected_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
        enrollment_public_key: enrollment.enrollment_public_key.clone(),
        expected_device_installation_binding_sha256: enrollment
            .device_installation_binding_sha256
            .clone(),
        not_before: acknowledged_at,
        not_after: not_after(acknowledged_at)?,
    };
    let envelope = sign_authorized_operation(signing_key, &acknowledgement, &core)?;
    let acknowledgement_canonical = acknowledgement.to_canonical_bytes()?;
    let envelope_canonical = envelope.to_canonical_bytes()?;
    let envelope_sha256 = sha256_hex(&envelope_canonical);
    let intent = CollectionIntent {
        schema: CollectionIntent::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        challenge_file_sha256: envelope_sha256.clone(),
        collection_id: core.collection_id,
        run_ordinal,
        expected_run_counter: counter,
        prior_collection_binding_sha256: request.prior_collection_binding_sha256,
        not_before: acknowledged_at,
        not_after: not_after(acknowledged_at)?,
        source_commit: oracle.source_commit,
        marketing_version: oracle.marketing_version,
        build_number: oracle.build_number,
        observer_revision: oracle.observer_revision,
        build_binding_sha256: enrollment.build_binding_sha256.clone(),
        installation_acknowledgement_sha256: enrollment.installation_acknowledgement_sha256.clone(),
        device_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
        run_acknowledgement_sha256: sha256_hex(&acknowledgement_canonical),
        authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
        authorization_envelope_signature: envelope.signature,
        authorization_envelope_sha256: envelope_sha256.clone(),
        authorized_target_manifest_sha256: enrollment.authorized_target_manifest_sha256.clone(),
        expected_target_identity_set_sha256: oracle.target_identity_set_sha256,
        enrollment_public_key: enrollment.enrollment_public_key.clone(),
        expected_device_installation_binding_sha256: enrollment
            .device_installation_binding_sha256
            .clone(),
        toolchain: oracle.toolchain,
        preupload_evidence_sha256: request.preupload_evidence_sha256,
        ipa_sha256: oracle.ipa_sha256,
        oracle_sha256,
        expected_inventory_sha256: expected_inventory_sha256(&LabOracle::from_canonical_bytes(
            oracle_canonical,
        )?)?,
    }
    .to_canonical_bytes()?;
    Ok(RunControl {
        acknowledgement: acknowledgement_canonical,
        authorization_envelope: envelope_canonical,
        collection_intent: intent,
    })
}

fn entry<T: ClosedArtifact>(
    export: &super::artifacts::UnsignedSessionExport,
    index: usize,
    expected: LogicalFilename,
) -> Result<(T, String), Lab002Error> {
    let value = export
        .entries
        .get(index)
        .ok_or(Lab002Error::InvalidEvidence(
            "signed export entry is missing",
        ))?;
    if value.logical_filename != expected
        || value.sha256 != sha256_hex(value.canonical_document.as_bytes())
    {
        return Err(Lab002Error::InvalidEvidence(
            "signed export entry identity is invalid",
        ));
    }
    Ok((
        T::from_canonical_bytes(value.canonical_document.as_bytes())?,
        value.sha256.clone(),
    ))
}

pub fn close_run(
    enrollment: &VerifiedEnrollment,
    run_acknowledgement: &[u8],
    authorization_envelope: &[u8],
    collection_intent: &[u8],
    signed_session_export: &[u8],
    completed_at: i64,
) -> Result<(RunClosure, VerifiedRun), Lab002Error> {
    let (acknowledgement, acknowledgement_sha256) =
        verified_artifact_sha256::<AuthorizationAcknowledgement>(run_acknowledgement)?;
    let (envelope, envelope_sha256) =
        verified_artifact_sha256::<AuthorizedOperationEnvelope>(authorization_envelope)?;
    let (_, core) = verify_authorized_operation::<
        AuthorizationAcknowledgement,
        CollectionChallengeCore,
    >(&envelope, &enrollment.authorization_public_key)?;
    let (intent, intent_sha256) = verified_artifact_sha256::<CollectionIntent>(collection_intent)?;
    let (signed_export, signed_export_sha256) =
        verified_artifact_sha256::<SignedSessionExport>(signed_session_export)?;
    let export = verify_session_export(&signed_export, &enrollment.enrollment_public_key)?;
    let (session, session_sha256) = entry::<SessionReport>(&export, 0, LogicalFilename::Session)?;
    let (_, main_app_sha256) = entry::<RoleReport>(&export, 1, LogicalFilename::MainApp)?;
    let (_, framework_sha256) = entry::<RoleReport>(&export, 2, LogicalFilename::Framework)?;
    let (_, share_extension_sha256) =
        entry::<RoleReport>(&export, 3, LogicalFilename::ShareExtension)?;
    let binding = CollectionBinding {
        schema: CollectionBinding::SCHEMA.into(),
        profile: LAB002_PROFILE.into(),
        installation_acknowledgement_sha256: enrollment.installation_acknowledgement_sha256.clone(),
        run_acknowledgement_sha256: acknowledgement_sha256,
        authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
        intent_sha256,
        device_enrollment_binding_sha256: enrollment.device_enrollment_binding_sha256.clone(),
        authorization_envelope_signature: envelope.signature,
        authorization_envelope_sha256: envelope_sha256.clone(),
        challenge_file_sha256: envelope_sha256,
        signed_session_export_sha256: signed_export_sha256,
        collection_id: session.collection_id.clone(),
        run_ordinal: session.run_ordinal,
        signed_run_counter: core.expected_run_counter,
        collected_run_counter: session.run_counter.clone(),
        session_id: session.session_id,
        enrollment_public_key: enrollment.enrollment_public_key.clone(),
        device_installation_binding_sha256: enrollment.device_installation_binding_sha256.clone(),
        environment: session.environment,
        session_sha256,
        role_file_hashes: RoleFileHashes {
            main_app_sha256,
            framework_sha256,
            share_extension_sha256,
        },
        completed_at,
    }
    .to_canonical_bytes()?;
    let verified = verify_run_chain(
        enrollment,
        RunArtifactBytes {
            run_acknowledgement,
            authorization_envelope,
            collection_intent,
            signed_session_export,
            collection_binding: &binding,
        },
    )?;
    if acknowledgement.run_ordinal != Some(verified.run_ordinal)
        || intent.run_ordinal != verified.run_ordinal
    {
        return Err(Lab002Error::InvalidEvidence(
            "run closure ordinal is inconsistent",
        ));
    }
    Ok((
        RunClosure {
            collection_binding: binding,
        },
        verified,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab002::artifacts::{
        AuthorizedTarget, OracleRole, OracleSlice, Presence, RequiredAppGroups,
        RequiredEntitlement, Toolchain, UnsignedEnrollmentReceipt,
    };
    use crate::lab002::{LabRole, host::sign_enrollment_receipt};
    use rand_core::Error as RngError;

    struct TestRng(u8);

    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            let mut bytes = [0_u8; 4];
            self.fill_bytes(&mut bytes);
            u32::from_le_bytes(bytes)
        }

        fn next_u64(&mut self) -> u64 {
            let mut bytes = [0_u8; 8];
            self.fill_bytes(&mut bytes);
            u64::from_le_bytes(bytes)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for TestRng {}

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

    fn assertions() -> AuthorizationAssertions {
        AuthorizationAssertions {
            confirmed: true,
            owns_or_explicitly_authorized_target: true,
            within_authorized_scope: true,
            understands_legal_limits: true,
            will_protect_output_and_not_resign_install_or_redistribute: true,
        }
    }

    fn absent_entitlement() -> RequiredEntitlement {
        RequiredEntitlement {
            presence: Presence::RequiredAbsent,
            value: None,
        }
    }

    fn target(role: LabRole, bundle_id: &str) -> AuthorizedTarget {
        AuthorizedTarget {
            role,
            bundle_id: bundle_id.into(),
            code_directory_identifier: bundle_id.into(),
            code_directory_team_identifier: "TEAMTEST01".into(),
            application_identifier: absent_entitlement(),
            developer_team_identifier: absent_entitlement(),
            application_groups: RequiredAppGroups {
                presence: Presence::RequiredAbsent,
                values: None,
            },
        }
    }

    fn manifest(host_key: &SigningKey) -> Vec<u8> {
        AuthorizedTargetManifest {
            schema: AuthorizedTargetManifest::SCHEMA.into(),
            profile: LAB002_PROFILE.into(),
            identity_nonce: digest(0x40),
            authorization_public_key: authorization_public_key(host_key),
            authorization_key_id: sha256_hex(host_key.verifying_key().as_bytes()),
            targets: vec![
                target(LabRole::MainApp, "com.orchardprobe.demolab"),
                target(LabRole::Framework, "com.orchardprobe.demolab.framework"),
                target(LabRole::ShareExtension, "com.orchardprobe.demolab.share"),
            ],
        }
        .to_canonical_bytes()
        .unwrap()
    }

    fn toolchain() -> Toolchain {
        Toolchain {
            xcode_version: "26.0".into(),
            xcode_build: "17A100".into(),
            iphoneos_sdk_version: "26.0".into(),
            iphoneos_sdk_build: "23A100".into(),
            xcodegen_version: "2.44.1".into(),
            xcodegen_architecture: "arm64".into(),
            xcodegen_executable_sha256: digest(0x41),
            fastlane_version: "2.228.0".into(),
            gemfile_lock_sha256: digest(0x42),
        }
    }

    fn oracle(
        host_key: &SigningKey,
        manifest_sha256: &str,
        build_binding_sha256: &str,
    ) -> LabOracle {
        let roles = LabRole::ALL
            .into_iter()
            .enumerate()
            .map(|(index, role)| OracleRole {
                role,
                fixture_relative_path: role.fixture_relative_path().into(),
                target_identity_binding_sha256: digest(0x50 + index as u8),
                slices: vec![OracleSlice {
                    ordinal: 0,
                    cpu_type: 16_777_228,
                    cpu_subtype: 0,
                    macho_uuid: "00112233445566778899aabbccddeeff".into(),
                    code_signature_sha256: digest(0x60 + index as u8),
                    slice_file_offset: 0,
                    slice_file_size: 4_096,
                    archive_cryptid: 0,
                    ipa_cryptid: 0,
                    section_slice_offset: 512,
                    section_file_offset: 512,
                    section_vm_offset: 512,
                    section_length: 256,
                    expected_plaintext_sha256: digest(0x70 + index as u8),
                    ipa_section_sha256: digest(0x70 + index as u8),
                }],
            })
            .collect();
        LabOracle {
            schema: LabOracle::SCHEMA.into(),
            profile: LAB002_PROFILE.into(),
            source_commit: "11".repeat(20),
            fixture_source_root: "fixtures/DemoLab".into(),
            marketing_version: "1.0".into(),
            build_number: "3".into(),
            configuration: "Release".into(),
            observer_revision: "lab002-observer-v1".into(),
            generator_revision: "11".repeat(20),
            build_binding_sha256: build_binding_sha256.into(),
            authorized_target_manifest_sha256: manifest_sha256.into(),
            authorization_public_key: authorization_public_key(host_key),
            authorization_key_id: sha256_hex(host_key.verifying_key().as_bytes()),
            target_identity_set_sha256: digest(0x43),
            toolchain: toolchain(),
            ipa_size: 4_096,
            ipa_sha256: digest(0x44),
            roles,
        }
    }

    fn closed_enrollment() -> (
        SigningKey,
        Vec<u8>,
        InstallationControl,
        Vec<u8>,
        VerifiedEnrollment,
    ) {
        let host_key = SigningKey::from_bytes(&[0x81; 32]);
        let enrollment_key = SigningKey::from_bytes(&[0x82; 32]);
        let manifest = manifest(&host_key);
        let build_binding = digest(0x45);
        let control = create_installation_control(
            &host_key,
            &manifest,
            &build_binding,
            environment(),
            assertions(),
            1_000,
            &mut TestRng(1),
        )
        .unwrap();
        let acknowledgement =
            AuthorizationAcknowledgement::from_canonical_bytes(&control.acknowledgement).unwrap();
        let envelope =
            AuthorizedOperationEnvelope::from_canonical_bytes(&control.authorization_envelope)
                .unwrap();
        let (_, core) = verify_authorized_operation::<
            AuthorizationAcknowledgement,
            super::super::artifacts::InstallationEnrollmentCore,
        >(&envelope, &authorization_public_key(&host_key))
        .unwrap();
        let enrollment_public_key = authorization_public_key(&enrollment_key);
        let receipt = sign_enrollment_receipt(
            &enrollment_key,
            &UnsignedEnrollmentReceipt {
                schema: UnsignedEnrollmentReceipt::SCHEMA.into(),
                profile: LAB002_PROFILE.into(),
                authorization_envelope_sha256: sha256_hex(&control.authorization_envelope),
                acknowledgement_sha256: sha256_hex(&control.acknowledgement),
                authorization_policy_version: AUTHORIZATION_POLICY_VERSION.into(),
                enrollment_challenge_response: core.enrollment_challenge,
                experiment_id: acknowledgement.experiment_id,
                build_binding_sha256: build_binding,
                enrollment_public_key: enrollment_public_key.clone(),
                device_installation_binding_sha256: digest(0x46),
                environment: environment(),
                created_at: 1_100,
            },
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
        let fingerprint = device_selection_fingerprint_sha256(
            &sha256_hex(&control.authorization_envelope),
            &enrollment_public_key,
            &digest(0x46),
            &core.device_selection_nonce,
        )
        .unwrap();
        let (_, verified) = close_enrollment(
            &manifest,
            &control.acknowledgement,
            &control.authorization_envelope,
            &receipt,
            &fingerprint,
            1_200,
        )
        .unwrap();
        (host_key, manifest, control, receipt, verified)
    }

    #[test]
    fn installation_control_and_receipt_close_one_exact_enrollment() {
        let (_, manifest, control, receipt, verified) = closed_enrollment();
        assert_eq!(
            verified.authorized_target_manifest_sha256,
            sha256_hex(&manifest)
        );
        assert_eq!(
            verified.installation_acknowledgement_sha256,
            sha256_hex(&control.acknowledgement)
        );
        assert_eq!(
            verified.signed_enrollment_receipt_sha256,
            sha256_hex(&receipt)
        );
        assert_eq!(verified.completed_at, 1_200);
    }

    #[test]
    fn authoring_rejects_missing_consent_and_short_fingerprint() {
        let host_key = SigningKey::from_bytes(&[0x81; 32]);
        let mut denied = assertions();
        denied.understands_legal_limits = false;
        assert!(
            create_installation_control(
                &host_key,
                &manifest(&host_key),
                &digest(0x45),
                environment(),
                denied,
                1_000,
                &mut TestRng(1),
            )
            .is_err()
        );

        let (_, manifest, control, receipt, _) = closed_enrollment();
        assert!(
            close_enrollment(
                &manifest,
                &control.acknowledgement,
                &control.authorization_envelope,
                &receipt,
                "abcd",
                1_200,
            )
            .is_err()
        );
    }

    #[test]
    fn run_control_binds_frozen_source_and_uses_distinct_random_values() {
        let (host_key, manifest, _, _, enrollment) = closed_enrollment();
        let oracle = oracle(&host_key, &sha256_hex(&manifest), &digest(0x45));
        let oracle_canonical = oracle.to_canonical_bytes().unwrap();
        let control = create_run_control(
            &host_key,
            &enrollment,
            &oracle_canonical,
            RunControlRequest {
                preupload_evidence_sha256: digest(0x47),
                run_ordinal: 1,
                prior_collection_binding_sha256: None,
                assertions: assertions(),
                acknowledged_at: 2_000,
            },
            &mut TestRng(9),
        )
        .unwrap();
        let acknowledgement =
            AuthorizationAcknowledgement::from_canonical_bytes(&control.acknowledgement).unwrap();
        let envelope =
            AuthorizedOperationEnvelope::from_canonical_bytes(&control.authorization_envelope)
                .unwrap();
        let (_, core) = verify_authorized_operation::<
            AuthorizationAcknowledgement,
            CollectionChallengeCore,
        >(&envelope, &authorization_public_key(&host_key))
        .unwrap();
        let intent = CollectionIntent::from_canonical_bytes(&control.collection_intent).unwrap();
        assert_eq!(acknowledgement.run_ordinal, Some(1));
        assert_eq!(core.expected_run_counter, "0000000000000001");
        assert_eq!(
            intent.challenge_file_sha256,
            sha256_hex(&control.authorization_envelope)
        );
        assert_eq!(intent.preupload_evidence_sha256, digest(0x47));
        assert_eq!(intent.oracle_sha256, sha256_hex(&oracle_canonical));
        assert_eq!(
            intent.expected_inventory_sha256,
            expected_inventory_sha256(&oracle).unwrap()
        );
        assert_ne!(acknowledgement.acknowledgement_id, core.challenge);
        assert_ne!(core.challenge, core.collection_id);
    }
}
