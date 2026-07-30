import CryptoKit
import Foundation
import XCTest
@testable import DemoLab

final class LAB002ProductionAuthorizationValidatorTests: XCTestCase {
    private let signingKey = try! Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 0x81, count: 32)
    )

    func testValidatesClosedEnrollmentAuthorization() throws {
        let envelope = try makeEnvelope(operation: .enrollment)
        let validator = try LAB002ProductionAuthorizationValidator(
            authorizationPublicKeyHex:
                signingKey.publicKey.rawRepresentation.hexLowercase
        )

        let metadata = try validator.validate(envelope)

        XCTAssertEqual(metadata.kind, .installationEnrollment)
        XCTAssertEqual(metadata.buildBindingSHA256, digest("3"))
        XCTAssertEqual(metadata.notBefore, 1_000)
        XCTAssertEqual(metadata.notAfter, 1_900)
        XCTAssertNil(metadata.expectedRunCounter)
        XCTAssertEqual(
            metadata.enrollmentFacts?.enrollmentChallenge,
            digest("6")
        )
        XCTAssertEqual(
            metadata.enrollmentFacts?.expectedEnvironment,
            try environmentRecord()
        )
    }

    func testValidatesClosedRunAuthorizationAndDerivesExactHashes()
        throws
    {
        let envelope = try makeEnvelope(operation: .run)
        let validator = try LAB002ProductionAuthorizationValidator(
            authorizationPublicKeyHex:
                signingKey.publicKey.rawRepresentation.hexLowercase
        )

        let metadata = try validator.validate(envelope)

        XCTAssertEqual(metadata.kind, .collectionRun)
        XCTAssertEqual(metadata.expectedRunCounter, 1)
        XCTAssertEqual(metadata.runFacts?.runOrdinal, 1)
        XCTAssertEqual(metadata.runFacts?.collectionID, digest("a"))
        XCTAssertEqual(
            metadata.runFacts?.challengeSHA256,
            Data(SHA256.hash(data: envelope)).hexLowercase
        )
        XCTAssertEqual(
            metadata.runFacts?.deviceEnrollmentBindingSHA256,
            digest("f")
        )
    }

    func testRejectsMutationUnknownFieldsAndNonCanonicalJSON() throws {
        let envelope = try makeEnvelope(operation: .run)
        let validator = try LAB002ProductionAuthorizationValidator(
            authorizationPublicKeyHex:
                signingKey.publicKey.rawRepresentation.hexLowercase
        )

        var mutated = envelope
        mutated[mutated.index(before: mutated.endIndex)] ^= 0x01
        XCTAssertThrowsError(try validator.validate(mutated))

        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: envelope)
                as? [String: Any]
        )
        object["unexpected"] = true
        XCTAssertThrowsError(
            try validator.validate(try canonical(object))
        )

        let nonCanonical = Data(
            String(decoding: envelope, as: UTF8.self)
                .replacingOccurrences(
                    of: "{\"acknowledgement_canonical\"",
                    with: "{ \"acknowledgement_canonical\""
                )
                .utf8
        )
        XCTAssertThrowsError(try validator.validate(nonCanonical))

        var floatingInteger = try XCTUnwrap(
            JSONSerialization.jsonObject(with: envelope)
                as? [String: Any]
        )
        let acknowledgement = try XCTUnwrap(
            floatingInteger["acknowledgement_canonical"] as? String
        )
        let floatingAcknowledgement = acknowledgement.replacingOccurrences(
            of: "\"acknowledged_at\":1000",
            with: "\"acknowledged_at\":1000.0"
        )
        XCTAssertNotEqual(floatingAcknowledgement, acknowledgement)
        let operationCore = try XCTUnwrap(
            floatingInteger["operation_core_canonical"] as? String
        )
        var floatingMessage = Data(
            "orchardprobe.demolab.lab002.authorized-operation.v1\0".utf8
        )
        appendFramed(Data(floatingAcknowledgement.utf8), to: &floatingMessage)
        appendFramed(Data(operationCore.utf8), to: &floatingMessage)
        floatingInteger["acknowledgement_canonical"] =
            floatingAcknowledgement
        floatingInteger["signature"] = try signingKey.signature(
            for: floatingMessage
        ).hexLowercase
        XCTAssertThrowsError(
            try validator.validate(try canonical(floatingInteger))
        )
    }

    func testRejectsDifferentPinnedAuthorizationKey() throws {
        let envelope = try makeEnvelope(operation: .enrollment)
        let otherKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: Data(repeating: 0x82, count: 32)
        )
        let validator = try LAB002ProductionAuthorizationValidator(
            authorizationPublicKeyHex:
                otherKey.publicKey.rawRepresentation.hexLowercase
        )

        XCTAssertThrowsError(try validator.validate(envelope))
    }

    func testRejectsEveryWeakPinnedAuthorizationKey() {
        let weakKeys = [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        ]
        for weakKey in weakKeys {
            XCTAssertThrowsError(
                try LAB002ProductionAuthorizationValidator(
                    authorizationPublicKeyHex: weakKey
                )
            )
        }
    }

    private enum Operation {
        case enrollment
        case run
    }

    private func makeEnvelope(operation: Operation) throws -> Data {
        let acknowledgement = try canonical(
            acknowledgementObject(operation: operation)
        )
        let core = try canonical(coreObject(operation: operation))
        var message = Data(
            "orchardprobe.demolab.lab002.authorized-operation.v1\0".utf8
        )
        appendFramed(acknowledgement, to: &message)
        appendFramed(core, to: &message)
        let signature = try signingKey.signature(for: message)
        let publicKey = signingKey.publicKey.rawRepresentation
        return try canonical(
            [
                "acknowledgement_canonical": String(
                    decoding: acknowledgement,
                    as: UTF8.self
                ),
                "authorization_key_id": Data(
                    SHA256.hash(data: publicKey)
                ).hexLowercase,
                "operation_core_canonical": String(
                    decoding: core,
                    as: UTF8.self
                ),
                "profile":
                    "orchardprobe.demolab.lab002.observation.v1",
                "schema":
                    "orchardprobe.lab002.authorized-operation-envelope.v1",
                "signature": signature.hexLowercase,
            ]
        )
    }

    private func acknowledgementObject(
        operation: Operation
    ) throws -> [String: Any] {
        let enrollment = operation == .enrollment
        return [
            "acknowledged_at": 1_000,
            "acknowledgement_id": digest("1"),
            "authorization_policy_version":
                "orchardprobe.authorized-use.v1",
            "authorized_actions": enrollment
                ? [
                    "install_exact_build",
                    "import_installation_enrollment",
                    "confirm_device_enrollment",
                    "export_enrollment_receipt",
                ]
                : [
                    "import_collection_challenge",
                    "start_clean_run",
                    "observe_main_app",
                    "observe_framework",
                    "invoke_share_extension",
                    "export_session_evidence",
                    "confirm_export_received",
                    "cleanup_report_subtree",
                ],
            "authorized_target_manifest_sha256": digest("4"),
            "build_binding_sha256": digest("3"),
            "confirmed": true,
            "data_categories": [
                "authorization_control_metadata",
                "sanitized_device_environment",
                "code_signature_metadata",
                "fixed_range_sha256",
                "closed_outcomes",
            ],
            "device_selection_nonce": digest("5"),
            "expected_enrollment_binding_sha256":
                enrollment ? NSNull() : digest("f"),
            "expected_environment":
                enrollment ? environmentObject() : NSNull(),
            "experiment_id": digest("2"),
            "not_after": 1_900,
            "not_before": 1_000,
            "operation": enrollment
                ? "install_and_enroll_exact_build"
                : "collect_fixed_range_run",
            "owns_or_explicitly_authorized_target": true,
            "profile": "orchardprobe.demolab.lab002.observation.v1",
            "retention_profile": "owner_only_lab002_experiment_v1",
            "run_ordinal": enrollment ? NSNull() : 1,
            "schema": "orchardprobe.lab002.authorized-use-ack.v1",
            "technique_profile":
                "first_party_fixed_range_disk_and_mapped_sha256",
            "understands_legal_limits": true,
            "will_protect_output_and_not_resign_install_or_redistribute":
                true,
            "within_authorized_scope": true,
        ]
    }

    private func coreObject(
        operation: Operation
    ) -> [String: Any] {
        switch operation {
        case .enrollment:
            return [
                "authorization_policy_version":
                    "orchardprobe.authorized-use.v1",
                "authorized_target_manifest_sha256": digest("4"),
                "build_binding_sha256": digest("3"),
                "device_selection_nonce": digest("5"),
                "enrollment_challenge": digest("6"),
                "expected_environment": environmentObject(),
                "experiment_id": digest("2"),
                "not_after": 1_900,
                "not_before": 1_000,
                "operation": "install_and_enroll_exact_build",
                "profile":
                    "orchardprobe.demolab.lab002.observation.v1",
                "schema":
                    "orchardprobe.lab002.installation-enrollment-core.v1",
            ]
        case .run:
            return [
                "authorization_policy_version":
                    "orchardprobe.authorized-use.v1",
                "build_binding_sha256": digest("3"),
                "challenge": digest("9"),
                "collection_id": digest("a"),
                "enrollment_public_key": digest("b"),
                "expected_device_installation_binding_sha256":
                    digest("c"),
                "expected_enrollment_binding_sha256": digest("f"),
                "expected_run_counter": "0000000000000001",
                "not_after": 1_900,
                "not_before": 1_000,
                "operation": "collect_fixed_range_run",
                "profile":
                    "orchardprobe.demolab.lab002.observation.v1",
                "run_ordinal": 1,
                "schema":
                    "orchardprobe.lab002.collection-challenge-core.v1",
            ]
        }
    }

    private func environmentObject() -> [String: String] {
        [
            "hardware_model": "iPhone17,1",
            "ios_build": "22A3354",
            "ios_product_version": "18.0",
        ]
    }

    private func environmentRecord() throws -> LAB002SessionEnvironment {
        try LAB002SessionEnvironment(
            hardwareModel: "iPhone17,1",
            iosProductVersion: "18.0",
            iosBuild: "22A3354"
        )
    }

    private func canonical(_ object: [String: Any]) throws -> Data {
        try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }

    private func appendFramed(_ bytes: Data, to output: inout Data) {
        var count = UInt32(bytes.count).bigEndian
        withUnsafeBytes(of: &count) {
            output.append(contentsOf: $0)
        }
        output.append(bytes)
    }

    private func digest(_ character: Character) -> String {
        String(repeating: String(character), count: 64)
    }
}
