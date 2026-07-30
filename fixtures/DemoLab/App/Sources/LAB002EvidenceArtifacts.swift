import CoreFoundation
import CryptoKit
import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers

enum LAB002EvidenceArtifactError: Error {
    case invalidArtifact
    case oversizedArtifact
    case signingKeyMismatch
    case explicitConfirmationRequired
    case exportNotConstructed
}

struct LAB002ShareArtifact: Equatable {
    enum Kind: Equatable {
        case enrollmentReceipt
        case sessionExport

        var filename: String {
            switch self {
            case .enrollmentReceipt:
                return "device-enrollment-receipt-v1.json"
            case .sessionExport:
                return "lab-002-session-export-v1.json"
            }
        }

        var maximumBytes: Int {
            switch self {
            case .enrollmentReceipt:
                return LAB002Limit.controlDocument
            case .sessionExport:
                return LAB002Limit.signedExport
            }
        }
    }

    let kind: Kind
    let canonicalBytes: Data

    init(kind: Kind, canonicalBytes: Data) throws {
        guard !canonicalBytes.isEmpty,
              canonicalBytes.count <= kind.maximumBytes,
              String(data: canonicalBytes, encoding: .utf8) != nil
        else {
            throw LAB002EvidenceArtifactError.oversizedArtifact
        }
        self.kind = kind
        self.canonicalBytes = canonicalBytes
    }

    var filename: String {
        kind.filename
    }

    func systemShareItemProvider() -> NSItemProvider {
        let provider = NSItemProvider()
        provider.suggestedName = filename
        let bytes = canonicalBytes
        provider.registerDataRepresentation(
            forTypeIdentifier: UTType.json.identifier,
            visibility: .all
        ) { completion in
            completion(bytes, nil)
            return nil
        }
        return provider
    }
}

struct LAB002SystemShareSheet: UIViewControllerRepresentable {
    let artifact: LAB002ShareArtifact

    func makeUIViewController(
        context: Context
    ) -> UIActivityViewController {
        let controller = UIActivityViewController(
            activityItems: [artifact.systemShareItemProvider()],
            applicationActivities: nil
        )
        anchorPopover(controller)
        return controller
    }

    func updateUIViewController(
        _ uiViewController: UIActivityViewController,
        context: Context
    ) {
        anchorPopover(uiViewController)
    }

    private func anchorPopover(_ controller: UIActivityViewController) {
        guard let popover = controller.popoverPresentationController else {
            return
        }
        popover.sourceView = controller.view
        popover.sourceRect = CGRect(
            x: controller.view.bounds.midX,
            y: controller.view.bounds.midY,
            width: 1,
            height: 1
        )
        popover.permittedArrowDirections = []
    }
}

struct LAB002EnrollmentCompletion {
    let state: LAB002InstallationState
    let receipt: LAB002ShareArtifact
    let deviceSelectionFingerprintSHA256: String
}

struct LAB002RecoveredEnrollmentReceipt {
    let artifact: LAB002ShareArtifact
    let authorizationEnvelope: Data
    let authorizationEnvelopeSHA256: String
    let deviceSelectionFingerprintSHA256: String
    let deviceInstallationBindingSHA256: String
    let receiptCreatedAt: Int64
}

struct LAB002ConstructedSessionExport {
    let snapshot: LAB002CompletedSessionSnapshot
    let artifact: LAB002ShareArtifact
}

protocol LAB002SessionEvidenceStoring {
    func complete(
        at completedAt: Int64
    ) throws -> LAB002SessionCompletionOutcome
    func completedSnapshot() throws -> LAB002CompletedSessionSnapshot
    func cleanup(
        expectedSnapshot: LAB002CompletedSessionSnapshot
    ) throws -> LAB002CleanupOutcome
}

struct LAB002ProductionSessionEvidenceStore: LAB002SessionEvidenceStoring {
    func complete(
        at completedAt: Int64
    ) throws -> LAB002SessionCompletionOutcome {
        try LAB002RoleReportSessionCompleter.complete(
            fixedBundle: .main,
            completedAt: completedAt
        )
    }

    func completedSnapshot() throws -> LAB002CompletedSessionSnapshot {
        try LAB002RoleReportEvidenceStore.completedSnapshot(
            fixedBundle: .main
        )
    }

    func cleanup(
        expectedSnapshot: LAB002CompletedSessionSnapshot
    ) throws -> LAB002CleanupOutcome {
        try LAB002RoleReportEvidenceStore.cleanupCompletedSession(
            fixedBundle: .main,
            expectedSnapshot: expectedSnapshot
        )
    }
}

#if DEBUG
struct LAB002TestSessionEvidenceStore: LAB002SessionEvidenceStoring {
    let containerURL: URL

    func complete(
        at completedAt: Int64
    ) throws -> LAB002SessionCompletionOutcome {
        try LAB002RoleReportTestHarness.completeSession(
            testContainerURL: containerURL,
            completedAt: completedAt
        )
    }

    func completedSnapshot() throws -> LAB002CompletedSessionSnapshot {
        try LAB002RoleReportTestHarness.completedSnapshot(
            testContainerURL: containerURL
        )
    }

    func cleanup(
        expectedSnapshot: LAB002CompletedSessionSnapshot
    ) throws -> LAB002CleanupOutcome {
        try LAB002RoleReportTestHarness.cleanupCompletedSession(
            testContainerURL: containerURL,
            expectedSnapshot: expectedSnapshot
        )
    }
}
#endif

enum LAB002EvidenceArtifactBuilder {
    private static let enrollmentReceiptDomain = Data(
        "orchardprobe.demolab.lab002.enrollment-receipt.v1\0".utf8
    )
    private static let sessionExportDomain = Data(
        "orchardprobe.demolab.lab002.session-export.v1\0".utf8
    )
    private static let deviceSelectionDomain = Data(
        "orchardprobe.demolab.lab002.device-selection.v1\0".utf8
    )

    static func enrollmentReceipt(
        authorizationEnvelope: Data,
        facts: LAB002VerifiedEnrollmentFacts,
        continuity: LAB002EnrollmentContinuity,
        deviceInstallationBindingSHA256: String,
        environment: LAB002SessionEnvironment,
        createdAt: Int64
    ) throws -> (
        artifact: LAB002ShareArtifact,
        deviceSelectionFingerprintSHA256: String
    ) {
        let enrollmentPublicKey =
            continuity.signingKey.publicKeyRaw.hexLowercase
        guard continuity.signingKey.publicKeyRaw.count == 32,
              continuity.state.enrollmentPublicKey == enrollmentPublicKey,
              environment == facts.expectedEnvironment,
              [
                  facts.acknowledgementSHA256,
                  facts.enrollmentChallenge,
                  facts.experimentID,
                  facts.deviceSelectionNonce,
              ].allSatisfy({ isLowerHex($0, count: 64) }),
              facts.authorizationPolicyVersion
                == LAB002SessionReport.policy,
              isLowerHex(deviceInstallationBindingSHA256, count: 64),
              createdAt >= 0
        else {
            throw LAB002EvidenceArtifactError.signingKeyMismatch
        }
        let envelopeSHA256 = sha256Hex(authorizationEnvelope)
        let unsigned = try canonical(
            [
                "acknowledgement_sha256": facts.acknowledgementSHA256,
                "authorization_envelope_sha256": envelopeSHA256,
                "authorization_policy_version":
                    facts.authorizationPolicyVersion,
                "build_binding_sha256":
                    continuity.state.buildBindingSHA256,
                "created_at": createdAt,
                "device_installation_binding_sha256":
                    deviceInstallationBindingSHA256,
                "enrollment_challenge_response":
                    facts.enrollmentChallenge,
                "enrollment_public_key": enrollmentPublicKey,
                "environment": environment.jsonObject,
                "experiment_id": facts.experimentID,
                "profile": LAB002SessionReport.profile,
                "schema":
                    "orchardprobe.lab002.device-enrollment-receipt-core.v1",
            ],
            maximum: LAB002Limit.controlDocument
        )
        let signature = try continuity.signingKey.signature(
            for: framed(
                domain: enrollmentReceiptDomain,
                canonicalBytes: unsigned
            )
        )
        guard signature.count == 64,
              let unsignedText = String(data: unsigned, encoding: .utf8)
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        let signed = try canonical(
            [
                "enrollment_public_key": enrollmentPublicKey,
                "profile": LAB002SessionReport.profile,
                "schema":
                    "orchardprobe.lab002.device-enrollment-receipt.v1",
                "signature": signature.hexLowercase,
                "unsigned_receipt_canonical": unsignedText,
            ],
            maximum: LAB002Limit.controlDocument
        )
        let fingerprint = try deviceSelectionFingerprint(
            authorizationEnvelopeSHA256: envelopeSHA256,
            enrollmentPublicKey: enrollmentPublicKey,
            deviceInstallationBindingSHA256:
                deviceInstallationBindingSHA256,
            deviceSelectionNonce: facts.deviceSelectionNonce
        )
        return (
            try LAB002ShareArtifact(
                kind: .enrollmentReceipt,
                canonicalBytes: signed
            ),
            fingerprint
        )
    }

    static func enrollmentReceiptRecoveryRecord(
        artifact: LAB002ShareArtifact,
        authorizationEnvelope: Data,
        deviceSelectionFingerprintSHA256: String
    ) throws -> Data {
        guard artifact.kind == .enrollmentReceipt,
              !authorizationEnvelope.isEmpty,
              authorizationEnvelope.count <= LAB002Limit.controlDocument,
              let authorizationText = String(
                  data: authorizationEnvelope,
                  encoding: .utf8
              ),
              isLowerHex(deviceSelectionFingerprintSHA256, count: 64),
              let receiptText = String(
                  data: artifact.canonicalBytes,
                  encoding: .utf8
              )
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        return try canonical(
            [
                "authorization_envelope_canonical": authorizationText,
                "device_selection_fingerprint_sha256":
                    deviceSelectionFingerprintSHA256,
                "receipt_canonical": receiptText,
                "schema":
                    "orchardprobe.lab002.enrollment-receipt-recovery.v1",
            ],
            maximum: LAB002Limit.enrollmentRecovery
        )
    }

    static func recoverEnrollmentReceipt(
        recoveryRecordBytes: Data,
        expectedState: LAB002InstallationState,
        authorizationMetadata: LAB002AuthorizationMetadata,
        expectedDeviceInstallationBindingSHA256: String,
        expectedEnvironment: LAB002SessionEnvironment
    ) throws -> LAB002RecoveredEnrollmentReceipt {
        let recovery = try enrollmentRecoveryFields(recoveryRecordBytes)
        guard authorizationMetadata.kind == .installationEnrollment,
              authorizationMetadata.expectedRunCounter == nil,
              authorizationMetadata.buildBindingSHA256
                == expectedState.buildBindingSHA256,
              let facts = authorizationMetadata.enrollmentFacts,
              expectedEnvironment == facts.expectedEnvironment,
              isLowerHex(
                  expectedDeviceInstallationBindingSHA256,
                  count: 64
              ),
              let signed = try JSONSerialization.jsonObject(
                  with: recovery.receiptCanonical,
                  options: []
              ) as? [String: Any],
              signed.count == 5,
              signed["schema"] as? String
                == "orchardprobe.lab002.device-enrollment-receipt.v1",
              signed["profile"] as? String == LAB002SessionReport.profile,
              let publicKeyHex = signed["enrollment_public_key"] as? String,
              publicKeyHex == expectedState.enrollmentPublicKey,
              let signatureHex = signed["signature"] as? String,
              let unsignedText =
                signed["unsigned_receipt_canonical"] as? String,
              let unsignedBytes = unsignedText.data(using: .utf8),
              try canonical(
                  signed,
                  maximum: LAB002Limit.controlDocument
              ) == recovery.receiptCanonical,
              let unsigned = try JSONSerialization.jsonObject(
                  with: unsignedBytes,
                  options: []
              ) as? [String: Any],
              unsigned.count == 12,
              unsigned["schema"] as? String
                == "orchardprobe.lab002.device-enrollment-receipt-core.v1",
              unsigned["profile"] as? String == LAB002SessionReport.profile,
              unsigned["authorization_policy_version"] as? String
                == facts.authorizationPolicyVersion,
              unsigned["build_binding_sha256"] as? String
                == expectedState.buildBindingSHA256,
              unsigned["enrollment_public_key"] as? String == publicKeyHex,
              unsigned["acknowledgement_sha256"] as? String
                == facts.acknowledgementSHA256,
              unsigned["enrollment_challenge_response"] as? String
                == facts.enrollmentChallenge,
              unsigned["experiment_id"] as? String == facts.experimentID,
              let createdAt = integer(unsigned["created_at"]),
              createdAt >= authorizationMetadata.notBefore,
              createdAt <= authorizationMetadata.notAfter,
              let receiptEnvironment = sessionEnvironment(
                  unsigned["environment"]
              ),
              receiptEnvironment == expectedEnvironment,
              let authorizationEnvelopeSHA256 =
                unsigned["authorization_envelope_sha256"] as? String,
              isLowerHex(authorizationEnvelopeSHA256, count: 64),
              Data(
                  SHA256.hash(data: recovery.authorizationEnvelope)
              ).hexLowercase
                == authorizationEnvelopeSHA256,
              let deviceInstallationBindingSHA256 =
                unsigned["device_installation_binding_sha256"] as? String,
              deviceInstallationBindingSHA256
                == expectedDeviceInstallationBindingSHA256,
              try canonical(
                  unsigned,
                  maximum: LAB002Limit.controlDocument
              ) == unsignedBytes,
              isLowerHex(signatureHex, count: 128),
              let publicKeyBytes = decodeHex(publicKeyHex),
              let signature = decodeHex(signatureHex),
              publicKeyBytes.count == 32,
              signature.count == 64
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        let publicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: publicKeyBytes
        )
        guard publicKey.isValidSignature(
            signature,
            for: try framed(
                domain: enrollmentReceiptDomain,
                canonicalBytes: unsignedBytes
            )
        ) else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        let expectedFingerprint = try deviceSelectionFingerprint(
            authorizationEnvelopeSHA256: authorizationEnvelopeSHA256,
            enrollmentPublicKey: publicKeyHex,
            deviceInstallationBindingSHA256:
                deviceInstallationBindingSHA256,
            deviceSelectionNonce: facts.deviceSelectionNonce
        )
        guard expectedFingerprint
                == recovery.deviceSelectionFingerprintSHA256
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        return try LAB002RecoveredEnrollmentReceipt(
            artifact: LAB002ShareArtifact(
                kind: .enrollmentReceipt,
                canonicalBytes: recovery.receiptCanonical
            ),
            authorizationEnvelope: recovery.authorizationEnvelope,
            authorizationEnvelopeSHA256: authorizationEnvelopeSHA256,
            deviceSelectionFingerprintSHA256:
                recovery.deviceSelectionFingerprintSHA256,
            deviceInstallationBindingSHA256:
                deviceInstallationBindingSHA256,
            receiptCreatedAt: createdAt
        )
    }

    static func enrollmentAuthorizationEnvelope(
        recoveryRecordBytes: Data
    ) throws -> Data {
        try enrollmentRecoveryFields(recoveryRecordBytes)
            .authorizationEnvelope
    }

    static func sessionExport(
        snapshot: LAB002CompletedSessionSnapshot,
        signingKey: any LAB002EnrollmentSigningKey
    ) throws -> LAB002ConstructedSessionExport {
        let publicKey = signingKey.publicKeyRaw.hexLowercase
        guard signingKey.publicKeyRaw.count == 32,
              publicKey == snapshot.enrollmentPublicKey,
              [
                  snapshot.collectionID,
                  snapshot.sessionID,
                  snapshot.challengeSHA256,
                  snapshot.buildBindingSHA256,
                  snapshot.enrollmentPublicKey,
                  snapshot.deviceInstallationBindingSHA256,
              ].allSatisfy({ isLowerHex($0, count: 64) }),
              snapshot.runOrdinal == 1 || snapshot.runOrdinal == 2,
              snapshot.runCounter == String(
                  format: "%016llx",
                  UInt64(snapshot.runOrdinal)
              )
        else {
            throw LAB002EvidenceArtifactError.signingKeyMismatch
        }
        let expectedNames = [
            LAB002FixedName.session,
            LAB002FixedName.mainAppReport,
            LAB002FixedName.frameworkReport,
            LAB002FixedName.shareExtensionReport,
        ]
        guard snapshot.documents.count == expectedNames.count,
              snapshot.documents.map(\.logicalFilename) == expectedNames
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        var entries = [[String: Any]]()
        for (index, document) in snapshot.documents.enumerated() {
            let maximum = index == 0
                ? LAB002Limit.sessionReport
                : LAB002Limit.roleReport
            guard document.canonicalBytes.count <= maximum,
                  let text = String(
                      data: document.canonicalBytes,
                      encoding: .utf8
                  ),
                  try isCanonicalJSONObject(document.canonicalBytes)
            else {
                throw LAB002EvidenceArtifactError.oversizedArtifact
            }
            entries.append([
                "canonical_document": text,
                "logical_filename": document.logicalFilename,
                "sha256": sha256Hex(document.canonicalBytes),
            ])
        }
        let unsigned = try canonical(
            [
                "build_binding_sha256": snapshot.buildBindingSHA256,
                "challenge_sha256": snapshot.challengeSHA256,
                "collection_id": snapshot.collectionID,
                "device_installation_binding_sha256":
                    snapshot.deviceInstallationBindingSHA256,
                "enrollment_public_key": snapshot.enrollmentPublicKey,
                "entries": entries,
                "profile": LAB002SessionReport.profile,
                "run_counter": snapshot.runCounter,
                "run_ordinal": Int64(snapshot.runOrdinal),
                "schema": "orchardprobe.lab002.session-export-core.v1",
                "session_id": snapshot.sessionID,
            ],
            maximum: 256 * 1024
        )
        let signature = try signingKey.signature(
            for: framed(
                domain: sessionExportDomain,
                canonicalBytes: unsigned
            )
        )
        guard signature.count == 64,
              let unsignedText = String(data: unsigned, encoding: .utf8)
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        let signed = try canonical(
            [
                "enrollment_public_key": snapshot.enrollmentPublicKey,
                "profile": LAB002SessionReport.profile,
                "schema": "orchardprobe.lab002.session-export.v1",
                "signature": signature.hexLowercase,
                "unsigned_export_canonical": unsignedText,
            ],
            maximum: LAB002Limit.signedExport
        )
        return LAB002ConstructedSessionExport(
            snapshot: snapshot,
            artifact: try LAB002ShareArtifact(
                kind: .sessionExport,
                canonicalBytes: signed
            )
        )
    }

    static func deviceSelectionFingerprint(
        authorizationEnvelopeSHA256: String,
        enrollmentPublicKey: String,
        deviceInstallationBindingSHA256: String,
        deviceSelectionNonce: String
    ) throws -> String {
        var message = deviceSelectionDomain
        for value in [
            authorizationEnvelopeSHA256,
            enrollmentPublicKey,
            deviceInstallationBindingSHA256,
            deviceSelectionNonce,
        ] {
            guard let bytes = decodeLowerHex(value), bytes.count == 32 else {
                throw LAB002EvidenceArtifactError.invalidArtifact
            }
            message.append(bytes)
        }
        return sha256Hex(message)
    }

    private static func framed(
        domain: Data,
        canonicalBytes: Data
    ) throws -> Data {
        guard let length = UInt32(exactly: canonicalBytes.count) else {
            throw LAB002EvidenceArtifactError.oversizedArtifact
        }
        var result = domain
        var bigEndianLength = length.bigEndian
        withUnsafeBytes(of: &bigEndianLength) {
            result.append(contentsOf: $0)
        }
        result.append(canonicalBytes)
        return result
    }

    private static func canonical(
        _ object: [String: Any],
        maximum: Int
    ) throws -> Data {
        guard JSONSerialization.isValidJSONObject(object) else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        let bytes = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard !bytes.isEmpty, bytes.count <= maximum else {
            throw LAB002EvidenceArtifactError.oversizedArtifact
        }
        return bytes
    }

    private static func enrollmentRecoveryFields(
        _ bytes: Data
    ) throws -> (
        authorizationEnvelope: Data,
        receiptCanonical: Data,
        deviceSelectionFingerprintSHA256: String
    ) {
        guard bytes.count <= LAB002Limit.enrollmentRecovery,
              let recovery = try JSONSerialization.jsonObject(
                  with: bytes,
                  options: []
              ) as? [String: Any],
              recovery.count == 4,
              recovery["schema"] as? String
                == "orchardprobe.lab002.enrollment-receipt-recovery.v1",
              let receiptText = recovery["receipt_canonical"] as? String,
              let receiptCanonical = receiptText.data(using: .utf8),
              !receiptCanonical.isEmpty,
              receiptCanonical.count <= LAB002Limit.controlDocument,
              let authorizationText =
                recovery["authorization_envelope_canonical"] as? String,
              let authorizationEnvelope = authorizationText.data(using: .utf8),
              !authorizationEnvelope.isEmpty,
              authorizationEnvelope.count <= LAB002Limit.controlDocument,
              let deviceSelectionFingerprintSHA256 =
                recovery["device_selection_fingerprint_sha256"] as? String,
              isLowerHex(deviceSelectionFingerprintSHA256, count: 64),
              try canonical(
                  recovery,
                  maximum: LAB002Limit.enrollmentRecovery
              ) == bytes
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        return (
            authorizationEnvelope,
            receiptCanonical,
            deviceSelectionFingerprintSHA256
        )
    }

    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              !CFNumberIsFloatType(number)
        else {
            return nil
        }
        let integer = number.int64Value
        return NSNumber(value: integer) == number ? integer : nil
    }

    private static func sessionEnvironment(
        _ value: Any?
    ) -> LAB002SessionEnvironment? {
        guard let object = value as? [String: Any],
              Set(object.keys) == [
                  "hardware_model",
                  "ios_build",
                  "ios_product_version",
              ],
              let hardwareModel = object["hardware_model"] as? String,
              let iosBuild = object["ios_build"] as? String,
              let iosProductVersion =
                object["ios_product_version"] as? String
        else {
            return nil
        }
        return try? LAB002SessionEnvironment(
            hardwareModel: hardwareModel,
            iosProductVersion: iosProductVersion,
            iosBuild: iosBuild
        )
    }

    private static func isCanonicalJSONObject(_ bytes: Data) throws -> Bool {
        let object = try JSONSerialization.jsonObject(with: bytes)
        guard JSONSerialization.isValidJSONObject(object) else {
            return false
        }
        return try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        ) == bytes
    }

    private static func sha256Hex(_ bytes: Data) -> String {
        Data(SHA256.hash(data: bytes)).hexLowercase
    }

    private static func isLowerHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count
            && value.utf8.allSatisfy {
                (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
            }
    }

    private static func decodeLowerHex(_ value: String) -> Data? {
        guard isLowerHex(value, count: 64) else { return nil }
        var result = Data()
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                return nil
            }
            result.append(byte)
            index = next
        }
        return result
    }

    private static func decodeHex(_ value: String) -> Data? {
        guard value.utf8.count % 2 == 0 else { return nil }
        var result = Data()
        var index = value.startIndex
        while index < value.endIndex {
            let next = value.index(index, offsetBy: 2)
            guard let byte = UInt8(value[index..<next], radix: 16) else {
                return nil
            }
            result.append(byte)
            index = next
        }
        return result
    }
}
