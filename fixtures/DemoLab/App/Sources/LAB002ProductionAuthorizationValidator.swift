import CoreFoundation
import CryptoKit
import Foundation

enum LAB002AuthorizationValidationError: Error {
    case invalidConfiguration
    case invalidEnvelope
    case invalidAcknowledgement
    case invalidOperationCore
    case authorizationKeyMismatch
    case invalidSignature
}

struct LAB002ProductionAuthorizationValidator:
    LAB002AuthorizationValidating
{
    private static let profile =
        "orchardprobe.demolab.lab002.observation.v1"
    private static let policy = "orchardprobe.authorized-use.v1"
    private static let envelopeSchema =
        "orchardprobe.lab002.authorized-operation-envelope.v1"
    private static let acknowledgementSchema =
        "orchardprobe.lab002.authorized-use-ack.v1"
    private static let enrollmentSchema =
        "orchardprobe.lab002.installation-enrollment-core.v1"
    private static let runSchema =
        "orchardprobe.lab002.collection-challenge-core.v1"
    private static let authorizationDomain = Data(
        "orchardprobe.demolab.lab002.authorized-operation.v1\0".utf8
    )
    private static let maximumObjectBytes = 3 * 1024
    private static let maximumEnvelopeBytes = LAB002Limit.controlDocument
    private static let maximumSafeInteger: UInt64 =
        9_007_199_254_740_991
    private static let weakPublicKeys: Set<String> = [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    ]

    private let authorizationPublicKey: Curve25519.Signing.PublicKey
    private let authorizationPublicKeyBytes: Data

    init(bundle: Bundle = .main) throws {
        guard let publicKeyHex = bundle.object(
            forInfoDictionaryKey: "LAB002AuthorizationPublicKey"
        ) as? String
        else {
            throw LAB002AuthorizationValidationError.invalidConfiguration
        }
        try self.init(authorizationPublicKeyHex: publicKeyHex)
    }

    init(authorizationPublicKeyHex: String) throws {
        guard !Self.weakPublicKeys.contains(authorizationPublicKeyHex),
              let bytes = Self.decodeLowerHex(
            authorizationPublicKeyHex,
            byteCount: 32
        ) else {
            throw LAB002AuthorizationValidationError.invalidConfiguration
        }
        do {
            authorizationPublicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: bytes
            )
        } catch {
            throw LAB002AuthorizationValidationError.invalidConfiguration
        }
        authorizationPublicKeyBytes = bytes
    }

    func validate(
        _ canonicalBytes: Data
    ) throws -> LAB002AuthorizationMetadata {
        let envelope = try Self.closedObject(
            canonicalBytes,
            maximum: Self.maximumEnvelopeBytes,
            keys: [
                "schema",
                "profile",
                "authorization_key_id",
                "acknowledgement_canonical",
                "operation_core_canonical",
                "signature",
            ],
            error: .invalidEnvelope
        )
        guard envelope["schema"] as? String == Self.envelopeSchema,
              envelope["profile"] as? String == Self.profile,
              let authorizationKeyID =
                envelope["authorization_key_id"] as? String,
              let acknowledgementString =
                envelope["acknowledgement_canonical"] as? String,
              let operationCoreString =
                envelope["operation_core_canonical"] as? String,
              let signatureHex = envelope["signature"] as? String,
              Self.isLowerHex(authorizationKeyID, byteCount: 32),
              let signature = Self.decodeLowerHex(
                  signatureHex,
                  byteCount: 64
              ),
              let acknowledgementBytes = acknowledgementString.data(
                  using: .utf8
              ),
              let operationCoreBytes = operationCoreString.data(
                  using: .utf8
              ),
              acknowledgementBytes.count <= Self.maximumObjectBytes,
              operationCoreBytes.count <= Self.maximumObjectBytes
        else {
            throw LAB002AuthorizationValidationError.invalidEnvelope
        }

        let expectedKeyID = Data(
            SHA256.hash(data: authorizationPublicKeyBytes)
        ).hexLowercase
        guard authorizationKeyID == expectedKeyID else {
            throw LAB002AuthorizationValidationError
                .authorizationKeyMismatch
        }

        let acknowledgement = try Self.acknowledgement(
            acknowledgementBytes
        )
        let metadata: LAB002AuthorizationMetadata
        switch acknowledgement.operation {
        case .installationEnrollment:
            metadata = try Self.enrollmentMetadata(
                acknowledgement: acknowledgement,
                acknowledgementBytes: acknowledgementBytes,
                coreBytes: operationCoreBytes
            )
        case .collectionRun:
            metadata = try Self.runMetadata(
                acknowledgement: acknowledgement,
                acknowledgementBytes: acknowledgementBytes,
                envelopeBytes: canonicalBytes,
                coreBytes: operationCoreBytes
            )
        }

        let message = try Self.authorizationMessage(
            acknowledgement: acknowledgementBytes,
            operationCore: operationCoreBytes
        )
        guard authorizationPublicKey.isValidSignature(
            signature,
            for: message
        ) else {
            throw LAB002AuthorizationValidationError.invalidSignature
        }
        return metadata
    }

    private struct Acknowledgement {
        let operation: LAB002AuthorizationKind
        let buildBindingSHA256: String
        let authorizedTargetManifestSHA256: String
        let acknowledgementID: String
        let experimentID: String
        let deviceSelectionNonce: String
        let runOrdinal: UInt8?
        let expectedEnvironment: LAB002SessionEnvironment?
        let expectedEnrollmentBindingSHA256: String?
        let notBefore: Int64
        let notAfter: Int64
    }

    private static func acknowledgement(
        _ bytes: Data
    ) throws -> Acknowledgement {
        let object = try closedObject(
            bytes,
            maximum: maximumObjectBytes,
            keys: [
                "schema",
                "profile",
                "authorization_policy_version",
                "acknowledgement_id",
                "experiment_id",
                "operation",
                "build_binding_sha256",
                "authorized_target_manifest_sha256",
                "technique_profile",
                "run_ordinal",
                "data_categories",
                "retention_profile",
                "authorized_actions",
                "device_selection_nonce",
                "expected_environment",
                "expected_enrollment_binding_sha256",
                "acknowledged_at",
                "not_before",
                "not_after",
                "confirmed",
                "owns_or_explicitly_authorized_target",
                "within_authorized_scope",
                "understands_legal_limits",
                "will_protect_output_and_not_resign_install_or_redistribute",
            ],
            error: .invalidAcknowledgement
        )
        guard object["schema"] as? String == acknowledgementSchema,
              object["profile"] as? String == profile,
              object["authorization_policy_version"] as? String == policy,
              let acknowledgementID =
                object["acknowledgement_id"] as? String,
              let experimentID = object["experiment_id"] as? String,
              let operationValue = object["operation"] as? String,
              let buildBindingSHA256 =
                object["build_binding_sha256"] as? String,
              let authorizedTargetManifestSHA256 =
                object["authorized_target_manifest_sha256"] as? String,
              object["technique_profile"] as? String
                == "first_party_fixed_range_disk_and_mapped_sha256",
              object["data_categories"] as? [String] == [
                  "authorization_control_metadata",
                  "sanitized_device_environment",
                  "code_signature_metadata",
                  "fixed_range_sha256",
                  "closed_outcomes",
              ],
              object["retention_profile"] as? String
                == "owner_only_lab002_experiment_v1",
              let deviceSelectionNonce =
                object["device_selection_nonce"] as? String,
              let acknowledgedAt = integer(object["acknowledged_at"]),
              let notBefore = integer(object["not_before"]),
              let notAfter = integer(object["not_after"]),
              safeTime(acknowledgedAt),
              safeTime(notBefore),
              safeTime(notAfter),
              acknowledgedAt == notBefore,
              notAfter.subtractingReportingOverflow(notBefore)
                == (900, false),
              boolean(object["confirmed"]) == true,
              boolean(
                  object["owns_or_explicitly_authorized_target"]
              ) == true,
              boolean(object["within_authorized_scope"]) == true,
              boolean(object["understands_legal_limits"]) == true,
              boolean(
                  object[
                      "will_protect_output_and_not_resign_install_or_redistribute"
                  ]
              ) == true,
              [
                  acknowledgementID,
                  experimentID,
                  buildBindingSHA256,
                  authorizedTargetManifestSHA256,
                  deviceSelectionNonce,
              ].allSatisfy({ isLowerHex($0, byteCount: 32) })
        else {
            throw LAB002AuthorizationValidationError
                .invalidAcknowledgement
        }

        let operation: LAB002AuthorizationKind
        let runOrdinal: UInt8?
        let environment: LAB002SessionEnvironment?
        let expectedEnrollmentBinding: String?
        switch operationValue {
        case "install_and_enroll_exact_build":
            guard object["run_ordinal"] is NSNull,
                  object["authorized_actions"] as? [String] == [
                      "install_exact_build",
                      "import_installation_enrollment",
                      "confirm_device_enrollment",
                      "export_enrollment_receipt",
                  ],
                  let environmentObject =
                    object["expected_environment"] as? [String: Any],
                  object["expected_enrollment_binding_sha256"] is NSNull
            else {
                throw LAB002AuthorizationValidationError
                    .invalidAcknowledgement
            }
            operation = .installationEnrollment
            runOrdinal = nil
            environment = try sessionEnvironment(environmentObject)
            expectedEnrollmentBinding = nil
        case "collect_fixed_range_run":
            guard let ordinalValue = integer(object["run_ordinal"]),
                  let ordinal = UInt8(exactly: ordinalValue),
                  ordinal == 1 || ordinal == 2,
                  object["authorized_actions"] as? [String] == [
                      "import_collection_challenge",
                      "start_clean_run",
                      "observe_main_app",
                      "observe_framework",
                      "invoke_share_extension",
                      "export_session_evidence",
                      "confirm_export_received",
                      "cleanup_report_subtree",
                  ],
                  object["expected_environment"] is NSNull,
                  let binding =
                    object[
                        "expected_enrollment_binding_sha256"
                    ] as? String,
                  isLowerHex(binding, byteCount: 32)
            else {
                throw LAB002AuthorizationValidationError
                    .invalidAcknowledgement
            }
            operation = .collectionRun
            runOrdinal = ordinal
            environment = nil
            expectedEnrollmentBinding = binding
        default:
            throw LAB002AuthorizationValidationError
                .invalidAcknowledgement
        }

        return Acknowledgement(
            operation: operation,
            buildBindingSHA256: buildBindingSHA256,
            authorizedTargetManifestSHA256:
                authorizedTargetManifestSHA256,
            acknowledgementID: acknowledgementID,
            experimentID: experimentID,
            deviceSelectionNonce: deviceSelectionNonce,
            runOrdinal: runOrdinal,
            expectedEnvironment: environment,
            expectedEnrollmentBindingSHA256:
                expectedEnrollmentBinding,
            notBefore: notBefore,
            notAfter: notAfter
        )
    }

    private static func enrollmentMetadata(
        acknowledgement: Acknowledgement,
        acknowledgementBytes: Data,
        coreBytes: Data
    ) throws -> LAB002AuthorizationMetadata {
        let core = try closedObject(
            coreBytes,
            maximum: maximumObjectBytes,
            keys: [
                "schema",
                "profile",
                "operation",
                "experiment_id",
                "enrollment_challenge",
                "build_binding_sha256",
                "authorized_target_manifest_sha256",
                "authorization_policy_version",
                "device_selection_nonce",
                "expected_environment",
                "not_before",
                "not_after",
            ],
            error: .invalidOperationCore
        )
        guard core["schema"] as? String == enrollmentSchema,
              core["profile"] as? String == profile,
              core["operation"] as? String
                == "install_and_enroll_exact_build",
              core["authorization_policy_version"] as? String == policy,
              let experimentID = core["experiment_id"] as? String,
              let challenge = core["enrollment_challenge"] as? String,
              let buildBindingSHA256 =
                core["build_binding_sha256"] as? String,
              let manifestSHA256 =
                core["authorized_target_manifest_sha256"] as? String,
              let nonce = core["device_selection_nonce"] as? String,
              let environmentObject =
                core["expected_environment"] as? [String: Any],
              let notBefore = integer(core["not_before"]),
              let notAfter = integer(core["not_after"]),
              let acknowledgementEnvironment =
                acknowledgement.expectedEnvironment,
              let environment = try? sessionEnvironment(
                  environmentObject
              ),
              experimentID == acknowledgement.experimentID,
              buildBindingSHA256
                == acknowledgement.buildBindingSHA256,
              manifestSHA256
                == acknowledgement.authorizedTargetManifestSHA256,
              nonce == acknowledgement.deviceSelectionNonce,
              environment == acknowledgementEnvironment,
              notBefore == acknowledgement.notBefore,
              notAfter == acknowledgement.notAfter,
              isLowerHex(challenge, byteCount: 32)
        else {
            throw LAB002AuthorizationValidationError.invalidOperationCore
        }

        return LAB002AuthorizationMetadata(
            kind: .installationEnrollment,
            buildBindingSHA256: buildBindingSHA256,
            notBefore: notBefore,
            notAfter: notAfter,
            expectedRunCounter: nil,
            enrollmentFacts: LAB002VerifiedEnrollmentFacts(
                acknowledgementSHA256: sha256Hex(
                    acknowledgementBytes
                ),
                authorizationPolicyVersion: policy,
                authorizedTargetManifestSHA256: manifestSHA256,
                enrollmentChallenge: challenge,
                experimentID: experimentID,
                deviceSelectionNonce: nonce,
                expectedEnvironment: environment
            )
        )
    }

    private static func runMetadata(
        acknowledgement: Acknowledgement,
        acknowledgementBytes: Data,
        envelopeBytes: Data,
        coreBytes: Data
    ) throws -> LAB002AuthorizationMetadata {
        let core = try closedObject(
            coreBytes,
            maximum: maximumObjectBytes,
            keys: [
                "schema",
                "profile",
                "operation",
                "challenge",
                "collection_id",
                "run_ordinal",
                "expected_run_counter",
                "build_binding_sha256",
                "authorization_policy_version",
                "expected_enrollment_binding_sha256",
                "enrollment_public_key",
                "expected_device_installation_binding_sha256",
                "not_before",
                "not_after",
            ],
            error: .invalidOperationCore
        )
        guard core["schema"] as? String == runSchema,
              core["profile"] as? String == profile,
              core["operation"] as? String
                == "collect_fixed_range_run",
              core["authorization_policy_version"] as? String == policy,
              let challenge = core["challenge"] as? String,
              let collectionID = core["collection_id"] as? String,
              let ordinalValue = integer(core["run_ordinal"]),
              let ordinal = UInt8(exactly: ordinalValue),
              let expectedCounter =
                core["expected_run_counter"] as? String,
              expectedCounter == String(
                  format: "%016llx",
                  UInt64(ordinal)
              ),
              let buildBindingSHA256 =
                core["build_binding_sha256"] as? String,
              let enrollmentBinding =
                core[
                    "expected_enrollment_binding_sha256"
                ] as? String,
              let enrollmentPublicKey =
                core["enrollment_public_key"] as? String,
              let installationBinding =
                core[
                    "expected_device_installation_binding_sha256"
                ] as? String,
              let notBefore = integer(core["not_before"]),
              let notAfter = integer(core["not_after"]),
              acknowledgement.runOrdinal == ordinal,
              buildBindingSHA256
                == acknowledgement.buildBindingSHA256,
              enrollmentBinding
                == acknowledgement.expectedEnrollmentBindingSHA256,
              notBefore == acknowledgement.notBefore,
              notAfter == acknowledgement.notAfter,
              [
                  challenge,
                  collectionID,
                  buildBindingSHA256,
                  enrollmentBinding,
                  enrollmentPublicKey,
                  installationBinding,
              ].allSatisfy({ isLowerHex($0, byteCount: 32) })
        else {
            throw LAB002AuthorizationValidationError.invalidOperationCore
        }

        return LAB002AuthorizationMetadata(
            kind: .collectionRun,
            buildBindingSHA256: buildBindingSHA256,
            notBefore: notBefore,
            notAfter: notAfter,
            expectedRunCounter: UInt64(ordinal),
            runFacts: LAB002VerifiedRunFacts(
                experimentID: acknowledgement.experimentID,
                authorizedTargetManifestSHA256:
                    acknowledgement.authorizedTargetManifestSHA256,
                collectionID: collectionID,
                runOrdinal: ordinal,
                challengeSHA256: sha256Hex(envelopeBytes),
                acknowledgementSHA256: sha256Hex(
                    acknowledgementBytes
                ),
                deviceEnrollmentBindingSHA256: enrollmentBinding,
                enrollmentPublicKey: enrollmentPublicKey,
                expectedDeviceInstallationBindingSHA256:
                    installationBinding
            )
        )
    }

    private static func authorizationMessage(
        acknowledgement: Data,
        operationCore: Data
    ) throws -> Data {
        guard let acknowledgementSize = UInt32(
            exactly: acknowledgement.count
        ),
        let operationSize = UInt32(exactly: operationCore.count)
        else {
            throw LAB002AuthorizationValidationError.invalidEnvelope
        }
        var result = authorizationDomain
        var acknowledgementSizeBE = acknowledgementSize.bigEndian
        withUnsafeBytes(of: &acknowledgementSizeBE) {
            result.append(contentsOf: $0)
        }
        result.append(acknowledgement)
        var operationSizeBE = operationSize.bigEndian
        withUnsafeBytes(of: &operationSizeBE) {
            result.append(contentsOf: $0)
        }
        result.append(operationCore)
        return result
    }

    private static func closedObject(
        _ bytes: Data,
        maximum: Int,
        keys: Set<String>,
        error: LAB002AuthorizationValidationError
    ) throws -> [String: Any] {
        guard !bytes.isEmpty,
              bytes.count <= maximum,
              let object = try? JSONSerialization.jsonObject(
                  with: bytes
              ) as? [String: Any],
              Set(object.keys) == keys,
              JSONSerialization.isValidJSONObject(object),
              let encoded = try? JSONSerialization.data(
                  withJSONObject: object,
                  options: [.sortedKeys, .withoutEscapingSlashes]
              ),
              encoded == bytes
        else {
            throw error
        }
        return object
    }

    private static func sessionEnvironment(
        _ object: [String: Any]
    ) throws -> LAB002SessionEnvironment {
        guard Set(object.keys) == [
            "hardware_model",
            "ios_product_version",
            "ios_build",
        ],
        let hardwareModel = object["hardware_model"] as? String,
        let productVersion = object["ios_product_version"] as? String,
        let build = object["ios_build"] as? String
        else {
            throw LAB002AuthorizationValidationError.invalidOperationCore
        }
        do {
            return try LAB002SessionEnvironment(
                hardwareModel: hardwareModel,
                iosProductVersion: productVersion,
                iosBuild: build
            )
        } catch {
            throw LAB002AuthorizationValidationError.invalidOperationCore
        }
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

    private static func boolean(_ value: Any?) -> Bool? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else {
            return nil
        }
        return number.boolValue
    }

    private static func safeTime(_ value: Int64) -> Bool {
        value >= 0 && UInt64(value) <= maximumSafeInteger
    }

    private static func sha256Hex(_ bytes: Data) -> String {
        Data(SHA256.hash(data: bytes)).hexLowercase
    }

    private static func isLowerHex(
        _ value: String,
        byteCount: Int
    ) -> Bool {
        value.utf8.count == byteCount * 2
            && value.utf8.allSatisfy {
                (0x30...0x39).contains($0)
                    || (0x61...0x66).contains($0)
            }
    }

    private static func decodeLowerHex(
        _ value: String,
        byteCount: Int
    ) -> Data? {
        guard isLowerHex(value, byteCount: byteCount) else {
            return nil
        }
        var result = Data()
        result.reserveCapacity(byteCount)
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
