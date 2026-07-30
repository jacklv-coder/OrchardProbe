import CoreFoundation
import Foundation

enum LAB002SessionError: Error {
    case invalidRecord
}

enum LAB002SessionStatus: String {
    case collecting
    case complete
    case failed
}

struct LAB002SessionEnvironment: Equatable {
    let hardwareModel: String
    let iosProductVersion: String
    let iosBuild: String

    init(
        hardwareModel: String,
        iosProductVersion: String,
        iosBuild: String
    ) throws {
        guard Self.isHardwareModel(hardwareModel),
              Self.isVersion(iosProductVersion),
              Self.isAppleBuild(iosBuild)
        else {
            throw LAB002SessionError.invalidRecord
        }
        self.hardwareModel = hardwareModel
        self.iosProductVersion = iosProductVersion
        self.iosBuild = iosBuild
    }

    fileprivate var jsonObject: [String: Any] {
        [
            "hardware_model": hardwareModel,
            "ios_build": iosBuild,
            "ios_product_version": iosProductVersion,
        ]
    }

    private static func isHardwareModel(_ value: String) -> Bool {
        guard value.utf8.count <= 32,
              value.hasPrefix("iPhone")
        else {
            return false
        }
        let suffix = value.dropFirst("iPhone".count)
        let parts = suffix.split(separator: ",", omittingEmptySubsequences: false)
        return parts.count == 2
            && parts.allSatisfy {
                !$0.isEmpty && $0.utf8.allSatisfy { (0x30...0x39).contains($0) }
            }
    }

    fileprivate static func isVersion(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return !value.isEmpty
            && value.utf8.count <= 32
            && (1...4).contains(parts.count)
            && parts.allSatisfy {
                !$0.isEmpty && $0.utf8.allSatisfy { (0x30...0x39).contains($0) }
            }
    }

    private static func isAppleBuild(_ value: String) -> Bool {
        guard (3...32).contains(value.utf8.count),
              value.utf8.allSatisfy({
                  (0x30...0x39).contains($0)
                      || (0x41...0x5a).contains($0)
                      || (0x61...0x7a).contains($0)
              }),
              let letter = value.utf8.firstIndex(where: {
                  !(0x30...0x39).contains($0)
              }),
              letter != value.utf8.startIndex,
              (0x41...0x5a).contains(value.utf8[letter])
        else {
            return false
        }
        return value.utf8.index(after: letter) != value.utf8.endIndex
    }
}

struct LAB002SessionReport: Equatable {
    static let schema = "orchardprobe.lab002.session-report.v1"
    static let profile = "orchardprobe.demolab.lab002.observation.v1"
    static let policy = "orchardprobe.authorized-use.v1"
    private static let maximumSafeInteger: Int64 = 9_007_199_254_740_991

    let observerRevision: String
    let buildBindingSHA256: String
    let collectionID: String
    let runOrdinal: UInt8
    let challengeSHA256: String
    let acknowledgementSHA256: String
    let authorizationEnvelopeSHA256: String
    let deviceEnrollmentBindingSHA256: String
    let enrollmentPublicKey: String
    let deviceInstallationBindingSHA256: String
    let environment: LAB002SessionEnvironment
    let sessionID: String
    let runCounter: String
    let createdAt: Int64
    let completedAt: Int64?
    let sourceCommit: String
    let marketingVersion: String
    let buildNumber: String
    let state: LAB002SessionStatus

    init(
        observerRevision: String,
        buildBindingSHA256: String,
        collectionID: String,
        runOrdinal: UInt8,
        challengeSHA256: String,
        acknowledgementSHA256: String,
        authorizationEnvelopeSHA256: String,
        deviceEnrollmentBindingSHA256: String,
        enrollmentPublicKey: String,
        deviceInstallationBindingSHA256: String,
        environment: LAB002SessionEnvironment,
        sessionID: String,
        runCounter: String,
        createdAt: Int64,
        completedAt: Int64?,
        sourceCommit: String,
        marketingVersion: String,
        buildNumber: String,
        state: LAB002SessionStatus
    ) throws {
        let digests = [
            buildBindingSHA256,
            collectionID,
            challengeSHA256,
            acknowledgementSHA256,
            authorizationEnvelopeSHA256,
            deviceEnrollmentBindingSHA256,
            enrollmentPublicKey,
            deviceInstallationBindingSHA256,
            sessionID,
        ]
        guard digests.allSatisfy({ Self.isLowerHex($0, count: 64) }),
              Self.isLowerHex(sourceCommit, count: 40),
              Self.isObserverRevision(observerRevision),
              LAB002SessionEnvironment.isVersion(marketingVersion),
              LAB002SessionEnvironment.isVersion(buildNumber),
              Self.isSafeTime(createdAt),
              runOrdinal == 1 || runOrdinal == 2,
              runCounter == String(
                  format: "%016llx",
                  UInt64(runOrdinal)
              ),
              (state == .collecting && completedAt == nil)
                || (state != .collecting
                    && completedAt.map {
                        Self.isSafeTime($0) && $0 >= createdAt
                    } == true)
        else {
            throw LAB002SessionError.invalidRecord
        }
        self.observerRevision = observerRevision
        self.buildBindingSHA256 = buildBindingSHA256
        self.collectionID = collectionID
        self.runOrdinal = runOrdinal
        self.challengeSHA256 = challengeSHA256
        self.acknowledgementSHA256 = acknowledgementSHA256
        self.authorizationEnvelopeSHA256 = authorizationEnvelopeSHA256
        self.deviceEnrollmentBindingSHA256 = deviceEnrollmentBindingSHA256
        self.enrollmentPublicKey = enrollmentPublicKey
        self.deviceInstallationBindingSHA256 = deviceInstallationBindingSHA256
        self.environment = environment
        self.sessionID = sessionID
        self.runCounter = runCounter
        self.createdAt = createdAt
        self.completedAt = completedAt
        self.sourceCommit = sourceCommit
        self.marketingVersion = marketingVersion
        self.buildNumber = buildNumber
        self.state = state
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= LAB002Limit.sessionReport,
              let object = try JSONSerialization.jsonObject(
                  with: canonicalBytes
              ) as? [String: Any],
              object.count == 22,
              object["schema"] as? String == Self.schema,
              object["profile"] as? String == Self.profile,
              object["authorization_policy_version"] as? String == Self.policy,
              let observerRevision = object["observer_revision"] as? String,
              let buildBinding = object["build_binding_sha256"] as? String,
              let collectionID = object["collection_id"] as? String,
              let runOrdinalValue = Self.integer(object["run_ordinal"]),
              let runOrdinal = UInt8(exactly: runOrdinalValue),
              let challenge = object["challenge_sha256"] as? String,
              let acknowledgement = object["acknowledgement_sha256"] as? String,
              let envelope = object["authorization_envelope_sha256"] as? String,
              let enrollmentBinding =
                object["device_enrollment_binding_sha256"] as? String,
              let publicKey = object["enrollment_public_key"] as? String,
              let installationBinding =
                object["device_installation_binding_sha256"] as? String,
              let environmentObject = object["environment"] as? [String: Any],
              environmentObject.count == 3,
              let hardware = environmentObject["hardware_model"] as? String,
              let product = environmentObject["ios_product_version"] as? String,
              let iosBuild = environmentObject["ios_build"] as? String,
              let sessionID = object["session_id"] as? String,
              let runCounter = object["run_counter"] as? String,
              let createdAt = Self.integer(object["created_at"]),
              let sourceCommit = object["source_commit"] as? String,
              let marketingVersion = object["marketing_version"] as? String,
              let buildNumber = object["build_number"] as? String,
              let stateValue = object["state"] as? String,
              let state = LAB002SessionStatus(rawValue: stateValue)
        else {
            throw LAB002SessionError.invalidRecord
        }
        let completedAt: Int64?
        if object["completed_at"] is NSNull {
            completedAt = nil
        } else {
            guard let value = Self.integer(object["completed_at"]) else {
                throw LAB002SessionError.invalidRecord
            }
            completedAt = value
        }
        try self.init(
            observerRevision: observerRevision,
            buildBindingSHA256: buildBinding,
            collectionID: collectionID,
            runOrdinal: runOrdinal,
            challengeSHA256: challenge,
            acknowledgementSHA256: acknowledgement,
            authorizationEnvelopeSHA256: envelope,
            deviceEnrollmentBindingSHA256: enrollmentBinding,
            enrollmentPublicKey: publicKey,
            deviceInstallationBindingSHA256: installationBinding,
            environment: LAB002SessionEnvironment(
                hardwareModel: hardware,
                iosProductVersion: product,
                iosBuild: iosBuild
            ),
            sessionID: sessionID,
            runCounter: runCounter,
            createdAt: createdAt,
            completedAt: completedAt,
            sourceCommit: sourceCommit,
            marketingVersion: marketingVersion,
            buildNumber: buildNumber,
            state: state
        )
        guard try canonicalData() == canonicalBytes else {
            throw LAB002SessionError.invalidRecord
        }
    }

    func canonicalData() throws -> Data {
        let object: [String: Any] = [
            "acknowledgement_sha256": acknowledgementSHA256,
            "authorization_envelope_sha256": authorizationEnvelopeSHA256,
            "authorization_policy_version": Self.policy,
            "build_binding_sha256": buildBindingSHA256,
            "build_number": buildNumber,
            "challenge_sha256": challengeSHA256,
            "collection_id": collectionID,
            "completed_at": completedAt ?? NSNull(),
            "created_at": createdAt,
            "device_enrollment_binding_sha256": deviceEnrollmentBindingSHA256,
            "device_installation_binding_sha256": deviceInstallationBindingSHA256,
            "enrollment_public_key": enrollmentPublicKey,
            "environment": environment.jsonObject,
            "marketing_version": marketingVersion,
            "observer_revision": observerRevision,
            "profile": Self.profile,
            "run_counter": runCounter,
            "run_ordinal": runOrdinal,
            "schema": Self.schema,
            "session_id": sessionID,
            "source_commit": sourceCommit,
            "state": state.rawValue,
        ]
        let data = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard data.count <= LAB002Limit.sessionReport else {
            throw LAB002SessionError.invalidRecord
        }
        return data
    }

    private static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else {
            return nil
        }
        let integer = number.int64Value
        return NSNumber(value: integer) == number ? integer : nil
    }

    private static func isSafeTime(_ value: Int64) -> Bool {
        value >= 0 && value <= maximumSafeInteger
    }

    private static func isLowerHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count
            && value.utf8.allSatisfy {
                (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
            }
    }

    private static func isObserverRevision(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 64 else {
            return false
        }
        var previousSeparator = true
        for byte in value.utf8 {
            let separator = byte == 0x2d || byte == 0x2e || byte == 0x5f
            guard separator
                    || (0x30...0x39).contains(byte)
                    || (0x61...0x7a).contains(byte),
                  !(separator && previousSeparator)
            else {
                return false
            }
            previousSeparator = separator
        }
        return !previousSeparator
    }
}
