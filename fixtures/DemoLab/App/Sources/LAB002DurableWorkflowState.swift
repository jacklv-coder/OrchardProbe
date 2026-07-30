import CoreFoundation
import Foundation

enum LAB002DurableWorkflowStateError: Error {
    case invalidRecord
}

struct LAB002EnrollmentControlState: Equatable {
    static let schema = "orchardprobe.lab002.enrollment-control-state.v1"

    let buildBindingSHA256: String
    let experimentID: String
    let deviceEnrollmentBindingSHA256: String

    init(
        buildBindingSHA256: String,
        experimentID: String,
        deviceEnrollmentBindingSHA256: String
    ) throws {
        guard [
            buildBindingSHA256,
            experimentID,
            deviceEnrollmentBindingSHA256,
        ].allSatisfy(Self.isDigest)
        else {
            throw LAB002DurableWorkflowStateError.invalidRecord
        }
        self.buildBindingSHA256 = buildBindingSHA256
        self.experimentID = experimentID
        self.deviceEnrollmentBindingSHA256 =
            deviceEnrollmentBindingSHA256
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= LAB002Limit.fixedState,
              let object = try JSONSerialization.jsonObject(
                  with: canonicalBytes
              ) as? [String: Any],
              Set(object.keys) == [
                  "build_binding_sha256",
                  "device_enrollment_binding_sha256",
                  "experiment_id",
                  "schema",
              ],
              object["schema"] as? String == Self.schema,
              let buildBindingSHA256 =
                object["build_binding_sha256"] as? String,
              let experimentID = object["experiment_id"] as? String,
              let deviceEnrollmentBindingSHA256 =
                object["device_enrollment_binding_sha256"] as? String
        else {
            throw LAB002DurableWorkflowStateError.invalidRecord
        }
        try self.init(
            buildBindingSHA256: buildBindingSHA256,
            experimentID: experimentID,
            deviceEnrollmentBindingSHA256:
                deviceEnrollmentBindingSHA256
        )
        guard try canonicalData() == canonicalBytes else {
            throw LAB002DurableWorkflowStateError.invalidRecord
        }
    }

    func canonicalData() throws -> Data {
        try Self.canonical([
            "build_binding_sha256": buildBindingSHA256,
            "device_enrollment_binding_sha256":
                deviceEnrollmentBindingSHA256,
            "experiment_id": experimentID,
            "schema": Self.schema,
        ])
    }

    fileprivate static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64
            && value.utf8.allSatisfy {
                (0x30...0x39).contains($0)
                    || (0x61...0x66).contains($0)
            }
    }

    fileprivate static func canonical(
        _ object: [String: Any]
    ) throws -> Data {
        let bytes = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard bytes.count <= LAB002Limit.fixedState else {
            throw LAB002DurableWorkflowStateError.invalidRecord
        }
        return bytes
    }
}

enum LAB002RunLifecyclePhase: String {
    case observingMainAndFramework = "observing_main_and_framework"
    case awaitingShareExtension = "awaiting_share_extension"
    case completionPending = "completion_pending"
    case completionCommitted = "completion_committed"
    case cleanupPending = "cleanup_pending"
    case cleanupCommitted = "cleanup_committed"
}

struct LAB002RunLifecycleState: Equatable {
    static let schema = "orchardprobe.lab002.run-lifecycle-state.v1"

    let buildBindingSHA256: String
    let sessionID: String
    let runOrdinal: UInt8
    let phase: LAB002RunLifecyclePhase

    init(
        buildBindingSHA256: String,
        sessionID: String,
        runOrdinal: UInt8,
        phase: LAB002RunLifecyclePhase
    ) throws {
        guard LAB002EnrollmentControlState.isDigest(
            buildBindingSHA256
        ),
        LAB002EnrollmentControlState.isDigest(sessionID),
        runOrdinal == 1 || runOrdinal == 2
        else {
            throw LAB002DurableWorkflowStateError.invalidRecord
        }
        self.buildBindingSHA256 = buildBindingSHA256
        self.sessionID = sessionID
        self.runOrdinal = runOrdinal
        self.phase = phase
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= LAB002Limit.fixedState,
              let object = try JSONSerialization.jsonObject(
                  with: canonicalBytes
              ) as? [String: Any],
              Set(object.keys) == [
                  "build_binding_sha256",
                  "phase",
                  "run_ordinal",
                  "schema",
                  "session_id",
              ],
              object["schema"] as? String == Self.schema,
              let buildBindingSHA256 =
                object["build_binding_sha256"] as? String,
              let sessionID = object["session_id"] as? String,
              let ordinal = Self.integer(object["run_ordinal"]),
              let runOrdinal = UInt8(exactly: ordinal),
              let phaseValue = object["phase"] as? String,
              let phase = LAB002RunLifecyclePhase(rawValue: phaseValue)
        else {
            throw LAB002DurableWorkflowStateError.invalidRecord
        }
        try self.init(
            buildBindingSHA256: buildBindingSHA256,
            sessionID: sessionID,
            runOrdinal: runOrdinal,
            phase: phase
        )
        guard try canonicalData() == canonicalBytes else {
            throw LAB002DurableWorkflowStateError.invalidRecord
        }
    }

    func changingPhase(
        to phase: LAB002RunLifecyclePhase
    ) throws -> LAB002RunLifecycleState {
        try LAB002RunLifecycleState(
            buildBindingSHA256: buildBindingSHA256,
            sessionID: sessionID,
            runOrdinal: runOrdinal,
            phase: phase
        )
    }

    func canonicalData() throws -> Data {
        try LAB002EnrollmentControlState.canonical([
            "build_binding_sha256": buildBindingSHA256,
            "phase": phase.rawValue,
            "run_ordinal": Int64(runOrdinal),
            "schema": Self.schema,
            "session_id": sessionID,
        ])
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
}
