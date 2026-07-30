import CoreFoundation
import Darwin
import Foundation

private enum LAB002RoleReportOutcome: String {
    case pass
    case fail
    case inconclusive
}

private struct LAB002RoleSession: Equatable {
    static let schema = "orchardprobe.lab002.session-report.v1"
    static let profile = "orchardprobe.demolab.lab002.observation.v1"
    static let policy = "orchardprobe.authorized-use.v1"

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
    let environment: [String: String]
    let sessionID: String
    let runCounter: String
    let createdAt: Int64
    let sourceCommit: String
    let marketingVersion: String
    let buildNumber: String
    let canonicalBytes: Data

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= LAB002Limit.sessionReport,
              let object = try JSONSerialization.jsonObject(
                  with: canonicalBytes
              ) as? [String: Any],
              object.count == 22,
              object["schema"] as? String == Self.schema,
              object["profile"] as? String == Self.profile,
              object["authorization_policy_version"] as? String == Self.policy,
              object["state"] as? String == "collecting",
              object["completed_at"] is NSNull,
              let observerRevision =
                object["observer_revision"] as? String,
              let buildBindingSHA256 =
                object["build_binding_sha256"] as? String,
              let collectionID = object["collection_id"] as? String,
              let ordinalValue = LAB002RoleJSON.integer(
                  object["run_ordinal"]
              ),
              let runOrdinal = UInt8(exactly: ordinalValue),
              let challengeSHA256 = object["challenge_sha256"] as? String,
              let acknowledgementSHA256 =
                object["acknowledgement_sha256"] as? String,
              let authorizationEnvelopeSHA256 =
                object["authorization_envelope_sha256"] as? String,
              let deviceEnrollmentBindingSHA256 =
                object["device_enrollment_binding_sha256"] as? String,
              let enrollmentPublicKey =
                object["enrollment_public_key"] as? String,
              let deviceInstallationBindingSHA256 =
                object["device_installation_binding_sha256"] as? String,
              let environmentObject =
                object["environment"] as? [String: Any],
              let environment = LAB002RoleJSON.environment(
                  environmentObject
              ),
              let sessionID = object["session_id"] as? String,
              let runCounter = object["run_counter"] as? String,
              let createdAt = LAB002RoleJSON.integer(object["created_at"]),
              let sourceCommit = object["source_commit"] as? String,
              let marketingVersion =
                object["marketing_version"] as? String,
              let buildNumber = object["build_number"] as? String,
              LAB002RoleJSON.observerRevision(observerRevision),
              LAB002RoleJSON.lowerHex(buildBindingSHA256, count: 64),
              LAB002RoleJSON.lowerHex(collectionID, count: 64),
              LAB002RoleJSON.lowerHex(challengeSHA256, count: 64),
              LAB002RoleJSON.lowerHex(acknowledgementSHA256, count: 64),
              LAB002RoleJSON.lowerHex(
                  authorizationEnvelopeSHA256,
                  count: 64
              ),
              LAB002RoleJSON.lowerHex(
                  deviceEnrollmentBindingSHA256,
                  count: 64
              ),
              LAB002RoleJSON.lowerHex(enrollmentPublicKey, count: 64),
              LAB002RoleJSON.lowerHex(
                  deviceInstallationBindingSHA256,
                  count: 64
              ),
              LAB002RoleJSON.lowerHex(sessionID, count: 64),
              LAB002RoleJSON.lowerHex(sourceCommit, count: 40),
              LAB002RoleJSON.version(marketingVersion),
              LAB002RoleJSON.version(buildNumber),
              LAB002RoleJSON.safeTime(createdAt),
              runOrdinal == 1 || runOrdinal == 2,
              runCounter == String(
                  format: "%016llx",
                  UInt64(runOrdinal)
              ),
              try LAB002RoleJSON.canonical(object) == canonicalBytes
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        self.observerRevision = observerRevision
        self.buildBindingSHA256 = buildBindingSHA256
        self.collectionID = collectionID
        self.runOrdinal = runOrdinal
        self.challengeSHA256 = challengeSHA256
        self.acknowledgementSHA256 = acknowledgementSHA256
        self.authorizationEnvelopeSHA256 = authorizationEnvelopeSHA256
        self.deviceEnrollmentBindingSHA256 =
            deviceEnrollmentBindingSHA256
        self.enrollmentPublicKey = enrollmentPublicKey
        self.deviceInstallationBindingSHA256 =
            deviceInstallationBindingSHA256
        self.environment = environment
        self.sessionID = sessionID
        self.runCounter = runCounter
        self.createdAt = createdAt
        self.sourceCommit = sourceCommit
        self.marketingVersion = marketingVersion
        self.buildNumber = buildNumber
        self.canonicalBytes = canonicalBytes
    }
}

struct LAB002RoleReport: Equatable {
    static let schema = "orchardprobe.lab002.role-report.v1"

    let role: LAB002Role
    let sessionID: String
    let diskInspectionCompletedAt: Int64
    let mappedHashCompletedAt: Int64
    let canonicalBytes: Data

    fileprivate init(
        session: LAB002RoleSession,
        observation: LAB002LocalRoleObservation,
        fixedRole: LAB002Role
    ) throws {
        guard observation.installed.slices.count == 1,
              observation.activeSliceIndex == 0,
              observation.diskInspectionCompletedAt >= session.createdAt,
              observation.mappedHashCompletedAt
                >= observation.diskInspectionCompletedAt,
              session.createdAt.addingReportingOverflow(1_140).overflow
                == false,
              observation.mappedHashCompletedAt
                <= session.createdAt + 1_140
        else {
            throw LAB002ObserverReason.unexpectedInstalledSlice
        }
        let active = observation.installed.slices[0]
        var reasons: [LAB002ObserverReason] = []
        let signing = active.signing
        if signing.presence != .present
            || signing.kind != .cms
            || signing.validation != .valid
        {
            reasons.append(.signatureInvalidOrUnchecked)
        }
        if active.encryption.cryptid != 1
            || active.encryption.cryptsize == 0
        {
            reasons.append(.encryptionCommandInvalid)
        }
        if !active.encryption.coversFixedSection {
            reasons.append(.encryptionDoesNotCoverRange)
        }
        let outcome: LAB002RoleReportOutcome
        if reasons.contains(.encryptionCommandInvalid)
            || reasons.contains(.encryptionDoesNotCoverRange)
        {
            outcome = .fail
        } else if reasons.isEmpty {
            outcome = .pass
        } else {
            outcome = .inconclusive
        }

        let signatureObject: [String: Any] = [
            "kind": signing.kind.rawValue,
            "presence": signing.presence.rawValue,
            "superblob_sha256": signing.superblobSHA256 ?? NSNull(),
            "validation": signing.validation.rawValue,
            "validator_id": signing.validatorID,
            "validator_revision": signing.validatorRevision,
        ]
        let slices: [[String: Any]] = observation.installed.slices.map {
            slice in
            [
                "cpu_subtype": Int64(slice.cpuSubtype),
                "cpu_type": Int64(slice.cpuType),
                "crypt_file_end": NSNumber(
                    value: slice.encryption.cryptFileEnd
                ),
                "crypt_file_start": NSNumber(
                    value: slice.encryption.cryptFileStart
                ),
                "cryptid": Int64(slice.encryption.cryptid),
                "cryptoff": NSNumber(value: slice.encryption.cryptoff),
                "cryptsize": NSNumber(value: slice.encryption.cryptsize),
                "disk_sha256": slice.diskSHA256,
                "encryption_command": slice.encryption.command.rawValue,
                "encryption_covers_section":
                    slice.encryption.coversFixedSection,
                "macho_uuid": slice.uuid,
                "mapped_sha256": observation.mappedSHA256,
                "ordinal": Int64(slice.ordinal),
                "section_file_offset": NSNumber(
                    value: slice.sectionFileOffset
                ),
                "section_length": NSNumber(value: slice.sectionLength),
                "section_name": "__oprobe",
                "section_slice_offset": NSNumber(
                    value: slice.sectionSliceOffset
                ),
                "section_vm_offset": NSNumber(
                    value: slice.sectionVMOffset
                ),
                "segment_name": "__TEXT",
                "slice_file_offset": NSNumber(
                    value: slice.sliceFileOffset
                ),
                "slice_file_size": NSNumber(value: slice.sliceFileSize),
            ]
        }
        let object: [String: Any] = [
            "acknowledgement_sha256": session.acknowledgementSHA256,
            "active_cpu_subtype": Int64(active.cpuSubtype),
            "active_cpu_type": Int64(active.cpuType),
            "active_macho_uuid": active.uuid,
            "active_slice_ordinal": Int64(active.ordinal),
            "authorization_envelope_sha256":
                session.authorizationEnvelopeSHA256,
            "authorization_policy_version": LAB002RoleSession.policy,
            "build_binding_sha256": session.buildBindingSHA256,
            "build_number": session.buildNumber,
            "challenge_sha256": session.challengeSHA256,
            "collection_id": session.collectionID,
            "container_kind": observation.installed.container.rawValue,
            "device_enrollment_binding_sha256":
                session.deviceEnrollmentBindingSHA256,
            "device_installation_binding_sha256":
                session.deviceInstallationBindingSHA256,
            "enrollment_public_key": session.enrollmentPublicKey,
            "environment": session.environment,
            "fixture_relative_path": fixedRole.fixtureRelativePath,
            "installed_file_size": NSNumber(
                value: observation.installed.fileSize
            ),
            "marketing_version": session.marketingVersion,
            "observer_revision": session.observerRevision,
            "outcome": outcome.rawValue,
            "phases": [
                [
                    "completed_at":
                        observation.diskInspectionCompletedAt,
                    "phase": "disk_inspection",
                ],
                [
                    "completed_at": observation.mappedHashCompletedAt,
                    "phase": "mapped_hash",
                ],
            ],
            "profile": LAB002RoleSession.profile,
            "reasons": reasons.map(\.rawValue),
            "role": fixedRole.rawValue,
            "run_counter": session.runCounter,
            "run_ordinal": Int64(session.runOrdinal),
            "schema": Self.schema,
            "session_id": session.sessionID,
            "signature": signatureObject,
            "slices": slices,
            "source_commit": session.sourceCommit,
            "target_identity_binding_sha256":
                observation.targetIdentityBindingSHA256,
        ]
        let bytes = try LAB002RoleJSON.canonical(object)
        guard bytes.count <= LAB002Limit.roleReport else {
            throw LAB002ObserverReason.reportLimitExceeded
        }
        try self.init(canonicalBytes: bytes)
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= LAB002Limit.roleReport,
              let object = try JSONSerialization.jsonObject(
                  with: canonicalBytes
              ) as? [String: Any],
              object.count == 33,
              object["schema"] as? String == Self.schema,
              object["profile"] as? String == LAB002RoleSession.profile,
              object["authorization_policy_version"] as? String
                == LAB002RoleSession.policy,
              let roleValue = object["role"] as? String,
              let role = LAB002Role(rawValue: roleValue),
              object["fixture_relative_path"] as? String
                == role.fixtureRelativePath,
              let sessionID = object["session_id"] as? String,
              let collectionID = object["collection_id"] as? String,
              let challenge = object["challenge_sha256"] as? String,
              let acknowledgement =
                object["acknowledgement_sha256"] as? String,
              let envelope =
                object["authorization_envelope_sha256"] as? String,
              let enrollmentBinding =
                object["device_enrollment_binding_sha256"] as? String,
              let enrollmentPublicKey =
                object["enrollment_public_key"] as? String,
              let installationBinding =
                object["device_installation_binding_sha256"] as? String,
              let buildBinding =
                object["build_binding_sha256"] as? String,
              let targetBinding =
                object["target_identity_binding_sha256"] as? String,
              [
                  sessionID,
                  collectionID,
                  challenge,
                  acknowledgement,
                  envelope,
                  enrollmentBinding,
                  enrollmentPublicKey,
                  installationBinding,
                  buildBinding,
                  targetBinding,
              ].allSatisfy({
                  LAB002RoleJSON.lowerHex($0, count: 64)
              }),
              let ordinalValue = LAB002RoleJSON.integer(
                  object["run_ordinal"]
              ),
              let runOrdinal = UInt8(exactly: ordinalValue),
              runOrdinal == 1 || runOrdinal == 2,
              object["run_counter"] as? String
                == String(format: "%016llx", UInt64(runOrdinal)),
              let sourceCommit = object["source_commit"] as? String,
              LAB002RoleJSON.lowerHex(sourceCommit, count: 40),
              let marketingVersion =
                object["marketing_version"] as? String,
              let buildNumber = object["build_number"] as? String,
              LAB002RoleJSON.version(marketingVersion),
              LAB002RoleJSON.version(buildNumber),
              let observerRevision =
                object["observer_revision"] as? String,
              LAB002RoleJSON.observerRevision(observerRevision),
              let environment = object["environment"] as? [String: Any],
              LAB002RoleJSON.environment(environment) != nil,
              let installedFileSize = LAB002RoleJSON.unsigned(
                  object["installed_file_size"]
              ),
              (1...100 * 1024 * 1024).contains(installedFileSize),
              let container = object["container_kind"] as? String,
              ["thin", "fat32", "fat64"].contains(container),
              let activeOrdinalValue = LAB002RoleJSON.integer(
                  object["active_slice_ordinal"]
              ),
              let activeOrdinal = Int(exactly: activeOrdinalValue),
              let activeCPUTypeValue = LAB002RoleJSON.integer(
                  object["active_cpu_type"]
              ),
              let activeCPUType = Int32(exactly: activeCPUTypeValue),
              let activeCPUSubtypeValue = LAB002RoleJSON.integer(
                  object["active_cpu_subtype"]
              ),
              let activeCPUSubtype = Int32(
                  exactly: activeCPUSubtypeValue
              ),
              let activeUUID = object["active_macho_uuid"] as? String,
              LAB002RoleJSON.lowerHex(activeUUID, count: 32),
              let signature = object["signature"] as? [String: Any],
              LAB002RoleJSON.validSignature(signature),
              let phases = object["phases"] as? [[String: Any]],
              let phaseTimes = LAB002RoleJSON.phaseTimes(phases),
              let sliceObjects = object["slices"] as? [[String: Any]],
              let slices = LAB002RoleJSON.validSlices(
                  sliceObjects,
                  installedFileSize: installedFileSize
              ),
              slices.indices.contains(activeOrdinal),
              slices[activeOrdinal].cpuType == activeCPUType,
              slices[activeOrdinal].cpuSubtype == activeCPUSubtype,
              slices[activeOrdinal].uuid == activeUUID,
              let outcomeValue = object["outcome"] as? String,
              let outcome = LAB002RoleReportOutcome(
                  rawValue: outcomeValue
              ),
              let reasonValues = object["reasons"] as? [String],
              reasonValues.count <= 8,
              Set(reasonValues).count == reasonValues.count,
              reasonValues.allSatisfy({
                  LAB002ObserverReason(rawValue: $0) != nil
              }),
              (outcome == .pass && reasonValues.isEmpty)
                || (outcome != .pass && !reasonValues.isEmpty),
              try LAB002RoleJSON.canonical(object) == canonicalBytes
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        self.role = role
        self.sessionID = sessionID
        diskInspectionCompletedAt = phaseTimes.disk
        mappedHashCompletedAt = phaseTimes.mapped
        self.canonicalBytes = canonicalBytes
    }

    fileprivate func matches(_ session: LAB002RoleSession) throws -> Bool {
        guard let object = try JSONSerialization.jsonObject(
            with: canonicalBytes
        ) as? [String: Any] else {
            return false
        }
        return object["collection_id"] as? String == session.collectionID
            && object["session_id"] as? String == session.sessionID
            && LAB002RoleJSON.integer(object["run_ordinal"])
                == Int64(session.runOrdinal)
            && object["run_counter"] as? String == session.runCounter
            && object["challenge_sha256"] as? String
                == session.challengeSHA256
            && object["acknowledgement_sha256"] as? String
                == session.acknowledgementSHA256
            && object["authorization_envelope_sha256"] as? String
                == session.authorizationEnvelopeSHA256
            && object["device_enrollment_binding_sha256"] as? String
                == session.deviceEnrollmentBindingSHA256
            && object["enrollment_public_key"] as? String
                == session.enrollmentPublicKey
            && object["device_installation_binding_sha256"] as? String
                == session.deviceInstallationBindingSHA256
            && object["environment"] as? [String: String]
                == session.environment
            && object["source_commit"] as? String == session.sourceCommit
            && object["marketing_version"] as? String
                == session.marketingVersion
            && object["build_number"] as? String == session.buildNumber
            && object["observer_revision"] as? String
                == session.observerRevision
            && object["build_binding_sha256"] as? String
                == session.buildBindingSHA256
            && diskInspectionCompletedAt >= session.createdAt
    }
}

private enum LAB002RoleJSON {
    static let maximumSafeInteger: UInt64 = 9_007_199_254_740_991

    struct SliceIdentity {
        let cpuType: Int32
        let cpuSubtype: Int32
        let uuid: String
    }

    static func canonical(_ object: [String: Any]) throws -> Data {
        let bytes = try JSONSerialization.data(
            withJSONObject: object,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        guard bytes.count <= LAB002Limit.roleReport else {
            throw LAB002ObserverReason.reportLimitExceeded
        }
        return bytes
    }

    static func integer(_ value: Any?) -> Int64? {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else {
            return nil
        }
        let integer = number.int64Value
        return NSNumber(value: integer) == number ? integer : nil
    }

    static func unsigned(_ value: Any?) -> UInt64? {
        guard let integer = integer(value), integer >= 0 else {
            return nil
        }
        return UInt64(integer)
    }

    static func safeTime(_ value: Int64) -> Bool {
        value >= 0 && UInt64(value) <= maximumSafeInteger
    }

    static func lowerHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count
            && value.utf8.allSatisfy {
                (0x30...0x39).contains($0)
                    || (0x61...0x66).contains($0)
            }
    }

    static func version(_ value: String) -> Bool {
        let parts = value.split(
            separator: ".",
            omittingEmptySubsequences: false
        )
        return !value.isEmpty
            && value.utf8.count <= 32
            && (1...4).contains(parts.count)
            && parts.allSatisfy {
                !$0.isEmpty && $0.utf8.allSatisfy {
                    (0x30...0x39).contains($0)
                }
            }
    }

    static func observerRevision(_ value: String) -> Bool {
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

    static func environment(
        _ object: [String: Any]
    ) -> [String: String]? {
        guard object.count == 3,
              let hardware = object["hardware_model"] as? String,
              let product = object["ios_product_version"] as? String,
              let build = object["ios_build"] as? String,
              hardware.utf8.count <= 32,
              hardware.hasPrefix("iPhone"),
              version(product),
              (3...32).contains(build.utf8.count),
              build.utf8.allSatisfy({
                  (0x30...0x39).contains($0)
                    || (0x41...0x5a).contains($0)
                    || (0x61...0x7a).contains($0)
              })
        else {
            return nil
        }
        let hardwareSuffix = hardware.dropFirst("iPhone".count)
        let hardwareParts = hardwareSuffix.split(
            separator: ",",
            omittingEmptySubsequences: false
        )
        guard hardwareParts.count == 2,
              hardwareParts.allSatisfy({
                  !$0.isEmpty && $0.utf8.allSatisfy {
                      (0x30...0x39).contains($0)
                  }
              }),
              let buildLetter = build.utf8.firstIndex(where: {
                  !(0x30...0x39).contains($0)
              }),
              buildLetter != build.utf8.startIndex,
              (0x41...0x5a).contains(build.utf8[buildLetter]),
              build.utf8.index(after: buildLetter) != build.utf8.endIndex
        else {
            return nil
        }
        return [
            "hardware_model": hardware,
            "ios_build": build,
            "ios_product_version": product,
        ]
    }

    static func validSignature(_ object: [String: Any]) -> Bool {
        guard object.count == 6,
              let presence = object["presence"] as? String,
              let kind = object["kind"] as? String,
              let validation = object["validation"] as? String,
              let validatorID = object["validator_id"] as? String,
              let validatorRevision =
                object["validator_revision"] as? String,
              ["present", "absent"].contains(presence),
              ["cms", "ad_hoc", "unknown", "not_applicable"].contains(kind),
              ["valid", "invalid", "not_checked", "not_applicable"]
                .contains(validation),
              observerRevision(validatorID),
              observerRevision(validatorRevision)
        else {
            return false
        }
        let digest: String?
        if object["superblob_sha256"] is NSNull {
            digest = nil
        } else {
            guard let value = object["superblob_sha256"] as? String else {
                return false
            }
            digest = value
        }
        if presence == "absent" {
            return kind == "not_applicable"
                && validation == "not_applicable"
                && digest == nil
        }
        return kind != "not_applicable"
            && validation != "not_applicable"
            && digest.map { lowerHex($0, count: 64) } == true
    }

    static func phaseTimes(
        _ phases: [[String: Any]]
    ) -> (disk: Int64, mapped: Int64)? {
        guard phases.count == 2,
              phases[0].count == 2,
              phases[0]["phase"] as? String == "disk_inspection",
              let disk = integer(phases[0]["completed_at"]),
              safeTime(disk),
              phases[1].count == 2,
              phases[1]["phase"] as? String == "mapped_hash",
              let mapped = integer(phases[1]["completed_at"]),
              safeTime(mapped),
              mapped >= disk
        else {
            return nil
        }
        return (disk, mapped)
    }

    static func validSlices(
        _ objects: [[String: Any]],
        installedFileSize: UInt64
    ) -> [SliceIdentity]? {
        guard (1...4).contains(objects.count) else {
            return nil
        }
        var result: [SliceIdentity] = []
        var previousEnd: UInt64 = 0
        for (index, object) in objects.enumerated() {
            guard object.count == 21,
                  integer(object["ordinal"]) == Int64(index),
                  let cpuTypeValue = integer(object["cpu_type"]),
                  let cpuType = Int32(exactly: cpuTypeValue),
                  let cpuSubtypeValue = integer(object["cpu_subtype"]),
                  let cpuSubtype = Int32(exactly: cpuSubtypeValue),
                  let uuid = object["macho_uuid"] as? String,
                  lowerHex(uuid, count: 32),
                  let sliceOffset = unsigned(object["slice_file_offset"]),
                  let sliceSize = unsigned(object["slice_file_size"]),
                  sliceSize > 0,
                  let sliceEnd = checkedAdd(sliceOffset, sliceSize),
                  sliceEnd <= installedFileSize,
                  sliceOffset >= previousEnd,
                  let sectionSliceOffset =
                    unsigned(object["section_slice_offset"]),
                  let sectionFileOffset =
                    unsigned(object["section_file_offset"]),
                  let expectedSectionFileOffset =
                    checkedAdd(sliceOffset, sectionSliceOffset),
                  sectionFileOffset == expectedSectionFileOffset,
                  let sectionVMOffset =
                    unsigned(object["section_vm_offset"]),
                  let sectionLength = unsigned(object["section_length"]),
                  (64...1024).contains(sectionLength),
                  let sectionEnd = checkedAdd(
                      sectionSliceOffset,
                      sectionLength
                  ),
                  sectionEnd <= sliceSize,
                  object["segment_name"] as? String == "__TEXT",
                  object["section_name"] as? String == "__oprobe",
                  let command = object["encryption_command"] as? String,
                  ["lc_encryption_info", "lc_encryption_info_64"]
                    .contains(command),
                  let cryptoff = unsigned(object["cryptoff"]),
                  let cryptsize = unsigned(object["cryptsize"]),
                  cryptsize > 0,
                  let cryptEnd = checkedAdd(cryptoff, cryptsize),
                  cryptEnd <= sliceSize,
                  let cryptFileStart =
                    unsigned(object["crypt_file_start"]),
                  cryptFileStart == checkedAdd(sliceOffset, cryptoff),
                  let cryptFileEnd =
                    unsigned(object["crypt_file_end"]),
                  cryptFileEnd == checkedAdd(cryptFileStart, cryptsize),
                  let cryptid = unsigned(object["cryptid"]),
                  cryptid <= UInt64(UInt32.max),
                  let coverage =
                    object["encryption_covers_section"] as? Bool,
                  coverage
                    == (cryptoff <= sectionSliceOffset
                        && cryptEnd >= sectionEnd),
                  let disk = object["disk_sha256"] as? String,
                  lowerHex(disk, count: 64),
                  let mapped = object["mapped_sha256"] as? String,
                  lowerHex(mapped, count: 64),
                  sectionVMOffset <= maximumSafeInteger
            else {
                return nil
            }
            previousEnd = sliceEnd
            result.append(
                SliceIdentity(
                    cpuType: cpuType,
                    cpuSubtype: cpuSubtype,
                    uuid: uuid
                )
            )
        }
        return result
    }

    private static func checkedAdd(
        _ left: UInt64,
        _ right: UInt64
    ) -> UInt64? {
        let result = left.addingReportingOverflow(right)
        return result.overflow ? nil : result.partialValue
    }
}

private final class LAB002RoleDescriptor {
    let rawValue: Int32

    init(_ rawValue: Int32) {
        self.rawValue = rawValue
    }

    deinit {
        Darwin.close(rawValue)
    }
}

private struct LAB002RoleFileIdentity: Equatable {
    let device: dev_t
    let inode: ino_t
    let mode: mode_t
    let links: nlink_t
    let owner: uid_t
    let size: off_t

    init(_ value: stat) {
        device = value.st_dev
        inode = value.st_ino
        mode = value.st_mode
        links = value.st_nlink
        owner = value.st_uid
        size = value.st_size
    }

    var isOwnerOnlyDirectory: Bool {
        mode & S_IFMT == S_IFDIR
            && owner == geteuid()
            && mode & 0o077 == 0
    }

    var isRegularOwnerOnly: Bool {
        mode & S_IFMT == S_IFREG
            && owner == geteuid()
            && mode & 0o077 == 0
            && links == 1
            && size >= 0
    }
}

private final class LAB002RoleReportStore {
    private static let renameExclusive = UInt32(0x0000_0004)
    private static let renameNoFollowAny = UInt32(0x0000_0010)

    private let currentURL: URL
    private let container: LAB002RoleDescriptor
    private let root: LAB002RoleDescriptor
    private let reports: LAB002RoleDescriptor
    private let current: LAB002RoleDescriptor
    private let lock: LAB002RoleDescriptor

    init(containerURL: URL) throws {
        container = try Self.openDirectory(
            url: containerURL,
            requireOwnerOnly: false
        )
        root = try Self.openDirectory(
            parent: container,
            name: LAB002FixedName.root
        )
        reports = try Self.openDirectory(
            parent: root,
            name: LAB002FixedName.reports
        )
        current = try Self.openDirectory(
            parent: reports,
            name: LAB002FixedName.currentReports
        )
        lock = try Self.openRegular(
            parent: root,
            name: LAB002FixedName.lock
        )
        currentURL = containerURL
            .appendingPathComponent(LAB002FixedName.root, isDirectory: true)
            .appendingPathComponent(
                LAB002FixedName.reports,
                isDirectory: true
            )
            .appendingPathComponent(
                LAB002FixedName.currentReports,
                isDirectory: true
            )
    }

    func publish(
        observation: LAB002LocalRoleObservation,
        fixedBundle: Bundle,
        fixedRole: LAB002Role
    ) throws {
        try withLock {
            try publishLocked(
                observation: observation,
                fixedBundle: fixedBundle,
                fixedRole: fixedRole
            )
        }
    }

#if DEBUG
    func publishForTesting(
        observation: LAB002LocalRoleObservation,
        fixedRole: LAB002Role
    ) throws {
        try withLock {
            try publishLocked(
                observation: observation,
                fixedBundle: nil,
                fixedRole: fixedRole
            )
        }
    }
#endif

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        guard flock(lock.rawValue, LOCK_EX | LOCK_NB) == 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        defer {
            _ = flock(lock.rawValue, LOCK_UN)
        }
        return try body()
    }

    private func publishLocked(
        observation: LAB002LocalRoleObservation,
        fixedBundle: Bundle?,
        fixedRole: LAB002Role
    ) throws {
        guard try Self.entryIdentity(
            parent: container,
            name: LAB002FixedName.root
        ) == Self.identity(root),
        try Self.entryIdentity(
            parent: root,
            name: LAB002FixedName.reports
        ) == Self.identity(reports),
        try Self.entryIdentity(
            parent: reports,
            name: LAB002FixedName.currentReports
        ) == Self.identity(current),
        try Self.entryIdentity(
            parent: root,
            name: LAB002FixedName.lock
        ) == Self.identity(lock)
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let names = try listEntries()
        if names.contains(fixedRole.reportName) {
            throw LAB002ObserverReason.duplicateRoleReport
        }
        let temporaryNames = Set([
            LAB002FixedName.sessionTemporary,
            LAB002FixedName.mainAppReportTemporary,
            LAB002FixedName.frameworkReportTemporary,
            LAB002FixedName.shareExtensionReportTemporary,
        ])
        guard names.isDisjoint(with: temporaryNames) else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        var expectedNames = Set([LAB002FixedName.session])
        expectedNames.formUnion(
            fixedRole.precedingRoles.map(\.reportName)
        )
        guard names == expectedNames else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }

        let session = try readSession()
        if let fixedBundle {
            try validateBundle(fixedBundle, matches: session)
        }
        let report = try LAB002RoleReport(
            session: session,
            observation: observation,
            fixedRole: fixedRole
        )
        guard try report.matches(session) else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }

        var lastMapped = session.createdAt
        for precedingRole in fixedRole.precedingRoles {
            let prior = try readReport(name: precedingRole.reportName)
            guard prior.role == precedingRole,
                  try prior.matches(session),
                  prior.diskInspectionCompletedAt >= lastMapped
            else {
                throw LAB002ObserverReason.staleOrConflictingSession
            }
            lastMapped = prior.mappedHashCompletedAt
        }
        guard report.diskInspectionCompletedAt >= lastMapped else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        try writeExclusive(report)
    }

    private func validateBundle(
        _ bundle: Bundle,
        matches session: LAB002RoleSession
    ) throws {
        guard bundle.object(
            forInfoDictionaryKey: "LAB002BuildBindingSHA256"
        ) as? String == session.buildBindingSHA256,
        bundle.object(
            forInfoDictionaryKey: "LAB002ObserverRevision"
        ) as? String == session.observerRevision,
        bundle.object(
            forInfoDictionaryKey: "LAB002SourceCommit"
        ) as? String == session.sourceCommit,
        bundle.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String == session.marketingVersion,
        bundle.object(
            forInfoDictionaryKey: "CFBundleVersion"
        ) as? String == session.buildNumber
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
    }

    private func readSession() throws -> LAB002RoleSession {
        try LAB002RoleSession(
            canonicalBytes: readBounded(
                name: LAB002FixedName.session,
                maximum: LAB002Limit.sessionReport
            )
        )
    }

    private func readReport(name: String) throws -> LAB002RoleReport {
        try LAB002RoleReport(
            canonicalBytes: readBounded(
                name: name,
                maximum: LAB002Limit.roleReport
            )
        )
    }

    private func readBounded(name: String, maximum: Int) throws -> Data {
        let descriptor = try Self.openRegular(parent: current, name: name)
        let before = try Self.identity(descriptor)
        guard before.isRegularOwnerOnly,
              before.size <= maximum
        else {
            throw LAB002ObserverReason.reportLimitExceeded
        }
        var bytes = [UInt8](repeating: 0, count: maximum + 1)
        let capacity = bytes.count
        var count = 0
        while count < capacity {
            let result = bytes.withUnsafeMutableBytes {
                Darwin.read(
                    descriptor.rawValue,
                    $0.baseAddress!.advanced(by: count),
                    capacity - count
                )
            }
            if result < 0, errno == EINTR {
                continue
            }
            guard result >= 0 else {
                throw LAB002ObserverReason.staleOrConflictingSession
            }
            if result == 0 {
                break
            }
            count += result
        }
        guard count <= maximum,
              try Self.identity(descriptor) == before,
              before.size == count,
              try Self.entryIdentity(parent: current, name: name) == before
        else {
            throw LAB002ObserverReason.reportLimitExceeded
        }
        return Data(bytes.prefix(count))
    }

    private func listEntries() throws -> Set<String> {
        let duplicate = dup(current.rawValue)
        guard duplicate >= 0, let stream = fdopendir(duplicate) else {
            if duplicate >= 0 {
                Darwin.close(duplicate)
            }
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        defer {
            closedir(stream)
        }
        var names = Set<String>()
        while let entry = readdir(stream) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                pointer in
                pointer.withMemoryRebound(
                    to: CChar.self,
                    capacity: Int(NAME_MAX) + 1
                ) {
                    String(cString: $0)
                }
            }
            if name == "." || name == ".." {
                continue
            }
            guard names.insert(name).inserted else {
                throw LAB002ObserverReason.staleOrConflictingSession
            }
        }
        return names
    }

    private func writeExclusive(_ report: LAB002RoleReport) throws {
        let role = report.role
        guard try Self.entryIdentity(
            parent: current,
            name: role.reportName
        ) == nil else {
            throw LAB002ObserverReason.duplicateRoleReport
        }
        guard try Self.entryIdentity(
            parent: current,
            name: role.temporaryReportName
        ) == nil else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let raw = role.temporaryReportName.withCString {
            openat(
                current.rawValue,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                0o600
            )
        }
        guard raw >= 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let descriptor = LAB002RoleDescriptor(raw)
        let bytes = report.canonicalBytes
        try bytes.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let result = Darwin.write(
                    descriptor.rawValue,
                    buffer.baseAddress!.advanced(by: offset),
                    buffer.count - offset
                )
                if result < 0, errno == EINTR {
                    continue
                }
                guard result > 0 else {
                    throw LAB002ObserverReason.staleOrConflictingSession
                }
                offset += result
            }
        }
        guard fsync(descriptor.rawValue) == 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let temporaryURL = currentURL.appendingPathComponent(
            role.temporaryReportName
        )
        do {
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: temporaryURL.path
            )
            var protectedURL = temporaryURL
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try protectedURL.setResourceValues(values)
        } catch {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        guard fsync(descriptor.rawValue) == 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let temporaryIdentity = try Self.identity(descriptor)
        guard temporaryIdentity.isRegularOwnerOnly,
              try Self.entryIdentity(
                  parent: current,
                  name: role.temporaryReportName
              ) == temporaryIdentity
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let flags = Self.renameExclusive | Self.renameNoFollowAny
        let result = role.temporaryReportName.withCString { source in
            role.reportName.withCString { destination in
                renameatx_np(
                    current.rawValue,
                    source,
                    current.rawValue,
                    destination,
                    flags
                )
            }
        }
        guard result == 0, fsync(current.rawValue) == 0,
              try Self.entryIdentity(
                  parent: current,
                  name: role.reportName
              ) == temporaryIdentity
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
    }

    private static func openDirectory(
        url: URL,
        requireOwnerOnly: Bool
    ) throws -> LAB002RoleDescriptor {
        let raw = url.withUnsafeFileSystemRepresentation {
            guard let pointer = $0 else { return Int32(-1) }
            return open(
                pointer,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard raw >= 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let descriptor = LAB002RoleDescriptor(raw)
        let fileIdentity = try identity(descriptor)
        guard fileIdentity.mode & S_IFMT == S_IFDIR,
              fileIdentity.owner == geteuid(),
              !requireOwnerOnly || fileIdentity.isOwnerOnlyDirectory
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        return descriptor
    }

    private static func openDirectory(
        parent: LAB002RoleDescriptor,
        name: String
    ) throws -> LAB002RoleDescriptor {
        let raw = name.withCString {
            openat(
                parent.rawValue,
                $0,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard raw >= 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let descriptor = LAB002RoleDescriptor(raw)
        let descriptorIdentity = try identity(descriptor)
        guard descriptorIdentity.isOwnerOnlyDirectory,
              try entryIdentity(parent: parent, name: name)
                == descriptorIdentity
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        return descriptor
    }

    private static func openRegular(
        parent: LAB002RoleDescriptor,
        name: String
    ) throws -> LAB002RoleDescriptor {
        let raw = name.withCString {
            openat(
                parent.rawValue,
                $0,
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
            )
        }
        guard raw >= 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let descriptor = LAB002RoleDescriptor(raw)
        let descriptorIdentity = try identity(descriptor)
        guard descriptorIdentity.isRegularOwnerOnly,
              try entryIdentity(parent: parent, name: name)
                == descriptorIdentity
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        return descriptor
    }

    private static func identity(
        _ descriptor: LAB002RoleDescriptor
    ) throws -> LAB002RoleFileIdentity {
        var value = stat()
        guard fstat(descriptor.rawValue, &value) == 0 else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        return LAB002RoleFileIdentity(value)
    }

    private static func entryIdentity(
        parent: LAB002RoleDescriptor,
        name: String
    ) throws -> LAB002RoleFileIdentity? {
        var value = stat()
        let result = name.withCString {
            fstatat(parent.rawValue, $0, &value, AT_SYMLINK_NOFOLLOW)
        }
        if result == 0 {
            return LAB002RoleFileIdentity(value)
        }
        if errno == ENOENT {
            return nil
        }
        throw LAB002ObserverReason.staleOrConflictingSession
    }
}

enum LAB002RoleReportPublisher {
    static func publish(
        _ observation: LAB002LocalRoleObservation,
        fixedBundle: Bundle,
        fixedRole: LAB002Role
    ) throws {
        guard let identifier = fixedBundle.object(
            forInfoDictionaryKey: "LAB002AppGroupIdentifier"
        ) as? String,
        identifier.hasPrefix("group."),
        identifier.utf8.count <= 255,
        let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: identifier
        )
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        try LAB002RoleReportStore(containerURL: containerURL).publish(
            observation: observation,
            fixedBundle: fixedBundle,
            fixedRole: fixedRole
        )
    }
}

#if DEBUG
enum LAB002RoleReportTestHarness {
    static func publish(
        _ observation: LAB002LocalRoleObservation,
        fixedRole: LAB002Role,
        testContainerURL: URL
    ) throws {
        try LAB002RoleReportStore(
            containerURL: testContainerURL
        ).publishForTesting(
            observation: observation,
            fixedRole: fixedRole
        )
    }
}
#endif
