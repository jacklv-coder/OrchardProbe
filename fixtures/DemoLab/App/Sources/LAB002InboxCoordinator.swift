import CryptoKit
import Darwin
import DemoFramework
import Foundation
import UIKit

enum LAB002AuthorizationKind {
    case installationEnrollment
    case collectionRun
}

struct LAB002AuthorizationMetadata {
    let kind: LAB002AuthorizationKind
    let buildBindingSHA256: String
    let notBefore: Int64
    let notAfter: Int64
    let expectedRunCounter: UInt64?
    let enrollmentFacts: LAB002VerifiedEnrollmentFacts?
    let runFacts: LAB002VerifiedRunFacts?

    init(
        kind: LAB002AuthorizationKind,
        buildBindingSHA256: String,
        notBefore: Int64,
        notAfter: Int64,
        expectedRunCounter: UInt64?,
        enrollmentFacts: LAB002VerifiedEnrollmentFacts? = nil,
        runFacts: LAB002VerifiedRunFacts? = nil
    ) {
        self.kind = kind
        self.buildBindingSHA256 = buildBindingSHA256
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.expectedRunCounter = expectedRunCounter
        self.enrollmentFacts = enrollmentFacts
        self.runFacts = runFacts
    }
}

struct LAB002VerifiedEnrollmentFacts {
    let acknowledgementSHA256: String
    let authorizationPolicyVersion: String
    let enrollmentChallenge: String
    let experimentID: String
    let deviceSelectionNonce: String
    let expectedEnvironment: LAB002SessionEnvironment
}

struct LAB002VerifiedRunFacts {
    let collectionID: String
    let runOrdinal: UInt8
    let challengeSHA256: String
    let acknowledgementSHA256: String
    let deviceEnrollmentBindingSHA256: String
    let enrollmentPublicKey: String
    let expectedDeviceInstallationBindingSHA256: String
}

struct LAB002RunBuildFacts {
    let observerRevision: String
    let sourceCommit: String
    let marketingVersion: String
    let buildNumber: String
}

protocol LAB002AuthorizationValidating {
    func validate(_ canonicalBytes: Data) throws -> LAB002AuthorizationMetadata
}

protocol LAB002RuntimeContextProviding {
    var buildBindingSHA256: String { get }
    var runBuildFacts: LAB002RunBuildFacts { get }

    func currentUnixTime() throws -> Int64
    func currentEnvironment() throws -> LAB002SessionEnvironment
    func deviceInstallationBinding(
        state: LAB002InstallationState
    ) throws -> String
}

protocol LAB002RunRoleObserving {
    func observeMainAndFramework() throws
}

private struct LAB002ProductionRunRoleObserver: LAB002RunRoleObserving {
    func observeMainAndFramework() throws {
        try observeCurrentMainExecutable()
        try observeCurrentFrameworkImage()
    }
}

#if DEBUG
struct LAB002NoopRunRoleObserver: LAB002RunRoleObserving {
    func observeMainAndFramework() throws {}
}
#endif

enum LAB002CoordinatorError: Error {
    case wrongOperation
    case wrongBuild
    case stale
    case authorizationStillValid
    case invalidWindow
    case invalidRuntimeContext
}

enum LAB002DiscardReason {
    case malformed
    case expired
    case buildMismatch
}

struct LAB002ConsumedRunAuthorization {
    let canonicalBytes: Data
    let metadata: LAB002AuthorizationMetadata
}

private struct LAB002ProductionRuntimeContext: LAB002RuntimeContextProviding {
    let buildBindingSHA256: String
    let runBuildFacts: LAB002RunBuildFacts
    private let identityNonce: Data

    init(bundle: Bundle = .main) throws {
        guard let buildBindingSHA256 = bundle.object(
            forInfoDictionaryKey: "LAB002BuildBindingSHA256"
        ) as? String,
        buildBindingSHA256.utf8.count == 64,
        buildBindingSHA256.utf8.allSatisfy({
            (0x30...0x39).contains($0) || (0x61...0x66).contains($0)
        })
        else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        guard let observerRevision = bundle.object(
            forInfoDictionaryKey: "LAB002ObserverRevision"
        ) as? String,
        let sourceCommit = bundle.object(
            forInfoDictionaryKey: "LAB002SourceCommit"
        ) as? String,
        let identityNonceHex = bundle.object(
            forInfoDictionaryKey: "LAB002IdentityNonce"
        ) as? String,
        let identityNonce = Self.decodeHex(identityNonceHex),
        identityNonce.count == 32,
        let marketingVersion = bundle.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String,
        let buildNumber = bundle.object(
            forInfoDictionaryKey: "CFBundleVersion"
        ) as? String
        else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        self.buildBindingSHA256 = buildBindingSHA256
        self.identityNonce = identityNonce
        runBuildFacts = LAB002RunBuildFacts(
            observerRevision: observerRevision,
            sourceCommit: sourceCommit,
            marketingVersion: marketingVersion,
            buildNumber: buildNumber
        )
    }

    func currentUnixTime() throws -> Int64 {
        let seconds = Date().timeIntervalSince1970
        guard seconds.isFinite,
              seconds >= 0,
              seconds < Double(Int64.max)
        else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        return Int64(seconds.rounded(.down))
    }

    func currentEnvironment() throws -> LAB002SessionEnvironment {
        try LAB002SessionEnvironment(
            hardwareModel: Self.sysctlString("hw.machine"),
            iosProductVersion: Self.sysctlString("kern.osproductversion"),
            iosBuild: Self.sysctlString("kern.osversion")
        )
    }

    func deviceInstallationBinding(
        state: LAB002InstallationState
    ) throws -> String {
        guard let publicKey = Self.decodeHex(state.enrollmentPublicKey),
              let installationNonce = Self.decodeHex(state.installationNonce),
              publicKey.count == 32,
              installationNonce.count == 32,
              let identifier = UIDevice.current.identifierForVendor?
                .uuidString.lowercased()
        else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        let environment = try currentEnvironment()
        var bytes = Data(
            "orchardprobe.demolab.lab002.device-installation.v1\0".utf8
        )
        bytes.append(identityNonce)
        bytes.append(publicKey)
        bytes.append(installationNonce)
        for value in [
            identifier,
            environment.hardwareModel,
            environment.iosProductVersion,
            environment.iosBuild,
        ] {
            let valueBytes = Data(value.utf8)
            var length = UInt32(valueBytes.count).bigEndian
            withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }
            bytes.append(valueBytes)
        }
        return Data(SHA256.hash(data: bytes)).hexLowercase
    }

    private static func sysctlString(_ name: String) throws -> String {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0,
              (2...33).contains(size)
        else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        var bytes = [UInt8](repeating: 0, count: size)
        guard sysctlbyname(name, &bytes, &size, nil, 0) == 0,
              size == bytes.count,
              bytes.last == 0
        else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        bytes.removeLast()
        guard let value = String(bytes: bytes, encoding: .ascii) else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        return value
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

actor LAB002InboxCoordinator {
    private static let allowedClockSkew: Int64 = 120

    private let storage: LAB002FixedStorage
    private let validator: LAB002AuthorizationValidating
    private let enrollment: LAB002EnrollmentStateCoordinator
    private let runtimeContext: any LAB002RuntimeContextProviding
    private let random: any LAB002RandomBytesGenerating
    private let runRoleObserver: any LAB002RunRoleObserving
    private let sessionEvidenceStore: any LAB002SessionEvidenceStoring
    private var completedSessionThisCoordinator:
        LAB002CompletedSessionSnapshot?
    private var constructedSessionExport: LAB002ConstructedSessionExport?

    init(validator: LAB002AuthorizationValidating) throws {
        let fixedStorage = try LAB002FixedStorage.production()
        storage = fixedStorage
        self.validator = validator
        enrollment = try LAB002EnrollmentStateCoordinator.production(
            storage: fixedStorage
        )
        runtimeContext = try LAB002ProductionRuntimeContext()
        random = LAB002SystemRandomBytes()
        runRoleObserver = LAB002ProductionRunRoleObserver()
        sessionEvidenceStore = LAB002ProductionSessionEvidenceStore()
    }

    #if DEBUG
    init(
        testContainerURL: URL,
        validator: LAB002AuthorizationValidating,
        enrollmentKeyStore: any LAB002EnrollmentKeyStoring,
        random: any LAB002RandomBytesGenerating,
        testRuntimeContext: any LAB002RuntimeContextProviding,
        testRunRoleObserver: any LAB002RunRoleObserving =
            LAB002NoopRunRoleObserver(),
        testSessionEvidenceStore:
            (any LAB002SessionEvidenceStoring)? = nil
    ) throws {
        let fixedStorage = try LAB002FixedStorage(
            testContainerURL: testContainerURL
        )
        storage = fixedStorage
        self.validator = validator
        enrollment = LAB002EnrollmentStateCoordinator(
            storage: fixedStorage,
            keyStore: enrollmentKeyStore,
            random: random
        )
        runtimeContext = testRuntimeContext
        self.random = random
        runRoleObserver = testRunRoleObserver
        sessionEvidenceStore = testSessionEvidenceStore
            ?? LAB002TestSessionEvidenceStore(
                containerURL: testContainerURL
            )
    }
    #endif

    func importAuthorization(from selectedDocumentURL: URL) throws {
        let bytes = try storage.readExternalDocument(
            selectedDocumentURL,
            maximum: LAB002Limit.controlDocument
        )
        _ = try validator.validate(bytes)
        try storage.withCoordinatorLock {
            try storage.publishAuthorization(bytes)
        }
    }

    func startCleanRun() throws -> LAB002ConsumedRunAuthorization {
        let consumed = try storage.withCoordinatorLock {
            let pending = try storage.quarantineRunAuthorization()
            let quarantined = pending.quarantined
            let metadata = try validator.validate(quarantined.bytes)
            let now = try runtimeContext.currentUnixTime()
            let buildBindingSHA256 = runtimeContext.buildBindingSHA256
            guard metadata.kind == .collectionRun,
                  let expectedCounter = metadata.expectedRunCounter,
                  let runFacts = metadata.runFacts,
                  let expectedOrdinal = UInt8(exactly: expectedCounter),
                  runFacts.runOrdinal == expectedOrdinal
            else {
                throw LAB002CoordinatorError.wrongOperation
            }
            try validateWindow(metadata, now: now)
            guard metadata.buildBindingSHA256 == buildBindingSHA256 else {
                throw LAB002CoordinatorError.wrongBuild
            }
            let continuity = try enrollment.loadForRun(
                buildBindingSHA256: buildBindingSHA256
            )
            guard continuity.state.enrollmentPublicKey
                    == runFacts.enrollmentPublicKey
            else {
                throw LAB002EnrollmentError.keyMismatch
            }
            let environment = try runtimeContext.currentEnvironment()
            let installationBinding = try runtimeContext
                .deviceInstallationBinding(state: continuity.state)
            guard installationBinding
                    == runFacts.expectedDeviceInstallationBindingSHA256
            else {
                throw LAB002EnrollmentError.buildMismatch
            }
            let counterRecord = try storage.readCounter()
            if let counterRecord,
               counterRecord.buildBindingSHA256 != buildBindingSHA256
            {
                throw LAB002StorageError.counterMismatch
            }
            let currentCounter = counterRecord?.counter ?? 0
            let hasSessionDirectory = try storage.hasSessionDirectory()
            if !pending.resumedAfterPersistence,
               currentCounter == expectedCounter || hasSessionDirectory
            {
                try storage.restoreAuthorization(quarantined)
                if hasSessionDirectory {
                    throw LAB002StorageError.existingEntry(
                        LAB002FixedName.currentReports
                    )
                }
                throw LAB002StorageError.counterMismatch
            }
            let recoverableSession = try storage.readRecoverableSession()
            let sessionID = try recoverableSession?.sessionID
                ?? random.bytes(count: 32).hexLowercase
            let createdAt = recoverableSession?.createdAt ?? now
            let report = try LAB002SessionReport(
                observerRevision: runtimeContext.runBuildFacts.observerRevision,
                buildBindingSHA256: buildBindingSHA256,
                collectionID: runFacts.collectionID,
                runOrdinal: runFacts.runOrdinal,
                challengeSHA256: runFacts.challengeSHA256,
                acknowledgementSHA256: runFacts.acknowledgementSHA256,
                authorizationEnvelopeSHA256: Data(
                    SHA256.hash(data: quarantined.bytes)
                ).hexLowercase,
                authorizationNotAfter: metadata.notAfter,
                deviceEnrollmentBindingSHA256:
                    runFacts.deviceEnrollmentBindingSHA256,
                enrollmentPublicKey: runFacts.enrollmentPublicKey,
                deviceInstallationBindingSHA256: installationBinding,
                environment: environment,
                sessionID: sessionID,
                runCounter: String(format: "%016llx", expectedCounter),
                createdAt: createdAt,
                completedAt: nil,
                sourceCommit: runtimeContext.runBuildFacts.sourceCommit,
                marketingVersion: runtimeContext.runBuildFacts.marketingVersion,
                buildNumber: runtimeContext.runBuildFacts.buildNumber,
                state: .collecting
            )
            if let recoverableSession {
                guard pending.resumedAfterPersistence,
                      currentCounter == expectedCounter,
                      recoverableSession == report
                else {
                    throw LAB002StorageError.counterMismatch
                }
            } else if currentCounter == expectedCounter {
                guard pending.resumedAfterPersistence else {
                    throw LAB002StorageError.counterMismatch
                }
            } else {
                guard !hasSessionDirectory else {
                    throw LAB002StorageError.existingEntry(
                        LAB002FixedName.currentReports
                    )
                }
                try storage.validateExpectedCounter(
                    expected: expectedCounter,
                    buildBindingSHA256: buildBindingSHA256
                )
                _ = try storage.commitExpectedCounter(
                    expected: expectedCounter,
                    buildBindingSHA256: buildBindingSHA256
                )
            }
            try storage.createOrRecoverSession(report)
            try storage.deleteAuthorization(quarantined)
            return LAB002ConsumedRunAuthorization(
                canonicalBytes: quarantined.bytes,
                metadata: metadata
            )
        }
        try runRoleObserver.observeMainAndFramework()
        return consumed
    }

    func completeRunAfterShareExtension()
        throws -> LAB002SessionCompletionOutcome
    {
        let completedAt = try runtimeContext.currentUnixTime()
        let outcome = try sessionEvidenceStore.complete(at: completedAt)
        if outcome == .committed {
            completedSessionThisCoordinator =
                try sessionEvidenceStore.completedSnapshot()
        }
        return outcome
    }

    func confirmInstallationEnrollment() throws -> LAB002EnrollmentCompletion {
        try storage.withCoordinatorLock {
            let hasQuarantinedAuthorization =
                try storage.hasQuarantinedAuthorization()
            if !hasQuarantinedAuthorization,
               try storage.readInstallationState() != nil
            {
                throw LAB002EnrollmentError.alreadyEnrolled
            }
            let pending = try storage.quarantineEnrollmentAuthorization()
            let quarantined = pending.quarantined
            let metadata = try validator.validate(quarantined.bytes)
            let now = try runtimeContext.currentUnixTime()
            let buildBindingSHA256 = runtimeContext.buildBindingSHA256
            guard metadata.kind == .installationEnrollment,
                  metadata.expectedRunCounter == nil,
                  let enrollmentFacts = metadata.enrollmentFacts
            else {
                throw LAB002CoordinatorError.wrongOperation
            }
            try validateWindow(metadata, now: now)
            guard now >= metadata.notBefore,
                  now <= metadata.notAfter
            else {
                throw LAB002CoordinatorError.stale
            }
            guard metadata.buildBindingSHA256 == buildBindingSHA256 else {
                throw LAB002CoordinatorError.wrongBuild
            }
            let environment = try runtimeContext.currentEnvironment()
            guard environment == enrollmentFacts.expectedEnvironment else {
                throw LAB002CoordinatorError.invalidRuntimeContext
            }
            let continuity: LAB002EnrollmentContinuity
            if pending.resumedAfterPersistence,
               try storage.readInstallationState() != nil
            {
                continuity = try enrollment.loadForRun(
                    buildBindingSHA256: buildBindingSHA256
                )
            } else {
                continuity = try enrollment.createAfterAuthenticatedEnrollment(
                    buildBindingSHA256: buildBindingSHA256
                )
            }
            let installationBinding = try runtimeContext
                .deviceInstallationBinding(state: continuity.state)
            let receipt = try LAB002EvidenceArtifactBuilder
                .enrollmentReceipt(
                    authorizationEnvelope: quarantined.bytes,
                    facts: enrollmentFacts,
                    continuity: continuity,
                    deviceInstallationBindingSHA256:
                        installationBinding,
                    environment: environment,
                    createdAt: now
                )
            try storage.deleteAuthorization(quarantined)
            return LAB002EnrollmentCompletion(
                state: continuity.state,
                receipt: receipt.artifact,
                deviceSelectionFingerprintSHA256:
                    receipt.deviceSelectionFingerprintSHA256
            )
        }
    }

    func exportLAB002Evidence() throws -> LAB002ShareArtifact {
        if let constructedSessionExport {
            return constructedSessionExport.artifact
        }
        let snapshot: LAB002CompletedSessionSnapshot
        if let completedSessionThisCoordinator {
            let current = try sessionEvidenceStore.completedSnapshot()
            guard current == completedSessionThisCoordinator else {
                throw LAB002ObserverReason.staleOrConflictingSession
            }
            snapshot = current
        } else {
            let completedAt = try runtimeContext.currentUnixTime()
            let outcome = try sessionEvidenceStore.complete(at: completedAt)
            guard outcome == .committed else {
                throw LAB002ObserverReason.staleOrConflictingSession
            }
            snapshot = try sessionEvidenceStore.completedSnapshot()
            completedSessionThisCoordinator = snapshot
        }
        let continuity = try enrollment.loadForRun(
            buildBindingSHA256: snapshot.buildBindingSHA256
        )
        guard continuity.state.enrollmentPublicKey
                == snapshot.enrollmentPublicKey
        else {
            throw LAB002EnrollmentError.keyMismatch
        }
        let constructed = try LAB002EvidenceArtifactBuilder.sessionExport(
            snapshot: snapshot,
            signingKey: continuity.signingKey
        )
        constructedSessionExport = constructed
        return constructed.artifact
    }

    func confirmExportReceivedAndCleanReports(
        confirmed: Bool
    ) throws -> LAB002CleanupOutcome {
        guard confirmed else {
            throw LAB002EvidenceArtifactError.explicitConfirmationRequired
        }
        guard let constructedSessionExport else {
            throw LAB002EvidenceArtifactError.exportNotConstructed
        }
        let outcome = try sessionEvidenceStore.cleanup(
            expectedSnapshot: constructedSessionExport.snapshot
        )
        completedSessionThisCoordinator = nil
        self.constructedSessionExport = nil
        return outcome
    }

    func discardStaleAuthorization() throws -> LAB002DiscardReason {
        try storage.withCoordinatorLock {
            let quarantined = try storage.quarantineAuthorization()
            let metadata: LAB002AuthorizationMetadata
            do {
                metadata = try validator.validate(quarantined.bytes)
            } catch {
                try storage.deleteAuthorization(quarantined)
                return .malformed
            }
            let now = try runtimeContext.currentUnixTime()
            let buildBindingSHA256 = runtimeContext.buildBindingSHA256
            if metadata.buildBindingSHA256 != buildBindingSHA256 {
                try storage.deleteAuthorization(quarantined)
                return .buildMismatch
            }
            let duration = metadata.notAfter.subtractingReportingOverflow(
                metadata.notBefore
            )
            guard !duration.overflow,
                  duration.partialValue == 900
            else {
                try storage.deleteAuthorization(quarantined)
                return .malformed
            }
            let latest = metadata.notAfter.addingReportingOverflow(
                Self.allowedClockSkew
            )
            guard !latest.overflow else {
                try storage.deleteAuthorization(quarantined)
                return .malformed
            }
            if now > latest.partialValue {
                try storage.deleteAuthorization(quarantined)
                return .expired
            }
            try storage.restoreAuthorization(quarantined)
            throw LAB002CoordinatorError.authorizationStillValid
        }
    }

    private func validateWindow(
        _ metadata: LAB002AuthorizationMetadata,
        now: Int64
    ) throws {
        let duration = metadata.notAfter.subtractingReportingOverflow(
            metadata.notBefore
        )
        guard !duration.overflow,
              duration.partialValue == 900
        else {
            throw LAB002CoordinatorError.invalidWindow
        }
        let earliest = metadata.notBefore.subtractingReportingOverflow(
            Self.allowedClockSkew
        )
        let latest = metadata.notAfter.addingReportingOverflow(
            Self.allowedClockSkew
        )
        guard !earliest.overflow,
              !latest.overflow,
              now >= earliest.partialValue,
              now <= latest.partialValue
        else {
            throw LAB002CoordinatorError.stale
        }
    }
}
