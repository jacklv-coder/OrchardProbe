import CryptoKit
import Darwin
import DemoFramework
import Foundation
import UIKit

enum LAB002AuthorizationKind: Equatable {
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
    let authorizedTargetManifestSHA256: String
    let enrollmentChallenge: String
    let experimentID: String
    let deviceSelectionNonce: String
    let expectedEnvironment: LAB002SessionEnvironment
}

struct LAB002VerifiedRunFacts {
    let experimentID: String
    let authorizedTargetManifestSHA256: String
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
    case enrollmentRequired
    case alreadyEnrolled
    case runPrerequisiteMismatch
}

enum LAB002WorkflowRecoveryState: Equatable {
    case ready
    case enrollmentReceipt(
        LAB002ShareArtifact,
        fingerprintSHA256: String
    )
    case pendingAuthorization(LAB002AuthorizationKind)
    case discardableAuthorization
    case runInProgress
    case completedRun
    case failedRun
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

    @discardableResult
    func importAuthorization(
        from selectedDocumentURL: URL
    ) throws -> LAB002AuthorizationMetadata {
        let bytes = try storage.readExternalDocument(
            selectedDocumentURL,
            maximum: LAB002Limit.controlDocument
        )
        let metadata = try validator.validate(bytes)
        try storage.withCoordinatorLock {
            try storage.publishAuthorization(bytes)
        }
        return metadata
    }

    func recoverWorkflowState() throws -> LAB002WorkflowRecoveryState {
        let state: LAB002WorkflowRecoveryState =
            try storage.withCoordinatorLock {
                let pending = try storage.readPendingAuthorization()
                let installationState = try storage.readInstallationState()
                let lifecycle = try storage.readRunLifecycle()
                if let lifecycle,
                   lifecycle.buildBindingSHA256
                    != runtimeContext.buildBindingSHA256
                {
                    return .failedRun
                }
                if lifecycle?.phase == .cleanupPending {
                    return .failedRun
                }
                let session = try storage.readRecoverableSession()
                let recoveredReceipt = try storage
                    .readEnrollmentReceipt()
                    .map {
                        guard let installationState else {
                            throw LAB002EnrollmentError.notEnrolled
                        }
                        let authorizationEnvelope =
                            try LAB002EvidenceArtifactBuilder
                            .enrollmentAuthorizationEnvelope(
                                recoveryRecordBytes: $0
                            )
                        let metadata = try validator.validate(
                            authorizationEnvelope
                        )
                        guard metadata.kind == .installationEnrollment,
                              metadata.buildBindingSHA256
                                == installationState.buildBindingSHA256,
                              installationState.buildBindingSHA256
                                == runtimeContext.buildBindingSHA256,
                              let facts = metadata.enrollmentFacts
                        else {
                            throw LAB002EvidenceArtifactError.invalidArtifact
                        }
                        let environment = try runtimeContext
                            .currentEnvironment()
                        guard environment == facts.expectedEnvironment else {
                            throw LAB002EvidenceArtifactError.invalidArtifact
                        }
                        let installationBinding = try runtimeContext
                            .deviceInstallationBinding(
                                state: installationState
                            )
                        let recovered =
                            try LAB002EvidenceArtifactBuilder
                            .recoverEnrollmentReceipt(
                                recoveryRecordBytes: $0,
                                expectedState: installationState,
                                authorizationMetadata: metadata,
                                expectedDeviceInstallationBindingSHA256:
                                    installationBinding,
                                expectedEnvironment: environment
                            )
                        return recovered
                    }

                if let session {
                    if let pending {
                        guard pending.isQuarantined,
                              session.state == .collecting,
                              lifecycle == nil
                                || lifecycleMatches(
                                    lifecycle,
                                    session: session,
                                    phase: .observingMainAndFramework
                                ),
                              let metadata = try? validator.validate(
                                  pending.bytes
                              ),
                              metadata.kind == .collectionRun,
                              let installationState,
                              try quarantinedRunMatchesSession(
                                  pending,
                                  metadata: metadata,
                                  session: session,
                                  installationState: installationState
                              )
                        else {
                            throw LAB002ObserverReason
                                .staleOrConflictingSession
                        }
                        return .pendingAuthorization(.collectionRun)
                    }
                    guard let installationState else {
                        return .failedRun
                    }
                    do {
                        guard try persistedSessionMatchesEnrollment(
                            session,
                            installationState: installationState
                        ) else {
                            return .failedRun
                        }
                    } catch {
                        return .failedRun
                    }
                    switch session.state {
                    case .collecting:
                        return lifecycleMatches(
                            lifecycle,
                            session: session,
                            phase: .awaitingShareExtension
                        ) ? .runInProgress : .failedRun
                    case .complete:
                        return lifecycleMatches(
                            lifecycle,
                            session: session,
                            phase: .completionCommitted
                        ) ? .completedRun : .failedRun
                    case .failed:
                        return .failedRun
                    }
                }

                guard let pending else {
                    if let lifecycle,
                       lifecycle.phase != .cleanupCommitted
                    {
                        return .failedRun
                    }
                    if let recoveredReceipt {
                        return .enrollmentReceipt(
                            recoveredReceipt.artifact,
                            fingerprintSHA256: recoveredReceipt
                                .deviceSelectionFingerprintSHA256
                        )
                    }
                    if installationState != nil {
                        return .failedRun
                    }
                    return .ready
                }
                guard let metadata = try? validator.validate(pending.bytes)
                else {
                    return .discardableAuthorization
                }
                if let recoveredReceipt,
                   pending.isQuarantined,
                   metadata.kind == .installationEnrollment,
                   Data(SHA256.hash(data: pending.bytes)).hexLowercase
                    == recoveredReceipt.authorizationEnvelopeSHA256
                {
                    let persisted =
                        try storage.quarantineEnrollmentAuthorization()
                    try storage.deleteAuthorization(persisted.quarantined)
                    return .enrollmentReceipt(
                        recoveredReceipt.artifact,
                        fingerprintSHA256: recoveredReceipt
                            .deviceSelectionFingerprintSHA256
                    )
                }
                let now = try runtimeContext.currentUnixTime()
                let duration =
                    metadata.notAfter.subtractingReportingOverflow(
                        metadata.notBefore
                    )
                let latest =
                    metadata.notAfter.addingReportingOverflow(
                        Self.allowedClockSkew
                    )
                let earliest =
                    metadata.notBefore.subtractingReportingOverflow(
                        Self.allowedClockSkew
                    )
                let enrollmentOutsideExactWindow =
                    metadata.kind == .installationEnrollment
                        && (now < metadata.notBefore
                            || now > metadata.notAfter)
                if metadata.buildBindingSHA256
                    != runtimeContext.buildBindingSHA256
                    || duration.overflow
                    || duration.partialValue != 900
                    || earliest.overflow
                    || latest.overflow
                    || now < earliest.partialValue
                    || now > latest.partialValue
                    || enrollmentOutsideExactWindow
                {
                    return .discardableAuthorization
                }
                if metadata.kind == .collectionRun {
                    guard let installationState else {
                        return .discardableAuthorization
                    }
                    if try !runAuthorizationPrerequisitesMatch(
                        metadata,
                        installationState: installationState,
                        allowCommittedCounter: false,
                        pinBindingIfMissing: false
                    ) {
                        return .discardableAuthorization
                    }
                } else if let installationState {
                    guard pending.isQuarantined,
                          try enrollmentAuthorizationCanResume(
                              metadata,
                              installationState: installationState,
                              now: now
                          )
                    else {
                        return .discardableAuthorization
                    }
                }
                return .pendingAuthorization(metadata.kind)
            }
        if state == .completedRun {
            completedSessionThisCoordinator =
                try sessionEvidenceStore.completedSnapshot()
            constructedSessionExport = nil
        }
        return state
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
            let nextCounter = currentCounter.addingReportingOverflow(1)
            guard !nextCounter.overflow else {
                throw LAB002StorageError.counterExhausted
            }
            guard nextCounter.partialValue == expectedCounter
                    || pending.resumedAfterPersistence
                        && currentCounter == expectedCounter
            else {
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
            guard try runAuthorizationPrerequisitesMatch(
                metadata,
                installationState: continuity.state,
                allowCommittedCounter: pending.resumedAfterPersistence
                    && recoverableSession != nil,
                pinBindingIfMissing: true
            ) else {
                throw LAB002CoordinatorError.invalidRuntimeContext
            }
            if let recoverableSession {
                guard pending.resumedAfterPersistence,
                      recoverableSession == report
                else {
                    throw LAB002StorageError.counterMismatch
                }
            } else {
                guard currentCounter != expectedCounter,
                      !hasSessionDirectory
                else {
                    throw LAB002StorageError.existingEntry(
                        LAB002FixedName.currentReports
                    )
                }
            }
            try storage.createOrRecoverSession(report)
            let observingLifecycle = try LAB002RunLifecycleState(
                buildBindingSHA256: buildBindingSHA256,
                sessionID: report.sessionID,
                runOrdinal: report.runOrdinal,
                phase: .observingMainAndFramework
            )
            let priorLifecycle = try storage.readRunLifecycle()
            if let priorLifecycle,
               lifecycleMatches(
                   priorLifecycle,
                   session: report,
                   phase: .observingMainAndFramework
               ),
               pending.resumedAfterPersistence
            {
                // The authorization is still quarantined, so observation
                // could not have started before this safe resume.
            } else {
                if expectedCounter == 1 {
                    guard priorLifecycle == nil else {
                        throw LAB002StorageError.counterMismatch
                    }
                } else {
                    guard let priorLifecycle,
                          priorLifecycle.phase == .cleanupCommitted,
                          priorLifecycle.runOrdinal + 1
                            == report.runOrdinal
                    else {
                        throw LAB002StorageError.counterMismatch
                    }
                }
                try storage.transitionRunLifecycle(
                    from: priorLifecycle,
                    to: observingLifecycle
                )
            }
            if currentCounter != expectedCounter {
                try storage.validateExpectedCounter(
                    expected: expectedCounter,
                    buildBindingSHA256: buildBindingSHA256
                )
                _ = try storage.commitExpectedCounter(
                    expected: expectedCounter,
                    buildBindingSHA256: buildBindingSHA256
                )
            }
            try storage.deleteAuthorization(quarantined)
            return LAB002ConsumedRunAuthorization(
                canonicalBytes: quarantined.bytes,
                metadata: metadata
            )
        }
        try runRoleObserver.observeMainAndFramework()
        try storage.withCoordinatorLock {
            guard let session = try storage.readSession(),
                  session.authorizationEnvelopeSHA256
                    == Data(
                        SHA256.hash(data: consumed.canonicalBytes)
                    ).hexLowercase
            else {
                throw LAB002ObserverReason.staleOrConflictingSession
            }
            let observing = try requiredLifecycle(
                matching: session,
                phase: .observingMainAndFramework
            )
            try storage.transitionRunLifecycle(
                from: observing,
                to: try observing.changingPhase(
                    to: .awaitingShareExtension
                )
            )
        }
        return consumed
    }

    func completeRunAfterShareExtension()
        throws -> LAB002SessionCompletionOutcome
    {
        let completedAt = try runtimeContext.currentUnixTime()
        try storage.withCoordinatorLock {
            guard let session = try storage.readSession(),
                  session.state == .collecting
            else {
                throw LAB002ObserverReason.staleOrConflictingSession
            }
            let awaiting = try requiredLifecycle(
                matching: session,
                phase: .awaitingShareExtension
            )
            let pending = try awaiting.changingPhase(
                to: .completionPending
            )
            try storage.transitionRunLifecycle(
                from: awaiting,
                to: pending
            )
        }
        let outcome: LAB002SessionCompletionOutcome
        do {
            outcome = try sessionEvidenceStore.complete(at: completedAt)
        } catch let completionError {
            do {
                try storage.withCoordinatorLock {
                    guard let session = try storage.readSession(),
                          session.state == .collecting
                    else {
                        throw LAB002ObserverReason
                            .staleOrConflictingSession
                    }
                    let pending = try requiredLifecycle(
                        matching: session,
                        phase: .completionPending
                    )
                    try storage.transitionRunLifecycle(
                        from: pending,
                        to: try pending.changingPhase(
                            to: .awaitingShareExtension
                        )
                    )
                }
            } catch {
                throw error
            }
            throw completionError
        }
        guard outcome == .committed else {
            return outcome
        }
        do {
            let snapshot = try sessionEvidenceStore.completedSnapshot()
            try storage.withCoordinatorLock {
                let pending = try requiredLifecycle(
                    matching: snapshot,
                    phase: .completionPending
                )
                try storage.transitionRunLifecycle(
                    from: pending,
                    to: try pending.changingPhase(
                        to: .completionCommitted
                    )
                )
            }
            completedSessionThisCoordinator = snapshot
            return .committed
        } catch {
            completedSessionThisCoordinator = nil
            return .committedDurabilityUncertain
        }
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
            let recoveryRecord = try LAB002EvidenceArtifactBuilder
                .enrollmentReceiptRecoveryRecord(
                    artifact: receipt.artifact,
                    authorizationEnvelope: quarantined.bytes,
                    deviceSelectionFingerprintSHA256:
                        receipt.deviceSelectionFingerprintSHA256
                )
            try storage.persistEnrollmentReceipt(recoveryRecord)
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
        guard let completedSessionThisCoordinator else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let current = try sessionEvidenceStore.completedSnapshot()
        guard current == completedSessionThisCoordinator else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        let snapshot = current
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
        let cleanupPending = try storage.withCoordinatorLock {
            let completed = try requiredLifecycle(
                matching: constructedSessionExport.snapshot,
                phase: .completionCommitted
            )
            let pending = try completed.changingPhase(
                to: .cleanupPending
            )
            try storage.transitionRunLifecycle(
                from: completed,
                to: pending
            )
            return pending
        }
        let outcome: LAB002CleanupOutcome
        do {
            outcome = try sessionEvidenceStore.cleanup(
                expectedSnapshot: constructedSessionExport.snapshot
            )
        } catch {
            do {
                try storage.withCoordinatorLock {
                    try storage.transitionRunLifecycle(
                        from: cleanupPending,
                        to: try cleanupPending.changingPhase(
                            to: .completionCommitted
                        )
                    )
                }
            } catch {
                completedSessionThisCoordinator = nil
                self.constructedSessionExport = nil
                throw error
            }
            throw error
        }
        completedSessionThisCoordinator = nil
        self.constructedSessionExport = nil
        guard outcome == .cleaned else {
            return outcome
        }
        do {
            try storage.withCoordinatorLock {
                try storage.transitionRunLifecycle(
                    from: cleanupPending,
                    to: try cleanupPending.changingPhase(
                        to: .cleanupCommitted
                    )
                )
            }
            return .cleaned
        } catch {
            return .cleanedDurabilityUncertain
        }
    }

    func discardStaleAuthorization() throws -> LAB002DiscardReason {
        try storage.withCoordinatorLock {
            let wasQuarantined =
                try storage.hasQuarantinedAuthorization()
            let quarantined =
                try storage.quarantineAuthorizationForDiscard()
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
            let earliest = metadata.notBefore.subtractingReportingOverflow(
                Self.allowedClockSkew
            )
            guard !earliest.overflow, !latest.overflow else {
                try storage.deleteAuthorization(quarantined)
                return .malformed
            }
            let enrollmentOutsideExactWindow =
                metadata.kind == .installationEnrollment
                    && (now < metadata.notBefore
                        || now > metadata.notAfter)
            if now < earliest.partialValue
                || now > latest.partialValue
                || enrollmentOutsideExactWindow
            {
                try storage.deleteAuthorization(quarantined)
                return .expired
            }
            let installationState = try storage.readInstallationState()
            let matchingPreObservationTransaction =
                if wasQuarantined,
                   metadata.kind == .collectionRun,
                   let installationState
                {
                    try quarantinedRunHasMatchingPreObservationTransaction(
                        bytes: quarantined.bytes,
                        metadata: metadata,
                        installationState: installationState
                    )
                } else {
                    false
                }
            if metadata.kind == .collectionRun
                && installationState == nil
            {
                try storage.deleteAuthorization(quarantined)
                return .enrollmentRequired
            }
            if metadata.kind == .installationEnrollment,
               installationState != nil
            {
                try storage.deleteAuthorization(quarantined)
                return .alreadyEnrolled
            }
            if metadata.kind == .collectionRun,
               let installationState,
               try !runAuthorizationPrerequisitesMatch(
                   metadata,
                   installationState: installationState,
                   allowCommittedCounter:
                    matchingPreObservationTransaction,
                   pinBindingIfMissing: false
               )
            {
                try storage.deleteAuthorization(quarantined)
                return .runPrerequisiteMismatch
            }
            try storage.restoreAuthorization(quarantined)
            throw LAB002CoordinatorError.authorizationStillValid
        }
    }

    private func runAuthorizationPrerequisitesMatch(
        _ metadata: LAB002AuthorizationMetadata,
        installationState: LAB002InstallationState,
        allowCommittedCounter: Bool,
        pinBindingIfMissing: Bool
    ) throws -> Bool {
        guard installationState.buildBindingSHA256
                == runtimeContext.buildBindingSHA256,
              let expectedCounter = metadata.expectedRunCounter,
              let runFacts = metadata.runFacts,
              let expectedOrdinal = UInt8(exactly: expectedCounter),
              runFacts.runOrdinal == expectedOrdinal
        else {
            throw LAB002CoordinatorError.invalidRuntimeContext
        }
        guard installationState.enrollmentPublicKey
                == runFacts.enrollmentPublicKey
        else {
            return false
        }
        let enrolled = try verifiedEnrollmentContinuity(
            installationState: installationState
        )
        guard enrolled.facts.experimentID == runFacts.experimentID,
              enrolled.facts.authorizedTargetManifestSHA256
                == runFacts.authorizedTargetManifestSHA256,
              metadata.notBefore >= enrolled.receiptCreatedAt
        else {
            return false
        }
        let installationBinding = try runtimeContext
            .deviceInstallationBinding(state: installationState)
        guard installationBinding
                == runFacts.expectedDeviceInstallationBindingSHA256
        else {
            return false
        }
        let counterRecord = try storage.readCounter()
        if let counterRecord,
           counterRecord.buildBindingSHA256
            != runtimeContext.buildBindingSHA256
        {
            throw LAB002StorageError.counterMismatch
        }
        let currentCounter = counterRecord?.counter ?? 0
        let nextCounter = currentCounter.addingReportingOverflow(1)
        guard !nextCounter.overflow else {
            throw LAB002StorageError.counterExhausted
        }
        let counterMatches =
            nextCounter.partialValue == expectedCounter
            || allowCommittedCounter && currentCounter == expectedCounter
        guard counterMatches else {
            return false
        }
        let expectedControl = try LAB002EnrollmentControlState(
            buildBindingSHA256: runtimeContext.buildBindingSHA256,
            experimentID: enrolled.facts.experimentID,
            deviceEnrollmentBindingSHA256:
                runFacts.deviceEnrollmentBindingSHA256
        )
        if let existing = try storage.readEnrollmentControl() {
            return existing == expectedControl
        }
        guard expectedCounter == 1 else {
            return false
        }
        if pinBindingIfMissing {
            try storage.createEnrollmentControl(expectedControl)
        }
        return true
    }

    private func enrollmentAuthorizationCanResume(
        _ metadata: LAB002AuthorizationMetadata,
        installationState: LAB002InstallationState,
        now: Int64
    ) throws -> Bool {
        guard metadata.kind == .installationEnrollment,
              metadata.expectedRunCounter == nil,
              let facts = metadata.enrollmentFacts,
              metadata.buildBindingSHA256
                == runtimeContext.buildBindingSHA256,
              installationState.buildBindingSHA256
                == runtimeContext.buildBindingSHA256
        else {
            return false
        }
        try validateWindow(metadata, now: now)
        guard now >= metadata.notBefore,
              now <= metadata.notAfter,
              try runtimeContext.currentEnvironment()
                == facts.expectedEnvironment
        else {
            return false
        }
        let continuity = try enrollment.loadForRun(
            buildBindingSHA256: runtimeContext.buildBindingSHA256
        )
        return continuity.state == installationState
    }

    private func quarantinedRunHasMatchingPreObservationTransaction(
        bytes: Data,
        metadata: LAB002AuthorizationMetadata,
        installationState: LAB002InstallationState
    ) throws -> Bool {
        guard let session = try storage.readRecoverableSession(),
              session.state == .collecting,
              lifecycleMatches(
                  try storage.readRunLifecycle(),
                  session: session,
                  phase: .observingMainAndFramework
              )
        else {
            return false
        }
        return try quarantinedRunMatchesSession(
            LAB002PendingAuthorization(
                bytes: bytes,
                isQuarantined: true
            ),
            metadata: metadata,
            session: session,
            installationState: installationState
        )
    }

    private func quarantinedRunMatchesSession(
        _ pending: LAB002PendingAuthorization,
        metadata: LAB002AuthorizationMetadata,
        session: LAB002SessionReport,
        installationState: LAB002InstallationState
    ) throws -> Bool {
        let now = try runtimeContext.currentUnixTime()
        try validateWindow(metadata, now: now)
        guard metadata.kind == .collectionRun,
              metadata.buildBindingSHA256
                == runtimeContext.buildBindingSHA256,
              let expectedCounter = metadata.expectedRunCounter,
              let facts = metadata.runFacts,
              try runAuthorizationPrerequisitesMatch(
                  metadata,
                  installationState: installationState,
                  allowCommittedCounter: true,
                  pinBindingIfMissing: false
              )
        else {
            return false
        }
        let environment = try runtimeContext.currentEnvironment()
        let installationBinding = try runtimeContext
            .deviceInstallationBinding(state: installationState)
        return session.observerRevision
                == runtimeContext.runBuildFacts.observerRevision
            && session.buildBindingSHA256
                == runtimeContext.buildBindingSHA256
            && session.collectionID == facts.collectionID
            && session.runOrdinal == facts.runOrdinal
            && session.challengeSHA256 == facts.challengeSHA256
            && session.acknowledgementSHA256
                == facts.acknowledgementSHA256
            && session.authorizationEnvelopeSHA256
                == Data(SHA256.hash(data: pending.bytes)).hexLowercase
            && session.authorizationNotAfter == metadata.notAfter
            && session.deviceEnrollmentBindingSHA256
                == facts.deviceEnrollmentBindingSHA256
            && session.enrollmentPublicKey == facts.enrollmentPublicKey
            && session.deviceInstallationBindingSHA256
                == installationBinding
            && session.environment == environment
            && session.runCounter
                == String(format: "%016llx", expectedCounter)
            && isInsideSkewWindow(
                session.createdAt,
                metadata: metadata
            )
            && session.sourceCommit
                == runtimeContext.runBuildFacts.sourceCommit
            && session.marketingVersion
                == runtimeContext.runBuildFacts.marketingVersion
            && session.buildNumber
                == runtimeContext.runBuildFacts.buildNumber
    }

    private func verifiedEnrollmentContinuity(
        installationState: LAB002InstallationState
    ) throws -> (
        facts: LAB002VerifiedEnrollmentFacts,
        receiptCreatedAt: Int64
    ) {
        guard let recovery = try storage.readEnrollmentReceipt()
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        let authorizationEnvelope =
            try LAB002EvidenceArtifactBuilder
            .enrollmentAuthorizationEnvelope(
                recoveryRecordBytes: recovery
            )
        let metadata = try validator.validate(authorizationEnvelope)
        guard metadata.kind == .installationEnrollment,
              metadata.buildBindingSHA256
                == installationState.buildBindingSHA256,
              installationState.buildBindingSHA256
                == runtimeContext.buildBindingSHA256,
              let facts = metadata.enrollmentFacts
        else {
            throw LAB002EvidenceArtifactError.invalidArtifact
        }
        let environment = try runtimeContext.currentEnvironment()
        let installationBinding = try runtimeContext
            .deviceInstallationBinding(state: installationState)
        let recovered =
            try LAB002EvidenceArtifactBuilder.recoverEnrollmentReceipt(
                recoveryRecordBytes: recovery,
                expectedState: installationState,
                authorizationMetadata: metadata,
                expectedDeviceInstallationBindingSHA256:
                    installationBinding,
                expectedEnvironment: environment
            )
        return (facts, recovered.receiptCreatedAt)
    }

    private func persistedSessionMatchesEnrollment(
        _ session: LAB002SessionReport,
        installationState: LAB002InstallationState
    ) throws -> Bool {
        let continuity = try enrollment.loadForRun(
            buildBindingSHA256: runtimeContext.buildBindingSHA256
        )
        guard continuity.state == installationState else {
            return false
        }
        let enrolled = try verifiedEnrollmentContinuity(
            installationState: installationState
        )
        let installationBinding = try runtimeContext
            .deviceInstallationBinding(state: installationState)
        guard let control = try storage.readEnrollmentControl(),
              let counter = try storage.readCounter()
        else {
            return false
        }
        return installationState.buildBindingSHA256
                == runtimeContext.buildBindingSHA256
            && installationState.enrollmentPublicKey
                == session.enrollmentPublicKey
            && installationBinding
                == session.deviceInstallationBindingSHA256
            && control.buildBindingSHA256
                == runtimeContext.buildBindingSHA256
            && control.experimentID == enrolled.facts.experimentID
            && control.deviceEnrollmentBindingSHA256
                == session.deviceEnrollmentBindingSHA256
            && counter.buildBindingSHA256
                == runtimeContext.buildBindingSHA256
            && counter.counter == UInt64(session.runOrdinal)
    }

    private func lifecycleMatches(
        _ lifecycle: LAB002RunLifecycleState?,
        session: LAB002SessionReport,
        phase: LAB002RunLifecyclePhase
    ) -> Bool {
        lifecycle?.buildBindingSHA256 == session.buildBindingSHA256
            && lifecycle?.sessionID == session.sessionID
            && lifecycle?.runOrdinal == session.runOrdinal
            && lifecycle?.phase == phase
    }

    private func requiredLifecycle(
        matching session: LAB002SessionReport,
        phase: LAB002RunLifecyclePhase
    ) throws -> LAB002RunLifecycleState {
        guard let lifecycle = try storage.readRunLifecycle(),
              lifecycleMatches(
                  lifecycle,
                  session: session,
                  phase: phase
              )
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        return lifecycle
    }

    private func requiredLifecycle(
        matching snapshot: LAB002CompletedSessionSnapshot,
        phase: LAB002RunLifecyclePhase
    ) throws -> LAB002RunLifecycleState {
        guard let lifecycle = try storage.readRunLifecycle(),
              lifecycle.buildBindingSHA256
                == snapshot.buildBindingSHA256,
              lifecycle.sessionID == snapshot.sessionID,
              lifecycle.runOrdinal == snapshot.runOrdinal,
              lifecycle.phase == phase
        else {
            throw LAB002ObserverReason.staleOrConflictingSession
        }
        return lifecycle
    }

    private func isInsideSkewWindow(
        _ time: Int64,
        metadata: LAB002AuthorizationMetadata
    ) -> Bool {
        let earliest = metadata.notBefore.subtractingReportingOverflow(
            Self.allowedClockSkew
        )
        let latest = metadata.notAfter.addingReportingOverflow(
            Self.allowedClockSkew
        )
        return !earliest.overflow
            && !latest.overflow
            && time >= earliest.partialValue
            && time <= latest.partialValue
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
