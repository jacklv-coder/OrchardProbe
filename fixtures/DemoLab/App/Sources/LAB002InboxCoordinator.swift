import Foundation

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
}

protocol LAB002AuthorizationValidating {
    func validate(_ canonicalBytes: Data) throws -> LAB002AuthorizationMetadata
}

protocol LAB002RuntimeContextProviding {
    var buildBindingSHA256: String { get }

    func currentUnixTime() throws -> Int64
}

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
        self.buildBindingSHA256 = buildBindingSHA256
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
}

actor LAB002InboxCoordinator {
    private static let allowedClockSkew: Int64 = 120

    private let storage: LAB002FixedStorage
    private let validator: LAB002AuthorizationValidating
    private let enrollment: LAB002EnrollmentStateCoordinator
    private let runtimeContext: any LAB002RuntimeContextProviding

    init(validator: LAB002AuthorizationValidating) throws {
        let fixedStorage = try LAB002FixedStorage.production()
        storage = fixedStorage
        self.validator = validator
        enrollment = try LAB002EnrollmentStateCoordinator.production(
            storage: fixedStorage
        )
        runtimeContext = try LAB002ProductionRuntimeContext()
    }

    #if DEBUG
    init(
        testContainerURL: URL,
        validator: LAB002AuthorizationValidating,
        enrollmentKeyStore: any LAB002EnrollmentKeyStoring,
        random: any LAB002RandomBytesGenerating,
        testRuntimeContext: any LAB002RuntimeContextProviding
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
        try storage.withCoordinatorLock {
            let quarantined = try storage.quarantineAuthorization()
            let metadata = try validator.validate(quarantined.bytes)
            let now = try runtimeContext.currentUnixTime()
            let buildBindingSHA256 = runtimeContext.buildBindingSHA256
            guard metadata.kind == .collectionRun,
                  let expectedCounter = metadata.expectedRunCounter
            else {
                throw LAB002CoordinatorError.wrongOperation
            }
            try validateWindow(metadata, now: now)
            guard metadata.buildBindingSHA256 == buildBindingSHA256 else {
                throw LAB002CoordinatorError.wrongBuild
            }
            _ = try enrollment.loadForRun(
                buildBindingSHA256: buildBindingSHA256
            )
            _ = try storage.commitExpectedCounter(
                expected: expectedCounter,
                buildBindingSHA256: buildBindingSHA256
            )
            try storage.deleteAuthorization(quarantined)
            return LAB002ConsumedRunAuthorization(
                canonicalBytes: quarantined.bytes,
                metadata: metadata
            )
        }
    }

    func confirmInstallationEnrollment() throws -> LAB002EnrollmentContinuity {
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
                  metadata.expectedRunCounter == nil
            else {
                throw LAB002CoordinatorError.wrongOperation
            }
            try validateWindow(metadata, now: now)
            guard metadata.buildBindingSHA256 == buildBindingSHA256 else {
                throw LAB002CoordinatorError.wrongBuild
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
            try storage.deleteAuthorization(quarantined)
            return continuity
        }
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
