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

enum LAB002CoordinatorError: Error {
    case wrongOperation
    case wrongBuild
    case stale
    case authorizationStillValid
    case invalidWindow
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

actor LAB002InboxCoordinator {
    private static let allowedClockSkew: Int64 = 120

    private let storage: LAB002FixedStorage
    private let validator: LAB002AuthorizationValidating

    init(validator: LAB002AuthorizationValidating) throws {
        storage = try LAB002FixedStorage.production()
        self.validator = validator
    }

    init(
        testContainerURL: URL,
        validator: LAB002AuthorizationValidating
    ) throws {
        storage = try LAB002FixedStorage(testContainerURL: testContainerURL)
        self.validator = validator
    }

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

    func startCleanRun(
        now: Int64,
        buildBindingSHA256: String
    ) throws -> LAB002ConsumedRunAuthorization {
        try storage.withCoordinatorLock {
            let quarantined = try storage.quarantineAuthorization()
            let metadata = try validator.validate(quarantined.bytes)
            guard metadata.kind == .collectionRun,
                  let expectedCounter = metadata.expectedRunCounter
            else {
                throw LAB002CoordinatorError.wrongOperation
            }
            try validateWindow(metadata, now: now)
            guard metadata.buildBindingSHA256 == buildBindingSHA256 else {
                throw LAB002CoordinatorError.wrongBuild
            }
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

    func discardStaleAuthorization(
        now: Int64,
        buildBindingSHA256: String
    ) throws -> LAB002DiscardReason {
        try storage.withCoordinatorLock {
            let quarantined = try storage.quarantineAuthorization()
            let metadata: LAB002AuthorizationMetadata
            do {
                metadata = try validator.validate(quarantined.bytes)
            } catch {
                try storage.deleteAuthorization(quarantined)
                return .malformed
            }
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
