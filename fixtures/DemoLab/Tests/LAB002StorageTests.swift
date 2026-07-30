import Darwin
import CryptoKit
import Foundation
import XCTest
@testable import DemoLab

private final class TestAuthorizationValidator: LAB002AuthorizationValidating {
    var metadata: LAB002AuthorizationMetadata
    var shouldFail = false

    init(
        kind: LAB002AuthorizationKind = .collectionRun,
        expectedCounter: UInt64? = 1,
        build: String = String(repeating: "a", count: 64)
    ) {
        metadata = LAB002AuthorizationMetadata(
            kind: kind,
            buildBindingSHA256: build,
            notBefore: 1_000,
            notAfter: 1_900,
            expectedRunCounter: expectedCounter,
            runFacts: kind == .collectionRun
                ? Self.runFacts(counter: expectedCounter ?? 1)
                : nil
        )
    }

    func validate(_ canonicalBytes: Data) throws -> LAB002AuthorizationMetadata {
        if shouldFail || canonicalBytes != Data("valid".utf8) {
            throw LAB002CoordinatorError.wrongOperation
        }
        return metadata
    }

    static func runFacts(counter: UInt64) -> LAB002VerifiedRunFacts {
        let signingKey = try! LAB002CryptoKitSigningKey(
            rawRepresentation: Data(repeating: 0x41, count: 32)
        )
        return LAB002VerifiedRunFacts(
            collectionID: String(repeating: "e", count: 64),
            runOrdinal: UInt8(counter),
            challengeSHA256: String(repeating: "d", count: 64),
            acknowledgementSHA256: String(repeating: "b", count: 64),
            deviceEnrollmentBindingSHA256: String(repeating: "f", count: 64),
            enrollmentPublicKey: signingKey.publicKeyRaw.hexLowercase,
            expectedDeviceInstallationBindingSHA256:
                String(repeating: "1", count: 64)
        )
    }
}

private final class TestEnrollmentKeyStore: LAB002EnrollmentKeyStoring {
    private var raw: Data?
    private var storedBuild: String?
    private(set) var createCount = 0

    init(
        seed: UInt8 = 0x41,
        preloaded: Bool = false,
        build: String = String(repeating: "a", count: 64)
    ) {
        raw = preloaded ? Data(repeating: seed, count: 32) : nil
        storedBuild = preloaded ? build : nil
        self.seed = seed
    }

    private let seed: UInt8

    func createOrRecoverForAuthenticatedEnrollment(
        buildBindingSHA256: String
    ) throws -> any LAB002EnrollmentSigningKey {
        if let raw {
            guard storedBuild == buildBindingSHA256 else {
                throw LAB002EnrollmentError.buildMismatch
            }
            return try LAB002CryptoKitSigningKey(rawRepresentation: raw)
        }
        createCount += 1
        let value = Data(repeating: seed, count: 32)
        raw = value
        storedBuild = buildBindingSHA256
        return try LAB002CryptoKitSigningKey(rawRepresentation: value)
    }

    func loadExisting(
        buildBindingSHA256: String
    ) throws -> any LAB002EnrollmentSigningKey {
        guard let raw else {
            throw LAB002EnrollmentError.notEnrolled
        }
        guard storedBuild == buildBindingSHA256 else {
            throw LAB002EnrollmentError.buildMismatch
        }
        return try LAB002CryptoKitSigningKey(rawRepresentation: raw)
    }
}

private final class TestRandomBytes: LAB002RandomBytesGenerating {
    let byte: UInt8
    var failureCount: Int

    init(byte: UInt8, failureCount: Int = 0) {
        self.byte = byte
        self.failureCount = failureCount
    }

    func bytes(count: Int) throws -> Data {
        if failureCount > 0 {
            failureCount -= 1
            throw LAB002EnrollmentError.randomnessFailure(errSecAllocate)
        }
        return Data(repeating: byte, count: count)
    }
}

private final class TestRuntimeContext: LAB002RuntimeContextProviding {
    let buildBindingSHA256: String
    let runBuildFacts: LAB002RunBuildFacts
    var now: Int64

    init(
        build: String = String(repeating: "a", count: 64),
        now: Int64 = 1_500,
        sourceCommit: String = String(repeating: "4", count: 40)
    ) {
        buildBindingSHA256 = build
        self.now = now
        runBuildFacts = LAB002RunBuildFacts(
            observerRevision: "lab002-observer-v1",
            sourceCommit: sourceCommit,
            marketingVersion: "1.0",
            buildNumber: "1"
        )
    }

    func currentUnixTime() throws -> Int64 {
        now
    }

    func currentEnvironment() throws -> LAB002SessionEnvironment {
        try LAB002SessionEnvironment(
            hardwareModel: "iPhone17,1",
            iosProductVersion: "18.0",
            iosBuild: "22A3354"
        )
    }

    func deviceInstallationBinding(
        state: LAB002InstallationState
    ) throws -> String {
        String(repeating: "1", count: 64)
    }
}

final class LAB002StorageTests: XCTestCase {
    private var temporaryRoot: URL!

    override func setUpWithError() throws {
        temporaryRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: temporaryRoot,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
    }

    override func tearDownWithError() throws {
        if temporaryRoot != nil {
            try FileManager.default.removeItem(at: temporaryRoot)
        }
    }

    func testImportIsExclusiveAndBounded() async throws {
        let validator = TestAuthorizationValidator()
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext()
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)

        try await coordinator.importAuthorization(from: source)
        do {
            try await coordinator.importAuthorization(from: source)
            XCTFail("duplicate import succeeded")
        } catch LAB002StorageError.existingEntry {
        }

        let oversized = temporaryRoot.appendingPathComponent("oversized.json")
        try Data(repeating: 0x61, count: LAB002Limit.controlDocument + 1)
            .write(to: oversized)
        do {
            try await coordinator.importAuthorization(from: oversized)
            XCTFail("oversized import succeeded")
        } catch LAB002StorageError.oversized {
        }
    }

    func testStartCommitsCounterAndConsumesAuthorization() async throws {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(expectedCounter: 1, build: build)
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: build
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        let consumed = try await coordinator.startCleanRun()
        XCTAssertEqual(consumed.canonicalBytes, Data("valid".utf8))

        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        XCTAssertEqual(try storage.readCounter()?.counter, 1)
        let session = try XCTUnwrap(storage.readSession())
        XCTAssertEqual(session.state, .collecting)
        XCTAssertEqual(session.runOrdinal, 1)
        XCTAssertEqual(session.runCounter, "0000000000000001")
        XCTAssertEqual(session.sessionID, String(repeating: "51", count: 32))
        XCTAssertEqual(
            session.authorizationEnvelopeSHA256,
            Data(SHA256.hash(data: Data("valid".utf8))).hexLowercase
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(LAB002FixedName.authorization)
                    .path
            )
        )
    }

    func testInvalidSourceCommitFailsBeforeStateConsumption() async throws {
        let build = String(repeating: "a", count: 64)
        let sourceCommit = String(repeating: "4", count: 64)
        let validator = TestAuthorizationValidator(
            expectedCounter: 1,
            build: build
        )
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext(
                build: build,
                sourceCommit: sourceCommit
            )
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: build
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        do {
            _ = try await coordinator.startCleanRun()
            XCTFail("invalid source commit started a run")
        } catch LAB002SessionError.invalidRecord {
        }

        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        XCTAssertNil(try storage.readSession())
        XCTAssertNil(try storage.readCounter())
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(
                        LAB002FixedName.authorizationQuarantine
                    )
                    .path
            )
        )
    }

    func testInterruptedRunResumesOnlyFromExistingQuarantine() async throws {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(
            expectedCounter: 1,
            build: build
        )
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: build
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        _ = try storage.quarantineAuthorization()
        _ = try storage.commitExpectedCounter(
            expected: 1,
            buildBindingSHA256: build
        )

        _ = try await coordinator.startCleanRun()

        XCTAssertEqual(try storage.readCounter()?.counter, 1)
        XCTAssertEqual(
            try storage.readSession()?.sessionID,
            String(repeating: "51", count: 32)
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(
                        LAB002FixedName.authorizationQuarantine
                    )
                    .path
            )
        )
    }

    func testFreshReplayCannotEnterInterruptedRunRecovery() async throws {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(
            expectedCounter: 1,
            build: build
        )
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: build
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        _ = try await coordinator.startCleanRun()
        try await coordinator.importAuthorization(from: source)

        do {
            _ = try await coordinator.startCleanRun()
            XCTFail("fresh replay entered interrupted-run recovery")
        } catch LAB002StorageError.existingEntry {
        }

        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        XCTAssertEqual(try storage.readCounter()?.counter, 1)
        XCTAssertNotNil(try storage.readSession())
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(
                        LAB002FixedName.authorization
                    )
                    .path
            )
        )
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(
                        LAB002FixedName.authorizationQuarantine
                    )
                    .path
            )
        )
    }

    func testInterruptedRunAfterSessionPublicationFinishesConsumption()
        async throws
    {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(
            expectedCounter: 1,
            build: build
        )
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: build
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        _ = try await coordinator.startCleanRun()
        try await coordinator.importAuthorization(from: source)
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        _ = try storage.quarantineAuthorization()

        _ = try await coordinator.startCleanRun()

        XCTAssertEqual(try storage.readCounter()?.counter, 1)
        XCTAssertNotNil(try storage.readSession())
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(
                        LAB002FixedName.authorizationQuarantine
                    )
                    .path
            )
        )
    }

    func testCounterRejectsSkipAndLeavesQuarantine() async throws {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(expectedCounter: 2, build: build)
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: build
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        do {
            _ = try await coordinator.startCleanRun()
            XCTFail("skipped counter succeeded")
        } catch LAB002StorageError.counterMismatch {
        }

        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(
                        LAB002FixedName.authorizationQuarantine
                    )
                    .path
            )
        )
        XCTAssertNil(try storage.readCounter())
    }

    func testDiscardRestoresCurrentAndDeletesExpiredOrMalformed() async throws {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(expectedCounter: 1, build: build)
        let runtimeContext = TestRuntimeContext(build: build)
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: runtimeContext
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        do {
            _ = try await coordinator.discardStaleAuthorization()
            XCTFail("current authorization was discarded")
        } catch LAB002CoordinatorError.authorizationStillValid {
        }

        runtimeContext.now = 2_021
        let expired = try await coordinator.discardStaleAuthorization()
        guard case .expired = expired else {
            return XCTFail("expected expired")
        }

        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        validator.shouldFail = true
        runtimeContext.now = 1_500
        let malformed = try await coordinator.discardStaleAuthorization()
        guard case .malformed = malformed else {
            return XCTFail("expected malformed")
        }
    }

    func testSymlinkedSourceAndQuarantineResidueFailClosed() async throws {
        let validator = TestAuthorizationValidator()
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext()
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: String(repeating: "a", count: 64)
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        let link = temporaryRoot.appendingPathComponent("link.json")
        try Data("valid".utf8).write(to: source)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)

        do {
            try await coordinator.importAuthorization(from: link)
            XCTFail("symlink import succeeded")
        } catch {
        }

        try await coordinator.importAuthorization(from: source)
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        let quarantine = storage.inboxURL.appendingPathComponent(
            LAB002FixedName.authorizationQuarantine
        )
        try Data("residue".utf8).write(to: quarantine)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: quarantine.path
        )
        do {
            _ = try await coordinator.startCleanRun()
            XCTFail("quarantine residue was ignored")
        } catch LAB002StorageError.existingEntry {
        }
    }

    func testCounterCanonicalFormAndOverflowFailClosed() throws {
        let build = String(repeating: "b", count: 64)
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        let record = try storage.withCoordinatorLock {
            try storage.commitExpectedCounter(
                expected: 1,
                buildBindingSHA256: build
            )
        }
        XCTAssertEqual(record.counter, 1)
        XCTAssertEqual(
            try LAB002CounterRecord(canonicalBytes: record.canonicalData()).counter,
            1
        )
        XCTAssertEqual(
            String(decoding: try record.canonicalData(), as: UTF8.self),
            """
            {"build_binding_sha256":"\(build)","counter":"0000000000000001","schema":"orchardprobe.lab002.run-counter-state.v1"}
            """
        )

        let nonCanonical = Data(
            """
             {"schema":"\(LAB002CounterRecord.schema)","counter":"0000000000000001","build_binding_sha256":"\(build)"}
            """.utf8
        )
        XCTAssertThrowsError(try LAB002CounterRecord(canonicalBytes: nonCanonical))

        // This shape existed only in an unshipped branch-local draft. Accepting
        // or migrating it would turn bytes outside the frozen contract into
        // trusted monotonic state.
        let unshippedDraft = Data(
            """
            {"build_binding_sha256":"\(build)","counter":"0000000000000001","profile":"orchardprobe.demolab.lab002.observation.v1","schema":"orchardprobe.lab002.run-counter.v1"}
            """.utf8
        )
        XCTAssertThrowsError(try LAB002CounterRecord(canonicalBytes: unshippedDraft))
    }

    func testEnrollmentCreatesExactStateAndRunOnlyLoadsIt() async throws {
        let build = String(repeating: "c", count: 64)
        let validator = TestAuthorizationValidator(
            kind: .installationEnrollment,
            expectedCounter: nil,
            build: build
        )
        let keyStore = TestEnrollmentKeyStore(seed: 0x61)
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: keyStore,
            random: TestRandomBytes(byte: 0x62),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        let continuity = try await coordinator.confirmInstallationEnrollment()

        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        let state = try XCTUnwrap(storage.readInstallationState())
        XCTAssertEqual(state, continuity.state)
        XCTAssertEqual(keyStore.createCount, 1)
        XCTAssertEqual(
            String(decoding: try state.canonicalData(), as: UTF8.self),
            """
            {"build_binding_sha256":"\(build)","enrollment_public_key":"\(state.enrollmentPublicKey)","installation_nonce":"\(String(repeating: "62", count: 32))","profile":"orchardprobe.demolab.lab002.observation.v1","schema":"orchardprobe.lab002.installation-nonce-state.v1"}
            """
        )

        validator.metadata = LAB002AuthorizationMetadata(
            kind: .collectionRun,
            buildBindingSHA256: build,
            notBefore: 1_000,
            notAfter: 1_900,
            expectedRunCounter: 1,
            runFacts: LAB002VerifiedRunFacts(
                collectionID: String(repeating: "e", count: 64),
                runOrdinal: 1,
                challengeSHA256: String(repeating: "d", count: 64),
                acknowledgementSHA256: String(repeating: "b", count: 64),
                deviceEnrollmentBindingSHA256:
                    String(repeating: "f", count: 64),
                enrollmentPublicKey: state.enrollmentPublicKey,
                expectedDeviceInstallationBindingSHA256:
                    String(repeating: "1", count: 64)
            )
        )
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        _ = try await coordinator.startCleanRun()
        XCTAssertEqual(keyStore.createCount, 1)
    }

    func testEnrollmentUsesInternalRuntimeClockAndBuildBinding() async throws {
        let expiredRoot = temporaryRoot.appendingPathComponent(
            "expired",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: expiredRoot,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let expiredBuild = String(repeating: "c", count: 64)
        let expiredValidator = TestAuthorizationValidator(
            kind: .installationEnrollment,
            expectedCounter: nil,
            build: expiredBuild
        )
        let expiredKeyStore = TestEnrollmentKeyStore(seed: 0x63)
        let expiredCoordinator = try LAB002InboxCoordinator(
            testContainerURL: expiredRoot,
            validator: expiredValidator,
            enrollmentKeyStore: expiredKeyStore,
            random: TestRandomBytes(byte: 0x64),
            testRuntimeContext: TestRuntimeContext(
                build: expiredBuild,
                now: 2_021
            )
        )
        let expiredSource = expiredRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: expiredSource)
        try await expiredCoordinator.importAuthorization(from: expiredSource)
        do {
            _ = try await expiredCoordinator.confirmInstallationEnrollment()
            XCTFail("expired enrollment succeeded")
        } catch LAB002CoordinatorError.stale {
        }
        XCTAssertEqual(expiredKeyStore.createCount, 0)

        let wrongBuildRoot = temporaryRoot.appendingPathComponent(
            "wrong-build",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: wrongBuildRoot,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let authorizedBuild = String(repeating: "d", count: 64)
        let compiledBuild = String(repeating: "e", count: 64)
        let wrongBuildValidator = TestAuthorizationValidator(
            kind: .installationEnrollment,
            expectedCounter: nil,
            build: authorizedBuild
        )
        let wrongBuildKeyStore = TestEnrollmentKeyStore(seed: 0x65)
        let wrongBuildCoordinator = try LAB002InboxCoordinator(
            testContainerURL: wrongBuildRoot,
            validator: wrongBuildValidator,
            enrollmentKeyStore: wrongBuildKeyStore,
            random: TestRandomBytes(byte: 0x66),
            testRuntimeContext: TestRuntimeContext(build: compiledBuild)
        )
        let wrongBuildSource = wrongBuildRoot.appendingPathComponent(
            "source.json"
        )
        try Data("valid".utf8).write(to: wrongBuildSource)
        try await wrongBuildCoordinator.importAuthorization(
            from: wrongBuildSource
        )
        do {
            _ = try await wrongBuildCoordinator.confirmInstallationEnrollment()
            XCTFail("cross-build enrollment succeeded")
        } catch LAB002CoordinatorError.wrongBuild {
        }
        XCTAssertEqual(wrongBuildKeyStore.createCount, 0)
    }

    func testRunCannotCreateRepairOrCrossBuildEnrollment() throws {
        let build = String(repeating: "d", count: 64)
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        let enrolledStore = TestEnrollmentKeyStore(seed: 0x71)
        let enrollment = LAB002EnrollmentStateCoordinator(
            storage: storage,
            keyStore: enrolledStore,
            random: TestRandomBytes(byte: 0x72)
        )
        _ = try enrollment.createAfterAuthenticatedEnrollment(
            buildBindingSHA256: build
        )

        XCTAssertThrowsError(
            try enrollment.loadForRun(
                buildBindingSHA256: String(repeating: "e", count: 64)
            )
        )

        let missingStore = TestEnrollmentKeyStore(seed: 0x73)
        let runOnly = LAB002EnrollmentStateCoordinator(
            storage: storage,
            keyStore: missingStore,
            random: TestRandomBytes(byte: 0x74)
        )
        XCTAssertThrowsError(
            try runOnly.loadForRun(buildBindingSHA256: build)
        )
        XCTAssertEqual(missingStore.createCount, 0)

        let mismatchedStore = TestEnrollmentKeyStore(
            seed: 0x75,
            preloaded: true,
            build: build
        )
        let mismatchedRun = LAB002EnrollmentStateCoordinator(
            storage: storage,
            keyStore: mismatchedStore,
            random: TestRandomBytes(byte: 0x76)
        )
        XCTAssertThrowsError(
            try mismatchedRun.loadForRun(buildBindingSHA256: build)
        )
        XCTAssertEqual(mismatchedStore.createCount, 0)
    }

    func testAuthenticatedEnrollmentRecoversOnlySameBuildOrphanedKey() throws {
        let build = String(repeating: "f", count: 64)
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        let keyStore = TestEnrollmentKeyStore(seed: 0x77)
        let random = TestRandomBytes(byte: 0x78, failureCount: 1)
        let enrollment = LAB002EnrollmentStateCoordinator(
            storage: storage,
            keyStore: keyStore,
            random: random
        )

        XCTAssertThrowsError(
            try enrollment.createAfterAuthenticatedEnrollment(
                buildBindingSHA256: build
            )
        )
        XCTAssertNil(try storage.readInstallationState())
        XCTAssertEqual(keyStore.createCount, 1)

        let continuity = try enrollment.createAfterAuthenticatedEnrollment(
            buildBindingSHA256: build
        )
        XCTAssertEqual(continuity.state.buildBindingSHA256, build)
        XCTAssertEqual(keyStore.createCount, 1)

        let crossBuildRoot = temporaryRoot.appendingPathComponent(
            "cross-build-orphan",
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: crossBuildRoot,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let crossBuildStorage = try LAB002FixedStorage(
            testContainerURL: crossBuildRoot
        )
        let orphanedStore = TestEnrollmentKeyStore(
            seed: 0x79,
            preloaded: true,
            build: build
        )
        let crossBuildEnrollment = LAB002EnrollmentStateCoordinator(
            storage: crossBuildStorage,
            keyStore: orphanedStore,
            random: TestRandomBytes(byte: 0x7a)
        )
        XCTAssertThrowsError(
            try crossBuildEnrollment.createAfterAuthenticatedEnrollment(
                buildBindingSHA256: String(repeating: "e", count: 64)
            )
        )
        XCTAssertNil(try crossBuildStorage.readInstallationState())
        XCTAssertEqual(orphanedStore.createCount, 0)
    }

    func testEnrollmentResumesOnlyItsValidatedQuarantineAfterStatePersistence()
        async throws
    {
        let build = String(repeating: "b", count: 64)
        let validator = TestAuthorizationValidator(
            kind: .installationEnrollment,
            expectedCounter: nil,
            build: build
        )
        let keyStore = TestEnrollmentKeyStore(seed: 0x7b)
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: keyStore,
            random: TestRandomBytes(byte: 0x7c),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        _ = try storage.quarantineAuthorization()
        let enrollment = LAB002EnrollmentStateCoordinator(
            storage: storage,
            keyStore: keyStore,
            random: TestRandomBytes(byte: 0x7c)
        )
        _ = try enrollment.createAfterAuthenticatedEnrollment(
            buildBindingSHA256: build
        )

        let continuity = try await coordinator.confirmInstallationEnrollment()
        XCTAssertEqual(continuity.state.buildBindingSHA256, build)
        XCTAssertEqual(keyStore.createCount, 1)
        XCTAssertThrowsError(try storage.quarantineAuthorization())

        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        do {
            _ = try await coordinator.confirmInstallationEnrollment()
            XCTFail("fresh re-enrollment accepted existing state")
        } catch LAB002EnrollmentError.alreadyEnrolled {
        }
        _ = try storage.quarantineAuthorization()
    }

    func testSessionReportHasExactCanonicalClosedForm() throws {
        let report = try makeSessionReport()
        let canonical = try report.canonicalData()
        XCTAssertEqual(
            String(decoding: canonical, as: UTF8.self),
            """
            {"acknowledgement_sha256":"\(String(repeating: "b", count: 64))","authorization_envelope_sha256":"\(String(repeating: "c", count: 64))","authorization_policy_version":"orchardprobe.authorized-use.v1","build_binding_sha256":"\(String(repeating: "a", count: 64))","build_number":"1","challenge_sha256":"\(String(repeating: "d", count: 64))","collection_id":"\(String(repeating: "e", count: 64))","completed_at":null,"created_at":1500,"device_enrollment_binding_sha256":"\(String(repeating: "f", count: 64))","device_installation_binding_sha256":"\(String(repeating: "1", count: 64))","enrollment_public_key":"\(String(repeating: "2", count: 64))","environment":{"hardware_model":"iPhone17,1","ios_build":"22A3354","ios_product_version":"18.0"},"marketing_version":"1.0","observer_revision":"lab002-observer-v1","profile":"orchardprobe.demolab.lab002.observation.v1","run_counter":"0000000000000001","run_ordinal":1,"schema":"orchardprobe.lab002.session-report.v1","session_id":"\(String(repeating: "3", count: 64))","source_commit":"\(String(repeating: "4", count: 40))","state":"collecting"}
            """
        )
        XCTAssertEqual(
            try LAB002SessionReport(canonicalBytes: canonical),
            report
        )

        let nonCanonical = Data(
            String(decoding: canonical, as: UTF8.self)
                .replacingOccurrences(
                    of: #"{"acknowledgement_sha256""#,
                    with: #"{ "acknowledgement_sha256""#
                )
                .utf8
        )
        XCTAssertThrowsError(
            try LAB002SessionReport(canonicalBytes: nonCanonical)
        )
    }

    func testExistingSessionRejectsRunBeforeCounterOrAuthorizationConsumption()
        async throws
    {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(
            expectedCounter: 1,
            build: build
        )
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator,
            enrollmentKeyStore: TestEnrollmentKeyStore(),
            random: TestRandomBytes(byte: 0x51),
            testRuntimeContext: TestRuntimeContext(build: build)
        )
        try await enroll(
            coordinator: coordinator,
            validator: validator,
            build: build
        )
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        try storage.createSession(makeSessionReport())
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        do {
            _ = try await coordinator.startCleanRun()
            XCTFail("existing session accepted a new run")
        } catch LAB002StorageError.existingEntry {
        }
        XCTAssertNil(try storage.readCounter())
        XCTAssertTrue(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(
                        LAB002FixedName.authorization
                    )
                    .path
            )
        )
    }

    func testSessionCreationIsExclusiveAndBounded() throws {
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        let report = try makeSessionReport()
        try storage.createSession(report)
        XCTAssertEqual(try storage.readSession(), report)
        XCTAssertThrowsError(try storage.createSession(report))

        let sessionURL = storage.reportsURL
            .appendingPathComponent(LAB002FixedName.currentReports)
            .appendingPathComponent(LAB002FixedName.session)
        try Data(repeating: 0x61, count: LAB002Limit.sessionReport + 1)
            .write(to: sessionURL)
        XCTAssertThrowsError(try storage.readSession())
    }

    func testSessionTemporaryPublicationIsRecoverable() throws {
        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        let currentURL = storage.reportsURL.appendingPathComponent(
            LAB002FixedName.currentReports,
            isDirectory: true
        )
        try FileManager.default.createDirectory(
            at: currentURL,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        let temporaryURL = currentURL.appendingPathComponent(
            LAB002FixedName.sessionTemporary
        )
        let report = try makeSessionReport()
        try report.canonicalData().write(to: temporaryURL)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: temporaryURL.path
        )

        try storage.createOrRecoverSession(report)

        XCTAssertEqual(try storage.readSession(), report)
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: temporaryURL.path)
        )
    }

    private func enroll(
        coordinator: LAB002InboxCoordinator,
        validator: TestAuthorizationValidator,
        build: String
    ) async throws {
        let expectedRunCounter = validator.metadata.expectedRunCounter ?? 1
        validator.metadata = LAB002AuthorizationMetadata(
            kind: .installationEnrollment,
            buildBindingSHA256: build,
            notBefore: 1_000,
            notAfter: 1_900,
            expectedRunCounter: nil
        )
        let source = temporaryRoot.appendingPathComponent("enrollment.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        _ = try await coordinator.confirmInstallationEnrollment()
        validator.metadata = LAB002AuthorizationMetadata(
            kind: .collectionRun,
            buildBindingSHA256: build,
            notBefore: 1_000,
            notAfter: 1_900,
            expectedRunCounter: expectedRunCounter,
            runFacts: TestAuthorizationValidator.runFacts(
                counter: expectedRunCounter
            )
        )
    }

    private func makeSessionReport() throws -> LAB002SessionReport {
        try LAB002SessionReport(
            observerRevision: "lab002-observer-v1",
            buildBindingSHA256: String(repeating: "a", count: 64),
            collectionID: String(repeating: "e", count: 64),
            runOrdinal: 1,
            challengeSHA256: String(repeating: "d", count: 64),
            acknowledgementSHA256: String(repeating: "b", count: 64),
            authorizationEnvelopeSHA256: String(repeating: "c", count: 64),
            deviceEnrollmentBindingSHA256: String(repeating: "f", count: 64),
            enrollmentPublicKey: String(repeating: "2", count: 64),
            deviceInstallationBindingSHA256: String(repeating: "1", count: 64),
            environment: LAB002SessionEnvironment(
                hardwareModel: "iPhone17,1",
                iosProductVersion: "18.0",
                iosBuild: "22A3354"
            ),
            sessionID: String(repeating: "3", count: 64),
            runCounter: "0000000000000001",
            createdAt: 1_500,
            completedAt: nil,
            sourceCommit: String(repeating: "4", count: 40),
            marketingVersion: "1.0",
            buildNumber: "1",
            state: .collecting
        )
    }
}
