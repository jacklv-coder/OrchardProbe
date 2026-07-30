import Darwin
import Foundation
import XCTest
@testable import DemoLab

private final class TestAuthorizationValidator: LAB002AuthorizationValidating {
    let metadata: LAB002AuthorizationMetadata
    var shouldFail = false

    init(expectedCounter: UInt64? = 1, build: String = String(repeating: "a", count: 64)) {
        metadata = LAB002AuthorizationMetadata(
            kind: .collectionRun,
            buildBindingSHA256: build,
            notBefore: 1_000,
            notAfter: 1_900,
            expectedRunCounter: expectedCounter
        )
    }

    func validate(_ canonicalBytes: Data) throws -> LAB002AuthorizationMetadata {
        if shouldFail || canonicalBytes != Data("valid".utf8) {
            throw LAB002CoordinatorError.wrongOperation
        }
        return metadata
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
            validator: validator
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
            validator: validator
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        let consumed = try await coordinator.startCleanRun(
            now: 1_500,
            buildBindingSHA256: build
        )
        XCTAssertEqual(consumed.canonicalBytes, Data("valid".utf8))

        let storage = try LAB002FixedStorage(testContainerURL: temporaryRoot)
        XCTAssertEqual(try storage.readCounter()?.counter, 1)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: storage.inboxURL
                    .appendingPathComponent(LAB002FixedName.authorization)
                    .path
            )
        )
    }

    func testCounterRejectsSkipAndLeavesQuarantine() async throws {
        let build = String(repeating: "a", count: 64)
        let validator = TestAuthorizationValidator(expectedCounter: 2, build: build)
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        do {
            _ = try await coordinator.startCleanRun(
                now: 1_500,
                buildBindingSHA256: build
            )
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
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator
        )
        let source = temporaryRoot.appendingPathComponent("source.json")
        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)

        do {
            _ = try await coordinator.discardStaleAuthorization(
                now: 1_500,
                buildBindingSHA256: build
            )
            XCTFail("current authorization was discarded")
        } catch LAB002CoordinatorError.authorizationStillValid {
        }

        let expired = try await coordinator.discardStaleAuthorization(
            now: 2_021,
            buildBindingSHA256: build
        )
        guard case .expired = expired else {
            return XCTFail("expected expired")
        }

        try Data("valid".utf8).write(to: source)
        try await coordinator.importAuthorization(from: source)
        validator.shouldFail = true
        let malformed = try await coordinator.discardStaleAuthorization(
            now: 1_500,
            buildBindingSHA256: build
        )
        guard case .malformed = malformed else {
            return XCTFail("expected malformed")
        }
    }

    func testSymlinkedSourceAndQuarantineResidueFailClosed() async throws {
        let validator = TestAuthorizationValidator()
        let coordinator = try LAB002InboxCoordinator(
            testContainerURL: temporaryRoot,
            validator: validator
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
            _ = try await coordinator.startCleanRun(
                now: 1_500,
                buildBindingSHA256: String(repeating: "a", count: 64)
            )
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
}
