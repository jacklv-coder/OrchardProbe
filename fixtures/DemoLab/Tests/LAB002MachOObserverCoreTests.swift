import CryptoKit
import Foundation
import XCTest
@testable import DemoLab

final class LAB002MachOObserverCoreTests: XCTestCase {
    func testThinImageProducesBoundedEvidence() throws {
        let bytes = makeThinMachO(uuidSeed: 0x10)

        let installed = try LAB002MachOObserverTestHarness.parseInstalled(bytes)

        XCTAssertEqual(installed.fileSize, 0x1200)
        XCTAssertEqual(installed.container, .thin)
        XCTAssertEqual(installed.slices.count, 1)
        let slice = try XCTUnwrap(installed.slices.first)
        XCTAssertEqual(slice.ordinal, 0)
        XCTAssertEqual(slice.cpuType, Int32(bitPattern: 0x0100_000c))
        XCTAssertEqual(slice.cpuSubtype, 0)
        XCTAssertEqual(
            slice.uuid,
            (0..<16).map { String(format: "%02x", 0x10 + $0) }.joined()
        )
        XCTAssertEqual(slice.sliceFileOffset, 0)
        XCTAssertEqual(slice.sliceFileSize, 0x1200)
        XCTAssertEqual(slice.sectionSliceOffset, 0x1000)
        XCTAssertEqual(slice.sectionFileOffset, 0x1000)
        XCTAssertEqual(slice.sectionVMOffset, 0x1000)
        XCTAssertEqual(slice.sectionLength, 0x100)
        XCTAssertEqual(
            slice.diskSHA256,
            Data(SHA256.hash(data: bytes.subdata(in: 0x1000..<0x1100)))
                .map { String(format: "%02x", $0) }
                .joined()
        )
        XCTAssertEqual(slice.encryption.command, .info64)
        XCTAssertEqual(slice.encryption.cryptoff, 0x800)
        XCTAssertEqual(slice.encryption.cryptsize, 0x900)
        XCTAssertEqual(slice.encryption.cryptFileStart, 0x800)
        XCTAssertEqual(slice.encryption.cryptFileEnd, 0x1100)
        XCTAssertEqual(slice.encryption.cryptid, 1)
        XCTAssertTrue(slice.encryption.coversFixedSection)
    }

    func testFatImageBindsEveryDeclaredSlice() throws {
        let installed = try LAB002MachOObserverTestHarness.parseInstalled(
            makeFat32MachO()
        )

        XCTAssertEqual(installed.container, .fat32)
        XCTAssertEqual(installed.slices.map(\.ordinal), [0, 1])
        XCTAssertEqual(installed.slices.map(\.sliceFileOffset), [0x1000, 0x3000])
        XCTAssertEqual(
            installed.slices.map(\.sectionFileOffset),
            [0x2000, 0x4000]
        )
        XCTAssertEqual(installed.slices.map(\.cpuSubtype), [0, 2])
        XCTAssertNotEqual(installed.slices[0].uuid, installed.slices[1].uuid)
    }

    func testMappedHeaderMustMatchInstalledCoordinatesAndAnchor() throws {
        let bytes = makeThinMachO(uuidSeed: 0x20)
        let installed = try LAB002MachOObserverTestHarness.parseInstalled(bytes)
        let slice = try XCTUnwrap(installed.slices.first)
        let header = bytes.subdata(in: 0..<232)

        XCTAssertEqual(
            try LAB002MachOObserverTestHarness.parseMappedHeader(
                header,
                matching: slice,
                anchorVMOffset: 0x1000
            ),
            LAB002MappedMachORange(
                sectionVMOffset: 0x1000,
                sectionLength: 0x100
            )
        )

        var wrongUUID = header
        wrongUUID[192] ^= 0xff
        assertMappedRejects(wrongUUID, matching: slice, anchor: 0x1000)
        assertMappedRejects(header, matching: slice, anchor: 0x0fff)
        assertMappedRejects(header, matching: slice, anchor: 0x1100)
    }

    func testMalformedFixedSectionCoordinatesAndRelocationsAreRejected() {
        var outOfBounds = makeThinMachO()
        writeLittleEndian(UInt32(0x1180), to: &outOfBounds, at: 152)
        assertRejects(outOfBounds, .fixedSectionOutOfBounds)

        var relocated = makeThinMachO()
        writeLittleEndian(UInt32(1), to: &relocated, at: 164)
        assertRejects(relocated, .fixedSectionHasFixups)

        var missing = makeThinMachO()
        missing[104] = UInt8(ascii: "x")
        assertRejects(missing, .missingOrDuplicateFixedSection)
    }

    func testEncryptionCommandAndCoverageAreClosed() {
        var wrongCommand = makeThinMachO()
        writeLittleEndian(UInt32(0x21), to: &wrongCommand, at: 208)
        assertRejects(wrongCommand, .encryptionCommandInvalid)

        var uncovered = makeThinMachO()
        writeLittleEndian(UInt32(0x100), to: &uncovered, at: 220)
        let installed = try? LAB002MachOObserverTestHarness.parseInstalled(
            uncovered
        )
        XCTAssertEqual(
            installed?.slices.first?.encryption.coversFixedSection,
            false
        )
    }

    func testClassicFixupTargetingTextIsRejected() {
        assertRejects(
            makeThinMachO(includeClassicTextFixup: true),
            .fixedSectionHasFixups
        )
    }

    func testChainedFixupTargetingTextIsRejected() {
        assertRejects(
            makeThinMachO(includeChainedTextFixup: true),
            .fixedSectionHasFixups
        )
    }

    func testFatSliceOverlapAndExcessCountAreRejected() {
        var overlap = makeFat32MachO()
        writeBigEndian(UInt32(0x2000), to: &overlap, at: 8 + 20 + 8)
        assertRejects(overlap, .inventoryMismatch)

        var tooMany = Data()
        appendBigEndian(UInt32(0xcafe_babe), to: &tooMany)
        appendBigEndian(UInt32(5), to: &tooMany)
        tooMany.append(Data(repeating: 0, count: 100))
        assertRejects(tooMany, .unexpectedInstalledSlice)
    }

    func testDescriptorReaderRejectsSymbolicLinks() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: false
        )
        defer { try? FileManager.default.removeItem(at: root) }
        let executable = root.appendingPathComponent("DemoLab")
        let symbolicLink = root.appendingPathComponent("DemoLab-link")
        try makeThinMachO().write(to: executable)
        try FileManager.default.createSymbolicLink(
            at: symbolicLink,
            withDestinationURL: executable
        )

        XCTAssertEqual(
            try LAB002MachOObserverTestHarness.parseInstalledFile(
                at: executable
            ).slices.count,
            1
        )
        XCTAssertThrowsError(
            try LAB002MachOObserverTestHarness.parseInstalledFile(
                at: symbolicLink
            )
        ) { error in
            XCTAssertEqual(
                (error as? LAB002ObserverReason)?.rawValue,
                LAB002ObserverReason.inventoryMismatch.rawValue
            )
        }
    }

    private func assertMappedRejects(
        _ bytes: Data,
        matching slice: LAB002MachOFixedSlice,
        anchor: UInt64
    ) {
        XCTAssertThrowsError(
            try LAB002MachOObserverTestHarness.parseMappedHeader(
                bytes,
                matching: slice,
                anchorVMOffset: anchor
            )
        ) { error in
            XCTAssertEqual(
                (error as? LAB002ObserverReason)?.rawValue,
                LAB002ObserverReason.inventoryMismatch.rawValue
            )
        }
    }

    private func assertRejects(
        _ bytes: Data,
        _ reason: LAB002ObserverReason
    ) {
        XCTAssertThrowsError(
            try LAB002MachOObserverTestHarness.parseInstalled(bytes)
        ) { error in
            XCTAssertEqual(
                (error as? LAB002ObserverReason)?.rawValue,
                reason.rawValue
            )
        }
    }
}

private func makeThinMachO(
    uuidSeed: UInt8 = 0x10,
    cpuSubtype: Int32 = 0,
    includeClassicTextFixup: Bool = false,
    includeChainedTextFixup: Bool = false
) -> Data {
    precondition(!(includeClassicTextFixup && includeChainedTextFixup))
    var segment = Data()
    appendLittleEndian(UInt32(0x19), to: &segment)
    appendLittleEndian(UInt32(152), to: &segment)
    appendFixedName("__TEXT", to: &segment)
    appendLittleEndian(UInt64(0x1_0000_0000), to: &segment)
    appendLittleEndian(UInt64(0x2000), to: &segment)
    appendLittleEndian(UInt64(0), to: &segment)
    appendLittleEndian(UInt64(0x1200), to: &segment)
    appendLittleEndian(UInt32(5), to: &segment)
    appendLittleEndian(UInt32(5), to: &segment)
    appendLittleEndian(UInt32(1), to: &segment)
    appendLittleEndian(UInt32(0), to: &segment)
    appendFixedName("__oprobe", to: &segment)
    appendFixedName("__TEXT", to: &segment)
    appendLittleEndian(UInt64(0x1_0000_1000), to: &segment)
    appendLittleEndian(UInt64(0x100), to: &segment)
    appendLittleEndian(UInt32(0x1000), to: &segment)
    appendLittleEndian(UInt32(2), to: &segment)
    appendLittleEndian(UInt32(0), to: &segment)
    appendLittleEndian(UInt32(0), to: &segment)
    appendLittleEndian(UInt32(0x8000_0400), to: &segment)
    appendLittleEndian(UInt32(0), to: &segment)
    appendLittleEndian(UInt32(0), to: &segment)
    appendLittleEndian(UInt32(0), to: &segment)

    var uuid = Data()
    appendLittleEndian(UInt32(0x1b), to: &uuid)
    appendLittleEndian(UInt32(24), to: &uuid)
    uuid.append(contentsOf: (0..<16).map { uuidSeed &+ UInt8($0) })

    var encryption = Data()
    appendLittleEndian(UInt32(0x2c), to: &encryption)
    appendLittleEndian(UInt32(24), to: &encryption)
    appendLittleEndian(UInt32(0x800), to: &encryption)
    appendLittleEndian(UInt32(0x900), to: &encryption)
    appendLittleEndian(UInt32(1), to: &encryption)
    appendLittleEndian(UInt32(0), to: &encryption)

    var dyldInfo = Data()
    if includeClassicTextFixup {
        appendLittleEndian(UInt32(0x8000_0022), to: &dyldInfo)
        appendLittleEndian(UInt32(48), to: &dyldInfo)
        appendLittleEndian(UInt32(0x300), to: &dyldInfo)
        appendLittleEndian(UInt32(6), to: &dyldInfo)
        for _ in 0..<8 {
            appendLittleEndian(UInt32(0), to: &dyldInfo)
        }
    }

    var chainedFixups = Data()
    if includeChainedTextFixup {
        appendLittleEndian(UInt32(0x8000_0034), to: &chainedFixups)
        appendLittleEndian(UInt32(16), to: &chainedFixups)
        appendLittleEndian(UInt32(0x300), to: &chainedFixups)
        appendLittleEndian(UInt32(62), to: &chainedFixups)
    }

    let commands = segment + uuid + encryption + dyldInfo + chainedFixups
    var result = Data()
    result.append(contentsOf: [0xcf, 0xfa, 0xed, 0xfe])
    appendLittleEndian(UInt32(0x0100_000c), to: &result)
    appendLittleEndian(UInt32(bitPattern: cpuSubtype), to: &result)
    appendLittleEndian(UInt32(2), to: &result)
    appendLittleEndian(
        UInt32(
            includeClassicTextFixup || includeChainedTextFixup ? 4 : 3
        ),
        to: &result
    )
    appendLittleEndian(UInt32(commands.count), to: &result)
    appendLittleEndian(UInt32(0), to: &result)
    appendLittleEndian(UInt32(0), to: &result)
    result.append(commands)
    result.append(Data(repeating: 0, count: 0x1200 - result.count))
    if includeClassicTextFixup {
        result.replaceSubrange(
            0x300..<0x306,
            with: [0x11, 0x20, 0x80, 0x20, 0x51, 0x00]
        )
    }
    if includeChainedTextFixup {
        var payload = Data()
        appendLittleEndian(UInt32(0), to: &payload)
        appendLittleEndian(UInt32(28), to: &payload)
        appendLittleEndian(UInt32(0), to: &payload)
        appendLittleEndian(UInt32(0), to: &payload)
        appendLittleEndian(UInt32(0), to: &payload)
        appendLittleEndian(UInt32(1), to: &payload)
        appendLittleEndian(UInt32(0), to: &payload)
        appendLittleEndian(UInt32(1), to: &payload)
        appendLittleEndian(UInt32(8), to: &payload)
        appendLittleEndian(UInt32(26), to: &payload)
        appendLittleEndian(UInt16(0x1000), to: &payload)
        appendLittleEndian(UInt16(1), to: &payload)
        appendLittleEndian(UInt64(0), to: &payload)
        appendLittleEndian(UInt32(0), to: &payload)
        appendLittleEndian(UInt16(2), to: &payload)
        appendLittleEndian(UInt16(0xffff), to: &payload)
        appendLittleEndian(UInt16(0), to: &payload)
        precondition(payload.count == 62)
        result.replaceSubrange(0x300..<0x33e, with: payload)
    }
    for index in 0..<0x100 {
        result[0x1000 + index] = UInt8(truncatingIfNeeded: index)
    }
    return result
}

private func makeFat32MachO() -> Data {
    let first = makeThinMachO(uuidSeed: 0x10, cpuSubtype: 0)
    let second = makeThinMachO(uuidSeed: 0x30, cpuSubtype: 2)
    var result = Data()
    appendBigEndian(UInt32(0xcafe_babe), to: &result)
    appendBigEndian(UInt32(2), to: &result)
    for (offset, subtype) in [(0x1000, 0), (0x3000, 2)] {
        appendBigEndian(UInt32(0x0100_000c), to: &result)
        appendBigEndian(UInt32(subtype), to: &result)
        appendBigEndian(UInt32(offset), to: &result)
        appendBigEndian(UInt32(0x1200), to: &result)
        appendBigEndian(UInt32(12), to: &result)
    }
    result.append(Data(repeating: 0, count: 0x4200 - result.count))
    result.replaceSubrange(0x1000..<0x2200, with: first)
    result.replaceSubrange(0x3000..<0x4200, with: second)
    return result
}

private func appendFixedName(_ value: String, to data: inout Data) {
    let bytes = Array(value.utf8)
    data.append(contentsOf: bytes)
    data.append(Data(repeating: 0, count: 16 - bytes.count))
}

private func appendLittleEndian<T: FixedWidthInteger>(
    _ value: T,
    to data: inout Data
) {
    var little = value.littleEndian
    withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
}

private func appendBigEndian<T: FixedWidthInteger>(
    _ value: T,
    to data: inout Data
) {
    var big = value.bigEndian
    withUnsafeBytes(of: &big) { data.append(contentsOf: $0) }
}

private func writeLittleEndian<T: FixedWidthInteger>(
    _ value: T,
    to data: inout Data,
    at offset: Int
) {
    var replacement = Data()
    appendLittleEndian(value, to: &replacement)
    data.replaceSubrange(offset..<(offset + replacement.count), with: replacement)
}

private func writeBigEndian<T: FixedWidthInteger>(
    _ value: T,
    to data: inout Data,
    at offset: Int
) {
    var replacement = Data()
    appendBigEndian(value, to: &replacement)
    data.replaceSubrange(offset..<(offset + replacement.count), with: replacement)
}
