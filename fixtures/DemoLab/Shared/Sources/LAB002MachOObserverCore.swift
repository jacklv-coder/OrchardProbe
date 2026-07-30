import CryptoKit
import Darwin
import Foundation

enum LAB002ObserverReason: String, Error {
    case identityMismatch = "identity_mismatch"
    case signatureInvalidOrUnchecked = "signature_invalid_or_unchecked"
    case inventoryMismatch = "inventory_mismatch"
    case missingOrDuplicateFixedSection = "missing_or_duplicate_fixed_section"
    case fixedSectionOutOfBounds = "fixed_section_out_of_bounds"
    case fixedSectionHasFixups = "fixed_section_has_fixups"
    case encryptionCommandInvalid = "encryption_command_invalid"
    case encryptionDoesNotCoverRange = "encryption_does_not_cover_range"
    case unexpectedInstalledSlice = "unexpected_installed_slice"
    case reportLimitExceeded = "report_limit_exceeded"
}

enum LAB002SignaturePresence: String {
    case present
    case absent
}

enum LAB002SignatureKind: String {
    case cms
    case adHoc = "ad_hoc"
    case unknown
    case notApplicable = "not_applicable"
}

enum LAB002SignatureValidation: String {
    case valid
    case invalid
    case notChecked = "not_checked"
    case notApplicable = "not_applicable"
}

struct LAB002SelectedEntitlements: Equatable {
    let applicationIdentifier: String?
    let developerTeamIdentifier: String?
    let applicationGroups: [String]?
}

struct LAB002MachOSigningMetadata: Equatable {
    let presence: LAB002SignaturePresence
    let kind: LAB002SignatureKind
    let validation: LAB002SignatureValidation
    let validatorID: String
    let validatorRevision: String
    let superblobSHA256: String?
    let codeDirectoryIdentifier: String?
    let codeDirectoryTeamIdentifier: String?
    let entitlements: LAB002SelectedEntitlements
}

enum LAB002MachOContainerKind: String {
    case thin
    case fat32
    case fat64
}

enum LAB002MachOEncryptionCommand: String {
    case info32 = "lc_encryption_info"
    case info64 = "lc_encryption_info_64"
}

struct LAB002MachOEncryptionEvidence: Equatable {
    let command: LAB002MachOEncryptionCommand
    let cryptoff: UInt64
    let cryptsize: UInt64
    let cryptFileStart: UInt64
    let cryptFileEnd: UInt64
    let cryptid: UInt32
    let coversFixedSection: Bool
}

struct LAB002MachOFixedSlice: Equatable {
    let ordinal: UInt8
    let cpuType: Int32
    let cpuSubtype: Int32
    let uuid: String
    let sliceFileOffset: UInt64
    let sliceFileSize: UInt64
    let sectionSliceOffset: UInt64
    let sectionFileOffset: UInt64
    let sectionVMOffset: UInt64
    let sectionLength: UInt64
    let diskSHA256: String
    let encryption: LAB002MachOEncryptionEvidence
    let signing: LAB002MachOSigningMetadata

    fileprivate let textVMAddress: UInt64
    fileprivate let sectionVMAddress: UInt64
}

struct LAB002InstalledMachO: Equatable {
    let fileSize: UInt64
    let container: LAB002MachOContainerKind
    let slices: [LAB002MachOFixedSlice]
}

struct LAB002MappedMachORange: Equatable {
    let sectionVMOffset: UInt64
    let sectionLength: UInt64
}

private enum LAB002ByteOrder {
    case little
    case big

    func uint16(_ bytes: Data, _ offset: Int) throws -> UInt16 {
        _ = try checkedRange(offset: offset, count: 2, limit: bytes.count)
        return self == .big
            ? (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
            : UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    func uint32(_ bytes: Data, _ offset: Int) throws -> UInt32 {
        _ = try checkedRange(offset: offset, count: 4, limit: bytes.count)
        var value = UInt32(0)
        for index in 0..<4 {
            let shift = self == .big ? (3 - index) * 8 : index * 8
            value |= UInt32(bytes[offset + index]) << UInt32(shift)
        }
        return value
    }

    func int32(_ bytes: Data, _ offset: Int) throws -> Int32 {
        Int32(bitPattern: try uint32(bytes, offset))
    }

    func uint64(_ bytes: Data, _ offset: Int) throws -> UInt64 {
        _ = try checkedRange(offset: offset, count: 8, limit: bytes.count)
        var value = UInt64(0)
        for index in 0..<8 {
            let shift = self == .big ? (7 - index) * 8 : index * 8
            value |= UInt64(bytes[offset + index]) << UInt64(shift)
        }
        return value
    }
}

private protocol LAB002MachOReading {
    var size: UInt64 { get }
    func read(offset: UInt64, count: Int) throws -> Data
    func validateUnchanged() throws
}

private extension LAB002MachOReading {
    func validateUnchanged() throws {}
}

private struct LAB002DataMachOReader: LAB002MachOReading {
    let data: Data
    let declaredSize: UInt64

    init(_ data: Data, declaredSize: UInt64? = nil) {
        self.data = data
        self.declaredSize = declaredSize ?? UInt64(data.count)
    }

    var size: UInt64 {
        declaredSize
    }

    func read(offset: UInt64, count: Int) throws -> Data {
        guard count >= 0 else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
        let result = offset.addingReportingOverflow(UInt64(count))
        guard !result.overflow,
              let startIndex = Int(exactly: offset),
              let endIndex = Int(exactly: result.partialValue),
              result.partialValue <= UInt64(data.count),
              startIndex <= endIndex
        else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
        return data.subdata(in: startIndex..<endIndex)
    }
}

private final class LAB002DescriptorMachOReader: LAB002MachOReading {
    private let descriptor: Int32
    private let initialStatus: stat

    let size: UInt64

    init(fixedExecutableURL: URL) throws {
        let opened = fixedExecutableURL.withUnsafeFileSystemRepresentation {
            path in
            guard let path else { return Int32(-1) }
            return Darwin.open(
                path,
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW
            )
        }
        guard opened >= 0 else {
            throw LAB002ObserverReason.inventoryMismatch
        }

        var status = stat()
        guard fstat(opened, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_nlink > 0,
              status.st_size >= 4,
              UInt64(status.st_size) <=
                LAB002MachOObserverCore.maximumExecutableBytes
        else {
            Darwin.close(opened)
            throw LAB002ObserverReason.inventoryMismatch
        }
        descriptor = opened
        initialStatus = status
        size = UInt64(status.st_size)
    }

    deinit {
        Darwin.close(descriptor)
    }

    func read(offset: UInt64, count: Int) throws -> Data {
        guard count >= 0,
              offset <= UInt64(Int64.max),
              UInt64(count) <= UInt64(Int.max)
        else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
        let end = offset.addingReportingOverflow(UInt64(count))
        guard !end.overflow, end.partialValue <= size else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
        var bytes = Data(count: count)
        var completed = 0
        while completed < count {
            let result: Int = bytes.withUnsafeMutableBytes { rawBytes in
                guard let baseAddress = rawBytes.baseAddress else {
                    return count == 0 ? 0 : -1
                }
                return pread(
                    descriptor,
                    baseAddress.advanced(by: completed),
                    count - completed,
                    off_t(offset) + off_t(completed)
                )
            }
            if result < 0, errno == EINTR {
                continue
            }
            guard result > 0 else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            completed += result
        }
        return bytes
    }

    func validateUnchanged() throws {
        var current = stat()
        guard fstat(descriptor, &current) == 0,
              current.st_dev == initialStatus.st_dev,
              current.st_ino == initialStatus.st_ino,
              current.st_mode == initialStatus.st_mode,
              current.st_nlink == initialStatus.st_nlink,
              current.st_size == initialStatus.st_size,
              current.st_mtimespec.tv_sec
                == initialStatus.st_mtimespec.tv_sec,
              current.st_mtimespec.tv_nsec
                == initialStatus.st_mtimespec.tv_nsec,
              current.st_ctimespec.tv_sec
                == initialStatus.st_ctimespec.tv_sec,
              current.st_ctimespec.tv_nsec
                == initialStatus.st_ctimespec.tv_nsec
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
    }
}

private struct LAB002SliceDescriptor {
    let ordinal: UInt8
    let offset: UInt64
    let size: UInt64
    let cpuType: Int32?
    let cpuSubtype: Int32?
}

private struct LAB002MachOMagic {
    let order: LAB002ByteOrder
    let is64Bit: Bool
}

private struct LAB002FixupSegment {
    let vmAddress: UInt64
    let vmSize: UInt64
    let isText: Bool
}

private struct LAB002SectionInterval {
    let index: Int
    let start: UInt64
    let end: UInt64
}

private struct LAB002ClassicFixupStream {
    enum Kind {
        case rebase
        case bind
    }

    let offset: UInt32
    let size: UInt32
    let kind: Kind
}

private struct LAB002ParsedSlice {
    let fixed: LAB002MachOFixedSlice
    let loadCommandBytes: Data
}

enum LAB002MachOObserverCore {
    static let maximumExecutableBytes: UInt64 = 100 * 1024 * 1024
    static let maximumLoadCommands = 4_096
    static let maximumLoadCommandBytes = 4 * 1024 * 1024
    static let maximumFixupPayloadBytes = 16 * 1024 * 1024

    private static let lcSegment: UInt32 = 0x1
    private static let lcSymtab: UInt32 = 0x2
    private static let lcDysymtab: UInt32 = 0xb
    private static let lcSegment64: UInt32 = 0x19
    private static let lcUUID: UInt32 = 0x1b
    private static let lcCodeSignature: UInt32 = 0x1d
    private static let lcDyldInfo: UInt32 = 0x22
    private static let lcDyldInfoOnly: UInt32 = 0x8000_0022
    private static let lcEncryptionInfo: UInt32 = 0x21
    private static let lcEncryptionInfo64: UInt32 = 0x2c
    private static let lcDyldChainedFixups: UInt32 = 0x8000_0034

    private static func parseInstalled<R: LAB002MachOReading>(
        _ reader: R
    ) throws -> LAB002InstalledMachO {
        guard (4...maximumExecutableBytes).contains(reader.size) else {
            throw LAB002ObserverReason.reportLimitExceeded
        }
        let magic = try reader.read(offset: 0, count: 4)
        let descriptors: [LAB002SliceDescriptor]
        let container: LAB002MachOContainerKind
        if classifyThinMagic(magic) != nil {
            container = .thin
            descriptors = [
                LAB002SliceDescriptor(
                    ordinal: 0,
                    offset: 0,
                    size: reader.size,
                    cpuType: nil,
                    cpuSubtype: nil
                ),
            ]
        } else if let fat = classifyFatMagic(magic) {
            container = fat.is64Bit ? .fat64 : .fat32
            descriptors = try parseFatDescriptors(
                reader,
                order: fat.order,
                is64Bit: fat.is64Bit
            )
        } else {
            throw LAB002ObserverReason.inventoryMismatch
        }

        var slices: [LAB002MachOFixedSlice] = []
        var uuids = Set<String>()
        for descriptor in descriptors {
            let parsed = try parseSlice(
                reader,
                descriptor: descriptor,
                inspectFixupPayloads: true,
                hashSection: true
            )
            guard uuids.insert(parsed.fixed.uuid).inserted else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            slices.append(parsed.fixed)
        }
        try reader.validateUnchanged()
        return LAB002InstalledMachO(
            fileSize: reader.size,
            container: container,
            slices: slices
        )
    }

    static func parseInstalledFile(
        at fixedExecutableURL: URL
    ) throws -> LAB002InstalledMachO {
        try parseInstalled(
            LAB002DescriptorMachOReader(
                fixedExecutableURL: fixedExecutableURL
            )
        )
    }

    static func parseInstalledBytes(
        _ bytes: Data
    ) throws -> LAB002InstalledMachO {
        try parseInstalled(LAB002DataMachOReader(bytes))
    }

    static func matchMappedHeader(
        _ headerBytes: Data,
        installed: LAB002InstalledMachO,
        anchorVMOffset: UInt64
    ) throws -> (
        activeSliceIndex: Int,
        mappedRange: LAB002MappedMachORange
    ) {
        var match: (Int, LAB002MappedMachORange)?
        for (index, slice) in installed.slices.enumerated() {
            guard let range = try? parseMappedHeader(
                headerBytes,
                matching: slice,
                anchorVMOffset: anchorVMOffset
            ) else {
                continue
            }
            guard match == nil else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            match = (index, range)
        }
        guard let match else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        return match
    }

    static func parseMappedHeader(
        _ headerBytes: Data,
        matching installed: LAB002MachOFixedSlice,
        anchorVMOffset: UInt64
    ) throws -> LAB002MappedMachORange {
        let reader = LAB002DataMachOReader(
            headerBytes,
            declaredSize: installed.sliceFileSize
        )
        let parsed = try parseSlice(
            reader,
            descriptor: LAB002SliceDescriptor(
                ordinal: installed.ordinal,
                offset: 0,
                size: installed.sliceFileSize,
                cpuType: installed.cpuType,
                cpuSubtype: installed.cpuSubtype
            ),
            inspectFixupPayloads: false,
            hashSection: false
        ).fixed
        let sectionEnd = try checkedAdd(
            parsed.sectionVMOffset,
            parsed.sectionLength,
            reason: .fixedSectionOutOfBounds
        )
        guard parsed.cpuType == installed.cpuType,
              parsed.cpuSubtype == installed.cpuSubtype,
              parsed.uuid == installed.uuid,
              parsed.sectionSliceOffset == installed.sectionSliceOffset,
              parsed.sectionVMOffset == installed.sectionVMOffset,
              parsed.sectionLength == installed.sectionLength,
              parsed.textVMAddress == installed.textVMAddress,
              parsed.sectionVMAddress == installed.sectionVMAddress,
              anchorVMOffset >= parsed.sectionVMOffset,
              anchorVMOffset < sectionEnd
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        return LAB002MappedMachORange(
            sectionVMOffset: parsed.sectionVMOffset,
            sectionLength: parsed.sectionLength
        )
    }

    private static func parseFatDescriptors<R: LAB002MachOReading>(
        _ reader: R,
        order: LAB002ByteOrder,
        is64Bit: Bool
    ) throws -> [LAB002SliceDescriptor] {
        let header = try reader.read(offset: 0, count: 8)
        let count = Int(try order.uint32(header, 4))
        guard (1...4).contains(count) else {
            throw LAB002ObserverReason.unexpectedInstalledSlice
        }
        let recordSize = is64Bit ? 32 : 20
        let tableSize = try checkedMultiply(
            UInt64(recordSize),
            UInt64(count),
            reason: .inventoryMismatch
        )
        let tableEnd = try checkedAdd(8, tableSize, reason: .inventoryMismatch)
        guard tableEnd <= reader.size else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let table = try reader.read(offset: 8, count: Int(tableSize))
        var descriptors: [LAB002SliceDescriptor] = []
        for index in 0..<count {
            let base = index * recordSize
            let cpuType = try order.int32(table, base)
            let cpuSubtype = try order.int32(table, base + 4)
            let offset = is64Bit
                ? try order.uint64(table, base + 8)
                : UInt64(try order.uint32(table, base + 8))
            let size = is64Bit
                ? try order.uint64(table, base + 16)
                : UInt64(try order.uint32(table, base + 12))
            let alignmentPower = is64Bit
                ? try order.uint32(table, base + 24)
                : try order.uint32(table, base + 16)
            guard size > 0,
                  offset >= tableEnd,
                  alignmentPower < 63,
                  offset % (UInt64(1) << UInt64(alignmentPower)) == 0,
                  try checkedAdd(
                    offset,
                    size,
                    reason: .inventoryMismatch
                  ) <= reader.size,
                  let ordinal = UInt8(exactly: index)
            else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            descriptors.append(
                LAB002SliceDescriptor(
                    ordinal: ordinal,
                    offset: offset,
                    size: size,
                    cpuType: cpuType,
                    cpuSubtype: cpuSubtype
                )
            )
        }
        let sorted = descriptors.sorted { $0.offset < $1.offset }
        for pair in zip(sorted, sorted.dropFirst()) {
            guard try checkedAdd(
                pair.0.offset,
                pair.0.size,
                reason: .inventoryMismatch
            ) <= pair.1.offset else {
                throw LAB002ObserverReason.inventoryMismatch
            }
        }
        return descriptors
    }

    private static func parseSlice<R: LAB002MachOReading>(
        _ reader: R,
        descriptor: LAB002SliceDescriptor,
        inspectFixupPayloads: Bool,
        hashSection: Bool
    ) throws -> LAB002ParsedSlice {
        let magicBytes = try reader.read(offset: descriptor.offset, count: 4)
        guard let magic = classifyThinMagic(magicBytes) else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let headerSize = magic.is64Bit ? 32 : 28
        let header = try reader.read(offset: descriptor.offset, count: headerSize)
        let cpuType = try magic.order.int32(header, 4)
        let cpuSubtype = try magic.order.int32(header, 8)
        let fileType = try magic.order.uint32(header, 12)
        guard descriptor.cpuType.map({ $0 == cpuType }) ?? true,
              descriptor.cpuSubtype.map({ $0 == cpuSubtype }) ?? true,
              fileType == 2 || fileType == 6
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let commandCount = Int(try magic.order.uint32(header, 16))
        let commandByteCount = Int(try magic.order.uint32(header, 20))
        guard commandCount <= maximumLoadCommands,
              commandByteCount <= maximumLoadCommandBytes,
              try checkedAdd(
                UInt64(headerSize),
                UInt64(commandByteCount),
                reason: .inventoryMismatch
              ) <= descriptor.size
        else {
            throw LAB002ObserverReason.reportLimitExceeded
        }
        let commands = try reader.read(
            offset: try checkedAdd(
                descriptor.offset,
                UInt64(headerSize),
                reason: .inventoryMismatch
            ),
            count: commandByteCount
        )

        var cursor = 0
        var uuid: String?
        var textVMAddress: UInt64?
        var fixedSection: (
            sliceOffset: UInt64,
            vmAddress: UInt64,
            length: UInt64,
            sectionIndex: Int
        )?
        var fileSections: [LAB002SectionInterval] = []
        var vmSections: [LAB002SectionInterval] = []
        var sectionIndex = 0
        var segments: [LAB002FixupSegment] = []
        var encryption: (
            command: LAB002MachOEncryptionCommand,
            cryptoff: UInt64,
            cryptsize: UInt64,
            cryptid: UInt32
        )?
        var classicStreams: [LAB002ClassicFixupStream] = []
        var chainedFixups: (offset: UInt32, size: UInt32)?
        var codeSignature: (offset: UInt32, size: UInt32)?
        var sawDysymtab = false
        var sawSymtab = false

        for _ in 0..<commandCount {
            guard cursor <= commands.count - 8 else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            let command = try magic.order.uint32(commands, cursor)
            let size = Int(try magic.order.uint32(commands, cursor + 4))
            let endResult = cursor.addingReportingOverflow(size)
            guard size >= 8,
                  !endResult.overflow,
                  endResult.partialValue >= cursor,
                  let commandEnd = Optional(endResult.partialValue),
                  commandEnd <= commands.count
            else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            let bytes = commands.subdata(in: cursor..<commandEnd)

            switch command {
            case lcUUID:
                guard size == 24, uuid == nil else {
                    throw LAB002ObserverReason.inventoryMismatch
                }
                uuid = lowerHex(bytes.subdata(in: 8..<24))
            case lcSymtab:
                guard size == 24, !sawSymtab else {
                    throw LAB002ObserverReason.inventoryMismatch
                }
                sawSymtab = true
            case lcDysymtab:
                guard size == 80, !sawDysymtab else {
                    throw LAB002ObserverReason.fixedSectionHasFixups
                }
                sawDysymtab = true
                guard try magic.order.uint32(bytes, 68) == 0,
                      try magic.order.uint32(bytes, 76) == 0
                else {
                    throw LAB002ObserverReason.fixedSectionHasFixups
                }
            case lcDyldInfo, lcDyldInfoOnly:
                guard size == 48, classicStreams.isEmpty else {
                    throw LAB002ObserverReason.fixedSectionHasFixups
                }
                classicStreams = [
                    LAB002ClassicFixupStream(
                        offset: try magic.order.uint32(bytes, 8),
                        size: try magic.order.uint32(bytes, 12),
                        kind: .rebase
                    ),
                    LAB002ClassicFixupStream(
                        offset: try magic.order.uint32(bytes, 16),
                        size: try magic.order.uint32(bytes, 20),
                        kind: .bind
                    ),
                    LAB002ClassicFixupStream(
                        offset: try magic.order.uint32(bytes, 24),
                        size: try magic.order.uint32(bytes, 28),
                        kind: .bind
                    ),
                    LAB002ClassicFixupStream(
                        offset: try magic.order.uint32(bytes, 32),
                        size: try magic.order.uint32(bytes, 36),
                        kind: .bind
                    ),
                ]
            case lcDyldChainedFixups:
                guard size == 16, chainedFixups == nil else {
                    throw LAB002ObserverReason.fixedSectionHasFixups
                }
                chainedFixups = (
                    try magic.order.uint32(bytes, 8),
                    try magic.order.uint32(bytes, 12)
                )
            case lcCodeSignature:
                guard size == 16, codeSignature == nil else {
                    throw LAB002ObserverReason.inventoryMismatch
                }
                codeSignature = (
                    try magic.order.uint32(bytes, 8),
                    try magic.order.uint32(bytes, 12)
                )
            case lcEncryptionInfo, lcEncryptionInfo64:
                let expectedCommand = magic.is64Bit
                    ? lcEncryptionInfo64
                    : lcEncryptionInfo
                let expectedSize = magic.is64Bit ? 24 : 20
                let reserved = magic.is64Bit
                    ? try magic.order.uint32(bytes, 20)
                    : 0
                guard command == expectedCommand,
                      size == expectedSize,
                      encryption == nil,
                      reserved == 0
                else {
                    throw LAB002ObserverReason.encryptionCommandInvalid
                }
                encryption = (
                    magic.is64Bit ? .info64 : .info32,
                    UInt64(try magic.order.uint32(bytes, 8)),
                    UInt64(try magic.order.uint32(bytes, 12)),
                    try magic.order.uint32(bytes, 16)
                )
            case lcSegment, lcSegment64:
                let expectedCommand = magic.is64Bit ? lcSegment64 : lcSegment
                guard command == expectedCommand else {
                    throw LAB002ObserverReason.inventoryMismatch
                }
                try parseSegment(
                    bytes,
                    order: magic.order,
                    is64Bit: magic.is64Bit,
                    sliceSize: descriptor.size,
                    loadCommandsEnd: UInt64(headerSize + commandByteCount),
                    sectionIndex: &sectionIndex,
                    fixedSection: &fixedSection,
                    fileSections: &fileSections,
                    vmSections: &vmSections,
                    segments: &segments,
                    textVMAddress: &textVMAddress
                )
            default:
                break
            }
            cursor = commandEnd
        }
        guard cursor == commands.count else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        guard let uuid else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        guard let textVMAddress, let fixedSection else {
            throw LAB002ObserverReason.missingOrDuplicateFixedSection
        }
        guard let encryption else {
            throw LAB002ObserverReason.encryptionCommandInvalid
        }
        guard encryption.cryptid <= 1,
              encryption.cryptsize > 0,
              try checkedAdd(
                encryption.cryptoff,
                encryption.cryptsize,
                reason: .encryptionCommandInvalid
              ) <= descriptor.size
        else {
            throw LAB002ObserverReason.encryptionCommandInvalid
        }
        try rejectOverlaps(
            fixedSection: fixedSection,
            fileSections: fileSections,
            vmSections: vmSections
        )
        try rejectOverlappingSegments(segments)
        if inspectFixupPayloads {
            try inspectClassicFixups(
                reader,
                descriptor: descriptor,
                streams: classicStreams,
                order: magic.order,
                segments: segments,
                pointerSize: magic.is64Bit ? 8 : 4
            )
            if let chainedFixups {
                try inspectChainedFixups(
                    reader,
                    descriptor: descriptor,
                    payloadOffset: chainedFixups.offset,
                    payloadSize: chainedFixups.size,
                    order: magic.order,
                    segments: segments,
                    imageVMAddress: textVMAddress
                )
            }
        }

        let sectionVMOffset = try checkedSubtract(
            fixedSection.vmAddress,
            textVMAddress,
            reason: .fixedSectionOutOfBounds
        )
        let sectionFileOffset = try checkedAdd(
            descriptor.offset,
            fixedSection.sliceOffset,
            reason: .fixedSectionOutOfBounds
        )
        let cryptFileStart = try checkedAdd(
            descriptor.offset,
            encryption.cryptoff,
            reason: .encryptionCommandInvalid
        )
        let cryptFileEnd = try checkedAdd(
            cryptFileStart,
            encryption.cryptsize,
            reason: .encryptionCommandInvalid
        )
        let sectionEnd = try checkedAdd(
            fixedSection.sliceOffset,
            fixedSection.length,
            reason: .fixedSectionOutOfBounds
        )
        let cryptSliceEnd = try checkedAdd(
            encryption.cryptoff,
            encryption.cryptsize,
            reason: .encryptionCommandInvalid
        )
        let covers = encryption.cryptoff <= fixedSection.sliceOffset
            && cryptSliceEnd >= sectionEnd
        let digest: String
        if hashSection {
            let sectionBytes = try reader.read(
                offset: sectionFileOffset,
                count: Int(fixedSection.length)
            )
            digest = lowerHex(Data(SHA256.hash(data: sectionBytes)))
        } else {
            digest = String(repeating: "0", count: 64)
        }
        let signing: LAB002MachOSigningMetadata
        if inspectFixupPayloads {
            if let codeSignature {
                guard UInt64(codeSignature.offset) >= sectionEnd else {
                    throw LAB002ObserverReason.inventoryMismatch
                }
            }
            signing = try inspectCodeSignature(
                reader,
                descriptor: descriptor,
                command: codeSignature
            )
        } else {
            signing = absentSigningMetadata()
        }
        return LAB002ParsedSlice(
            fixed: LAB002MachOFixedSlice(
                ordinal: descriptor.ordinal,
                cpuType: cpuType,
                cpuSubtype: cpuSubtype,
                uuid: uuid,
                sliceFileOffset: descriptor.offset,
                sliceFileSize: descriptor.size,
                sectionSliceOffset: fixedSection.sliceOffset,
                sectionFileOffset: sectionFileOffset,
                sectionVMOffset: sectionVMOffset,
                sectionLength: fixedSection.length,
                diskSHA256: digest,
                encryption: LAB002MachOEncryptionEvidence(
                    command: encryption.command,
                    cryptoff: encryption.cryptoff,
                    cryptsize: encryption.cryptsize,
                    cryptFileStart: cryptFileStart,
                    cryptFileEnd: cryptFileEnd,
                    cryptid: encryption.cryptid,
                    coversFixedSection: covers
                ),
                signing: signing,
                textVMAddress: textVMAddress,
                sectionVMAddress: fixedSection.vmAddress
            ),
            loadCommandBytes: commands
        )
    }

    private static func inspectCodeSignature<R: LAB002MachOReading>(
        _ reader: R,
        descriptor: LAB002SliceDescriptor,
        command: (offset: UInt32, size: UInt32)?
    ) throws -> LAB002MachOSigningMetadata {
        guard let command else {
            return absentSigningMetadata()
        }
        guard command.size >= 12,
              UInt64(command.size) <= UInt64(maximumFixupPayloadBytes),
              try checkedAdd(
                UInt64(command.offset),
                UInt64(command.size),
                reason: .inventoryMismatch
              ) <= descriptor.size
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let absolute = try checkedAdd(
            descriptor.offset,
            UInt64(command.offset),
            reason: .inventoryMismatch
        )
        let blob = try reader.read(
            offset: absolute,
            count: Int(command.size)
        )
        let order = LAB002ByteOrder.big
        guard try order.uint32(blob, 0) == 0xfade_0cc0,
              Int(try order.uint32(blob, 4)) == blob.count
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let count = Int(try order.uint32(blob, 8))
        guard (1...64).contains(count),
              12 + count * 8 <= blob.count
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }

        var slots: [UInt32: Data] = [:]
        var intervals: [(start: Int, end: Int)] = []
        for index in 0..<count {
            let slot = try order.uint32(blob, 12 + index * 8)
            let offset = Int(try order.uint32(blob, 16 + index * 8))
            guard slots[slot] == nil,
                  offset >= 12 + count * 8,
                  offset <= blob.count - 8
            else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            let length = Int(try order.uint32(blob, offset + 4))
            guard length >= 8, offset + length <= blob.count else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            slots[slot] = blob.subdata(in: offset..<(offset + length))
            intervals.append((offset, offset + length))
        }
        intervals.sort { $0.start < $1.start }
        for pair in zip(intervals, intervals.dropFirst()) {
            guard pair.0.end <= pair.1.start else {
                throw LAB002ObserverReason.inventoryMismatch
            }
        }

        guard let codeDirectory = slots[0],
              try order.uint32(codeDirectory, 0) == 0xfade_0c02,
              Int(try order.uint32(codeDirectory, 4))
                == codeDirectory.count,
              codeDirectory.count >= 44
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let version = try order.uint32(codeDirectory, 8)
        let flags = try order.uint32(codeDirectory, 12)
        let hashOffset = Int(try order.uint32(codeDirectory, 16))
        let identifierOffset = Int(try order.uint32(codeDirectory, 20))
        let specialSlotCount = Int(
            try order.uint32(codeDirectory, 24)
        )
        let codeSlotCount = Int(try order.uint32(codeDirectory, 28))
        let codeLimit32 = UInt64(try order.uint32(codeDirectory, 32))
        let hashSize = Int(codeDirectory[36])
        let hashType = codeDirectory[37]
        let pageSizePower = codeDirectory[39]
        let minimumLength: Int
        switch version {
        case 0x20200..<0x20300:
            minimumLength = 52
        case 0x20300..<0x20400:
            minimumLength = 64
        case 0x20400..<0x20500:
            minimumLength = 88
        case 0x20500..<0x20600:
            minimumLength = 96
        case 0x20600:
            minimumLength = 108
        default:
            throw LAB002ObserverReason.inventoryMismatch
        }
        guard codeDirectory.count >= minimumLength,
              try order.uint32(codeDirectory, 40) == 0,
              pageSizePower >= 12,
              pageSizePower <= 16,
              hashSizeForType(hashType) == hashSize
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        if version >= 0x20300 {
            guard try order.uint32(codeDirectory, 52) == 0 else {
                throw LAB002ObserverReason.inventoryMismatch
            }
        }
        let codeLimit64 = version >= 0x20300
            ? try order.uint64(codeDirectory, 56)
            : 0
        let codeLimit = codeLimit64 == 0 ? codeLimit32 : codeLimit64
        let pageSize = UInt64(1) << UInt64(pageSizePower)
        let expectedCodeSlots = Int(
            (try checkedAdd(
                codeLimit,
                pageSize - 1,
                reason: .inventoryMismatch
            )) / pageSize
        )
        let specialBytes = specialSlotCount * hashSize
        let codeBytes = codeSlotCount * hashSize
        guard codeLimit > 0,
              codeLimit == UInt64(command.offset),
              codeLimit <= maximumExecutableBytes,
              codeSlotCount == expectedCodeSlots,
              hashOffset >= specialBytes,
              hashOffset + codeBytes <= codeDirectory.count
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let dynamicDataStart = hashOffset - specialBytes
        guard dynamicDataStart >= minimumLength else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let identifier = try codeSignatureString(
            codeDirectory,
            offset: identifierOffset,
            upperBound: dynamicDataStart
        )
        let teamIdentifier: String
        if version >= 0x20200 {
            teamIdentifier = try codeSignatureString(
                codeDirectory,
                offset: Int(try order.uint32(codeDirectory, 48)),
                upperBound: dynamicDataStart
            )
        } else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        guard isBundleIdentifier(identifier),
              isTeamIdentifier(teamIdentifier)
        else {
            throw LAB002ObserverReason.identityMismatch
        }

        let entitlements: LAB002SelectedEntitlements
        if let entitlementBlob = slots[5] {
            guard try order.uint32(entitlementBlob, 0) == 0xfade_7171 else {
                throw LAB002ObserverReason.identityMismatch
            }
            let payload = entitlementBlob.subdata(
                in: 8..<entitlementBlob.count
            )
            guard let object = try PropertyListSerialization.propertyList(
                from: payload,
                options: [],
                format: nil
            ) as? [String: Any] else {
                throw LAB002ObserverReason.identityMismatch
            }
            entitlements = try selectedEntitlements(object)
        } else {
            entitlements = LAB002SelectedEntitlements(
                applicationIdentifier: nil,
                developerTeamIdentifier: nil,
                applicationGroups: nil
            )
        }

        let isAdHoc = flags & 0x2 != 0
        let hasCMS: Bool
        if let cms = slots[0x1_0000], cms.count > 8 {
            hasCMS = try order.uint32(cms, 0) == 0xfade_0b01
        } else {
            hasCMS = false
        }
        return LAB002MachOSigningMetadata(
            presence: .present,
            kind: isAdHoc ? .adHoc : (hasCMS ? .cms : .unknown),
            validation: .notChecked,
            validatorID: "demolab-bounded-codesign-parser",
            validatorRevision: "1",
            superblobSHA256: lowerHex(Data(SHA256.hash(data: blob))),
            codeDirectoryIdentifier: identifier,
            codeDirectoryTeamIdentifier: teamIdentifier,
            entitlements: entitlements
        )
    }

    private static func codeSignatureString(
        _ bytes: Data,
        offset: Int,
        upperBound: Int
    ) throws -> String {
        guard offset >= 8,
              offset < upperBound,
              upperBound <= bytes.count,
              let terminator = bytes[offset..<upperBound].firstIndex(of: 0),
              terminator > offset,
              let value = String(
                data: bytes.subdata(in: offset..<terminator),
                encoding: .utf8
              ),
              value.unicodeScalars.allSatisfy({
                  $0.value >= 0x20 && $0.value != 0x7f
              })
        else {
            throw LAB002ObserverReason.identityMismatch
        }
        return value
    }

    private static func hashSizeForType(_ type: UInt8) -> Int? {
        switch type {
        case 1: return 20
        case 2: return 32
        case 3: return 20
        case 4: return 48
        default: return nil
        }
    }

    private static func selectedEntitlements(
        _ object: [String: Any]
    ) throws -> LAB002SelectedEntitlements {
        func optionalString(_ key: String) throws -> String? {
            guard let value = object[key] else { return nil }
            guard let string = value as? String else {
                throw LAB002ObserverReason.identityMismatch
            }
            return string
        }
        let applicationIdentifier = try optionalString(
            "application-identifier"
        )
        let developerTeamIdentifier = try optionalString(
            "com.apple.developer.team-identifier"
        )
        let applicationGroups: [String]?
        if let value = object["com.apple.security.application-groups"] {
            guard let groups = value as? [String],
                  !groups.isEmpty,
                  groups == groups.sorted(),
                  Set(groups).count == groups.count,
                  groups.allSatisfy({
                      $0.hasPrefix("group.")
                          && isBundleIdentifier(
                              String($0.dropFirst("group.".count))
                          )
                  })
            else {
                throw LAB002ObserverReason.identityMismatch
            }
            applicationGroups = groups
        } else {
            applicationGroups = nil
        }
        if let developerTeamIdentifier,
           !isTeamIdentifier(developerTeamIdentifier) {
            throw LAB002ObserverReason.identityMismatch
        }
        return LAB002SelectedEntitlements(
            applicationIdentifier: applicationIdentifier,
            developerTeamIdentifier: developerTeamIdentifier,
            applicationGroups: applicationGroups
        )
    }

    private static func isBundleIdentifier(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 255
            && value.split(
                separator: ".",
                omittingEmptySubsequences: false
            ).allSatisfy {
                !$0.isEmpty && $0.utf8.allSatisfy {
                    (0x30...0x39).contains($0)
                        || (0x41...0x5a).contains($0)
                        || (0x61...0x7a).contains($0)
                        || $0 == 0x2d
                }
            }
    }

    private static func isTeamIdentifier(_ value: String) -> Bool {
        value.utf8.count == 10
            && value.utf8.allSatisfy {
                (0x30...0x39).contains($0)
                    || (0x41...0x5a).contains($0)
            }
    }

    private static func absentSigningMetadata()
        -> LAB002MachOSigningMetadata {
        LAB002MachOSigningMetadata(
            presence: .absent,
            kind: .notApplicable,
            validation: .notApplicable,
            validatorID: "demolab-bounded-codesign-parser",
            validatorRevision: "1",
            superblobSHA256: nil,
            codeDirectoryIdentifier: nil,
            codeDirectoryTeamIdentifier: nil,
            entitlements: LAB002SelectedEntitlements(
                applicationIdentifier: nil,
                developerTeamIdentifier: nil,
                applicationGroups: nil
            )
        )
    }

    private static func parseSegment(
        _ bytes: Data,
        order: LAB002ByteOrder,
        is64Bit: Bool,
        sliceSize: UInt64,
        loadCommandsEnd: UInt64,
        sectionIndex: inout Int,
        fixedSection: inout (
            sliceOffset: UInt64,
            vmAddress: UInt64,
            length: UInt64,
            sectionIndex: Int
        )?,
        fileSections: inout [LAB002SectionInterval],
        vmSections: inout [LAB002SectionInterval],
        segments: inout [LAB002FixupSegment],
        textVMAddress: inout UInt64?
    ) throws {
        let headerSize = is64Bit ? 72 : 56
        let sectionSize = is64Bit ? 80 : 68
        guard bytes.count >= headerSize else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let segmentName = try fixedName(bytes, offset: 8)
        let vmAddress = is64Bit
            ? try order.uint64(bytes, 24)
            : UInt64(try order.uint32(bytes, 24))
        let vmSize = is64Bit
            ? try order.uint64(bytes, 32)
            : UInt64(try order.uint32(bytes, 28))
        let fileOffset = is64Bit
            ? try order.uint64(bytes, 40)
            : UInt64(try order.uint32(bytes, 32))
        let fileSize = is64Bit
            ? try order.uint64(bytes, 48)
            : UInt64(try order.uint32(bytes, 36))
        let initialProtection = is64Bit
            ? try order.uint32(bytes, 60)
            : try order.uint32(bytes, 44)
        let sectionCount = Int(
            is64Bit
                ? try order.uint32(bytes, 64)
                : try order.uint32(bytes, 48)
        )
        let sectionBytesResult = sectionSize.multipliedReportingOverflow(
            by: sectionCount
        )
        let expectedSizeResult = headerSize.addingReportingOverflow(
            sectionBytesResult.partialValue
        )
        guard !sectionBytesResult.overflow,
              !expectedSizeResult.overflow,
              expectedSizeResult.partialValue == bytes.count,
              try checkedAdd(
                fileOffset,
                fileSize,
                reason: .fixedSectionOutOfBounds
              ) <= sliceSize
        else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
        if segmentName == "__TEXT" {
            guard textVMAddress == nil else {
                throw LAB002ObserverReason.inventoryMismatch
            }
            textVMAddress = vmAddress
        }
        segments.append(
            LAB002FixupSegment(
                vmAddress: vmAddress,
                vmSize: vmSize,
                isText: segmentName == "__TEXT"
            )
        )

        for index in 0..<sectionCount {
            let base = headerSize + index * sectionSize
            let sectionName = try fixedName(bytes, offset: base)
            let declaredSegmentName = try fixedName(bytes, offset: base + 16)
            let address = is64Bit
                ? try order.uint64(bytes, base + 32)
                : UInt64(try order.uint32(bytes, base + 32))
            let length = is64Bit
                ? try order.uint64(bytes, base + 40)
                : UInt64(try order.uint32(bytes, base + 36))
            let offset = UInt64(
                try order.uint32(bytes, base + (is64Bit ? 48 : 40))
            )
            let relocationOffset = try order.uint32(
                bytes,
                base + (is64Bit ? 56 : 48)
            )
            let relocationCount = try order.uint32(
                bytes,
                base + (is64Bit ? 60 : 52)
            )
            let flags = try order.uint32(
                bytes,
                base + (is64Bit ? 64 : 56)
            )
            let currentIndex = sectionIndex
            sectionIndex += 1
            if length > 0 {
                let vmEnd = try checkedAdd(
                    address,
                    length,
                    reason: .fixedSectionOutOfBounds
                )
                vmSections.append(
                    LAB002SectionInterval(
                        index: currentIndex,
                        start: address,
                        end: vmEnd
                    )
                )
                if flags & 0xff != 1 {
                    let fileEnd = try checkedAdd(
                        offset,
                        length,
                        reason: .fixedSectionOutOfBounds
                    )
                    guard fileEnd <= sliceSize else {
                        throw LAB002ObserverReason.fixedSectionOutOfBounds
                    }
                    fileSections.append(
                        LAB002SectionInterval(
                            index: currentIndex,
                            start: offset,
                            end: fileEnd
                        )
                    )
                }
            }
            guard sectionName == "__oprobe",
                  declaredSegmentName == "__TEXT"
            else {
                continue
            }
            guard fixedSection == nil else {
                throw LAB002ObserverReason.missingOrDuplicateFixedSection
            }
            guard segmentName == "__TEXT",
                  initialProtection & 0x4 != 0,
                  (64...1024).contains(length),
                  flags & 0xff == 0,
                  flags & 0x8000_0000 != 0,
                  flags & 0x0000_0400 != 0
            else {
                throw LAB002ObserverReason.fixedSectionOutOfBounds
            }
            guard relocationOffset == 0, relocationCount == 0 else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            let segmentFileEnd = try checkedAdd(
                fileOffset,
                fileSize,
                reason: .fixedSectionOutOfBounds
            )
            let segmentVMEnd = try checkedAdd(
                vmAddress,
                vmSize,
                reason: .fixedSectionOutOfBounds
            )
            let sectionFileEnd = try checkedAdd(
                offset,
                length,
                reason: .fixedSectionOutOfBounds
            )
            let sectionVMEnd = try checkedAdd(
                address,
                length,
                reason: .fixedSectionOutOfBounds
            )
            guard offset >= loadCommandsEnd,
                  offset >= fileOffset,
                  sectionFileEnd <= segmentFileEnd,
                  address >= vmAddress,
                  sectionVMEnd <= segmentVMEnd,
                  try checkedSubtract(
                    offset,
                    fileOffset,
                    reason: .fixedSectionOutOfBounds
                  ) == (try checkedSubtract(
                    address,
                    vmAddress,
                    reason: .fixedSectionOutOfBounds
                  ))
            else {
                throw LAB002ObserverReason.fixedSectionOutOfBounds
            }
            fixedSection = (offset, address, length, currentIndex)
        }
    }

    private static func inspectClassicFixups<R: LAB002MachOReading>(
        _ reader: R,
        descriptor: LAB002SliceDescriptor,
        streams: [LAB002ClassicFixupStream],
        order: LAB002ByteOrder,
        segments: [LAB002FixupSegment],
        pointerSize: UInt64
    ) throws {
        for stream in streams {
            guard (stream.offset == 0) == (stream.size == 0) else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            guard stream.size > 0 else { continue }
            let payload = try readPayload(
                reader,
                descriptor: descriptor,
                offset: stream.offset,
                size: stream.size
            )
            try inspectClassicOpcodes(
                payload,
                kind: stream.kind,
                segments: segments,
                pointerSize: pointerSize
            )
        }
        _ = order
    }

    private static func inspectClassicOpcodes(
        _ bytes: Data,
        kind: LAB002ClassicFixupStream.Kind,
        segments: [LAB002FixupSegment],
        pointerSize: UInt64
    ) throws {
        var cursor = 0
        var state: (segment: Int, offset: UInt64)?
        while cursor < bytes.count {
            let byte = bytes[cursor]
            cursor += 1
            let opcode = byte & 0xf0
            let immediate = byte & 0x0f
            switch kind {
            case .rebase:
                switch opcode {
                case 0x00, 0x10:
                    break
                case 0x20:
                    state = try setFixupState(
                        segments: segments,
                        index: immediate,
                        offset: try readULEB(bytes, cursor: &cursor)
                    )
                case 0x30:
                    let delta = try readULEB(bytes, cursor: &cursor)
                    try addFixupOffset(&state, delta: delta)
                case 0x40:
                    try addFixupOffset(
                        &state,
                        delta: UInt64(immediate) * pointerSize
                    )
                case 0x50:
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: UInt64(immediate),
                        stride: pointerSize,
                        width: pointerSize
                    )
                case 0x60:
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: try readULEB(bytes, cursor: &cursor),
                        stride: pointerSize,
                        width: pointerSize
                    )
                case 0x70:
                    let stride = try checkedAdd(
                        pointerSize,
                        try readULEB(bytes, cursor: &cursor),
                        reason: .fixedSectionHasFixups
                    )
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: 1,
                        stride: stride,
                        width: pointerSize
                    )
                case 0x80:
                    let count = try readULEB(bytes, cursor: &cursor)
                    let stride = try checkedAdd(
                        pointerSize,
                        try readULEB(bytes, cursor: &cursor),
                        reason: .fixedSectionHasFixups
                    )
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: count,
                        stride: stride,
                        width: pointerSize
                    )
                default:
                    throw LAB002ObserverReason.fixedSectionHasFixups
                }
            case .bind:
                switch opcode {
                case 0x00, 0x10, 0x30, 0x50:
                    break
                case 0x20:
                    _ = try readULEB(bytes, cursor: &cursor)
                case 0x40:
                    guard let terminator = bytes[cursor...]
                        .firstIndex(of: 0) else {
                        throw LAB002ObserverReason.fixedSectionHasFixups
                    }
                    cursor = terminator + 1
                case 0x60:
                    try skipSLEB(bytes, cursor: &cursor)
                case 0x70:
                    state = try setFixupState(
                        segments: segments,
                        index: immediate,
                        offset: try readULEB(bytes, cursor: &cursor)
                    )
                case 0x80:
                    try addFixupOffset(
                        &state,
                        delta: try readULEB(bytes, cursor: &cursor)
                    )
                case 0x90:
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: 1,
                        stride: pointerSize,
                        width: pointerSize
                    )
                case 0xa0:
                    let stride = try checkedAdd(
                        pointerSize,
                        try readULEB(bytes, cursor: &cursor),
                        reason: .fixedSectionHasFixups
                    )
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: 1,
                        stride: stride,
                        width: pointerSize
                    )
                case 0xb0:
                    let stride = try checkedAdd(
                        pointerSize,
                        UInt64(immediate) * pointerSize,
                        reason: .fixedSectionHasFixups
                    )
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: 1,
                        stride: stride,
                        width: pointerSize
                    )
                case 0xc0:
                    let count = try readULEB(bytes, cursor: &cursor)
                    let stride = try checkedAdd(
                        pointerSize,
                        try readULEB(bytes, cursor: &cursor),
                        reason: .fixedSectionHasFixups
                    )
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: count,
                        stride: stride,
                        width: pointerSize
                    )
                case 0xd0 where immediate == 0:
                    _ = try readULEB(bytes, cursor: &cursor)
                case 0xd0 where immediate == 1:
                    try advanceFixups(
                        segments,
                        state: &state,
                        count: 1,
                        stride: pointerSize,
                        width: pointerSize
                    )
                default:
                    throw LAB002ObserverReason.fixedSectionHasFixups
                }
            }
        }
    }

    private static func inspectChainedFixups<R: LAB002MachOReading>(
        _ reader: R,
        descriptor: LAB002SliceDescriptor,
        payloadOffset: UInt32,
        payloadSize: UInt32,
        order: LAB002ByteOrder,
        segments: [LAB002FixupSegment],
        imageVMAddress: UInt64
    ) throws {
        guard payloadSize > 0 else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        let payload = try readPayload(
            reader,
            descriptor: descriptor,
            offset: payloadOffset,
            size: payloadSize
        )
        guard payload.count >= 28,
              try order.uint32(payload, 0) == 0
        else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        let startsOffset = Int(try order.uint32(payload, 4))
        let importsOffset = Int(try order.uint32(payload, 8))
        let symbolsOffset = Int(try order.uint32(payload, 12))
        let importsCount = Int(try order.uint32(payload, 16))
        let importsFormat = try order.uint32(payload, 20)
        let symbolsFormat = try order.uint32(payload, 24)
        guard startsOffset >= 28,
              startsOffset <= payload.count - 4
        else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        let starts = payload.subdata(in: startsOffset..<payload.count)
        let segmentCount = Int(try order.uint32(starts, 0))
        let offsetsEnd = 4 + segmentCount * 4
        guard segmentCount == segments.count, offsetsEnd <= starts.count else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        var recordIntervals: [(start: Int, end: Int)] = []
        for (index, segment) in segments.enumerated() {
            let infoOffset = Int(try order.uint32(starts, 4 + index * 4))
            guard infoOffset != 0 else { continue }
            guard infoOffset >= offsetsEnd,
                  infoOffset <= starts.count - 22
            else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            let info = starts.subdata(in: infoOffset..<starts.count)
            let recordSize = Int(try order.uint32(info, 0))
            let pageSize = try order.uint16(info, 4)
            let pointerFormat = try order.uint16(info, 6)
            let segmentOffset = try order.uint64(info, 8)
            let pageCount = Int(try order.uint16(info, 20))
            let pagesEnd = 22 + pageCount * 2
            guard pageSize == 0x1000 || pageSize == 0x4000 else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            let expectedOffset = try checkedSubtract(
                segment.vmAddress,
                imageVMAddress,
                reason: .fixedSectionHasFixups
            )
            let roundedVMSize = try checkedAdd(
                segment.vmSize,
                UInt64(pageSize) - 1,
                reason: .fixedSectionHasFixups
            )
            let expectedPages = Int(roundedVMSize / UInt64(pageSize))
            guard recordSize >= pagesEnd,
                  recordSize <= info.count,
                  (1...14).contains(pointerFormat),
                  segmentOffset == expectedOffset,
                  pageCount == expectedPages
            else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            recordIntervals.append(
                (infoOffset, infoOffset + recordSize)
            )
            if segment.isText {
                for page in 0..<pageCount {
                    guard try order.uint16(info, 22 + page * 2) == 0xffff else {
                        throw LAB002ObserverReason.fixedSectionHasFixups
                    }
                }
            } else {
                for page in 0..<pageCount {
                    let start = try order.uint16(info, 22 + page * 2)
                    guard start == 0xffff
                            || (start & 0x8000 == 0
                                && start < pageSize
                                && UInt64(page) * UInt64(pageSize)
                                    + UInt64(start) < segment.vmSize)
                    else {
                        throw LAB002ObserverReason.fixedSectionHasFixups
                    }
                }
            }
        }
        recordIntervals.sort { $0.start < $1.start }
        for pair in zip(recordIntervals, recordIntervals.dropFirst()) {
            guard pair.0.end <= pair.1.start else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
        }

        let startsExtent = recordIntervals.last.map {
            max(offsetsEnd, $0.end)
        } ?? offsetsEnd
        let startsEnd = startsOffset + startsExtent
        guard startsEnd <= payload.count,
              symbolsFormat == 0,
              (1...3).contains(importsFormat)
        else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        if importsCount == 0 {
            guard (importsOffset == 0 && symbolsOffset == 0)
                    || (importsOffset >= startsEnd
                        && importsOffset <= payload.count
                        && symbolsOffset >= importsOffset
                        && symbolsOffset <= payload.count)
            else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            return
        }

        let importRecordSize: Int
        switch importsFormat {
        case 1:
            importRecordSize = 4
        case 2:
            importRecordSize = 8
        case 3:
            importRecordSize = 16
        default:
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        let importsEnd = importsOffset + importsCount * importRecordSize
        guard importsOffset >= startsEnd,
              importsEnd <= payload.count,
              symbolsOffset >= importsEnd,
              symbolsOffset < payload.count
        else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        let symbols = payload.subdata(in: symbolsOffset..<payload.count)
        for importIndex in 0..<importsCount {
            let recordOffset = importsOffset + importIndex * importRecordSize
            let nameOffset: Int
            switch importsFormat {
            case 1, 2:
                nameOffset = Int(
                    try order.uint32(payload, recordOffset) >> 9
                )
            case 3:
                let record = try order.uint64(payload, recordOffset)
                guard record & 0x0000_0000_fffe_0000 == 0,
                      let converted = Int(exactly: record >> 32)
                else {
                    throw LAB002ObserverReason.fixedSectionHasFixups
                }
                nameOffset = converted
            default:
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            guard nameOffset < symbols.count,
                  symbols[nameOffset] != 0,
                  symbols[nameOffset...].contains(0)
            else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
        }
    }

    private static func readPayload<R: LAB002MachOReading>(
        _ reader: R,
        descriptor: LAB002SliceDescriptor,
        offset: UInt32,
        size: UInt32
    ) throws -> Data {
        guard UInt64(size) <= UInt64(maximumFixupPayloadBytes),
              try checkedAdd(
                UInt64(offset),
                UInt64(size),
                reason: .fixedSectionHasFixups
              ) <= descriptor.size
        else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        return try reader.read(
            offset: try checkedAdd(
                descriptor.offset,
                UInt64(offset),
                reason: .fixedSectionHasFixups
            ),
            count: Int(size)
        )
    }

    private static func setFixupState(
        segments: [LAB002FixupSegment],
        index: UInt8,
        offset: UInt64
    ) throws -> (segment: Int, offset: UInt64) {
        let index = Int(index)
        guard segments.indices.contains(index), offset <= segments[index].vmSize else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        return (index, offset)
    }

    private static func addFixupOffset(
        _ state: inout (segment: Int, offset: UInt64)?,
        delta: UInt64
    ) throws {
        guard var current = state else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        current.offset = try checkedAdd(
            current.offset,
            delta,
            reason: .fixedSectionHasFixups
        )
        state = current
    }

    private static func advanceFixups(
        _ segments: [LAB002FixupSegment],
        state: inout (segment: Int, offset: UInt64)?,
        count: UInt64,
        stride: UInt64,
        width: UInt64
    ) throws {
        guard var current = state,
              segments.indices.contains(current.segment)
        else {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        let segment = segments[current.segment]
        if count > 0, segment.isText {
            throw LAB002ObserverReason.fixedSectionHasFixups
        }
        if count > 0 {
            let lastStart = try checkedAdd(
                current.offset,
                try checkedMultiply(
                    count - 1,
                    stride,
                    reason: .fixedSectionHasFixups
                ),
                reason: .fixedSectionHasFixups
            )
            guard try checkedAdd(
                lastStart,
                width,
                reason: .fixedSectionHasFixups
            ) <= segment.vmSize else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
        }
        current.offset = try checkedAdd(
            current.offset,
            try checkedMultiply(
                count,
                stride,
                reason: .fixedSectionHasFixups
            ),
            reason: .fixedSectionHasFixups
        )
        state = current
    }

    private static func readULEB(
        _ bytes: Data,
        cursor: inout Int
    ) throws -> UInt64 {
        var value = UInt64(0)
        for shift in stride(from: 0, through: 63, by: 7) {
            guard cursor < bytes.count else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            let byte = bytes[cursor]
            cursor += 1
            if shift == 63, byte & 0xfe != 0 {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            value |= UInt64(byte & 0x7f) << UInt64(shift)
            if byte & 0x80 == 0 {
                return value
            }
        }
        throw LAB002ObserverReason.fixedSectionHasFixups
    }

    private static func skipSLEB(
        _ bytes: Data,
        cursor: inout Int
    ) throws {
        for _ in 0..<10 {
            guard cursor < bytes.count else {
                throw LAB002ObserverReason.fixedSectionHasFixups
            }
            let byte = bytes[cursor]
            cursor += 1
            if byte & 0x80 == 0 {
                return
            }
        }
        throw LAB002ObserverReason.fixedSectionHasFixups
    }

    private static func rejectOverlaps(
        fixedSection: (
            sliceOffset: UInt64,
            vmAddress: UInt64,
            length: UInt64,
            sectionIndex: Int
        ),
        fileSections: [LAB002SectionInterval],
        vmSections: [LAB002SectionInterval]
    ) throws {
        let fileEnd = try checkedAdd(
            fixedSection.sliceOffset,
            fixedSection.length,
            reason: .fixedSectionOutOfBounds
        )
        let vmEnd = try checkedAdd(
            fixedSection.vmAddress,
            fixedSection.length,
            reason: .fixedSectionOutOfBounds
        )
        guard !fileSections.contains(where: {
            $0.index != fixedSection.sectionIndex
                && $0.start < fileEnd
                && fixedSection.sliceOffset < $0.end
        }),
        !vmSections.contains(where: {
            $0.index != fixedSection.sectionIndex
                && $0.start < vmEnd
                && fixedSection.vmAddress < $0.end
        }) else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
    }

    private static func rejectOverlappingSegments(
        _ segments: [LAB002FixupSegment]
    ) throws {
        let intervals = try segments.compactMap { segment
            -> (UInt64, UInt64)? in
            guard segment.vmSize > 0 else { return nil }
            return (
                segment.vmAddress,
                try checkedAdd(
                    segment.vmAddress,
                    segment.vmSize,
                    reason: .inventoryMismatch
                )
            )
        }.sorted { $0.0 < $1.0 }
        for pair in zip(intervals, intervals.dropFirst()) {
            guard pair.0.1 <= pair.1.0 else {
                throw LAB002ObserverReason.inventoryMismatch
            }
        }
    }

    private static func fixedName(
        _ bytes: Data,
        offset: Int
    ) throws -> String {
        _ = try checkedRange(offset: offset, count: 16, limit: bytes.count)
        let field = bytes.subdata(in: offset..<(offset + 16))
        guard let terminator = field.firstIndex(of: 0),
              terminator > 0,
              field.suffix(from: terminator + 1).allSatisfy({ $0 == 0 }),
              let value = String(
                data: field.subdata(in: 0..<terminator),
                encoding: .ascii
              )
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        return value
    }

    private static func classifyThinMagic(
        _ bytes: Data
    ) -> LAB002MachOMagic? {
        switch Array(bytes) {
        case [0xce, 0xfa, 0xed, 0xfe]:
            return LAB002MachOMagic(order: .little, is64Bit: false)
        case [0xcf, 0xfa, 0xed, 0xfe]:
            return LAB002MachOMagic(order: .little, is64Bit: true)
        case [0xfe, 0xed, 0xfa, 0xce]:
            return LAB002MachOMagic(order: .big, is64Bit: false)
        case [0xfe, 0xed, 0xfa, 0xcf]:
            return LAB002MachOMagic(order: .big, is64Bit: true)
        default:
            return nil
        }
    }

    private static func classifyFatMagic(
        _ bytes: Data
    ) -> LAB002MachOMagic? {
        switch Array(bytes) {
        case [0xca, 0xfe, 0xba, 0xbe]:
            return LAB002MachOMagic(order: .big, is64Bit: false)
        case [0xca, 0xfe, 0xba, 0xbf]:
            return LAB002MachOMagic(order: .big, is64Bit: true)
        case [0xbe, 0xba, 0xfe, 0xca]:
            return LAB002MachOMagic(order: .little, is64Bit: false)
        case [0xbf, 0xba, 0xfe, 0xca]:
            return LAB002MachOMagic(order: .little, is64Bit: true)
        default:
            return nil
        }
    }
}

#if DEBUG
enum LAB002MachOObserverTestHarness {
    static func parseInstalled(_ bytes: Data) throws -> LAB002InstalledMachO {
        try LAB002MachOObserverCore.parseInstalledBytes(bytes)
    }

    static func parseMappedHeader(
        _ bytes: Data,
        matching installed: LAB002MachOFixedSlice,
        anchorVMOffset: UInt64
    ) throws -> LAB002MappedMachORange {
        try LAB002MachOObserverCore.parseMappedHeader(
            bytes,
            matching: installed,
            anchorVMOffset: anchorVMOffset
        )
    }

    static func parseInstalledFile(
        at fixedExecutableURL: URL
    ) throws -> LAB002InstalledMachO {
        try LAB002MachOObserverCore.parseInstalledFile(
            at: fixedExecutableURL
        )
    }
}
#endif

private func checkedRange(
    offset: Int,
    count: Int,
    limit: Int
) throws -> Range<Int> {
    guard offset >= 0, count >= 0 else {
        throw LAB002ObserverReason.fixedSectionOutOfBounds
    }
    let result = offset.addingReportingOverflow(count)
    guard !result.overflow,
          result.partialValue >= offset,
          result.partialValue <= limit
    else {
        throw LAB002ObserverReason.fixedSectionOutOfBounds
    }
    return offset..<result.partialValue
}

private func checkedAdd(
    _ left: UInt64,
    _ right: UInt64,
    reason: LAB002ObserverReason
) throws -> UInt64 {
    let result = left.addingReportingOverflow(right)
    guard !result.overflow else { throw reason }
    return result.partialValue
}

private func checkedSubtract(
    _ left: UInt64,
    _ right: UInt64,
    reason: LAB002ObserverReason
) throws -> UInt64 {
    let result = left.subtractingReportingOverflow(right)
    guard !result.overflow else { throw reason }
    return result.partialValue
}

private func checkedMultiply(
    _ left: UInt64,
    _ right: UInt64,
    reason: LAB002ObserverReason
) throws -> UInt64 {
    let result = left.multipliedReportingOverflow(by: right)
    guard !result.overflow else { throw reason }
    return result.partialValue
}

private func lowerHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}
