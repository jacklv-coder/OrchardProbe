import CryptoKit
import Darwin
import Foundation
import MachO

enum LAB002Role: String {
    case mainApp = "main_app"
    case framework
    case shareExtension = "share_extension"

    var bindingByte: UInt8 {
        switch self {
        case .mainApp: return 1
        case .framework: return 2
        case .shareExtension: return 3
        }
    }

    var fixtureRelativePath: String {
        switch self {
        case .mainApp:
            return "DemoLab.app/DemoLab"
        case .framework:
            return "DemoLab.app/Frameworks/DemoFramework.framework/DemoFramework"
        case .shareExtension:
            return "DemoLab.app/PlugIns/DemoShareExtension.appex/DemoShareExtension"
        }
    }

    var reportName: String {
        switch self {
        case .mainApp: return LAB002FixedName.mainAppReport
        case .framework: return LAB002FixedName.frameworkReport
        case .shareExtension: return LAB002FixedName.shareExtensionReport
        }
    }

    var temporaryReportName: String {
        switch self {
        case .mainApp: return LAB002FixedName.mainAppReportTemporary
        case .framework: return LAB002FixedName.frameworkReportTemporary
        case .shareExtension:
            return LAB002FixedName.shareExtensionReportTemporary
        }
    }

    var precedingRoles: [LAB002Role] {
        switch self {
        case .mainApp: return []
        case .framework: return [.mainApp]
        case .shareExtension: return [.mainApp, .framework]
        }
    }
}

struct LAB002LocalRoleObservation: Equatable {
    let installed: LAB002InstalledMachO
    let activeSliceIndex: Int
    let targetIdentityBindingSHA256: String
    let mappedSHA256: String
    let diskInspectionCompletedAt: Int64
    let mappedHashCompletedAt: Int64
}

enum LAB002LiveMachOObserver {
    static func observe(
        fixedBundle: Bundle,
        compiledAnchor: UnsafeRawPointer,
        fixedRole: LAB002Role
    ) throws -> LAB002LocalRoleObservation {
        guard let executableURL = fixedBundle.executableURL else {
            throw LAB002ObserverReason.inventoryMismatch
        }

        var image = Dl_info()
        guard dladdr(compiledAnchor, &image) != 0,
              let imageBase = image.dli_fbase,
              let imagePath = image.dli_fname
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let loadedURL = URL(fileURLWithPath: String(cString: imagePath))
        guard loadedURL.standardizedFileURL.path
                == executableURL.standardizedFileURL.path
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }

        let installed = try LAB002MachOObserverCore.parseInstalledFile(
            at: executableURL
        )
        let diskCompletedAt = try currentWholeSecond()

        let base = UnsafeRawPointer(imageBase)
        let header = base.load(as: mach_header_64.self)
        guard header.magic == MH_MAGIC_64,
              header.ncmds <= 4_096,
              header.sizeofcmds <= 4 * 1024 * 1024
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let headerByteCountResult = MemoryLayout<mach_header_64>.size
            .addingReportingOverflow(Int(header.sizeofcmds))
        guard !headerByteCountResult.overflow else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        try requireReadableExecutableRegion(
            start: base,
            count: headerByteCountResult.partialValue
        )
        let headerBytes = Data(
            bytes: base,
            count: headerByteCountResult.partialValue
        )
        let anchorAddress = UInt(bitPattern: compiledAnchor)
        let baseAddress = UInt(bitPattern: base)
        guard anchorAddress >= baseAddress else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        let anchorVMOffset = UInt64(anchorAddress - baseAddress)
        let active = try LAB002MachOObserverCore.matchMappedHeader(
            headerBytes,
            installed: installed,
            anchorVMOffset: anchorVMOffset
        )
        let targetIdentityBindingSHA256 = try targetIdentityBinding(
            fixedBundle: fixedBundle,
            fixedRole: fixedRole,
            signing: installed.slices[active.activeSliceIndex].signing
        )
        let range = active.mappedRange
        guard range.sectionLength <= UInt64(Int.max),
              range.sectionVMOffset <= UInt64(Int.max)
        else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
        let mappedStart = base.advanced(by: Int(range.sectionVMOffset))
        try requireReadableExecutableRegion(
            start: mappedStart,
            count: Int(range.sectionLength)
        )
        let mappedBytes = Data(
            bytes: mappedStart,
            count: Int(range.sectionLength)
        )
        let mappedSHA256 = Data(SHA256.hash(data: mappedBytes))
            .map { String(format: "%02x", $0) }
            .joined()
        let mappedCompletedAt = try currentWholeSecond()
        guard mappedCompletedAt >= diskCompletedAt else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        return LAB002LocalRoleObservation(
            installed: installed,
            activeSliceIndex: active.activeSliceIndex,
            targetIdentityBindingSHA256: targetIdentityBindingSHA256,
            mappedSHA256: mappedSHA256,
            diskInspectionCompletedAt: diskCompletedAt,
            mappedHashCompletedAt: mappedCompletedAt
        )
    }

    private static func requireReadableExecutableRegion(
        start: UnsafeRawPointer,
        count: Int
    ) throws {
        guard count > 0 else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
        var regionAddress = vm_address_t(UInt(bitPattern: start))
        var regionSize = vm_size_t(0)
        var information = vm_region_basic_info_data_64_t()
        var informationCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.size
                / MemoryLayout<integer_t>.size
        )
        var objectName = mach_port_t(0)
        let result = withUnsafeMutablePointer(to: &information) {
            informationPointer in
            informationPointer.withMemoryRebound(
                to: integer_t.self,
                capacity: Int(informationCount)
            ) {
                vm_region_64(
                    mach_task_self_,
                    &regionAddress,
                    &regionSize,
                    VM_REGION_BASIC_INFO_64,
                    $0,
                    &informationCount,
                    &objectName
                )
            }
        }
        if objectName != MACH_PORT_NULL {
            mach_port_deallocate(mach_task_self_, objectName)
        }
        let requestedStart = UInt64(UInt(bitPattern: start))
        let requestedEnd = requestedStart.addingReportingOverflow(
            UInt64(count)
        )
        let regionEnd = UInt64(regionAddress).addingReportingOverflow(
            UInt64(regionSize)
        )
        guard result == KERN_SUCCESS,
              !requestedEnd.overflow,
              !regionEnd.overflow,
              UInt64(regionAddress) <= requestedStart,
              requestedEnd.partialValue <= regionEnd.partialValue,
              information.protection & VM_PROT_READ != 0,
              information.protection & VM_PROT_EXECUTE != 0
        else {
            throw LAB002ObserverReason.fixedSectionOutOfBounds
        }
    }

    private static func targetIdentityBinding(
        fixedBundle: Bundle,
        fixedRole: LAB002Role,
        signing: LAB002MachOSigningMetadata
    ) throws -> String {
        guard signing.presence == .present,
              let bundleIdentifier = fixedBundle.bundleIdentifier,
              let nonceHex = fixedBundle.object(
                forInfoDictionaryKey: "LAB002IdentityNonce"
              ) as? String
        else {
            throw LAB002ObserverReason.identityMismatch
        }
        return try targetIdentityBinding(
            bundleIdentifier: bundleIdentifier,
            nonceHex: nonceHex,
            fixedRole: fixedRole,
            signing: signing
        )
    }

    private static func targetIdentityBinding(
        bundleIdentifier: String,
        nonceHex: String,
        fixedRole: LAB002Role,
        signing: LAB002MachOSigningMetadata
    ) throws -> String {
        guard signing.presence == .present,
              let codeDirectoryIdentifier =
                signing.codeDirectoryIdentifier,
              let teamIdentifier =
                signing.codeDirectoryTeamIdentifier,
              bundleIdentifier == codeDirectoryIdentifier,
              let nonce = lowerHexBytes(nonceHex),
              nonce.count == 32
        else {
            throw LAB002ObserverReason.identityMismatch
        }
        let entitlements = signing.entitlements
        if let applicationIdentifier =
            entitlements.applicationIdentifier {
            guard applicationIdentifier
                    == "\(teamIdentifier).\(bundleIdentifier)"
            else {
                throw LAB002ObserverReason.identityMismatch
            }
        }
        if let developerTeamIdentifier =
            entitlements.developerTeamIdentifier {
            guard developerTeamIdentifier == teamIdentifier else {
                throw LAB002ObserverReason.identityMismatch
            }
        }

        var bytes = Data(
            "orchardprobe.demolab.lab002.target-identity.v1\0".utf8
        )
        bytes.append(nonce)
        bytes.append(fixedRole.bindingByte)
        try appendFramed(bundleIdentifier, to: &bytes)
        try appendFramed(codeDirectoryIdentifier, to: &bytes)
        try appendFramed(teamIdentifier, to: &bytes)
        try appendOptionalEntitlement(
            entitlements.applicationIdentifier,
            to: &bytes
        )
        try appendOptionalEntitlement(
            entitlements.developerTeamIdentifier,
            to: &bytes
        )
        if let groups = entitlements.applicationGroups {
            bytes.append(1)
            appendBigEndian(UInt32(groups.count), to: &bytes)
            for group in groups {
                try appendFramed(group, to: &bytes)
            }
        } else {
            bytes.append(0)
        }
        return Data(SHA256.hash(data: bytes))
            .map { String(format: "%02x", $0) }
            .joined()
    }

#if DEBUG
    static func testTargetIdentityBinding(
        bundleIdentifier: String,
        nonceHex: String,
        fixedRole: LAB002Role,
        signing: LAB002MachOSigningMetadata
    ) throws -> String {
        try targetIdentityBinding(
            bundleIdentifier: bundleIdentifier,
            nonceHex: nonceHex,
            fixedRole: fixedRole,
            signing: signing
        )
    }
#endif

    private static func appendOptionalEntitlement(
        _ value: String?,
        to bytes: inout Data
    ) throws {
        if let value {
            bytes.append(1)
            try appendFramed(value, to: &bytes)
        } else {
            bytes.append(0)
        }
    }

    private static func appendFramed(
        _ value: String,
        to bytes: inout Data
    ) throws {
        let encoded = Data(value.utf8)
        guard let count = UInt32(exactly: encoded.count),
              !encoded.isEmpty,
              value.unicodeScalars.count <= 256,
              value.precomposedStringWithCanonicalMapping == value,
              !value.unicodeScalars.contains(where: {
                  $0.value == 0
                      || CharacterSet.controlCharacters.contains($0)
              })
        else {
            throw LAB002ObserverReason.identityMismatch
        }
        appendBigEndian(count, to: &bytes)
        bytes.append(encoded)
    }

    private static func appendBigEndian<T: FixedWidthInteger>(
        _ value: T,
        to bytes: inout Data
    ) {
        var big = value.bigEndian
        withUnsafeBytes(of: &big) {
            bytes.append(contentsOf: $0)
        }
    }

    private static func lowerHexBytes(_ value: String) -> Data? {
        guard value.utf8.count.isMultiple(of: 2),
              value.utf8.allSatisfy({
                  (0x30...0x39).contains($0)
                      || (0x61...0x66).contains($0)
              })
        else {
            return nil
        }
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

    private static func currentWholeSecond() throws -> Int64 {
        let value = Date().timeIntervalSince1970
        let whole = value.rounded(.towardZero)
        guard value.isFinite,
              whole >= 0,
              whole <= 9_007_199_254_740_991
        else {
            throw LAB002ObserverReason.inventoryMismatch
        }
        return Int64(whole)
    }
}
