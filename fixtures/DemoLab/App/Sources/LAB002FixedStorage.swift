import Darwin
import Foundation

enum LAB002StorageError: Error {
    case invalidRoot
    case unsafeEntry(String)
    case missingEntry(String)
    case existingEntry(String)
    case oversized(String)
    case io(String, Int32)
    case lockUnavailable
    case invalidCounter
    case counterMismatch
    case counterExhausted
}

private let lab002RenameExclusive = UInt32(0x0000_0004)
private let lab002RenameNoFollowAny = UInt32(0x0000_0010)

final class LAB002FileDescriptor {
    let rawValue: Int32

    init(_ rawValue: Int32) {
        self.rawValue = rawValue
    }

    deinit {
        Darwin.close(rawValue)
    }
}

struct LAB002FileIdentity: Equatable {
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

    var isRegularOwnerOnly: Bool {
        mode & S_IFMT == S_IFREG
            && owner == geteuid()
            && mode & 0o077 == 0
            && links == 1
            && size >= 0
    }

    var isOwnerOnlyDirectory: Bool {
        mode & S_IFMT == S_IFDIR
            && owner == geteuid()
            && mode & 0o077 == 0
    }
}

struct LAB002QuarantinedAuthorization {
    let bytes: Data
    fileprivate let descriptor: LAB002FileDescriptor
    fileprivate let identity: LAB002FileIdentity
}

struct LAB002EnrollmentAuthorization {
    let quarantined: LAB002QuarantinedAuthorization
    let resumedAfterPersistence: Bool
}

struct LAB002CounterRecord {
    static let schema = "orchardprobe.lab002.run-counter-state.v1"

    let buildBindingSHA256: String
    let counter: UInt64

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= LAB002Limit.fixedState,
              let object = try JSONSerialization.jsonObject(
                  with: canonicalBytes,
                  options: []
              ) as? [String: Any],
              object.count == 3,
              let buildBinding = object["build_binding_sha256"] as? String,
              let counterString = object["counter"] as? String,
              let schema = object["schema"] as? String,
              schema == Self.schema,
              Self.isLowerHex(buildBinding, count: 64),
              Self.isLowerHex(counterString, count: 16),
              let counter = UInt64(counterString, radix: 16)
        else {
            throw LAB002StorageError.invalidCounter
        }
        buildBindingSHA256 = buildBinding
        self.counter = counter
        guard try canonicalData() == canonicalBytes else {
            throw LAB002StorageError.invalidCounter
        }
    }

    init(buildBindingSHA256: String, counter: UInt64) throws {
        guard Self.isLowerHex(buildBindingSHA256, count: 64) else {
            throw LAB002StorageError.invalidCounter
        }
        self.buildBindingSHA256 = buildBindingSHA256
        self.counter = counter
    }

    func canonicalData() throws -> Data {
        let counterString = String(format: "%016llx", counter)
        let text = """
        {"build_binding_sha256":"\(buildBindingSHA256)","counter":"\(counterString)","schema":"\(Self.schema)"}
        """
        guard let data = text.data(using: .utf8),
              data.count <= LAB002Limit.fixedState
        else {
            throw LAB002StorageError.invalidCounter
        }
        return data
    }

    private static func isLowerHex(_ value: String, count: Int) -> Bool {
        value.utf8.count == count
            && value.utf8.allSatisfy {
                (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains($0)
                    || (UInt8(ascii: "a") ... UInt8(ascii: "f")).contains($0)
            }
    }
}

final class LAB002FixedStorage {
    let rootURL: URL
    let inboxURL: URL
    let stateURL: URL
    let reportsURL: URL

    private let rootDirectory: LAB002FileDescriptor
    private let inboxDirectory: LAB002FileDescriptor
    private let stateDirectory: LAB002FileDescriptor

    static func production() throws -> LAB002FixedStorage {
        guard let identifier = Bundle.main.object(
            forInfoDictionaryKey: "LAB002AppGroupIdentifier"
        ) as? String,
        identifier.hasPrefix("group."),
        identifier.utf8.count <= 255,
        let containerURL = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: identifier
        )
        else {
            throw LAB002StorageError.invalidRoot
        }
        return try LAB002FixedStorage(containerURL: containerURL)
    }

    convenience init(testContainerURL: URL) throws {
        try self.init(containerURL: testContainerURL)
    }

    private init(containerURL: URL) throws {
        let container = try Self.openDirectory(url: containerURL, ownerOnly: false)
        let root = try Self.ensureDirectory(
            parent: container,
            parentURL: containerURL,
            name: LAB002FixedName.root
        )
        let inbox = try Self.ensureDirectory(
            parent: root.descriptor,
            parentURL: root.url,
            name: LAB002FixedName.inbox
        )
        let state = try Self.ensureDirectory(
            parent: root.descriptor,
            parentURL: root.url,
            name: LAB002FixedName.state
        )
        let reports = try Self.ensureDirectory(
            parent: root.descriptor,
            parentURL: root.url,
            name: LAB002FixedName.reports
        )

        rootURL = root.url
        inboxURL = inbox.url
        stateURL = state.url
        reportsURL = reports.url
        rootDirectory = root.descriptor
        inboxDirectory = inbox.descriptor
        stateDirectory = state.descriptor
    }

    func withCoordinatorLock<T>(_ body: () throws -> T) throws -> T {
        let descriptor = try openOrCreateRegularFile(
            directory: rootDirectory,
            directoryURL: rootURL,
            name: LAB002FixedName.lock,
            mode: 0o600
        )
        guard flock(descriptor.rawValue, LOCK_EX | LOCK_NB) == 0 else {
            throw LAB002StorageError.lockUnavailable
        }
        defer {
            _ = flock(descriptor.rawValue, LOCK_UN)
        }
        return try body()
    }

    func readExternalDocument(_ url: URL, maximum: Int) throws -> Data {
        let accessed = url.startAccessingSecurityScopedResource()
        defer {
            if accessed {
                url.stopAccessingSecurityScopedResource()
            }
        }
        let descriptor = try Self.openRegularFile(url: url)
        return try Self.readBounded(descriptor, maximum: maximum, label: "selected document")
    }

    func publishAuthorization(_ bytes: Data) throws {
        guard bytes.count <= LAB002Limit.controlDocument else {
            throw LAB002StorageError.oversized(LAB002FixedName.authorization)
        }
        try writeAtomic(
            directory: inboxDirectory,
            directoryURL: inboxURL,
            destination: LAB002FixedName.authorization,
            temporary: LAB002FixedName.authorizationTemporary,
            bytes: bytes,
            replacing: nil
        )
    }

    func quarantineAuthorization() throws -> LAB002QuarantinedAuthorization {
        guard try entryIdentity(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine
        ) == nil
        else {
            throw LAB002StorageError.existingEntry(
                LAB002FixedName.authorizationQuarantine
            )
        }
        let sourceDescriptor = try openRegularFile(
            directory: inboxDirectory,
            name: LAB002FixedName.authorization
        )
        let sourceIdentity = try identity(sourceDescriptor)
        let sourceEntry = try requireMatchingEntry(
            directory: inboxDirectory,
            name: LAB002FixedName.authorization,
            descriptorIdentity: sourceIdentity
        )
        guard sourceEntry.isRegularOwnerOnly else {
            throw LAB002StorageError.unsafeEntry(LAB002FixedName.authorization)
        }

        try rename(
            directory: inboxDirectory,
            source: LAB002FixedName.authorization,
            destination: LAB002FixedName.authorizationQuarantine,
            exclusive: true
        )
        try sync(inboxDirectory, label: LAB002FixedName.inbox)
        _ = try requireMatchingEntry(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine,
            descriptorIdentity: sourceIdentity
        )
        let bytes = try Self.readBounded(
            sourceDescriptor,
            maximum: LAB002Limit.controlDocument,
            label: LAB002FixedName.authorizationQuarantine
        )
        return LAB002QuarantinedAuthorization(
            bytes: bytes,
            descriptor: sourceDescriptor,
            identity: sourceIdentity
        )
    }

    func quarantineEnrollmentAuthorization() throws
        -> LAB002EnrollmentAuthorization
    {
        guard try entryIdentity(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine
        ) != nil
        else {
            return LAB002EnrollmentAuthorization(
                quarantined: try quarantineAuthorization(),
                resumedAfterPersistence: false
            )
        }
        guard try entryIdentity(
            directory: inboxDirectory,
            name: LAB002FixedName.authorization
        ) == nil
        else {
            throw LAB002StorageError.existingEntry(
                LAB002FixedName.authorization
            )
        }
        let descriptor = try openRegularFile(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine
        )
        let descriptorIdentity = try identity(descriptor)
        let entry = try requireMatchingEntry(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine,
            descriptorIdentity: descriptorIdentity
        )
        guard entry.isRegularOwnerOnly else {
            throw LAB002StorageError.unsafeEntry(
                LAB002FixedName.authorizationQuarantine
            )
        }
        let bytes = try Self.readBounded(
            descriptor,
            maximum: LAB002Limit.controlDocument,
            label: LAB002FixedName.authorizationQuarantine
        )
        return LAB002EnrollmentAuthorization(
            quarantined: LAB002QuarantinedAuthorization(
                bytes: bytes,
                descriptor: descriptor,
                identity: descriptorIdentity
            ),
            resumedAfterPersistence: true
        )
    }

    func hasQuarantinedAuthorization() throws -> Bool {
        try entryIdentity(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine
        ) != nil
    }

    func restoreAuthorization(_ record: LAB002QuarantinedAuthorization) throws {
        _ = try requireMatchingEntry(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine,
            descriptorIdentity: record.identity
        )
        try rename(
            directory: inboxDirectory,
            source: LAB002FixedName.authorizationQuarantine,
            destination: LAB002FixedName.authorization,
            exclusive: true
        )
        try sync(inboxDirectory, label: LAB002FixedName.inbox)
        _ = try requireMatchingEntry(
            directory: inboxDirectory,
            name: LAB002FixedName.authorization,
            descriptorIdentity: record.identity
        )
    }

    func deleteAuthorization(_ record: LAB002QuarantinedAuthorization) throws {
        _ = try requireMatchingEntry(
            directory: inboxDirectory,
            name: LAB002FixedName.authorizationQuarantine,
            descriptorIdentity: record.identity
        )
        let result = LAB002FixedName.authorizationQuarantine.withCString {
            unlinkat(inboxDirectory.rawValue, $0, 0)
        }
        guard result == 0 else {
            throw LAB002StorageError.io(
                "unlink \(LAB002FixedName.authorizationQuarantine)",
                errno
            )
        }
        try sync(inboxDirectory, label: LAB002FixedName.inbox)
    }

    func commitExpectedCounter(
        expected: UInt64,
        buildBindingSHA256: String
    ) throws -> LAB002CounterRecord {
        let priorIdentity = try entryIdentity(
            directory: stateDirectory,
            name: LAB002FixedName.counter
        )
        let priorCounter: UInt64
        if priorIdentity == nil {
            guard expected == 1 else {
                throw LAB002StorageError.counterMismatch
            }
            priorCounter = 0
        } else {
            let descriptor = try openRegularFile(
                directory: stateDirectory,
                name: LAB002FixedName.counter
            )
            let descriptorIdentity = try identity(descriptor)
            _ = try requireMatchingEntry(
                directory: stateDirectory,
                name: LAB002FixedName.counter,
                descriptorIdentity: descriptorIdentity
            )
            let bytes = try Self.readBounded(
                descriptor,
                maximum: LAB002Limit.fixedState,
                label: LAB002FixedName.counter
            )
            let record = try LAB002CounterRecord(canonicalBytes: bytes)
            guard record.buildBindingSHA256 == buildBindingSHA256 else {
                throw LAB002StorageError.counterMismatch
            }
            priorCounter = record.counter
        }

        guard priorCounter != UInt64.max else {
            throw LAB002StorageError.counterExhausted
        }
        let next = priorCounter + 1
        guard next == expected else {
            throw LAB002StorageError.counterMismatch
        }
        let record = try LAB002CounterRecord(
            buildBindingSHA256: buildBindingSHA256,
            counter: next
        )
        try writeAtomic(
            directory: stateDirectory,
            directoryURL: stateURL,
            destination: LAB002FixedName.counter,
            temporary: LAB002FixedName.counterTemporary,
            bytes: try record.canonicalData(),
            replacing: priorIdentity
        )
        return record
    }

    func readCounter() throws -> LAB002CounterRecord? {
        guard try entryIdentity(
            directory: stateDirectory,
            name: LAB002FixedName.counter
        ) != nil
        else {
            return nil
        }
        let descriptor = try openRegularFile(
            directory: stateDirectory,
            name: LAB002FixedName.counter
        )
        let descriptorIdentity = try identity(descriptor)
        _ = try requireMatchingEntry(
            directory: stateDirectory,
            name: LAB002FixedName.counter,
            descriptorIdentity: descriptorIdentity
        )
        let bytes = try Self.readBounded(
            descriptor,
            maximum: LAB002Limit.fixedState,
            label: LAB002FixedName.counter
        )
        return try LAB002CounterRecord(canonicalBytes: bytes)
    }

    func createInstallationState(_ record: LAB002InstallationState) throws {
        try writeAtomic(
            directory: stateDirectory,
            directoryURL: stateURL,
            destination: LAB002FixedName.installationNonce,
            temporary: LAB002FixedName.installationNonceTemporary,
            bytes: try record.canonicalData(),
            replacing: nil
        )
    }

    func readInstallationState() throws -> LAB002InstallationState? {
        guard try entryIdentity(
            directory: stateDirectory,
            name: LAB002FixedName.installationNonce
        ) != nil
        else {
            return nil
        }
        let descriptor = try openRegularFile(
            directory: stateDirectory,
            name: LAB002FixedName.installationNonce
        )
        let descriptorIdentity = try identity(descriptor)
        _ = try requireMatchingEntry(
            directory: stateDirectory,
            name: LAB002FixedName.installationNonce,
            descriptorIdentity: descriptorIdentity
        )
        let bytes = try Self.readBounded(
            descriptor,
            maximum: LAB002Limit.fixedState,
            label: LAB002FixedName.installationNonce
        )
        return try LAB002InstallationState(canonicalBytes: bytes)
    }

    private func writeAtomic(
        directory: LAB002FileDescriptor,
        directoryURL: URL,
        destination: String,
        temporary: String,
        bytes: Data,
        replacing expectedDestinationIdentity: LAB002FileIdentity?
    ) throws {
        guard try entryIdentity(directory: directory, name: temporary) == nil else {
            throw LAB002StorageError.existingEntry(temporary)
        }
        if expectedDestinationIdentity == nil {
            guard try entryIdentity(directory: directory, name: destination) == nil else {
                throw LAB002StorageError.existingEntry(destination)
            }
        } else {
            guard let destinationIdentity = try entryIdentity(
                directory: directory,
                name: destination
            ), destinationIdentity == expectedDestinationIdentity,
            destinationIdentity.isRegularOwnerOnly
            else {
                throw LAB002StorageError.unsafeEntry(destination)
            }
        }

        let temporaryDescriptor = try createRegularFile(
            directory: directory,
            name: temporary,
            mode: 0o600
        )
        do {
            try writeAll(bytes, to: temporaryDescriptor, label: temporary)
            try sync(temporaryDescriptor, label: temporary)
            let temporaryURL = directoryURL.appendingPathComponent(
                temporary,
                isDirectory: false
            )
            try applyProtectionAndBackupExclusion(temporaryURL)
            let temporaryIdentity = try identity(temporaryDescriptor)
            _ = try requireMatchingEntry(
                directory: directory,
                name: temporary,
                descriptorIdentity: temporaryIdentity
            )
            try rename(
                directory: directory,
                source: temporary,
                destination: destination,
                exclusive: expectedDestinationIdentity == nil
            )
            try sync(directory, label: directoryURL.lastPathComponent)
            _ = try requireMatchingEntry(
                directory: directory,
                name: destination,
                descriptorIdentity: temporaryIdentity
            )
        } catch {
            throw error
        }
    }

    private func rename(
        directory: LAB002FileDescriptor,
        source: String,
        destination: String,
        exclusive: Bool
    ) throws {
        var flags = lab002RenameNoFollowAny
        if exclusive {
            flags |= lab002RenameExclusive
        }
        let result = source.withCString { sourcePointer in
            destination.withCString { destinationPointer in
                renameatx_np(
                    directory.rawValue,
                    sourcePointer,
                    directory.rawValue,
                    destinationPointer,
                    flags
                )
            }
        }
        guard result == 0 else {
            throw LAB002StorageError.io(
                "rename \(source) to \(destination)",
                errno
            )
        }
    }

    private func openOrCreateRegularFile(
        directory: LAB002FileDescriptor,
        directoryURL: URL,
        name: String,
        mode: mode_t
    ) throws -> LAB002FileDescriptor {
        if try entryIdentity(directory: directory, name: name) == nil {
            let descriptor = try createRegularFile(
                directory: directory,
                name: name,
                mode: mode
            )
            try applyProtectionAndBackupExclusion(
                directoryURL.appendingPathComponent(name)
            )
            return descriptor
        }
        return try openRegularFile(directory: directory, name: name)
    }

    private func createRegularFile(
        directory: LAB002FileDescriptor,
        name: String,
        mode: mode_t
    ) throws -> LAB002FileDescriptor {
        let raw = name.withCString {
            openat(
                directory.rawValue,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode
            )
        }
        guard raw >= 0 else {
            throw LAB002StorageError.io("create \(name)", errno)
        }
        let descriptor = LAB002FileDescriptor(raw)
        let descriptorIdentity = try identity(descriptor)
        guard descriptorIdentity.isRegularOwnerOnly else {
            throw LAB002StorageError.unsafeEntry(name)
        }
        _ = try requireMatchingEntry(
            directory: directory,
            name: name,
            descriptorIdentity: descriptorIdentity
        )
        return descriptor
    }

    private func openRegularFile(
        directory: LAB002FileDescriptor,
        name: String
    ) throws -> LAB002FileDescriptor {
        let raw = name.withCString {
            openat(
                directory.rawValue,
                $0,
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
            )
        }
        guard raw >= 0 else {
            if errno == ENOENT {
                throw LAB002StorageError.missingEntry(name)
            }
            throw LAB002StorageError.io("open \(name)", errno)
        }
        let descriptor = LAB002FileDescriptor(raw)
        guard try identity(descriptor).isRegularOwnerOnly else {
            throw LAB002StorageError.unsafeEntry(name)
        }
        return descriptor
    }

    private func entryIdentity(
        directory: LAB002FileDescriptor,
        name: String
    ) throws -> LAB002FileIdentity? {
        var value = stat()
        let result = name.withCString {
            fstatat(directory.rawValue, $0, &value, AT_SYMLINK_NOFOLLOW)
        }
        if result == 0 {
            return LAB002FileIdentity(value)
        }
        if errno == ENOENT {
            return nil
        }
        throw LAB002StorageError.io("stat \(name)", errno)
    }

    private func requireMatchingEntry(
        directory: LAB002FileDescriptor,
        name: String,
        descriptorIdentity: LAB002FileIdentity
    ) throws -> LAB002FileIdentity {
        guard let entry = try entryIdentity(directory: directory, name: name),
              entry == descriptorIdentity
        else {
            throw LAB002StorageError.unsafeEntry(name)
        }
        return entry
    }

    private func identity(
        _ descriptor: LAB002FileDescriptor
    ) throws -> LAB002FileIdentity {
        var value = stat()
        guard fstat(descriptor.rawValue, &value) == 0 else {
            throw LAB002StorageError.io("fstat", errno)
        }
        return LAB002FileIdentity(value)
    }

    private func writeAll(
        _ bytes: Data,
        to descriptor: LAB002FileDescriptor,
        label: String
    ) throws {
        try bytes.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                return
            }
            var offset = 0
            while offset < rawBuffer.count {
                let result = Darwin.write(
                    descriptor.rawValue,
                    base.advanced(by: offset),
                    rawBuffer.count - offset
                )
                if result < 0 {
                    if errno == EINTR {
                        continue
                    }
                    throw LAB002StorageError.io("write \(label)", errno)
                }
                guard result > 0 else {
                    throw LAB002StorageError.io("write \(label)", EIO)
                }
                offset += result
            }
        }
    }

    private func sync(
        _ descriptor: LAB002FileDescriptor,
        label: String
    ) throws {
        guard fsync(descriptor.rawValue) == 0 else {
            throw LAB002StorageError.io("fsync \(label)", errno)
        }
    }

    private func applyProtectionAndBackupExclusion(_ url: URL) throws {
        do {
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: url.path
            )
            var protectedURL = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try protectedURL.setResourceValues(values)
        } catch {
            throw LAB002StorageError.unsafeEntry(url.lastPathComponent)
        }
    }

    private static func openDirectory(
        url: URL,
        ownerOnly: Bool
    ) throws -> LAB002FileDescriptor {
        let raw = url.withUnsafeFileSystemRepresentation { pointer in
            guard let pointer else {
                return Int32(-1)
            }
            return open(pointer, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard raw >= 0 else {
            throw LAB002StorageError.invalidRoot
        }
        let descriptor = LAB002FileDescriptor(raw)
        var value = stat()
        guard fstat(raw, &value) == 0 else {
            throw LAB002StorageError.io("fstat root", errno)
        }
        let identity = LAB002FileIdentity(value)
        guard identity.mode & S_IFMT == S_IFDIR,
              identity.owner == geteuid(),
              !ownerOnly || identity.isOwnerOnlyDirectory
        else {
            throw LAB002StorageError.invalidRoot
        }
        return descriptor
    }

    private static func ensureDirectory(
        parent: LAB002FileDescriptor,
        parentURL: URL,
        name: String
    ) throws -> (descriptor: LAB002FileDescriptor, url: URL) {
        let result = name.withCString {
            mkdirat(parent.rawValue, $0, 0o700)
        }
        guard result == 0 || errno == EEXIST else {
            throw LAB002StorageError.io("mkdir \(name)", errno)
        }
        let raw = name.withCString {
            openat(
                parent.rawValue,
                $0,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
            )
        }
        guard raw >= 0 else {
            throw LAB002StorageError.io("open directory \(name)", errno)
        }
        let descriptor = LAB002FileDescriptor(raw)
        var value = stat()
        guard fstat(raw, &value) == 0,
              LAB002FileIdentity(value).isOwnerOnlyDirectory
        else {
            throw LAB002StorageError.unsafeEntry(name)
        }
        let url = parentURL.appendingPathComponent(name, isDirectory: true)
        do {
            try FileManager.default.setAttributes(
                [.protectionKey: FileProtectionType.complete],
                ofItemAtPath: url.path
            )
            var protectedURL = url
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try protectedURL.setResourceValues(values)
        } catch {
            throw LAB002StorageError.unsafeEntry(name)
        }
        return (descriptor, url)
    }

    private static func openRegularFile(url: URL) throws -> LAB002FileDescriptor {
        let raw = url.withUnsafeFileSystemRepresentation { pointer in
            guard let pointer else {
                return Int32(-1)
            }
            return open(
                pointer,
                O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
            )
        }
        guard raw >= 0 else {
            throw LAB002StorageError.io("open selected document", errno)
        }
        let descriptor = LAB002FileDescriptor(raw)
        var value = stat()
        guard fstat(raw, &value) == 0,
              LAB002FileIdentity(value).mode & S_IFMT == S_IFREG
        else {
            throw LAB002StorageError.unsafeEntry("selected document")
        }
        return descriptor
    }

    private static func readBounded(
        _ descriptor: LAB002FileDescriptor,
        maximum: Int,
        label: String
    ) throws -> Data {
        var before = stat()
        guard fstat(descriptor.rawValue, &before) == 0 else {
            throw LAB002StorageError.io("fstat \(label)", errno)
        }
        let beforeIdentity = LAB002FileIdentity(before)
        guard beforeIdentity.mode & S_IFMT == S_IFREG,
              beforeIdentity.size >= 0,
              beforeIdentity.size <= maximum
        else {
            throw LAB002StorageError.oversized(label)
        }

        var storage = [UInt8](repeating: 0, count: maximum + 1)
        var offset = 0
        while offset < storage.count {
            let remaining = storage.count - offset
            let result = storage.withUnsafeMutableBytes { buffer in
                Darwin.read(
                    descriptor.rawValue,
                    buffer.baseAddress!.advanced(by: offset),
                    remaining
                )
            }
            if result < 0 {
                if errno == EINTR {
                    continue
                }
                throw LAB002StorageError.io("read \(label)", errno)
            }
            if result == 0 {
                break
            }
            offset += result
        }
        guard offset <= maximum else {
            throw LAB002StorageError.oversized(label)
        }
        var after = stat()
        guard fstat(descriptor.rawValue, &after) == 0 else {
            throw LAB002StorageError.io("fstat \(label)", errno)
        }
        let afterIdentity = LAB002FileIdentity(after)
        guard beforeIdentity == afterIdentity,
              afterIdentity.size == offset
        else {
            throw LAB002StorageError.unsafeEntry(label)
        }
        return Data(storage.prefix(offset))
    }
}
