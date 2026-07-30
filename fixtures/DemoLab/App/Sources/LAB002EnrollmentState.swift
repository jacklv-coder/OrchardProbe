import CryptoKit
import Foundation
import Security

enum LAB002EnrollmentError: Error {
    case invalidState
    case alreadyEnrolled
    case notEnrolled
    case keyUnavailable(OSStatus)
    case keyMismatch
    case buildMismatch
    case randomnessFailure(OSStatus)
}

struct LAB002InstallationState: Equatable {
    static let schema = "orchardprobe.lab002.installation-nonce-state.v1"
    static let profile = "orchardprobe.demolab.lab002.observation.v1"

    let buildBindingSHA256: String
    let enrollmentPublicKey: String
    let installationNonce: String

    init(
        buildBindingSHA256: String,
        enrollmentPublicKey: String,
        installationNonce: String
    ) throws {
        guard Self.isLowerHex(buildBindingSHA256),
              Self.isLowerHex(enrollmentPublicKey),
              Self.isLowerHex(installationNonce)
        else {
            throw LAB002EnrollmentError.invalidState
        }
        self.buildBindingSHA256 = buildBindingSHA256
        self.enrollmentPublicKey = enrollmentPublicKey
        self.installationNonce = installationNonce
    }

    init(canonicalBytes: Data) throws {
        guard canonicalBytes.count <= LAB002Limit.fixedState,
              let object = try JSONSerialization.jsonObject(
                  with: canonicalBytes,
                  options: []
              ) as? [String: Any],
              object.count == 5,
              let buildBinding = object["build_binding_sha256"] as? String,
              let publicKey = object["enrollment_public_key"] as? String,
              let nonce = object["installation_nonce"] as? String,
              let profile = object["profile"] as? String,
              let schema = object["schema"] as? String,
              profile == Self.profile,
              schema == Self.schema
        else {
            throw LAB002EnrollmentError.invalidState
        }
        try self.init(
            buildBindingSHA256: buildBinding,
            enrollmentPublicKey: publicKey,
            installationNonce: nonce
        )
        guard try canonicalData() == canonicalBytes else {
            throw LAB002EnrollmentError.invalidState
        }
    }

    func canonicalData() throws -> Data {
        let text = """
        {"build_binding_sha256":"\(buildBindingSHA256)","enrollment_public_key":"\(enrollmentPublicKey)","installation_nonce":"\(installationNonce)","profile":"\(Self.profile)","schema":"\(Self.schema)"}
        """
        guard let data = text.data(using: .utf8),
              data.count <= LAB002Limit.fixedState
        else {
            throw LAB002EnrollmentError.invalidState
        }
        return data
    }

    static func isLowerHex(_ value: String) -> Bool {
        value.utf8.count == 64
            && value.utf8.allSatisfy {
                (UInt8(ascii: "0") ... UInt8(ascii: "9")).contains($0)
                    || (UInt8(ascii: "a") ... UInt8(ascii: "f")).contains($0)
            }
    }
}

protocol LAB002EnrollmentSigningKey {
    var publicKeyRaw: Data { get }
    func signature(for bytes: Data) throws -> Data
}

protocol LAB002EnrollmentKeyStoring {
    func createOrRecoverForAuthenticatedEnrollment(
        buildBindingSHA256: String
    ) throws -> any LAB002EnrollmentSigningKey
    func loadExisting(
        buildBindingSHA256: String
    ) throws -> any LAB002EnrollmentSigningKey
}

protocol LAB002RandomBytesGenerating {
    func bytes(count: Int) throws -> Data
}

struct LAB002CryptoKitSigningKey: LAB002EnrollmentSigningKey {
    private let privateKey: Curve25519.Signing.PrivateKey

    init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    init(rawRepresentation: Data) throws {
        privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: rawRepresentation)
    }

    var publicKeyRaw: Data {
        privateKey.publicKey.rawRepresentation
    }

    func signature(for bytes: Data) throws -> Data {
        try privateKey.signature(for: bytes)
    }
}

final class LAB002KeychainEnrollmentKeyStore: LAB002EnrollmentKeyStoring {
    private static let service = "com.orchardprobe.demolab.lab002.enrollment-key.v1"
    private static let account = "ed25519-private-key"

    private let accessGroup: String

    static func production() throws -> LAB002KeychainEnrollmentKeyStore {
        guard let accessGroup = Bundle.main.object(
            forInfoDictionaryKey: "LAB002KeychainAccessGroup"
        ) as? String,
        !accessGroup.isEmpty,
        accessGroup.utf8.count <= 255,
        !accessGroup.contains("$(")
        else {
            throw LAB002EnrollmentError.invalidState
        }
        return LAB002KeychainEnrollmentKeyStore(accessGroup: accessGroup)
    }

    private init(accessGroup: String) {
        self.accessGroup = accessGroup
    }

    func createOrRecoverForAuthenticatedEnrollment(
        buildBindingSHA256: String
    ) throws -> any LAB002EnrollmentSigningKey {
        do {
            return try loadExisting(
                buildBindingSHA256: buildBindingSHA256
            )
        } catch LAB002EnrollmentError.notEnrolled {
        }

        let privateKey = Curve25519.Signing.PrivateKey()
        var query = baseQuery()
        query[kSecValueData as String] = privateKey.rawRepresentation
        query[kSecAttrGeneric as String] = Data(buildBindingSHA256.utf8)
        query[kSecAttrAccessible as String] =
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            return try loadExisting(
                buildBindingSHA256: buildBindingSHA256
            )
        }
        guard status == errSecSuccess else {
            throw LAB002EnrollmentError.keyUnavailable(status)
        }
        return LAB002CryptoKitSigningKey(privateKey: privateKey)
    }

    func loadExisting(
        buildBindingSHA256: String
    ) throws -> any LAB002EnrollmentSigningKey {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            throw LAB002EnrollmentError.notEnrolled
        }
        guard status == errSecSuccess,
              let attributes = result as? [String: Any],
              let raw = attributes[kSecValueData as String] as? Data,
              raw.count == 32,
              let storedBuild = attributes[kSecAttrGeneric as String] as? Data,
              attributes[kSecAttrAccessible as String] as? String
                == kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String
        else {
            throw LAB002EnrollmentError.keyUnavailable(
                status == errSecSuccess ? errSecDecode : status
            )
        }
        guard storedBuild == Data(buildBindingSHA256.utf8) else {
            throw LAB002EnrollmentError.buildMismatch
        }
        do {
            return try LAB002CryptoKitSigningKey(rawRepresentation: raw)
        } catch {
            throw LAB002EnrollmentError.keyUnavailable(errSecDecode)
        }
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
            kSecAttrAccessGroup as String: accessGroup,
            kSecAttrSynchronizable as String: false,
        ]
    }
}

struct LAB002SystemRandomBytes: LAB002RandomBytesGenerating {
    func bytes(count: Int) throws -> Data {
        guard count == 32 else {
            throw LAB002EnrollmentError.invalidState
        }
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw LAB002EnrollmentError.randomnessFailure(status)
        }
        return data
    }
}

struct LAB002EnrollmentContinuity {
    let state: LAB002InstallationState
    let signingKey: any LAB002EnrollmentSigningKey
}

final class LAB002EnrollmentStateCoordinator {
    private let storage: LAB002FixedStorage
    private let keyStore: any LAB002EnrollmentKeyStoring
    private let random: any LAB002RandomBytesGenerating

    static func production(
        storage: LAB002FixedStorage
    ) throws -> LAB002EnrollmentStateCoordinator {
        try LAB002EnrollmentStateCoordinator(
            storage: storage,
            keyStore: LAB002KeychainEnrollmentKeyStore.production(),
            random: LAB002SystemRandomBytes()
        )
    }

    init(
        storage: LAB002FixedStorage,
        keyStore: any LAB002EnrollmentKeyStoring,
        random: any LAB002RandomBytesGenerating
    ) {
        self.storage = storage
        self.keyStore = keyStore
        self.random = random
    }

    func createAfterAuthenticatedEnrollment(
        buildBindingSHA256: String
    ) throws -> LAB002EnrollmentContinuity {
        guard LAB002InstallationState.isLowerHex(buildBindingSHA256) else {
            throw LAB002EnrollmentError.invalidState
        }
        guard try storage.readInstallationState() == nil else {
            throw LAB002EnrollmentError.alreadyEnrolled
        }
        let signingKey = try keyStore.createOrRecoverForAuthenticatedEnrollment(
            buildBindingSHA256: buildBindingSHA256
        )
        let nonce = try random.bytes(count: 32)
        guard signingKey.publicKeyRaw.count == 32,
              nonce.count == 32
        else {
            throw LAB002EnrollmentError.invalidState
        }
        let state = try LAB002InstallationState(
            buildBindingSHA256: buildBindingSHA256,
            enrollmentPublicKey: signingKey.publicKeyRaw.hexLowercase,
            installationNonce: nonce.hexLowercase
        )
        try storage.createInstallationState(state)
        return LAB002EnrollmentContinuity(state: state, signingKey: signingKey)
    }

    func loadForRun(
        buildBindingSHA256: String
    ) throws -> LAB002EnrollmentContinuity {
        guard let state = try storage.readInstallationState() else {
            throw LAB002EnrollmentError.notEnrolled
        }
        guard state.buildBindingSHA256 == buildBindingSHA256 else {
            throw LAB002EnrollmentError.buildMismatch
        }
        let signingKey = try keyStore.loadExisting(
            buildBindingSHA256: buildBindingSHA256
        )
        guard signingKey.publicKeyRaw.count == 32,
              signingKey.publicKeyRaw.hexLowercase == state.enrollmentPublicKey
        else {
            throw LAB002EnrollmentError.keyMismatch
        }
        return LAB002EnrollmentContinuity(state: state, signingKey: signingKey)
    }
}

extension Data {
    var hexLowercase: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
