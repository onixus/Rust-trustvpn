import Foundation
import Security

func tr(_ english: String, _ russian: String) -> String {
    Locale.preferredLanguages.first?.hasPrefix("ru") == true ? russian : english
}
enum AppError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case .message(let text) = self { return text }; return nil }
}
struct ProfilePlan: Decodable {
    let ok: Bool
    let profile: String?
    let hostname: String?
    let name: String?
    let dns: [String]?
    let routes: [String]?
    let mtu: Int?
    let ipv6: Bool?
    let message: String?
    static func parse(_ data: Data) throws -> ProfilePlan {
        guard !data.isEmpty, data.count <= 1_048_576 else { throw AppError.message(tr("Profile is too large or empty", "Профиль пуст или слишком большой")) }
        let pointer = data.withUnsafeBytes { rtrust_ios_prepare($0.bindMemory(to: UInt8.self).baseAddress, data.count) }
        guard let pointer else { throw AppError.message("Core unavailable") }
        defer { rtrust_ios_free(pointer) }
        let result = try JSONDecoder().decode(Self.self, from: Data(bytes: pointer, count: strlen(pointer)))
        guard result.ok, result.profile != nil, result.dns != nil, result.routes != nil else { throw AppError.message(result.message ?? "Invalid profile") }
        return result
    }
    static func export(_ raw: String, format: Int32) throws -> ExportResult {
        let data = Data(raw.utf8)
        let pointer = data.withUnsafeBytes { rtrust_ios_export($0.bindMemory(to: UInt8.self).baseAddress, data.count, format) }
        guard let pointer else { throw AppError.message("Core unavailable") }
        defer { rtrust_ios_free(pointer) }
        let result = try JSONDecoder().decode(ExportResult.self, from: Data(bytes: pointer, count: strlen(pointer)))
        guard result.ok, result.content != nil else { throw AppError.message(result.message ?? "Export failed") }
        return result
    }
}
struct ExportResult: Decodable {
    let ok: Bool
    let content: String?
    let losses: [String]?
    let message: String?
}
struct SavedProfile: Codable, Identifiable, Equatable {
    var id: String
    var name: String
    var hostname: String
    var content: String
    var remoteID: String?
    var revision: String?
    static func imported(_ plan: ProfilePlan, id: String = UUID().uuidString) -> Self {
        Self(id: id, name: plan.name?.isEmpty == false ? plan.name! : (plan.hostname ?? "Profile"), hostname: plan.hostname ?? "", content: plan.profile!)
    }
}
struct PortalSession: Codable, Equatable {
    var origin: String
    var token: String
    var backgroundSync = false
    var lastSync: Date?
    var authExpired = false
}
struct VaultData: Codable {
    var version = 1
    var profiles: [SavedProfile] = []
    var selected: String?
    var portal: PortalSession?
    var active: SavedProfile? { profiles.first { $0.id == selected } }
    mutating func repairSelection() {
        if active == nil { selected = profiles.first?.id }
    }
    func validate() throws {
        guard version == 1, profiles.count <= 64, Set(profiles.map(\.id)).count == profiles.count,
              (profiles.isEmpty && selected == nil) || active != nil else { throw AppError.message("Invalid profile vault") }
    }
}
// One atomic Keychain item. App is the only writer; provider reads a coherent snapshot.
// Errors never reset the vault, and no plaintext fallback is used.
enum ProfileVault {
    private static let lock = NSLock()
    static var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "org.rtrusttunnel.ios.profile",
         kSecAttrAccount as String: "active",
         kSecAttrAccessGroup as String: Bundle.main.object(forInfoDictionaryKey: "SharedKeychainGroup") as? String ?? "invalid"]
    }
    private static func read() throws -> VaultData {
        var lookup = query
        lookup[kSecReturnData as String] = true
        lookup[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &value)
        if status == errSecItemNotFound { return VaultData() }
        guard status == errSecSuccess, let data = value as? Data, data.count <= 8 * 1024 * 1024 else {
            throw AppError.message(tr("Cannot read Keychain. Unlock iPhone.", "Не удалось прочитать Keychain. Разблокируйте iPhone."))
        }
        // Explicit migration from the first single-profile preview; preserve credentials.
        if let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], object["schema_version"] != nil {
            let profile = SavedProfile.imported(try ProfilePlan.parse(data), id: "migrated-profile")
            return VaultData(profiles: [profile], selected: profile.id)
        }
        let result = try JSONDecoder().decode(VaultData.self, from: data)
        try result.validate()
        return result
    }
    static func snapshot() throws -> VaultData {
        lock.lock(); defer { lock.unlock() }; return try read()
    }
    static func edit(_ mutation: (inout VaultData) throws -> Void) throws {
        lock.lock(); defer { lock.unlock() }
        var vault = try read()
        try mutation(&vault)
        try vault.validate()
        let data = try JSONEncoder().encode(vault)
        guard data.count <= 8 * 1024 * 1024 else { throw AppError.message("Profile storage limit reached") }
        let attributes: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        var status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound { status = SecItemAdd(query.merging(attributes) { _, new in new } as CFDictionary, nil) }
        guard status == errSecSuccess else { throw AppError.message("Cannot store profile in Keychain") }
    }
    static func load() throws -> Data {
        guard let profile = try snapshot().active else { throw AppError.message("Select a profile first") }
        return Data(profile.content.utf8)
    }
}
