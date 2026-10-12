import Foundation
import BackgroundTasks

private final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
struct PortalClient {
    let session: PortalSession
    private let configuration: URLSessionConfiguration
    init(session: PortalSession, configuration: URLSessionConfiguration = .ephemeral) {
        self.session = session; self.configuration = configuration
    }
    static func origin(_ input: String) throws -> String {
        guard var c = URLComponents(string: input.trimmingCharacters(in: .whitespacesAndNewlines)),
              c.scheme?.lowercased() == "https", let host = c.host, !host.isEmpty,
              c.user == nil, c.password == nil, c.query == nil, c.fragment == nil,
              (c.path.isEmpty || c.path == "/"), c.port != 0 else { throw AppError.message(tr("Enter an HTTPS origin without a path", "Введите HTTPS-адрес без пути и параметров")) }
        c.scheme = "https"; c.path = ""
        guard let value = c.string else { throw AppError.message("Invalid portal URL") }
        return value
    }
    static func identifier(_ value: String, max: Int = 80) throws -> String {
        guard !value.isEmpty, value.utf8.count <= max, value.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95 }) else { throw AppError.message("Invalid portal identifier") }
        return value
    }
    func request(_ path: String, body: [String: Any]? = nil) async throws -> [String: Any] {
        guard path.hasPrefix("/portal/v2/"), !path.contains("..") else { throw AppError.message("Invalid portal path") }
        let origin = try Self.origin(session.origin)
        guard let url = URL(string: origin + path) else { throw AppError.message("Invalid portal URL") }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if !session.token.isEmpty {
            _ = try Self.identifier(session.token, max: 128)
            guard session.token.count >= 40 else { throw AppError.message("Invalid portal token") }
            request.setValue("Bearer " + session.token, forHTTPHeaderField: "Authorization")
        }
        if let body {
            let data = try JSONSerialization.data(withJSONObject: body)
            guard data.count <= 2 * 1024 * 1024 else { throw AppError.message("Request too large") }
            request.httpMethod = "POST"; request.httpBody = data
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let configuration = self.configuration.copy() as! URLSessionConfiguration
        configuration.httpCookieStorage = nil; configuration.urlCache = nil
        configuration.timeoutIntervalForResource = 30
        let transport = URLSession(configuration: configuration, delegate: NoRedirects(), delegateQueue: nil)
        defer { transport.invalidateAndCancel() }
        let (bytes, response) = try await transport.bytes(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            var message = code == 401 ? tr("Portal registration expired", "Регистрация на сервере истекла") : tr("Portal request failed", "Ошибка запроса к серверу")
            if code == 409 {
                // At most 512 bytes, used only to classify the conflict; never shown or logged.
                var body = Data()
                do {
                    for try await byte in bytes {
                        guard body.count < 512 else { body.removeAll(); break }
                        body.append(byte)
                    }
                } catch { body.removeAll() }
                message = Self.conflictMessage(body) ?? message
            }
            throw NSError(domain: "RTrustPortal", code: code, userInfo: [NSLocalizedDescriptionKey: message])
        }
        guard response.expectedContentLength <= 2 * 1024 * 1024 else { throw AppError.message("Response too large") }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 2 * 1024 * 1024 else { throw AppError.message("Response too large") }
            data.append(byte)
        }
        try Task.checkCancellation()
        guard let result = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw AppError.message("Invalid portal response") }
        return result
    }
    /// Exact server `detail` values for device profile limits; any other 409 keeps the generic text.
    static func conflictMessage(_ body: Data) -> String? {
        guard let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any], let detail = object["detail"] as? String else { return nil }
        switch detail {
        case "Too many profiles for client sync":
            return tr("The portal assigns more than 64 profiles to this device. Sync stopped; local profiles are preserved. Remove extra profiles from this device on the portal.",
                      "На портале назначено больше 64 профилей для этого устройства. Синхронизация остановлена, локальные профили сохранены. Снимите лишние профили с устройства на портале.")
        case "Device profile limit reached (64)":
            return tr("Limit of 64 profiles per device reached", "Достигнут лимит 64 профиля на устройство")
        default: return nil
        }
    }
    static func enroll(origin: String, code: String, name: String) async throws -> PortalSession {
        let origin = try Self.origin(origin)
        let client = Self(session: PortalSession(origin: origin, token: ""))
        let capabilities = try await client.request("/portal/v2/capabilities")
        guard capabilities["version"] as? Int == 2, !code.isEmpty, code.count <= 512, !name.isEmpty, name.count <= 80 else { throw AppError.message("Invalid enrollment") }
        let response = try await client.request("/portal/v2/enroll", body: ["code": code, "name": name, "platform": "ios"])
        guard let token = response["token"] as? String, token.count >= 40, (response["device_id"] as? Int ?? 0) > 0, (response["expires_in"] as? Int ?? 0) > 0 else { throw AppError.message("Invalid enrollment response") }
        _ = try identifier(token, max: 128)
        return PortalSession(origin: origin, token: token)
    }
    struct Metadata: Equatable {
        let revision: String
        let origin: String?
        /// Byte comparison, like Java `String.equals`; Swift `==` would merge canonically equivalent strings.
        static func == (a: Self, b: Self) -> Bool { sameBytes(a.revision, b.revision) && sameBytes(a.origin, b.origin) }
    }
    static func sameBytes(_ a: String?, _ b: String?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (a?, b?): return a.utf8.elementsEqual(b.utf8)
        default: return false
        }
    }
    /// Same policy as Android `PortalClient.originLabel`: 1...80 printable ASCII (0x20-0x7E).
    static func originLabel(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 80 && value.utf8.allSatisfy { (0x20...0x7E).contains($0) }
    }
    static func metadata(_ response: [String: Any]) throws -> [String: Metadata] {
        guard let profiles = response["profiles"] as? [[String: Any]], profiles.count <= 64 else { throw AppError.message("Invalid profile list") }
        var result: [String: Metadata] = [:]
        for item in profiles {
            guard let id = item["id"] as? String, let revision = item["revision"] as? String,
                  !revision.isEmpty, revision.utf8.count <= 256,
                  revision.utf8.allSatisfy({ (33...126).contains($0) }) else { throw AppError.message("Invalid profile metadata") }
            _ = try identifier(id)
            var origin: String?
            if let rawOrigin = item["origin"], !(rawOrigin is NSNull) {
                guard let value = rawOrigin as? String, originLabel(value) else { throw AppError.message("Invalid profile metadata") }
                origin = value
            }
            guard result[id] == nil else { throw AppError.message("Duplicate profile identifier") }
            result[id] = Metadata(revision: revision, origin: origin)
        }
        return result
    }
    func download() async throws -> [SavedProfile] {
        let before = try Self.metadata(try await request("/portal/v2/profiles"))
        var result: [SavedProfile] = []
        for id in before.keys.sorted() {
            try Task.checkCancellation()
            let revision = before[id]!.revision
            let response = try await request("/portal/v2/profiles/" + id + "/export", body: ["format":"profile_json", "revision":revision, "include_secrets":true, "accept_losses":false])
            guard let content = response["content"] as? String else { throw AppError.message("Invalid profile export") }
            var profile = SavedProfile.imported(try ProfilePlan.parse(Data(content.utf8)), id: "portal:" + id)
            profile.remoteID = id; profile.revision = revision
            result.append(profile)
        }
        try Task.checkCancellation()
        let after = try Self.metadata(try await request("/portal/v2/profiles"))
        try Task.checkCancellation()
        guard before == after else { throw AppError.message("Profile list changed during synchronization") }
        return result
    }
    func upload(_ profile: SavedProfile) async throws {
        let preview = try await request("/portal/v2/profile-imports/preview", body: ["intent":"external_stored", "content":profile.content])
        guard let id = preview["preview_id"] as? String else { throw AppError.message("Invalid import response") }
        _ = try Self.identifier(id)
        _ = try await request("/portal/v2/profile-imports/" + id + "/commit", body: ["action":"create", "consent":true])
    }
}
enum PortalSync {
    static var identifier: String { (Bundle.main.bundleIdentifier ?? "org.rtrusttunnel.ios") + ".portal-sync" }
    static func run(background: Bool) async throws { try await PortalSyncRunner.shared.run(background: background) }
    /// Pure commit step run inside `ProfileVault.edit`: replaces managed profiles and keeps local ones.
    /// Returns false without touching `vault` when the registration changed or background sync was disabled.
    @discardableResult
    static func apply(_ vault: inout VaultData, session: PortalSession, remote: [SavedProfile], background: Bool, now: Date) -> Bool {
        guard let current = vault.portal, PortalClient.sameBytes(current.origin, session.origin),
              PortalClient.sameBytes(current.token, session.token), !background || current.backgroundSync else { return false }
        vault.profiles = vault.profiles.filter { $0.remoteID == nil } + remote
        vault.repairSelection()
        vault.portal?.lastSync = now; vault.portal?.authExpired = false
        return true
    }
    /// Dependencies are injectable only for synthetic tests; production uses the Keychain vault.
    static func perform(background: Bool,
                        client: (PortalSession) -> PortalClient = { PortalClient(session: $0) },
                        snapshot: () throws -> VaultData = { try ProfileVault.snapshot() },
                        edit: ((inout VaultData) throws -> Void) throws -> Void = { try ProfileVault.edit($0) },
                        now: () -> Date = { Date() }) async throws {
        guard let session = try snapshot().portal, !background || session.backgroundSync else { return }
        do {
            let remote = try await client(session).download()
            try Task.checkCancellation()
            let committed = now()
            try edit { vault in apply(&vault, session: session, remote: remote, background: background, now: committed) }
        } catch {
            if (error as NSError).domain == "RTrustPortal", (error as NSError).code == 401 {
                try? edit { vault in
                    if let current = vault.portal, PortalClient.sameBytes(current.origin, session.origin),
                       PortalClient.sameBytes(current.token, session.token) {
                        vault.portal?.backgroundSync = false; vault.portal?.authExpired = true
                    }
                }
            }
            throw error
        }
    }
    static func schedule() {
        BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: identifier)
        guard (try? ProfileVault.snapshot().portal?.backgroundSync) == true else { return }
        let task = BGAppRefreshTaskRequest(identifier: identifier)
        task.earliestBeginDate = Date().addingTimeInterval(3600)
        try? BGTaskScheduler.shared.submit(task)
    }
    static func register() {
        BGTaskScheduler.shared.register(forTaskWithIdentifier: identifier, using: nil) { task in
            let work = Task {
                var success = false
                do { try await run(background: true); success = true } catch { }
                schedule()
                task.setTaskCompleted(success: success)
            }
            task.expirationHandler = { work.cancel() }
        }
    }
}

private actor PortalSyncRunner {
    static let shared = PortalSyncRunner()
    private var running = false
    func run(background: Bool) async throws {
        guard !running else { throw AppError.message("Synchronization already running") }
        running = true; defer { running = false }
        try await PortalSync.perform(background: background)
    }
}
