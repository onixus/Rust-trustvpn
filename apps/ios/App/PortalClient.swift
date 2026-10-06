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
            throw NSError(domain: "RTrustPortal", code: code, userInfo: [NSLocalizedDescriptionKey: code == 401 ? tr("Portal registration expired", "Регистрация на сервере истекла") : tr("Portal request failed", "Ошибка запроса к серверу")])
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
    func download() async throws -> [SavedProfile] {
        let response = try await request("/portal/v2/profiles")
        guard let metadata = response["profiles"] as? [[String: Any]], metadata.count <= 64 else { throw AppError.message("Invalid profile list") }
        var result: [SavedProfile] = []
        for item in metadata {
            guard let id = item["id"] as? String, let revision = item["revision"] as? String, !revision.isEmpty, revision.count <= 256 else { throw AppError.message("Invalid profile metadata") }
            _ = try Self.identifier(id)
            let response = try await request("/portal/v2/profiles/" + id + "/export", body: ["format":"profile_json", "revision":revision, "include_secrets":true, "accept_losses":false])
            guard let content = response["content"] as? String else { throw AppError.message("Invalid profile export") }
            var profile = SavedProfile.imported(try ProfilePlan.parse(Data(content.utf8)), id: "portal:" + id)
            profile.remoteID = id; profile.revision = revision
            result.append(profile)
        }
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
    static func perform(background: Bool) async throws {
        guard let session = try ProfileVault.snapshot().portal, !background || session.backgroundSync else { return }
        do {
            let remote = try await PortalClient(session: session).download()
            try Task.checkCancellation()
            try ProfileVault.edit { vault in
                guard vault.portal?.origin == session.origin, vault.portal?.token == session.token,
                      !background || vault.portal?.backgroundSync == true else { return }
                vault.profiles = vault.profiles.filter { $0.remoteID == nil } + remote
                vault.repairSelection()
                vault.portal?.lastSync = Date(); vault.portal?.authExpired = false
            }
        } catch {
            if (error as NSError).domain == "RTrustPortal", (error as NSError).code == 401 {
                try? ProfileVault.edit { vault in
                    if vault.portal?.origin == session.origin && vault.portal?.token == session.token {
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
