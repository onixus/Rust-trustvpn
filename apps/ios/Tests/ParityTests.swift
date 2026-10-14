import XCTest
import CoreImage
import UIKit
import NetworkExtension
@testable import RTrustTunnel

final class FixtureProtocol: URLProtocol {
    typealias Handler = @Sendable (URLRequest) throws -> (Int, Data)
    /// Lock-protected so handlers can be swapped from tests while URL loading threads read them.
    private final class Box: @unchecked Sendable {
        let lock = NSLock()
        var handler: Handler?
    }
    private static let box = Box()
    static var handler: Handler? {
        get { box.lock.lock(); defer { box.lock.unlock() }; return box.handler }
        set { box.lock.lock(); box.handler = newValue; box.lock.unlock() }
    }
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "fixture.invalid" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            guard let handler = Self.handler else { throw URLError(.resourceUnavailable) }
            let (status, data) = try handler(request)
            let response = HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: "HTTP/1.1", headerFields: ["Content-Type":"application/json"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch { client?.urlProtocol(self, didFailWithError: error) }
    }
    override func stopLoading() {}
}
final class ParityTests: XCTestCase {
    let raw = "hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='ios-test-canary'\n"
    func testCodecExportPreservesCredentialsAndPolicy() throws {
        let plan = try ProfilePlan.parse(Data(raw.utf8))
        for format: Int32 in [0,1,2,3] {
            let result = try ProfilePlan.export(plan.profile!, format: format)
            // CLI export intentionally carries a policy; re-import validates it.
            let restored = try ProfilePlan.parse(Data(result.content!.utf8))
            XCTAssertTrue(restored.profile!.contains("ios-test-canary"))
        }
        XCTAssertThrowsError(try ProfilePlan.parse(Data("password='ios-test-canary'".utf8))) { error in
            XCTAssertFalse(error.localizedDescription.contains("canary"))
        }
    }
    func testQRImageDecodesLocallyAndRejectsInvalidData() throws {
        let payload = "hy2://synthetic@192.0.2.1:443/?sni=test.example"
        let filter = CIFilter(name: "CIQRCodeGenerator", parameters: ["inputMessage": Data(payload.utf8), "inputCorrectionLevel":"M"])!
        let image = filter.outputImage!.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
        let cg = CIContext().createCGImage(image, from: image.extent)!
        // QR codes require a quiet zone of at least four modules.
        let data = UIGraphicsImageRenderer(size: CGSize(width: cg.width + 64, height: cg.height + 64)).pngData { context in
            UIColor.white.setFill()
            context.fill(CGRect(x: 0, y: 0, width: cg.width + 64, height: cg.height + 64))
            context.cgContext.interpolationQuality = .none
            UIImage(cgImage: cg).draw(at: CGPoint(x: 32, y: 32))
        }
        XCTAssertEqual(try QRImage.decode(data), payload)
        XCTAssertThrowsError(try QRImage.decode(Data("not an image".utf8)))
    }
    func testSelectionRepairAndCorruptVaultRejection() throws {
        let profile = SavedProfile.imported(try ProfilePlan.parse(Data(raw.utf8)), id: "local")
        var vault = VaultData(profiles: [profile], selected: "missing")
        XCTAssertThrowsError(try vault.validate())
        vault.repairSelection(); XCTAssertEqual(vault.selected, "local"); try vault.validate()
        vault.profiles.append(profile); XCTAssertThrowsError(try vault.validate())
        vault.profiles = []; vault.repairSelection(); XCTAssertNil(vault.selected); try vault.validate()
    }
    func testAppSelectionAndWidgetDefaultRemainIndependent() throws {
        let first = SavedProfile.imported(try ProfilePlan.parse(Data(raw.utf8)), id: "first")
        let second = SavedProfile.imported(try ProfilePlan.parse(Data(raw.utf8)), id: "second")
        var vault = VaultData(profiles: [first, second], selected: "second", defaultProfileID: "first")
        XCTAssertEqual(try vault.connectionProfile(id: vault.selected).id, "second")
        XCTAssertEqual(try vault.connectionProfile(id: nil).id, "first")
        vault.profiles.removeLast(); vault.repairSelection()
        XCTAssertThrowsError(try vault.connectionProfile(id: "second"))
        XCTAssertEqual(try vault.connectionProfile(id: nil).id, "first")
    }
    func testOriginRejectsCredentialAndPathConfusion() throws {
        for url in ["http://example.com", "https://user:secret@example.com", "https://example.com/path", "https://example.com?token=secret", "https://example.com#fragment", "https://example.com:0"] {
            XCTAssertThrowsError(try PortalClient.origin(url))
        }
        XCTAssertEqual(try PortalClient.origin("https://example.com/"), "https://example.com")
        XCTAssertThrowsError(try PortalClient.identifier("../secret"))
    }
    func testPortalDownloadRevisionAndSanitizedFailure() async throws {
        let config = URLSessionConfiguration.ephemeral; config.protocolClasses = [FixtureProtocol.self]
        let token = String(repeating: "a", count: 40)
        let client = PortalClient(session: PortalSession(origin: "https://fixture.invalid", token: token), configuration: config)
        let raw = self.raw
        FixtureProtocol.handler = { request in
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer " + token)
            if request.url!.path == "/portal/v2/profiles" {
                return (200, Data("{\"profiles\":[{\"id\":\"one\",\"revision\":\"r1\"}]}".utf8))
            }
            XCTAssertEqual(request.url!.path, "/portal/v2/profiles/one/export")
            XCTAssertEqual(request.httpMethod, "POST")
            return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
        }
        let profiles = try await client.download()
        XCTAssertEqual(profiles.count, 1); XCTAssertEqual(profiles.first?.remoteID, "one"); XCTAssertEqual(profiles.first?.revision, "r1")
        FixtureProtocol.handler = { _ in (401, Data("secret-token".utf8)) }
        do { _ = try await client.download(); XCTFail("401 accepted") } catch {
            XCTAssertEqual((error as NSError).code, 401); XCTAssertFalse(error.localizedDescription.contains("secret-token"))
        }
        FixtureProtocol.handler = { _ in (302, Data()) }
        do { _ = try await client.download(); XCTFail("redirect accepted") } catch { XCTAssertEqual((error as NSError).code, 302) }
        FixtureProtocol.handler = { _ in (409, Data("{\"detail\":\"Too many profiles for client sync\"}".utf8)) }
        do { _ = try await client.download(); XCTFail("409 accepted") } catch {
            XCTAssertEqual((error as NSError).code, 409)
            XCTAssertEqual(error.localizedDescription, PortalClient.conflictMessage(Data("{\"detail\":\"Too many profiles for client sync\"}".utf8)))
            XCTAssertTrue(error.localizedDescription.contains("64")); XCTAssertFalse(error.localizedDescription.contains("Too many"))
        }
        FixtureProtocol.handler = { _ in (409, Data("{\"detail\":\"Profile revision conflict\"}".utf8)) }
        do { _ = try await client.download(); XCTFail("409 accepted") } catch {
            XCTAssertEqual((error as NSError).code, 409)
            XCTAssertEqual(error.localizedDescription, PortalClient.conflictMessage(Data()))
            XCTAssertFalse(error.localizedDescription.contains("revision conflict"))
        }
        FixtureProtocol.handler = nil
    }
    func testPortalLimitConflictClassification() {
        let revision = PortalClient.conflictMessage(Data())
        let sync = PortalClient.conflictMessage(Data("{\"detail\":\"Too many profiles for client sync\"}".utf8))
        let device = PortalClient.conflictMessage(Data("{\"detail\":\"Device profile limit reached (64)\"}".utf8))
        XCTAssertEqual(Set([revision, sync, device]).count, 3)
        XCTAssertEqual(revision, tr("The profile changed on the portal. Sync again and retry. Local data is preserved.",
                                    "Профиль изменился на портале. Синхронизируйте список и повторите. Локальные данные сохранены."))
        for body in ["{\"detail\":\"Profile revision conflict\"}", "{\"detail\":\"too many profiles for client sync\"}", "{\"detail\":[\"Too many profiles for client sync\"]}", "Too many profiles for client sync", ""] {
            XCTAssertEqual(PortalClient.conflictMessage(Data(body.utf8)), revision, body)
        }
    }
}

@MainActor
private final class StartConfigurationFixture: VPNStartConfiguration {
    var isEnabled = false
    var events: [String] = []
    var failure: String?
    var startedProfileID: String?
    func step(_ event: String) throws {
        events.append(event)
        if failure == event { throw NSError(domain: "Fixture", code: 1) }
    }
    func saveToPreferences() async throws {
        XCTAssertTrue(isEnabled, "Re-enable the VPN before saving")
        try step("save")
    }
    func loadFromPreferences() async throws { try step("load") }
    func startTunnel(profileID: String?) throws { startedProfileID = profileID; try step("start") }
}

extension ParityTests {
    @MainActor
    func testDisconnectRemainsAvailableAfterProfilesDisappear() throws {
        let profile = SavedProfile.imported(try ProfilePlan.parse(Data(raw.utf8)), id: "remote")
        var vault = VaultData(profiles: [profile], selected: "remote")
        vault.profiles = []
        vault.repairSelection()
        for status: NEVPNStatus in [.connected, .connecting, .reasserting, .disconnecting] {
            XCTAssertTrue(VPNController.canToggle(active: VPNController.isActive(status), hasProfile: vault.active != nil, busy: false, supported: true))
        }
        XCTAssertFalse(VPNController.canToggle(active: false, hasProfile: false, busy: false, supported: true))
        XCTAssertTrue(VPNController.canToggle(active: false, hasProfile: true, busy: false, supported: true))
        XCTAssertFalse(VPNController.canToggle(active: true, hasProfile: false, busy: true, supported: true))
        XCTAssertFalse(VPNController.canToggle(active: true, hasProfile: true, busy: false, supported: false))
    }

    @MainActor
    func testStartReenablesDisabledConfigurationBeforeStarting() async throws {
        let configuration = StartConfigurationFixture()
        try await VPNController.start(configuration)
        XCTAssertTrue(configuration.isEnabled)
        XCTAssertEqual(configuration.events, ["save", "load", "start"])
    }

    @MainActor
    func testAppStartPassesSelectedIDAndWidgetStartOmitsIt() async throws {
        let app = StartConfigurationFixture()
        try await VPNController.start(app, profileID: "second")
        XCTAssertEqual(app.startedProfileID, "second")
        let widget = StartConfigurationFixture()
        try await VPNController.start(widget)
        XCTAssertNil(widget.startedProfileID)
    }
    @MainActor
    func testStartDoesNotContinueAfterPreferenceFailure() async {
        for failure in ["save", "load"] {
            let configuration = StartConfigurationFixture()
            configuration.failure = failure
            do {
                try await VPNController.start(configuration)
                XCTFail("Preference failure must prevent starting")
            } catch {
                XCTAssertEqual(configuration.events, failure == "save" ? ["save"] : ["save", "load"])
            }
        }
    }
}


/// Lock-protected fixture state: URLProtocol handlers run on URL loading threads.
final class FixtureCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var counts: [String: Int] = [:]
    func next(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; counts[key, default: 0] += 1; return counts[key]! }
    subscript(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; return counts[key, default: 0] }
}
/// Parks a fixture request until the test has cancelled the surrounding Task.
final class FixtureGate: @unchecked Sendable {
    private let lock = NSLock()
    private var hasArrived = false
    private let released = DispatchSemaphore(value: 0)
    func arriveAndWait() {
        lock.lock(); hasArrived = true; lock.unlock()
        _ = released.wait(timeout: .now() + 10)
    }
    var arrived: Bool { lock.lock(); defer { lock.unlock() }; return hasArrived }
    func open() { released.signal() }
}
/// In-memory stand-in for the Keychain vault with the same read/mutate/validate/write order.
final class FixtureVault: @unchecked Sendable {
    private let lock = NSLock()
    private var data: VaultData
    init(_ data: VaultData) { self.data = data }
    func snapshot() -> VaultData { lock.lock(); defer { lock.unlock() }; return data }
    func edit(_ mutation: (inout VaultData) throws -> Void) throws {
        lock.lock(); defer { lock.unlock() }
        var vault = data
        try mutation(&vault)
        try vault.validate()
        data = vault
    }
    func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        return try encoder.encode(snapshot())
    }
}

extension ParityTests {
    static let fixtureToken = String(repeating: "a", count: 40)
    static func fixtureClient(_ session: PortalSession) -> PortalClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        return PortalClient(session: session, configuration: config)
    }
    /// Local profile plus a stale managed profile; background sync enabled.
    static func fixtureVault(selected: String = "portal:old") -> FixtureVault {
        let local = SavedProfile(id: "local", name: "local", hostname: "local.invalid", content: "synthetic-local")
        let old = SavedProfile(id: "portal:old", name: "old", hostname: "old.invalid", content: "synthetic-old", remoteID: "old", revision: "r0")
        return FixtureVault(VaultData(profiles: [local, old], selected: selected, defaultProfileID: selected,
                                      portal: PortalSession(origin: "https://fixture.invalid", token: fixtureToken, backgroundSync: true, authExpired: true)))
    }
    static func sync(_ vault: FixtureVault, background: Bool) async throws {
        try await PortalSync.perform(background: background, client: { fixtureClient($0) },
                                     snapshot: { vault.snapshot() }, edit: { try vault.edit($0) },
                                     now: { Date(timeIntervalSince1970: 42) })
    }
    static func listResponse(_ profiles: [[String: Any]]) throws -> (Int, Data) {
        (200, try JSONSerialization.data(withJSONObject: ["profiles": profiles]))
    }

    func testPortalWholeBatchFenceSequences() async throws {
        let client = Self.fixtureClient(PortalSession(origin: "https://fixture.invalid", token: Self.fixtureToken))
        let initial: [[String: Any]] = [["id": "one", "revision": "r1", "origin": "portal_managed"], ["id": "two", "revision": "r1"]]
        let reordered: [[String: Any]] = [["id": "two", "revision": "r1", "origin": NSNull()], initial[0]]
        let duplicate: [[String: Any]] = [initial[0], initial[0]]
        let changedRevision: [[String: Any]] = [["id": "one", "revision": "r2", "origin": "portal_managed"], initial[1]]
        let changedOrigin: [[String: Any]] = [["id": "one", "revision": "r1", "origin": "external_stored"], initial[1]]
        let added = initial + [["id": "three", "revision": "r1"]]
        let cases: [([[String: Any]], [[String: Any]], Bool)] = [
            (initial, initial, true), (initial, reordered, true), ([], [], true),
            (initial, changedRevision, false), (initial, changedOrigin, false),
            (initial, added, false), (initial, [], false), (initial, duplicate, false),
            (duplicate, initial, false), (initial, [["id": "one", "revision": 12]], false)
        ]
        defer { FixtureProtocol.handler = nil }
        let raw = self.raw
        for (before, after, succeeds) in cases {
            let counter = FixtureCounter()
            let first = try Self.listResponse(before), second = try Self.listResponse(after)
            FixtureProtocol.handler = { request in
                if request.url!.path == "/portal/v2/profiles" { return counter.next("lists") == 1 ? first : second }
                _ = counter.next("exports")
                return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
            }
            do {
                let downloaded = try await client.download()
                XCTAssertTrue(succeeds, "Changed list accepted")
                XCTAssertEqual(downloaded.count, before.count)
            } catch { XCTAssertFalse(succeeds, "Stable list rejected") }
            if before.count == 2, before[0]["id"] as? String == before[1]["id"] as? String {
                XCTAssertEqual(counter["exports"], 0, "Initial duplicates rejected before exports")
            } else { XCTAssertEqual(counter["lists"], 2, "Recheck includes empty lists") }
        }
    }
    /// Shared with Android PortalClientTest.originPolicy: identical inputs and expectations.
    func testPortalOriginLabelPolicy() throws {
        let rejected = ["", "\u{200B}", "portal\u{200B}managed", "\u{202E}portal", "\u{0085}", "\u{007F}", "\u{FEFF}portal",
                        "line\n", "\u{00E9}", String(repeating: "x", count: 81)]
        let accepted = ["portal_managed", "external_stored", "future source", "~", String(repeating: "x", count: 80)]
        for origin in rejected {
            XCTAssertFalse(PortalClient.originLabel(origin), "origin rejected: \(origin.unicodeScalars.map { String($0.value, radix: 16) })")
            XCTAssertThrowsError(try PortalClient.metadata(["profiles": [["id": "one", "revision": "r1", "origin": origin]]]))
        }
        for origin in accepted {
            XCTAssertTrue(PortalClient.originLabel(origin), "origin accepted: \(origin)")
            XCTAssertEqual(try PortalClient.metadata(["profiles": [["id": "one", "revision": "r1", "origin": origin]]])["one"]?.origin, origin)
        }
        XCTAssertThrowsError(try PortalClient.metadata(["profiles": [["id": "one", "revision": "r1", "origin": 12]]]))
        // Byte comparison like Java String.equals: canonically equivalent strings differ.
        XCTAssertNotEqual(PortalClient.Metadata(revision: "r1", origin: "\u{00E9}"), PortalClient.Metadata(revision: "r1", origin: "e\u{0301}"))
        XCTAssertEqual(PortalClient.Metadata(revision: "r1", origin: nil), PortalClient.Metadata(revision: "r1", origin: nil))
        XCTAssertNotEqual(PortalClient.Metadata(revision: "r1", origin: nil), PortalClient.Metadata(revision: "r1", origin: "portal_managed"))
    }
    func testPortalMalformedMetadataAndUnknownOrigin() throws {
        for revision in ["", "has space", "line\n", "é", String(repeating: "x", count: 257)] {
            XCTAssertThrowsError(try PortalClient.metadata(["profiles": [["id": "one", "revision": revision]]]))
        }
        let missing = try PortalClient.metadata(["profiles": [["id": "one", "revision": "r1"]]])
        let null = try PortalClient.metadata(["profiles": [["id": "one", "revision": "r1", "origin": NSNull()]]])
        XCTAssertEqual(missing, null)
        XCTAssertNil(missing["one"]?.origin)
        let future = try PortalClient.metadata(["profiles": [["id": "one", "revision": "r1", "origin": "future_source"]]])
        XCTAssertEqual(future["one"]?.origin, "future_source")
    }
}


extension ParityTests {
    /// Failure points through the production PortalSync.perform: vault keeps managed and local profiles.
    func testPortalFailedSyncKeepsVault() async throws {
        defer { FixtureProtocol.handler = nil }
        let raw = self.raw
        let stable = try Self.listResponse([["id": "one", "revision": "r1"], ["id": "two", "revision": "r1"]])
        let rotated = try Self.listResponse([["id": "one", "revision": "r2"], ["id": "two", "revision": "r1"]])
        // 0 first export, 1 mid-batch export, 2 recheck I/O, 3 recheck changed.
        for mode in 0..<4 {
            let vault = Self.fixtureVault()
            let original = try vault.encoded()
            let counter = FixtureCounter()
            FixtureProtocol.handler = { request in
                if request.url!.path == "/portal/v2/profiles" {
                    let list = counter.next("lists")
                    if list == 2 && mode == 2 { throw URLError(.timedOut) }
                    return list == 2 && mode == 3 ? rotated : stable
                }
                let export = counter.next("exports")
                if (export == 1 && mode == 0) || (export == 2 && mode == 1) { throw URLError(.networkConnectionLost) }
                return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
            }
            do { try await Self.sync(vault, background: true); XCTFail("Failed batch committed, mode \(mode)") } catch { }
            XCTAssertEqual(try vault.encoded(), original, "Vault unchanged, mode \(mode)")
            XCTAssertEqual(vault.snapshot().profiles.map(\.id), ["local", "portal:old"])
        }
    }
    /// Registration replaced, disabled or removed while the batch was downloading.
    func testPortalRegistrationFence() async throws {
        defer { FixtureProtocol.handler = nil }
        let raw = self.raw
        let stable = try Self.listResponse([["id": "one", "revision": "r1"]])
        for change in ["token", "disabled", "removed"] {
            for background in [true, false] {
                let vault = Self.fixtureVault(selected: "local")
                FixtureProtocol.handler = { request in
                    if request.url!.path == "/portal/v2/profiles" { return stable }
                    try vault.edit { data in
                        switch change {
                        case "token": data.portal?.token = String(repeating: "b", count: 40)
                        case "disabled": data.portal?.backgroundSync = false
                        default: data.portal = nil
                        }
                    }
                    return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
                }
                try await Self.sync(vault, background: background)
                // Foreground sync is user-initiated and ignores the background toggle (unchanged semantics).
                if !background && change == "disabled" {
                    XCTAssertEqual(vault.snapshot().profiles.map(\.id), ["local", "portal:one"])
                } else {
                    XCTAssertEqual(vault.snapshot().profiles.map(\.id), ["local", "portal:old"], "\(change) background=\(background)")
                    XCTAssertNil(vault.snapshot().portal?.lastSync)
                }
            }
        }
    }
    func testPortalSuccessfulSyncReplacesManagedKeepsLocal() async throws {
        defer { FixtureProtocol.handler = nil }
        let raw = self.raw
        let stable = try Self.listResponse([["id": "two", "revision": "r1"], ["id": "one", "revision": "r1"]])
        FixtureProtocol.handler = { request in
            if request.url!.path == "/portal/v2/profiles" { return stable }
            return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
        }
        let vault = Self.fixtureVault()
        try await Self.sync(vault, background: true)
        let data = vault.snapshot()
        XCTAssertEqual(data.profiles.map(\.id), ["local", "portal:one", "portal:two"])
        XCTAssertEqual(data.defaultProfileID, "local"); XCTAssertEqual(data.selected, "local")
        XCTAssertEqual(data.portal?.lastSync, Date(timeIntervalSince1970: 42)); XCTAssertEqual(data.portal?.authExpired, false)
    }
    /// A real Task is cancelled while an export or the recheck list is in flight.
    func testPortalTaskCancellationDuringExportAndRecheck() async throws {
        defer { FixtureProtocol.handler = nil }
        let raw = self.raw
        let stable = try Self.listResponse([["id": "one", "revision": "r1"], ["id": "two", "revision": "r1"]])
        for duringRecheck in [false, true] {
            let vault = Self.fixtureVault()
            let original = try vault.encoded()
            let counter = FixtureCounter(), gate = FixtureGate()
            FixtureProtocol.handler = { request in
                if request.url!.path == "/portal/v2/profiles" {
                    if counter.next("lists") == 2 && duringRecheck { gate.arriveAndWait() }
                    return stable
                }
                if counter.next("exports") == 1 && !duringRecheck { gate.arriveAndWait() }
                return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
            }
            let task = Task { try await Self.sync(vault, background: true) }
            let deadline = Date().addingTimeInterval(10)
            while !gate.arrived && Date() < deadline { try await Task.sleep(nanoseconds: 1_000_000) }
            XCTAssertTrue(gate.arrived, "Fixture request reached")
            task.cancel()
            gate.open()
            do {
                try await task.value
                XCTFail("Cancelled sync committed")
            } catch {
                // Task.checkCancellation throws CancellationError; URLSession may surface the same cancel as URLError.cancelled.
                XCTAssertTrue(error is CancellationError || (error as? URLError)?.code == .cancelled, "Unexpected error \(error)")
            }
            XCTAssertEqual(try vault.encoded(), original, "Vault unchanged, recheck=\(duringRecheck)")
            if !duringRecheck { XCTAssertEqual(counter["exports"], 1, "No export after cancellation") }
            XCTAssertLessThanOrEqual(counter["lists"], 2)
        }
    }
}

/// UI variant 3: the presentation must stay honest about what was observed.
final class StateModelTests: XCTestCase {
    private let now: Double = 1_000_000
    private func check(_ outcome: String, age: Double = 1000, ttl: Double = 6000) -> [String: Any] {
        ["outcome": outcome, "observed_at_ms": NSNumber(value: now - age), "valid_for_ms": NSNumber(value: ttl), "reason": "session_running"]
    }
    private func snapshot(_ outcomes: [String: [String: Any]]) -> [String: Any] {
        var value: [String: Any] = ["schema": 2]
        for (key, observation) in outcomes { value[key] = observation }
        return value
    }
    func testGreenOnlyWhenEveryCheckPassedAndFresh() {
        let all = Dictionary(uniqueKeysWithValues: ObservationStatus.keys.map { ($0, check("passed")) })
        XCTAssertEqual(ObservationStatus.level(snapshot(all), nowMs: now), .verified)
        var stale = all; stale["dns"] = check("passed", age: 7000)
        XCTAssertEqual(ObservationStatus.level(snapshot(stale), nowMs: now), .running, "Expired pass is not green")
        var shortTTL = all; shortTTL["route"] = check("passed", age: 2000, ttl: 1000)
        XCTAssertEqual(ObservationStatus.level(snapshot(shortTTL), nowMs: now), .running, "TTL below 6 s is honoured")
        var future = all; future["guard"] = check("passed", age: -5000)
        XCTAssertEqual(ObservationStatus.level(snapshot(future), nowMs: now), .running, "Clock skew is not green")
        var missing = all; missing.removeValue(forKey: "connectivity")
        XCTAssertEqual(ObservationStatus.level(snapshot(missing), nowMs: now), .running, "Missing check is not passed")
        var configured = all; configured["transport"] = check("configured")
        XCTAssertEqual(ObservationStatus.level(snapshot(configured), nowMs: now), .running)
        var wrongSchema = snapshot(all); wrongSchema["schema"] = 1
        XCTAssertEqual(ObservationStatus.level(wrongSchema, nowMs: now), .running, "Unknown schema is ignored")
        XCTAssertEqual(ObservationStatus.level(nil, nowMs: now), .running)
    }
    func testFailedCheckIsWarningAndNamed() {
        let value = snapshot(["transport": check("configured"), "dns": check("failed"), "route": check("passed")])
        XCTAssertEqual(ObservationStatus.level(value, nowMs: now), .warning)
        XCTAssertEqual(ObservationStatus.firstFailed(value, nowMs: now), "dns")
    }
    func testTransportLevelNeverVerified() {
        for status: NEVPNStatus in [.invalid, .disconnected, .connecting, .connected, .reasserting, .disconnecting] {
            for failed in [false, true] {
                let level = TunnelLevel.transport(status, attemptFailed: failed)
                XCTAssertNotEqual(level, .verified); XCTAssertNotEqual(level, .warning)
            }
        }
        XCTAssertEqual(TunnelLevel.transport(.connected), .running)
        XCTAssertEqual(TunnelLevel.transport(.disconnected, attemptFailed: true), .error)
        XCTAssertEqual(TunnelLevel.transport(nil), .off)
        XCTAssertEqual(TunnelLevel.verified.tone, .green)
        XCTAssertEqual(TunnelLevel.running.tone, .blue)
    }
    func testRowsShowNoDataInsteadOfPassed() {
        let off = ObservationStatus.rows(status: .disconnected, level: .off, snapshot: nil, nowMs: now)
        XCTAssertEqual(off.map(\.id), ObservationStatus.keys)
        XCTAssertTrue(off.allSatisfy { $0.dot == .empty })
        // A snapshot is never rendered unless connected.
        let all = Dictionary(uniqueKeysWithValues: ObservationStatus.keys.map { ($0, check("passed")) })
        let connecting = ObservationStatus.rows(status: .connecting, level: .connecting, snapshot: snapshot(all), nowMs: now)
        XCTAssertEqual(connecting[0].dot, .ring(.blue))
        XCTAssertTrue(connecting.dropFirst().allSatisfy { $0.dot == .empty })
        let running = ObservationStatus.rows(status: .connected, level: .running,
                                             snapshot: snapshot(["transport": check("configured"), "route": check("passed", age: 9000)]), nowMs: now)
        XCTAssertEqual(running.map(\.dot), [.filled(.blue), .ring(.grey), .empty, .empty, .empty])
        let error = ObservationStatus.rows(status: .disconnected, level: .error, snapshot: nil, nowMs: now)
        XCTAssertEqual(error[0].dot, .filled(.red))
    }
    @MainActor
    func testOnlyAnUnrequestedEndOfAttemptIsAnError() {
        let model = VPNModel()
        VPNController.userStopped = false
        model.track(.connecting); model.track(.disconnected)
        XCTAssertTrue(model.attemptFailed)
        XCTAssertEqual(model.level, .error)
        model.track(.connecting); model.track(.connected)
        XCTAssertFalse(model.attemptFailed)
        VPNController.userStopped = true
        model.track(.disconnecting); model.track(.disconnected)
        XCTAssertFalse(model.attemptFailed, "A requested stop is not a failure")
        XCTAssertFalse(VPNController.userStopped, "The stop flag is consumed")
        model.track(.connected); model.track(.disconnected)
        XCTAssertFalse(model.attemptFailed, "A tunnel that was up and ended is shown as off, not as a failed attempt")
    }
    @MainActor
    func testReconnectThenExternalStopIsNotAFailedAttempt() {
        let model = VPNModel()
        VPNController.userStopped = false
        for status: NEVPNStatus in [.connecting, .connected, .reasserting, .disconnected] { model.track(status) }
        XCTAssertFalse(model.attemptFailed)
        XCTAssertEqual(model.level, .off)
    }
    @MainActor
    func testNoProfileNamedUnlessThisAppStartedIt() {
        let model = VPNModel()
        let office = SavedProfile(id: "a", name: "Synthetic Office", hostname: "office.invalid", content: "")
        let home = SavedProfile(id: "b", name: "Synthetic Home", hostname: "home.invalid", content: "")
        model.vault = VaultData(profiles: [office, home], selected: "a", defaultProfileID: "b")
        // Widget or On Demand start: no profile ID recorded by the app.
        model.track(.disconnected); model.recordStart(nil)
        for status: NEVPNStatus in [.connecting, .connected] {
            model.track(status)
            for text in [model.homeTag(model.level), model.homeDescription(model.level)] {
                XCTAssertFalse(text.contains("Synthetic"), text); XCTAssertFalse(text.contains(".invalid"), text)
            }
            XCTAssertNil(model.runningProfile)
        }
        model.track(.disconnected)
        // App start records the profile it passed; the name is shown and cleared on stop.
        model.recordStart("a"); model.track(.connecting)
        XCTAssertTrue(model.homeTag(model.level).contains("SYNTHETIC OFFICE"))
        XCTAssertTrue(model.homeDescription(model.level).contains("office.invalid"))
        model.track(.connected); model.track(.disconnected)
        XCTAssertNil(model.runningProfileID)
        model.track(.connecting)
        XCTAssertFalse(model.homeTag(model.level).contains("SYNTHETIC"))
    }
    @MainActor
    func testRestartOutsideTheAppClearsTheRecordedProfile() {
        let model = VPNModel()
        model.vault = VaultData(profiles: [SavedProfile(id: "a", name: "Synthetic Office", hostname: "office.invalid", content: "")],
                                selected: "a", defaultProfileID: "a")
        let first = Date(timeIntervalSince1970: 1_000), second = Date(timeIntervalSince1970: 2_000)
        model.track(.disconnected)
        model.recordStart("a"); model.track(.connecting)
        model.track(.connected, connectedDate: first)
        XCTAssertEqual(model.runningProfile?.id, "a")
        model.track(.connected, connectedDate: first)
        XCTAssertEqual(model.runningProfile?.id, "a", "Same session keeps the name")
        // Suspended app missed .disconnected; On Demand restarted with the default profile.
        model.track(.connected, connectedDate: second)
        XCTAssertNil(model.runningProfileID)
        XCTAssertFalse(model.homeTag(model.level).contains("SYNTHETIC"))
        model.recordStart("a"); model.track(.connected, connectedDate: first); model.track(.connected, connectedDate: nil)
        XCTAssertNil(model.runningProfileID, "A missing connected date is not proof of the same session")
    }
    func testLocalizationTablesHaveTheSameKeys() throws {
        let bundle = Bundle(for: VPNModel.self)
        let tables = try ["en", "ru"].map { language -> [String: String] in
            let path = try XCTUnwrap(bundle.path(forResource: "Localizable", ofType: "strings", inDirectory: nil, forLocalization: language))
            return try XCTUnwrap(NSDictionary(contentsOfFile: path) as? [String: String])
        }
        XCTAssertEqual(Set(tables[0].keys), Set(tables[1].keys))
        for key in ["v3.value.nodata", "v3.slide.connect", "v3.desc.running", "v3.reason.not_checked", "v3.widget.last"] {
            XCTAssertNotNil(tables[0][key]); XCTAssertNotNil(tables[1][key])
        }
    }
}
