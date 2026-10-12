import XCTest
import CoreImage
import UIKit
import NetworkExtension
@testable import RTrustTunnel

final class FixtureProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, Data))?
    override class func canInit(with request: URLRequest) -> Bool { request.url?.host == "fixture.invalid" }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let (status, data) = try Self.handler!(request)
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
        FixtureProtocol.handler = nil
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


extension ParityTests {
    func testPortalWholeBatchFenceSequences() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        let client = PortalClient(session: PortalSession(origin: "https://fixture.invalid", token: String(repeating: "a", count: 40)), configuration: config)
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
            var lists = 0, exports = 0
            FixtureProtocol.handler = { request in
                if request.url!.path == "/portal/v2/profiles" {
                    lists += 1
                    return (200, try JSONSerialization.data(withJSONObject: ["profiles": lists == 1 ? before : after]))
                }
                exports += 1
                return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
            }
            let local = SavedProfile.imported(try ProfilePlan.parse(Data(raw.utf8)), id: "local")
            var retained = [local]
            do {
                let downloaded = try await client.download()
                XCTAssertTrue(succeeds, "Changed list accepted")
                if succeeds { retained = downloaded; XCTAssertEqual(retained.count, before.count) }
            } catch {
                XCTAssertFalse(succeeds, "Stable list rejected")
                XCTAssertEqual(retained.map(\.id), ["local"], "No partial local replacement")
            }
            if before.count == 2, before[0]["id"] as? String == before[1]["id"] as? String {
                XCTAssertEqual(exports, 0, "Initial duplicates rejected before exports")
            } else { XCTAssertEqual(lists, 2, "Recheck includes empty lists") }
        }
    }
    func testPortalMalformedMetadataAndUnknownOrigin() throws {
        for revision in ["", "has space", "line\n", "é", String(repeating: "x", count: 257)] {
            XCTAssertThrowsError(try PortalClient.metadata(["profiles": [["id": "one", "revision": revision]]]))
        }
        for origin: Any in ["", "line\n", 12, String(repeating: "x", count: 81)] {
            XCTAssertThrowsError(try PortalClient.metadata(["profiles": [["id": "one", "revision": "r1", "origin": origin]]]))
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
    func testPortalPostfetchFailureAndCancellationKeepCallerState() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [FixtureProtocol.self]
        let client = PortalClient(session: PortalSession(origin: "https://fixture.invalid", token: String(repeating: "a", count: 40)), configuration: config)
        defer { FixtureProtocol.handler = nil }
        let raw = self.raw
        for cancelExport in [false, true] {
            var lists = 0
            FixtureProtocol.handler = { request in
                if request.url!.path == "/portal/v2/profiles" {
                    lists += 1
                    if lists == 2 { throw URLError(.timedOut) }
                    return (200, try JSONSerialization.data(withJSONObject: ["profiles": [["id": "one", "revision": "r1"]]]))
                }
                if cancelExport { throw URLError(.cancelled) }
                return (200, try JSONSerialization.data(withJSONObject: ["content": raw]))
            }
            var retained = [SavedProfile.imported(try ProfilePlan.parse(Data(raw.utf8)), id: "local")]
            do { retained = try await client.download(); XCTFail("Failed batch accepted") }
            catch { XCTAssertEqual(retained.map(\.id), ["local"]) }
        }
    }
}
