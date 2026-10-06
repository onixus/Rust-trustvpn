import XCTest
import CoreImage
import UIKit
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
