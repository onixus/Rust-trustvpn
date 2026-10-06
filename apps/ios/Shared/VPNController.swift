import Foundation
import NetworkExtension
import WidgetKit
import AppIntents

@MainActor
enum VPNController {
    static var supportsVPN: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return true
        #endif
    }
    static var providerID: String { (Bundle.main.object(forInfoDictionaryKey: "BaseBundleID") as? String ?? "org.rtrusttunnel.ios") + ".PacketTunnel" }
    static func manager() async throws -> NETunnelProviderManager? {
        guard supportsVPN else { return nil }
        return try await NETunnelProviderManager.loadAllFromPreferences().first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerID
        }
    }
    static func isActive(_ status: NEVPNStatus) -> Bool { status != .disconnected && status != .invalid }
    private static var changing = false
    static func toggleExisting() async throws {
        guard supportsVPN else { throw NSError(domain: "RTrustVPN", code: 1, userInfo: [NSLocalizedDescriptionKey: "VPN requires a physical iPhone"] ) }
        guard !changing else { return }
        changing = true; defer { changing = false }
        guard let manager = try await manager() else {
            throw NSError(domain: "RTrustVPN", code: 2, userInfo: [NSLocalizedDescriptionKey: "Open R-TrustTunnel and connect once to authorize VPN"])
        }
        if isActive(manager.connection.status) {
            // Otherwise On Demand can immediately undo the user's explicit Disconnect.
            manager.isOnDemandEnabled = false
            try await manager.saveToPreferences()
            manager.connection.stopVPNTunnel()
        } else { try manager.connection.startVPNTunnel() }
        WidgetState.update(manager.connection.status)
    }
}
struct ToggleVPNIntent: AppIntent {
    static var title: LocalizedStringResource = "Toggle VPN"
    static var description = IntentDescription("Connect or disconnect the configured R-TrustTunnel VPN.")
    static var openAppWhenRun: Bool = true
    static var authenticationPolicy: IntentAuthenticationPolicy = .requiresLocalDeviceAuthentication
    @MainActor func perform() async throws -> some IntentResult {
        try await VPNController.toggleExisting()
        return .result()
    }
}
