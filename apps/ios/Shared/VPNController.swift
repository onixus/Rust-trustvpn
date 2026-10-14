import Foundation
import NetworkExtension
import SwiftUI
import WidgetKit
import AppIntents

@MainActor
protocol VPNStartConfiguration: AnyObject {
    var isEnabled: Bool { get set }
    func saveToPreferences() async throws
    func loadFromPreferences() async throws
    func startTunnel(profileID: String?) throws
}

extension NETunnelProviderManager: VPNStartConfiguration {
    func startTunnel(profileID: String?) throws { try connection.startVPNTunnel(options: profileID.map { ["profileID": $0 as NSString] }) }
}

@MainActor
enum VPNController {
    static func canToggle(active: Bool, hasProfile: Bool, busy: Bool, supported: Bool) -> Bool {
        supported && !busy && (active || hasProfile)
    }

    static func start(_ manager: any VPNStartConfiguration, profileID: String? = nil) async throws {
        // Selecting another VPN disables this configuration. Persist and reload before starting.
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        try manager.startTunnel(profileID: profileID)
    }

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
    /// Set when the app or the widget intent asks the tunnel to stop, so the resulting
    /// disconnect is not shown as a failed connection attempt. Kept in the app group so a
    /// stop from another process is seen too, and it expires so a stop that never produced
    /// a disconnect cannot hide a later failure. Consumed by VPNModel.
    static var userStopped: Bool {
        get { ((WidgetState.defaults ?? .standard).object(forKey: stopKey) as? Date).map { Date().timeIntervalSince($0) < 30 } ?? false }
        set { (WidgetState.defaults ?? .standard).set(newValue ? Date() : nil, forKey: stopKey) }
    }
    private static let stopKey = "userStoppedAt"
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
            userStopped = true
            manager.connection.stopVPNTunnel()
        } else { try await start(manager) }
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

// MARK: - UI variant 3: state model and palette (shared by app and widget)

/// Presentation level. Green (`verified`) is reachable only from fresh passed checks;
/// the widget never shows it because WidgetKit cannot keep a result fresh.
enum TunnelLevel: String, CaseIterable {
    case off, connecting, disconnecting, running, verified, warning, error
    var tone: StateTone {
        switch self {
        case .off: return .grey
        // Same as desktop: a pending transition is blue, drawn outlined.
        case .connecting, .disconnecting, .running: return .blue
        case .verified: return .green
        case .warning: return .yellow
        case .error: return .red
        }
    }
    /// Transport level from the system VPN status alone; never `verified`.
    static func transport(_ status: NEVPNStatus?, attemptFailed: Bool = false) -> TunnelLevel {
        switch status {
        case .connected: return .running
        case .connecting, .reasserting: return .connecting
        case .disconnecting: return .disconnecting
        default: return attemptFailed ? .error : .off
        }
    }
}
enum StateTone { case grey, blue, green, yellow, red }

extension Color {
    init(rgb: UInt32, opacity: Double = 1) {
        self.init(.sRGB, red: Double((rgb >> 16) & 0xFF) / 255, green: Double((rgb >> 8) & 0xFF) / 255,
                  blue: Double(rgb & 0xFF) / 255, opacity: opacity)
    }
}
/// Dark and light (frosted glass) colours, matching Android Palette.java.
struct Palette {
    let light: Bool
    init(_ scheme: ColorScheme) { light = scheme == .light }
    var bg: Color { Color(rgb: light ? 0xE8EDF5 : 0x08090B) }
    var text: Color { Color(rgb: light ? 0x0E1726 : 0xF4F5F7) }
    var muted: Color { Color(rgb: light ? 0x4A566B : 0x8A93A0) }
    var card: Color { light ? Color.white.opacity(0.55) : Color(rgb: 0x121418) }
    var cardStroke: Color { light ? Color.white.opacity(0.85) : Color(rgb: 0x1B1E24) }
    var chip: Color { light ? Color.white.opacity(0.6) : Color(rgb: 0x15181D) }
    var field: Color { light ? Color.white.opacity(0.8) : Color(rgb: 0x1A1D23) }
    var rule: Color { light ? Color(rgb: 0x0E1726, opacity: 0.08) : Color(rgb: 0x1E2128) }
    var empty: Color { Color(rgb: light ? 0x8C97A8 : 0x4A515C) }
    var blueSoft: Color { Color(rgb: light ? 0xDCE9FF : 0x14243A) }
    var onBlue: Color { light ? .white : Color(rgb: 0x06213D) }
    var danger: Color { Color(rgb: light ? 0xC2272D : 0xFF6B70) }
    /// Dot, knob and fill tone.
    func fill(_ tone: StateTone) -> Color {
        switch tone {
        case .grey: return Color(rgb: light ? 0x8C97A8 : 0x6B7A8C)
        case .blue: return Color(rgb: 0x4DA3FF)
        case .green: return Color(rgb: 0x3DD68C)
        case .yellow: return Color(rgb: 0xE0A526)
        case .red: return Color(rgb: 0xE5484D)
        }
    }
    /// Text tone for a state; darker in the light theme for contrast.
    func text(_ tone: StateTone) -> Color {
        switch tone {
        case .grey: return Color(rgb: light ? 0x5B6678 : 0x9AA6B4)
        case .blue: return Color(rgb: light ? 0x1F6FE0 : 0x4DA3FF)
        case .green: return Color(rgb: light ? 0x138A4E : 0x3DD68C)
        case .yellow: return Color(rgb: light ? 0x8F6200 : 0xE0A526)
        case .red: return Color(rgb: light ? 0xC2272D : 0xFF6B70)
        }
    }
    /// Icon colour on a filled state knob.
    func onFill(_ tone: StateTone) -> Color {
        if !light { return Color(rgb: 0x08090B) }
        return tone == .yellow || tone == .green ? Color(rgb: 0x08090B) : .white
    }
}
/// Power glyph used by the slide control and widgets (system SF Symbol, no bundled assets).
struct PowerGlyph: View {
    var color: Color
    var size: CGFloat = 20
    var body: some View {
        Image(systemName: "power").font(.system(size: size, weight: .bold)).foregroundStyle(color).accessibilityHidden(true)
    }
}
