import SwiftUI
import WidgetKit
import NetworkExtension

struct VPNEntry: TimelineEntry {
    let date: Date
    let status: NEVPNStatus?
}
struct VPNProvider: TimelineProvider {
    func placeholder(in context: Context) -> VPNEntry { VPNEntry(date: .now, status: nil) }
    func getSnapshot(in context: Context, completion: @escaping (VPNEntry) -> Void) { completion(entry()) }
    func getTimeline(in context: Context, completion: @escaping (Timeline<VPNEntry>) -> Void) {
        completion(Timeline(entries: [entry(), VPNEntry(date: Date().addingTimeInterval(60), status: nil)], policy: .after(Date().addingTimeInterval(60))))
    }
    private func entry() -> VPNEntry {
        let defaults = WidgetState.defaults
        let age = Date().timeIntervalSince1970 - (defaults?.double(forKey: "statusDate") ?? 0)
        let status = age >= 0 && age < 90 ? NEVPNStatus(rawValue: defaults?.integer(forKey: "vpnStatus") ?? 0) : nil
        return VPNEntry(date: .now, status: status)
    }
}
struct VPNWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: VPNEntry
    private var label: String {
        switch entry.status {
        case .connected: return "Connected"
        case .connecting, .reasserting: return "Connecting"
        case .disconnecting: return "Disconnecting"
        case .disconnected, .invalid: return "Disconnected"
        default: return "Open to check"
        }
    }
    var body: some View {
        VStack(spacing: 10) {
            if family == .systemSmall { Text("R-TrustTunnel").font(.headline); Text("Last status").font(.caption2); Text(LocalizedStringKey(label)).font(.caption).foregroundStyle(.secondary) }
            if #available(iOS 17.0, *) {
                Button(intent: ToggleVPNIntent()) { Image(systemName: "power").font(.title).padding(8) }
                    .buttonStyle(.borderedProminent).tint(entry.status == .connected ? .green : .blue)
                    .accessibilityLabel("Toggle VPN")
            } else { Link(destination: URL(string: "rtrust://home")!) { Image(systemName: "power").font(.title) } }
        }
        .privacySensitive()
        .modifier(WidgetBackground())
    }
}
private struct WidgetBackground: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 17.0, *) { content.containerBackground(.fill.tertiary, for: .widget) }
        else { content.padding() }
    }
}
@main
struct RTrustWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: WidgetState.kind, provider: VPNProvider()) { VPNWidgetView(entry: $0) }
            .configurationDisplayName("VPN control")
            .description("Open R-TrustTunnel to securely toggle VPN. Authorize VPN in the app first.")
            .supportedFamilies([.systemSmall, .accessoryCircular])
    }
}
