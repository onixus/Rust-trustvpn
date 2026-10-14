import SwiftUI
import WidgetKit
import NetworkExtension

struct VPNEntry: TimelineEntry {
    let date: Date
    let status: NEVPNStatus?
    /// When the app last recorded the status; shown as the age of the last observation.
    let observedAt: Date?
}
struct VPNProvider: TimelineProvider {
    func placeholder(in context: Context) -> VPNEntry { VPNEntry(date: .now, status: nil, observedAt: nil) }
    func getSnapshot(in context: Context, completion: @escaping (VPNEntry) -> Void) { completion(entry()) }
    func getTimeline(in context: Context, completion: @escaping (Timeline<VPNEntry>) -> Void) {
        completion(Timeline(entries: [entry(), VPNEntry(date: Date().addingTimeInterval(60), status: nil, observedAt: nil)], policy: .after(Date().addingTimeInterval(60))))
    }
    private func entry() -> VPNEntry {
        let defaults = WidgetState.defaults
        let time = defaults?.double(forKey: "statusDate") ?? 0
        let age = Date().timeIntervalSince1970 - time
        guard age >= 0 && age < 90 else { return VPNEntry(date: .now, status: nil, observedAt: nil) }
        return VPNEntry(date: .now, status: NEVPNStatus(rawValue: defaults?.integer(forKey: "vpnStatus") ?? 0),
                        observedAt: Date(timeIntervalSince1970: time))
    }
}
/// The widget shows only the last recorded transport status. It never shows green:
/// check results expire within seconds and WidgetKit cannot keep them fresh.
struct VPNWidgetView: View {
    @Environment(\.widgetFamily) private var family
    @Environment(\.colorScheme) private var scheme
    let entry: VPNEntry
    private var level: TunnelLevel? { entry.status.map { TunnelLevel.transport($0) } }
    private var lines: (LocalizedStringKey, LocalizedStringKey) {
        switch level {
        case .connecting?: return ("v3.tunnel", entry.status == .reasserting ? "v3.reconnecting.2" : "v3.connecting.2")
        case .disconnecting?: return ("v3.tunnel", "v3.disconnecting.2")
        case .running?: return ("v3.tunnel", "v3.running.2")
        case .some: return ("v3.off.1", "v3.off.2")
        case nil: return ("R-TrustTunnel", "v3.widget.unknown")
        }
    }
    var body: some View {
        Group {
            if family == .accessoryCircular { circular } else { small }
        }
        .privacySensitive()
        .modifier(WidgetBackground(color: family == .accessoryCircular ? .clear : Palette(scheme).bg))
    }
    private var small: some View {
        let palette = Palette(scheme)
        let tone = level?.tone ?? .grey
        return VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .top, spacing: 6) {
                VStack(alignment: .leading, spacing: 0) {
                    Text(lines.0).foregroundStyle(palette.text)
                    Text(lines.1).foregroundStyle(palette.text(tone))
                }
                .font(.system(size: 17, weight: .heavy)).lineLimit(1).minimumScaleFactor(0.6)
                Spacer(minLength: 0)
                toggle {
                    ZStack {
                        if level == .connecting { Circle().strokeBorder(palette.fill(.blue), lineWidth: 2.5) }
                        else { Circle().fill(palette.fill(tone)) }
                        PowerGlyph(color: level == .connecting ? palette.text(.blue) : palette.onFill(tone), size: 18)
                    }
                    .frame(width: 44, height: 44)
                }
            }
            Spacer(minLength: 8)
            // Check ladder: only transport is known here; other checks are "no data".
            HStack(spacing: 4) {
                ForEach(0..<5, id: \.self) { index in
                    Capsule().fill(index == 0 && (level == .running || level == .connecting) ? palette.fill(.blue)
                                   : (palette.light ? Color(rgb: 0x0E1726, opacity: 0.12) : Color(rgb: 0x2A2E36)))
                        .frame(height: 5)
                }
            }
            .accessibilityHidden(true)
            Spacer(minLength: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.observedAt == nil ? "v3.widget.open" : "v3.widget.last").font(.system(size: 13, weight: .heavy)).foregroundStyle(palette.text)
                if let observed = entry.observedAt {
                    Text(observed, style: .relative).font(.system(size: 11)).foregroundStyle(palette.muted)
                }
            }
            .lineLimit(1)
        }
    }
    /// Lock Screen is rendered monochrome: state is carried by the ring, not by colour.
    private var circular: some View {
        let on = level == .running
        let pending = level == .connecting || level == .disconnecting
        return toggle {
            ZStack {
                if on { Circle().strokeBorder(lineWidth: 3) }
                else if pending { Circle().strokeBorder(style: StrokeStyle(lineWidth: 3, dash: [4, 4])) }
                else { AccessoryWidgetBackground() }
                VStack(spacing: 1) {
                    Image(systemName: "power").font(.system(size: 18, weight: .bold))
                    Text(on ? "v3.widget.on" : pending ? "…" : "VPN").font(.system(size: 10, weight: .heavy))
                }
            }
        }
    }
    @ViewBuilder private func toggle<Label: View>(@ViewBuilder _ label: () -> Label) -> some View {
        if #available(iOS 17.0, *) {
            Button(intent: ToggleVPNIntent()) { label() }
                .buttonStyle(.plain)
                .accessibilityLabel(Text("Toggle VPN"))
        } else {
            Link(destination: URL(string: "rtrust://home")!) { label() }
                .accessibilityLabel(Text("Toggle VPN"))
        }
    }
}
private struct WidgetBackground: ViewModifier {
    let color: Color
    func body(content: Content) -> some View {
        if #available(iOS 17.0, *) { content.containerBackground(color, for: .widget) }
        else { content.padding().background(color) }
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
