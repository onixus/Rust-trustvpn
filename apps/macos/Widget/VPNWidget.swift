// macOS desktop widget and Control Center control for the native desktop app.
// The extension is sandboxed and only reads the status file written by the app;
// it holds no profiles or credentials. Actions are rtrust-widget:// links that
// macOS delivers to the app, carrying the per-launch token from the status file.
import AppIntents
import AppKit
import notify
import os
import SwiftUI
import WidgetKit

enum Phase: String, Decodable {
    case off, connecting, on, problem, disconnecting, closed
}

struct Status: Decodable {
    let version: Int
    let phase: Phase
    let mode: String?
    let since: Double
    let token: String
}

struct VPNEntry: TimelineEntry {
    let date: Date
    /// nil: the app is not running or its status cannot be read.
    let status: Status?
}

enum StatusFile {
    static let kind = "org.rtrusttunnel.vpn"
    static let controlKind = "org.rtrusttunnel.vpn.control"
    // Real home, not the sandbox container; the path is granted read-only by
    // the extension's temporary-exception entitlement.
    static var url: URL {
        let home = getpwuid(getuid()).flatMap { $0.pointee.pw_dir.map { String(cString: $0) } } ?? NSHomeDirectory()
        return URL(fileURLWithPath: home)
            .appendingPathComponent("Library/Application Support/org.rtrusttunnel.Native/Widget/status.json")
    }
    static var appBundleID: String {
        Bundle.main.object(forInfoDictionaryKey: "RTrustAppBundleID") as? String ?? "org.rtrusttunnel.Native"
    }

    static let log = Logger(subsystem: "org.rtrusttunnel.widget", category: "status")

    static func read() -> Status? {
        guard !NSRunningApplication.runningApplications(withBundleIdentifier: appBundleID).isEmpty else {
            log.notice("app \(appBundleID, privacy: .public) is not running")
            return nil
        }
        let data: Data
        do { data = try Data(contentsOf: url) } catch {
            log.error("cannot read status: \(error.localizedDescription, privacy: .public)")
            return nil
        }
        guard data.count <= 4096,
              let status = try? JSONDecoder().decode(Status.self, from: data),
              status.version == 1, status.phase != .closed,
              status.token.count == 32, status.token.allSatisfy(\.isHexDigit)
        else {
            log.error("invalid or closed status (\(data.count, privacy: .public) bytes)")
            return nil
        }
        return status
    }
}

struct VPNProvider: TimelineProvider {
    func placeholder(in context: Context) -> VPNEntry { VPNEntry(date: .now, status: nil) }
    func getSnapshot(in context: Context, completion: @escaping (VPNEntry) -> Void) {
        completion(VPNEntry(date: .now, status: context.isPreview ? nil : StatusFile.read()))
    }
    func getTimeline(in context: Context, completion: @escaping (Timeline<VPNEntry>) -> Void) {
        // The app requests a reload on every change; the periodic refresh only
        // corrects the tile after the app crashed without saying goodbye.
        completion(Timeline(entries: [VPNEntry(date: .now, status: StatusFile.read())],
                            policy: .after(Date().addingTimeInterval(15 * 60))))
    }
}

private extension Status {
    var active: Bool { phase != .off }
    var title: LocalizedStringKey {
        switch phase {
        case .on: return "Подключено"
        case .connecting: return "Подключение…"
        case .disconnecting: return "Отключение…"
        case .problem: return "Нет связи"
        case .off, .closed: return "Отключено"
        }
    }
    var color: Color {
        switch phase {
        case .on: return .green
        case .connecting, .disconnecting: return .yellow
        case .problem: return .orange
        case .off, .closed: return .secondary
        }
    }
    var symbol: String {
        switch phase {
        case .on: return "lock.shield.fill"
        case .problem: return "exclamationmark.shield.fill"
        default: return "shield"
        }
    }
    var action: URL? {
        switch phase {
        case .off: return URL(string: "rtrust-widget://connect?t=\(token)")
        case .on, .problem, .connecting: return URL(string: "rtrust-widget://disconnect?t=\(token)")
        case .disconnecting, .closed: return nil
        }
    }
}

private let openURL = URL(string: "rtrust-widget://open")!

struct VPNWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: VPNEntry

    var body: some View {
        Group {
            if let status = entry.status {
                if family == .systemSmall { small(status) } else { medium(status) }
            } else {
                closed
            }
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }

    private var header: some View {
        Label("R-TrustTunnel", systemImage: "network.badge.shield.half.filled")
            .font(.caption.weight(.semibold))
            .foregroundStyle(.secondary)
            .lineLimit(1)
    }

    private func state(_ status: Status) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Image(systemName: status.symbol).foregroundStyle(status.color)
                Text(status.title).font(.headline).lineLimit(1)
            }
            if let mode = status.mode {
                Text(mode).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            if status.phase == .on {
                Text(Date(timeIntervalSince1970: status.since), style: .relative)
                    .font(.caption2.monospacedDigit()).foregroundStyle(.secondary)
            }
        }
    }

    private func actionLabel(_ status: Status) -> some View {
        Label(status.active ? "Отключить" : "Подключить", systemImage: "power")
            .font(.callout.weight(.semibold))
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6)
            .background(status.active ? Color.orange.opacity(0.85) : Color.accentColor,
                        in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .foregroundStyle(.white)
    }

    // A small tile has one tap target: the whole widget performs the action.
    private func small(_ status: Status) -> some View {
        VStack(alignment: .leading) {
            header
            Spacer(minLength: 4)
            state(status)
            Spacer(minLength: 4)
            if status.action != nil { actionLabel(status) }
        }
        .widgetURL(status.action ?? openURL)
    }

    private func medium(_ status: Status) -> some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading) {
                header
                Spacer(minLength: 4)
                state(status)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            VStack(spacing: 8) {
                if let action = status.action { Link(destination: action) { actionLabel(status) } }
                Link(destination: openURL) {
                    Text("Открыть").font(.callout).frame(maxWidth: .infinity).padding(.vertical, 6)
                        .background(.quaternary, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
            }
            .frame(width: 130)
        }
    }

    private var closed: some View {
        VStack(alignment: .leading) {
            header
            Spacer(minLength: 4)
            Text("Приложение не запущено").font(.headline)
            Text("Нажмите, чтобы открыть").font(.caption).foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .widgetURL(openURL)
    }
}

struct RTrustWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: StatusFile.kind, provider: VPNProvider()) { VPNWidgetView(entry: $0) }
            .configurationDisplayName("VPN")
            .description("Состояние R-TrustTunnel и быстрое подключение профиля по умолчанию.")
            .supportedFamilies([.systemSmall, .systemMedium])
    }
}

#if RTRUST_CONTROL
// Control Center toggle, built only when signed with a Team ID (linkd rejects
// App Intents clients without one). The intent runs in this sandboxed extension, so it
// asks the app through a Darwin notification named with the per-launch token:
// only processes that can read the 0600 status file know the name. Darwin
// notifications do not activate the app, unlike the widget links.
struct ControlState {
    let phase: Phase?
    var isOn: Bool { phase == .on || phase == .problem || phase == .connecting }
}

@available(macOS 26.0, *)
struct ControlProvider: ControlValueProvider {
    var previewValue: ControlState { ControlState(phase: .off) }
    func currentValue() async throws -> ControlState { ControlState(phase: StatusFile.read()?.phase) }
}

@available(macOS 26.0, *)
struct SetVPNIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Подключить или отключить VPN"
    static let isDiscoverable = false

    @Parameter(title: "Подключено")
    var value: Bool

    func perform() async throws -> some IntentResult {
        guard let status = StatusFile.read() else {
            // Not running: open the app instead of switching anything.
            let opened = await MainActor.run { NSWorkspace.shared.open(openURL) }
            StatusFile.log.notice("toggle \(value, privacy: .public): no status, opening app (\(opened, privacy: .public))")
            return .result()
        }
        // Must match widget::notification_name in apps/native/src/widget.rs.
        let result = notify_post("org.rtrusttunnel.Native.\(status.token).\(value ? "connect" : "disconnect")")
        StatusFile.log.notice("toggle \(value, privacy: .public) from \(status.phase.rawValue, privacy: .public): notify_post \(result, privacy: .public)")
        return .result()
    }
}

@available(macOS 26.0, *)
struct RTrustControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: StatusFile.controlKind, provider: ControlProvider()) { state in
            ControlWidgetToggle(isOn: state.isOn, action: SetVPNIntent()) {
                Label("R-TrustTunnel", systemImage: "network.badge.shield.half.filled")
            } valueLabel: { isOn in
                switch state.phase {
                case .problem?: Label("Нет связи", systemImage: "exclamationmark.shield.fill")
                case .connecting?: Label("Подключение…", systemImage: "shield.lefthalf.filled")
                case .disconnecting?: Label("Отключение…", systemImage: "shield.lefthalf.filled")
                case nil: Label("Не запущено", systemImage: "shield")
                default: Label(isOn ? "Подключено" : "Отключено",
                               systemImage: isOn ? "lock.shield.fill" : "shield.slash")
                }
            }
            .tint(state.phase == .problem ? .orange : .green)
        }
        .displayName("R-TrustTunnel VPN")
        .description("Подключить или отключить профиль по умолчанию.")
    }
}

#endif

@main
struct RTrustWidgets: WidgetBundle {
    var body: some Widget {
        RTrustWidget()
        #if RTRUST_CONTROL
        if #available(macOS 26.0, *) { RTrustControl() }
        #endif
    }
}
