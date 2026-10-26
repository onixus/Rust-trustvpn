import SwiftUI
import PhotosUI
import VisionKit
import UniformTypeIdentifiers
import UIKit
import NetworkExtension

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        PortalSync.register(); return true
    }
}
/// Appearance setting; stored in app preferences, never in the vault or App Group.
enum ThemeMode: String, CaseIterable, Identifiable {
    case system, dark, light
    static let key = "ui.theme"
    var id: String { rawValue }
    var scheme: ColorScheme? { self == .dark ? .dark : self == .light ? .light : nil }
}
@main
struct RTrustApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = VPNModel()
    @Environment(\.scenePhase) private var phase
    @AppStorage(ThemeMode.key) private var theme = ThemeMode.system.rawValue
    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .privacyShield()
                .preferredColorScheme(ThemeMode(rawValue: theme)?.scheme)
                .onChange(of: phase) { state in
                    if state == .active { Task { await model.refresh() } }
                    if state == .background { PortalSync.schedule() }
                }
        }
    }
}
/// Covers its content while the scene is inactive or screen capture is reported.
/// Applied to the root and to every sheet, since an overlay on the root does not
/// cover presented sheets. System alerts and pickers are not covered.
struct PrivacyShield: ViewModifier {
    @Environment(\.scenePhase) private var phase
    @State private var captured = UIScreen.main.isCaptured
    func body(content: Content) -> some View {
        content
            .overlay { if phase != .active || captured { PrivacyCover() } }
            .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in captured = UIScreen.main.isCaptured }
    }
}
extension View {
    func privacyShield() -> some View { modifier(PrivacyShield()) }
}
/// Opaque cover while inactive or while screen capture is reported.
struct PrivacyCover: View {
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        let palette = Palette(scheme)
        ZStack {
            palette.bg.ignoresSafeArea()
            Label("R-TrustTunnel", systemImage: "lock.shield").font(.title).foregroundStyle(palette.text)
        }
    }
}

// MARK: - Design components

extension View {
    /// Card surface: solid in the dark theme, frosted glass (material + white veil) in the light theme.
    func glass(_ palette: Palette, radius: CGFloat = 24) -> some View {
        let shape = RoundedRectangle(cornerRadius: radius, style: .continuous)
        return background {
            if palette.light { shape.fill(.ultraThinMaterial).overlay(shape.fill(Color.white.opacity(0.35))) }
            else { shape.fill(palette.card) }
        }
        .overlay(shape.strokeBorder(palette.cardStroke, lineWidth: 1))
    }
}
/// Screen background; the light theme adds large blurred colour blobs behind the glass.
struct Backdrop: View {
    let palette: Palette
    var accent: Color = Color(rgb: 0x4DA3FF)
    var body: some View {
        GeometryReader { geometry in
            ZStack(alignment: .topLeading) {
                palette.bg
                if palette.light {
                    blob(accent, size: 300, opacity: 0.4, x: -90, y: 60)
                    blob(Color(rgb: 0xB9AEFF), size: 260, opacity: 0.45, x: geometry.size.width - 180, y: geometry.size.height * 0.4)
                    blob(Color(rgb: 0x9FDCFF), size: 280, opacity: 0.45, x: 40, y: geometry.size.height - 220)
                }
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
    private func blob(_ color: Color, size: CGFloat, opacity: Double, x: CGFloat, y: CGFloat) -> some View {
        Circle().fill(color).frame(width: size, height: size).blur(radius: 70).opacity(opacity).offset(x: x, y: y)
    }
}
struct StateDot: View {
    let dot: CheckDot
    let palette: Palette
    var size: CGFloat = 10
    var body: some View {
        Group {
            switch dot {
            case .filled(let tone): Circle().fill(palette.fill(tone))
            case .ring(let tone): Circle().strokeBorder(palette.fill(tone), lineWidth: 2)
            case .empty: Circle().strokeBorder(palette.empty, lineWidth: 2)
            }
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}
struct CardLabel: View {
    let text: String
    let palette: Palette
    var body: some View {
        Text(text.uppercased()).font(.system(size: 11, weight: .heavy)).tracking(0.9).foregroundStyle(palette.muted)
    }
}
/// Slide-to-act control: the knob must be dragged to the end, so a pocket tap cannot
/// connect or disconnect. Forward slides left to right; reverse (disconnect/cancel)
/// starts on the right. A tap only nudges the knob. VoiceOver's activate action acts
/// directly, so assistive-technology users are not asked to drag.
struct SlideToAct: View {
    let text: String
    let knob: Color
    let icon: Color
    let outline: Bool
    let reverse: Bool
    let palette: Palette
    let action: () -> Void
    @Environment(\.isEnabled) private var enabled
    @State private var progress: CGFloat = 0
    @State private var start: CGFloat?
    private let height: CGFloat = 64, pad: CGFloat = 6
    var body: some View {
        GeometryReader { geometry in
            let size = height - 2 * pad
            let range = max(1, geometry.size.width - 2 * pad - size)
            ZStack(alignment: .leading) {
                Text(reverse ? "←  " + text : text + "  →")
                    .font(.system(size: 15, weight: .bold)).foregroundStyle(palette.muted)
                    .lineLimit(1).minimumScaleFactor(0.75)
                    .frame(maxWidth: .infinity, alignment: reverse ? .trailing : .leading)
                    .padding(reverse ? .trailing : .leading, pad + size + 14)
                    .padding(reverse ? .leading : .trailing, 16)
                    .opacity(Double(max(0, 1 - progress * 1.6)))
                ZStack {
                    if outline { Circle().strokeBorder(knob, lineWidth: 2.5) } else { Circle().fill(knob) }
                    PowerGlyph(color: icon, size: 20)
                }
                .frame(width: size, height: size)
                .offset(x: pad + (reverse ? 1 - progress : progress) * range)
                .gesture(DragGesture(minimumDistance: 0)
                    .onChanged { value in
                        if start == nil { start = progress }
                        let delta = value.translation.width / range
                        progress = min(1, max(0, (start ?? 0) + (reverse ? -delta : delta)))
                    }
                    .onEnded { value in
                        start = nil
                        if progress > 0.8 { withAnimation(.easeOut(duration: 0.18)) { progress = 1 }; fire() }
                        else if abs(value.translation.width) < 8 && progress < 0.05 { nudge() }
                        else { withAnimation(.easeOut(duration: 0.18)) { progress = 0 } }
                    })
            }
            .frame(width: geometry.size.width, height: height)
            .contentShape(Rectangle())
            .onTapGesture { nudge() }
        }
        .frame(height: height)
        .glass(palette, radius: height / 2)
        .opacity(enabled ? 1 : 0.55)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(text)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { if enabled { action() } }
        // A direction change mid-drag must not turn the partial drag into a full one.
        .onChange(of: reverse) { _ in start = nil; progress = 0 }
    }
    private func fire() {
        if enabled {
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
            action()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { withAnimation(.easeOut(duration: 0.18)) { progress = 0 } }
    }
    private func nudge() {
        guard start == nil else { return }
        withAnimation(.easeOut(duration: 0.2)) { progress = 0.18 }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.21) {
            if start == nil { withAnimation(.easeIn(duration: 0.2)) { progress = 0 } }
        }
    }
}
/// Shown host: server-managed profiles keep their host out of the list, as before.
func shownHost(_ profile: SavedProfile) -> String {
    profile.remoteID == nil ? profile.hostname : tr("Server profile", "Серверный профиль")
}

// MARK: - Navigation

enum Route: Hashable { case profiles, checks, settings }

struct RootView: View {
    @ObservedObject var model: VPNModel
    @State private var path: [Route] = []
    @State private var add = false
    @State private var incoming = ""
    @State private var exported: SavedProfile?
    @State private var deleting: SavedProfile?
    @State private var renaming: SavedProfile?
    @State private var name = ""
    var body: some View {
        NavigationStack(path: $path) {
            HomeView(model: model, open: { path.append($0) }, add: openAdd)
                .navigationDestination(for: Route.self) { route in
                    switch route {
                    case .profiles:
                        ProfilesView(model: model, add: openAdd, export: { exported = $0 },
                                     rename: { renaming = $0; name = $0.name }, delete: { deleting = $0 })
                    case .checks: ChecksView(model: model)
                    case .settings: SettingsView(model: model)
                    }
                }
        }
        .sheet(isPresented: $add) { ImportView(model: model, initial: incoming).privacyShield() }
        .sheet(item: $exported) { ExportView(profile: $0).privacyShield() }
        .alert(tr("Delete profile?", "Удалить профиль?"), isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button(tr("Delete", "Удалить"), role: .destructive) { if let item = deleting { model.delete(item.id) }; deleting = nil }
            Button(tr("Cancel", "Отмена"), role: .cancel) { deleting = nil }
        } message: { Text(tr("Server profiles can return on the next synchronization.", "Серверный профиль может вернуться при следующей синхронизации.")) }
        .alert(tr("Rename", "Переименовать"), isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField(tr("Name", "Название"), text: $name)
            Button(tr("Save", "Сохранить")) { if let item = renaming { model.rename(item.id, name: name) }; renaming = nil }
            Button(tr("Cancel", "Отмена"), role: .cancel) { renaming = nil }
        }
        .onOpenURL { url in
            guard ["tt", "hy2", "hysteria2", "vless"].contains(url.scheme?.lowercased() ?? ""), url.absoluteString.utf8.count <= 1_048_576 else { return }
            incoming = url.absoluteString; add = true
        }
    }
    private func openAdd() { incoming = ""; add = true }
}

// MARK: - Home

struct HomeView: View {
    @ObservedObject var model: VPNModel
    let open: (Route) -> Void
    let add: () -> Void
    @Environment(\.colorScheme) private var scheme
    @ScaledMetric(relativeTo: .largeTitle) private var headlineSize: CGFloat = 44
    /// Re-evaluated every second while the tunnel is active so expired results lose
    /// their colour on time; the rest of the app is not invalidated by the clock.
    var body: some View {
        TimelineView(.animation(minimumInterval: 1, paused: !model.active)) { _ in content }
    }
    @ViewBuilder private var content: some View {
        let palette = Palette(scheme)
        let level = model.level
        ZStack {
            Backdrop(palette: palette, accent: palette.fill(level.tone))
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    header(palette, level)
                    headline(palette, level)
                    Text(model.homeDescription(level)).font(.subheadline).foregroundStyle(palette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                    Button { open(.checks) } label: { checks(palette, level) }
                        .buttonStyle(.plain)
                        .accessibilityHint(loc("v3.checks.open"))
                    HStack(alignment: .top, spacing: 10) {
                        profileCard(palette).frame(maxWidth: .infinity)
                        onDemandCard(palette).frame(maxWidth: .infinity)
                    }
                    .fixedSize(horizontal: false, vertical: true)
                    notes(palette)
                }
                .padding(.horizontal, 20).padding(.top, 8).padding(.bottom, 16)
            }
            .safeAreaInset(edge: .bottom) { slide(palette, level).padding(.horizontal, 20).padding(.bottom, 8) }
        }
        .toolbar(.hidden, for: .navigationBar)
        .animation(.easeInOut(duration: 0.25), value: level)
    }
    private var profile: SavedProfile? { model.vault.active }
    /// While the tunnel is up, the card names only the profile this app started.
    private var cardTitle: String {
        if model.active { return model.runningProfile?.name ?? loc("v3.card.unknown") }
        return profile?.name ?? loc("v3.card.noprofile")
    }
    private var cardDetail: String {
        if model.active { return model.runningProfile.map(shownHost) ?? loc("v3.card.unknown.detail") }
        return profile.map(shownHost) ?? loc("v3.add")
    }
    private func header(_ palette: Palette, _ level: TunnelLevel) -> some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Circle().fill(palette.fill(level.tone)).frame(width: 8, height: 8)
                Text(model.homeTag(level)).font(.system(size: 12, weight: .bold)).tracking(0.9).foregroundStyle(palette.muted).lineLimit(1)
            }
            .padding(.vertical, 8).padding(.horizontal, 12)
            .glass(palette, radius: 16)
            .accessibilityElement(children: .combine)
            Spacer(minLength: 8)
            roundButton("list.bullet", loc("v3.profiles"), palette) { open(.profiles) }
            roundButton("gearshape", loc("v3.settings"), palette) { open(.settings) }
        }
    }
    private func roundButton(_ symbol: String, _ label: String, _ palette: Palette, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol).font(.system(size: 17, weight: .semibold)).foregroundStyle(palette.text)
                .frame(width: 44, height: 44).glass(palette, radius: 22)
        }
        .buttonStyle(.plain).accessibilityLabel(label)
    }
    private func lines(_ level: TunnelLevel) -> (String, String) {
        switch level {
        case .off: return (loc("v3.off.1"), loc("v3.off.2"))
        case .connecting: return (loc("v3.tunnel"), loc(model.state == .reasserting ? "v3.reconnecting.2" : "v3.connecting.2"))
        case .disconnecting: return (loc("v3.tunnel"), loc("v3.disconnecting.2"))
        case .running: return (loc("v3.tunnel"), loc("v3.running.2"))
        case .verified: return (loc("v3.tunnel"), loc("v3.verified.2"))
        case .warning: return (loc("v3.warning.1"), loc("v3.warning.2"))
        case .error: return (loc("v3.error.1"), loc("v3.error.2"))
        }
    }
    private func headline(_ palette: Palette, _ level: TunnelLevel) -> some View {
        let (first, second) = lines(level)
        return VStack(alignment: .leading, spacing: 0) {
            Text(first).foregroundStyle(palette.text)
            Text(second).foregroundStyle(palette.text(level.tone))
        }
        .font(.system(size: headlineSize, weight: .heavy)).tracking(-0.8)
        .lineLimit(1).minimumScaleFactor(0.5)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isHeader)
    }
    private func checks(_ palette: Palette, _ level: TunnelLevel) -> some View {
        let rows = ObservationStatus.rows(status: model.state, level: level, snapshot: model.snapshot)
        return VStack(spacing: 0) {
            ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                HStack(spacing: 12) {
                    StateDot(dot: row.dot, palette: palette)
                    Text(row.name).font(.body.weight(.bold)).foregroundStyle(palette.text)
                    Spacer()
                    Text(row.value).font(.footnote.weight(.semibold)).foregroundStyle(row.tone.map { palette.text($0) } ?? palette.muted)
                }
                .padding(.vertical, 10)
                .accessibilityElement(children: .combine)
                if index < rows.count - 1 { Rectangle().fill(palette.rule).frame(height: 1) }
            }
        }
        .padding(.vertical, 6).padding(.horizontal, 16)
        .glass(palette)
        .contentShape(Rectangle())
    }
    private func profileCard(_ palette: Palette) -> some View {
        Button { profile == nil ? add() : open(.profiles) } label: {
            VStack(alignment: .leading, spacing: 6) {
                CardLabel(text: loc("v3.card.profile"), palette: palette)
                Text(cardTitle).font(.body.weight(.heavy)).foregroundStyle(palette.text).lineLimit(1)
                Text(cardDetail).font(.caption).foregroundStyle(palette.muted).lineLimit(2)
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(14).glass(palette, radius: 22)
        }
        .buttonStyle(.plain)
    }
    private func onDemandCard(_ palette: Palette) -> some View {
        Button { open(.settings) } label: {
            VStack(alignment: .leading, spacing: 6) {
                CardLabel(text: loc("v3.card.ondemand"), palette: palette)
                Text(loc(model.onDemand ? "v3.on" : "v3.off")).font(.body.weight(.heavy)).foregroundStyle(palette.text)
                Text("VPN On Demand").font(.caption).foregroundStyle(palette.muted).lineLimit(1)
            }
            .frame(maxWidth: .infinity, alignment: .leading).padding(14).glass(palette, radius: 22)
        }
        .buttonStyle(.plain)
    }
    @ViewBuilder private func notes(_ palette: Palette) -> some View {
        if !VPNController.supportsVPN {
            Text(tr("Simulator: import and interface testing. VPN requires a physical iPhone.", "Симулятор: проверка импорта и интерфейса. Для VPN нужен физический iPhone."))
                .font(.footnote).foregroundStyle(palette.muted)
        }
        if let error = model.error { Text(error).font(.footnote).foregroundStyle(palette.danger) }
    }
    private func slide(_ palette: Palette, _ level: TunnelLevel) -> some View {
        let active = model.active
        let text: String
        switch level {
        case .off: text = loc("v3.slide.connect")
        case .connecting: text = loc("v3.slide.cancel")
        case .disconnecting: text = loc("v3.value.disconnecting")
        case .error: text = loc("v3.slide.retry")
        default: text = loc("v3.slide.disconnect")
        }
        let enabled = model.state != .disconnecting && VPNController.canToggle(
            active: active, hasProfile: model.vault.active != nil, busy: model.busy, supported: VPNController.supportsVPN)
        return SlideToAct(text: text, knob: palette.fill(level.tone), icon: level == .connecting ? palette.text(.blue) : palette.onFill(level.tone),
                          outline: level == .connecting, reverse: active, palette: palette) {
            Task { await model.toggle() }
        }
        .disabled(!enabled)
    }
}

// MARK: - Profiles

struct ProfilesView: View {
    @ObservedObject var model: VPNModel
    let add: () -> Void
    let export: (SavedProfile) -> Void
    let rename: (SavedProfile) -> Void
    let delete: (SavedProfile) -> Void
    @State private var query = ""
    @Environment(\.colorScheme) private var scheme
    private var filtered: [SavedProfile] {
        let needle = query.trimmingCharacters(in: .whitespaces)
        guard !needle.isEmpty else { return model.vault.profiles }
        return model.vault.profiles.filter { $0.name.localizedCaseInsensitiveContains(needle) || shownHost($0).localizedCaseInsensitiveContains(needle) }
    }
    var body: some View {
        let palette = Palette(scheme)
        ZStack {
            Backdrop(palette: palette)
            List {
                if model.vault.profiles.isEmpty {
                    Text(tr("Add a profile to get started", "Добавьте профиль для подключения")).foregroundStyle(palette.muted)
                        .listRowBackground(Color.clear).listRowSeparator(.hidden)
                } else if filtered.isEmpty {
                    Text(loc("v3.no.match")).foregroundStyle(palette.muted).listRowBackground(Color.clear).listRowSeparator(.hidden)
                }
                ForEach(filtered) { profile in
                    row(profile, palette)
                        .listRowBackground(Color.clear).listRowSeparator(.hidden)
                        .listRowInsets(EdgeInsets(top: 6, leading: 20, bottom: 6, trailing: 20))
                        .swipeActions(edge: .trailing) {
                            Button(tr("Delete", "Удалить"), role: .destructive) { delete(profile) }.disabled(!model.canEdit)
                            Button(tr("Export", "Экспорт")) { export(profile) }.tint(palette.text(.blue))
                        }
                        .contextMenu { actions(profile) }
                }
                Text(loc("v3.profiles.hint")).font(.caption).foregroundStyle(palette.muted)
                    .listRowBackground(Color.clear).listRowSeparator(.hidden)
                if let error = model.error {
                    Text(error).font(.footnote).foregroundStyle(palette.danger).listRowBackground(Color.clear).listRowSeparator(.hidden)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
            .searchable(text: $query, prompt: loc("v3.profiles.search"))
        }
        .navigationTitle(loc("v3.profiles"))
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Text(loc("v3.profiles.count", model.vault.profiles.count)).font(.footnote.weight(.bold)).foregroundStyle(palette.muted)
            }
        }
        .safeAreaInset(edge: .bottom) {
            Button(action: add) {
                Label(loc("v3.add"), systemImage: "plus").font(.body.weight(.heavy))
                    .frame(maxWidth: .infinity).frame(height: 58)
                    .foregroundStyle(palette.onBlue)
                    .background(Capsule().fill(palette.text(.blue)))
            }
            .buttonStyle(.plain)
            .disabled(!model.canEdit).opacity(model.canEdit ? 1 : 0.5)
            .padding(.horizontal, 20).padding(.bottom, 8)
        }
    }
    @ViewBuilder private func actions(_ profile: SavedProfile) -> some View {
        Button(tr("Make default for widgets", "По умолчанию для виджетов")) { model.makeDefault(profile.id) }.disabled(!model.canEdit)
        Button(tr("Export", "Экспорт")) { export(profile) }
        Button(tr("Rename", "Переименовать")) { rename(profile) }.disabled(!model.canEdit)
        Button(tr("Delete", "Удалить"), role: .destructive) { delete(profile) }.disabled(!model.canEdit)
    }
    private func row(_ profile: SavedProfile, _ palette: Palette) -> some View {
        let selected = model.vault.selected == profile.id
        let running = model.runningProfile?.id == profile.id
        return HStack(spacing: 12) {
            Button { model.select(profile.id) } label: {
                HStack(spacing: 12) {
                    Text(String(profile.name.prefix(2)).uppercased()).font(.footnote.weight(.heavy))
                        .foregroundStyle(selected ? palette.text(.blue) : palette.muted)
                        .frame(width: 44, height: 44)
                        .background(RoundedRectangle(cornerRadius: 15, style: .continuous).fill(selected ? palette.blueSoft : palette.chip))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 4) {
                        Text(profile.name).font(.body.weight(.heavy)).foregroundStyle(palette.text).lineLimit(1)
                        Text(shownHost(profile)).font(.caption).foregroundStyle(palette.muted).lineLimit(1)
                        HStack(spacing: 6) {
                            if model.vault.defaultProfile?.id == profile.id { chip(loc("v3.tag.default"), palette) }
                            chip(loc(profile.remoteID == nil ? "v3.tag.local" : "v3.tag.server"), palette)
                        }
                    }
                    Spacer(minLength: 4)
                    if running || selected { status(palette, running: running) }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(!model.canEdit)
            .accessibilityAddTraits(selected ? .isSelected : [])
            Menu { actions(profile) } label: {
                Image(systemName: "ellipsis").font(.body.weight(.bold)).foregroundStyle(palette.muted).frame(width: 32, height: 44)
            }
            .accessibilityLabel(tr("Actions", "Действия"))
        }
        .padding(14)
        .glass(palette)
    }
    private func chip(_ text: String, _ palette: Palette) -> some View {
        Text(text).font(.caption2).foregroundStyle(palette.muted).lineLimit(1)
            .padding(.vertical, 4).padding(.horizontal, 8)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(palette.chip))
    }
    /// The tunnel state is shown only on the profile this app started.
    private func status(_ palette: Palette, running: Bool) -> some View {
        TimelineView(.animation(minimumInterval: 1, paused: !(running && model.active))) { _ in
            let level = model.level
            let tone: StateTone = running ? level.tone : .grey
            let text = running ? loc("v3.tag." + level.rawValue).lowercased() : loc("v3.state.selected")
            HStack(spacing: 6) {
                Circle().fill(palette.fill(tone)).frame(width: 7, height: 7)
                Text(text).font(.caption.weight(.heavy)).foregroundStyle(palette.text(tone)).lineLimit(1)
            }
            .padding(.vertical, 6).padding(.horizontal, 10)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(tone == .grey ? palette.chip : palette.blueSoft))
        }
    }
}

// MARK: - Checks

struct ChecksView: View {
    @ObservedObject var model: VPNModel
    @Environment(\.colorScheme) private var scheme
    @Environment(\.scenePhase) private var scenePhase
    /// Re-evaluated every second while the tunnel is active so expired results lose
    /// their colour on time; the rest of the app is not invalidated by the clock.
    var body: some View {
        TimelineView(.animation(minimumInterval: 1, paused: !model.active)) { _ in content }
    }
    @ViewBuilder private var content: some View {
        let palette = Palette(scheme)
        let level = model.level
        let snapshot = model.snapshot
        ZStack {
            Backdrop(palette: palette, accent: palette.fill(level.tone))
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(ObservationStatus.rows(status: model.state, level: level, snapshot: snapshot)) { row in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack(spacing: 12) {
                                StateDot(dot: row.dot, palette: palette)
                                Text(row.name).font(.body.weight(.bold)).foregroundStyle(palette.text)
                                Spacer()
                                Text(row.value).font(.footnote.weight(.semibold)).foregroundStyle(row.tone.map { palette.text($0) } ?? palette.muted)
                            }
                            Text(loc("v3.note." + row.id)).font(.footnote).foregroundStyle(palette.muted).fixedSize(horizontal: false, vertical: true)
                            if let reason = reasonText(snapshot, row.id) {
                                Text(reason).font(.footnote).foregroundStyle(palette.muted).fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(14).frame(maxWidth: .infinity, alignment: .leading).glass(palette, radius: 22)
                        .accessibilityElement(children: .combine)
                    }
                    if let received = model.snapshotReceived {
                        Text(loc("v3.checks.received", received.formatted(date: .omitted, time: .standard)))
                            .font(.caption).foregroundStyle(palette.muted)
                    }
                    Text(loc("v3.checks.note")).font(.caption).foregroundStyle(palette.muted).fixedSize(horizontal: false, vertical: true)
                    flows(palette)
                }
                .padding(.horizontal, 20).padding(.vertical, 12)
            }
        }
        .navigationTitle(loc("v3.checks"))
        .onDisappear { model.stopFlowCapture() }
        .onChange(of: scenePhase) { phase in if phase != .active { model.stopFlowCapture() } }
    }
    private func reasonText(_ snapshot: [String: Any]?, _ key: String) -> String? {
        guard model.state == .connected, let code = ObservationStatus.reason(snapshot, key) else { return nil }
        let text = loc("v3.reason." + code)
        return text == "v3.reason." + code ? nil : text
    }
    /// Existing local flow-decision diagnostics (explicit, bounded, no addresses).
    private func flows(_ palette: Palette) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            CardLabel(text: tr("Local flow decisions", "Локальные решения маршрутизации"), palette: palette)
            Button(model.flowWanted ? tr("Stop observing", "Завершить наблюдение") : tr("Observe current flows", "Наблюдать текущие потоки")) {
                if model.flowWanted { model.stopFlowCapture() } else { model.startFlowCapture() }
            }
            .font(.body.weight(.bold))
            .disabled(!model.active && !model.flowWanted)
            Text(tr("Explicit local capture only. No addresses, traffic or profile credentials are recorded or sent. Shows decisions for up to 32 recent events, not a destination history or packet-delivery audit.", "Только явное локальное наблюдение. Адреса, трафик и пароли не записываются и не отправляются. До 32 текущих решений, а не история адресов или проверка доставки пакетов."))
                .font(.footnote).foregroundStyle(palette.muted).fixedSize(horizontal: false, vertical: true)
            if model.flowWanted { Text(model.flowSummary).font(.caption).foregroundStyle(palette.text) }
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading).glass(palette, radius: 22)
    }
}

// MARK: - Add profile

struct ImportView: View {
    @ObservedObject var model: VPNModel
    let initial: String
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var scheme
    @State private var input = ""
    @FocusState private var inputFocused: Bool
    @State private var filePicker = false
    @State private var camera = false
    @State private var photo: PhotosPickerItem?
    private var scannerAvailable: Bool { DataScannerViewController.isSupported && DataScannerViewController.isAvailable }
    var body: some View {
        let palette = Palette(scheme)
        NavigationStack {
            ZStack {
                Backdrop(palette: palette)
                ScrollView {
                    VStack(alignment: .leading, spacing: 14) {
                        if let preview = model.preview { previewCard(preview, palette) }
                        scanTile(palette)
                        HStack(spacing: 10) {
                            PhotosPicker(selection: $photo, matching: .images) {
                                tile("photo", loc("v3.qr.photo"), loc("v3.qr.photo.detail"), palette)
                            }
                            .buttonStyle(.plain)
                            Button { filePicker = true } label: { tile("doc", loc("v3.file"), loc("v3.file.detail"), palette) }
                                .buttonStyle(.plain)
                        }
                        pasteCard(palette)
                        NavigationLink { PortalView(model: model) } label: { portalRow(palette) }.buttonStyle(.plain)
                        if let error = model.error { Text(error).font(.footnote).foregroundStyle(palette.danger) }
                        Label(loc("v3.keychain.note"), systemImage: "lock").font(.caption).foregroundStyle(palette.muted)
                    }
                    .padding(.horizontal, 20).padding(.vertical, 12)
                }
            }
            .navigationTitle(loc("v3.add.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button(loc("v3.close")) { dismiss() } } }
            .onAppear { input = initial; model.preview = nil }
            .onDisappear { model.preview = nil }
            .fileImporter(isPresented: $filePicker, allowedContentTypes: [.data, .text]) { result in
                do {
                    let url = try result.get(); let access = url.startAccessingSecurityScopedResource()
                    defer { if access { url.stopAccessingSecurityScopedResource() } }
                    let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
                    model.previewImport(try handle.read(upToCount: 1_048_577) ?? Data())
                } catch { model.report(error) }
            }
            .onChange(of: photo) { item in
                Task {
                    do {
                        guard let data = try await item?.loadTransferable(type: Data.self) else { return }
                        let raw = try await Task.detached { try QRImage.decode(data) }.value
                        model.previewImport(Data(raw.utf8))
                    } catch { model.report(error) }
                    photo = nil
                }
            }
            .sheet(isPresented: $camera) {
                QRScanner { raw in camera = false; model.previewImport(Data(raw.utf8)) } failed: { camera = false; model.error = tr("Camera unavailable. Use QR from image.", "Камера недоступна. Выберите QR из изображения.") }
                    .ignoresSafeArea()
                    .privacyShield()
            }
        }
    }
    private func previewCard(_ preview: SavedProfile, _ palette: Palette) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            CardLabel(text: tr("Import preview", "Предпросмотр импорта"), palette: palette)
            Text(preview.name).font(.title3.weight(.heavy)).foregroundStyle(palette.text)
            Text(preview.hostname).font(.subheadline).foregroundStyle(palette.muted)
            Text(tr("Routing and DNS policy validated. Credentials are hidden.", "Маршрутизация и DNS проверены. Учётные данные скрыты.")).font(.caption).foregroundStyle(palette.muted)
            HStack(spacing: 10) {
                Button { model.acceptImport(); if model.preview == nil { dismiss() } } label: {
                    Text(tr("Add profile", "Добавить профиль")).font(.body.weight(.heavy)).frame(maxWidth: .infinity).frame(height: 48)
                        .foregroundStyle(palette.onBlue).background(Capsule().fill(palette.text(.blue)))
                }
                .buttonStyle(.plain).disabled(!model.canEdit)
                Button { model.preview = nil } label: {
                    Text(tr("Cancel", "Отмена")).font(.body.weight(.bold)).frame(height: 48).padding(.horizontal, 18)
                        .foregroundStyle(palette.text).background(Capsule().fill(palette.chip))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(14).frame(maxWidth: .infinity, alignment: .leading).glass(palette, radius: 22)
    }
    private func scanTile(_ palette: Palette) -> some View {
        Button { camera = true } label: {
            VStack(spacing: 12) {
                Image(systemName: "qrcode.viewfinder").font(.system(size: 84, weight: .thin)).foregroundStyle(Color(rgb: 0x4DA3FF))
                Text(scannerAvailable ? loc("v3.scan.detail") : loc("v3.scan.unavailable"))
                    .font(.footnote.weight(.semibold)).foregroundStyle(Color(rgb: 0xC9D3E0)).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity).frame(height: 200)
            .background(RoundedRectangle(cornerRadius: 28, style: .continuous).fill(Color(rgb: 0x05070A)))
        }
        .buttonStyle(.plain)
        .disabled(!scannerAvailable)
        .accessibilityLabel(loc("v3.scan"))
    }
    private func tile(_ symbol: String, _ title: String, _ detail: String, _ palette: Palette) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Image(systemName: symbol).font(.title3).foregroundStyle(palette.text(.blue)).accessibilityHidden(true)
            Text(title).font(.body.weight(.heavy)).foregroundStyle(palette.text)
            Text(detail).font(.caption).foregroundStyle(palette.muted)
        }
        .padding(14).frame(maxWidth: .infinity, minHeight: 112, alignment: .topLeading).glass(palette, radius: 22)
    }
    private func pasteCard(_ palette: Palette) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(loc("v3.paste.title")).font(.body.weight(.heavy)).foregroundStyle(palette.text)
            HStack(spacing: 8) {
                SecureField("tt:// · hy2:// · vless:// · TOML · YAML · JSON · conf", text: $input).focused($inputFocused)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .padding(.horizontal, 14).frame(height: 44)
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(palette.field))
                Button(tr("Preview", "Предпросмотр")) { inputFocused = false; model.previewImport(Data(input.utf8)); input = "" }
                    .font(.body.weight(.bold))
                    .disabled(input.isEmpty || !model.canEdit)
            }
            Text(loc("v3.paste.note")).font(.caption).foregroundStyle(palette.muted)
        }
        .padding(14).glass(palette, radius: 22)
    }
    private func portalRow(_ palette: Palette) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "icloud").font(.title3).foregroundStyle(palette.text(.blue)).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(loc("v3.portal")).font(.body.weight(.heavy)).foregroundStyle(palette.text)
                Text(loc("v3.portal.detail")).font(.caption).foregroundStyle(palette.muted)
            }
            Spacer()
            Image(systemName: "chevron.right").foregroundStyle(palette.muted).accessibilityHidden(true)
        }
        .padding(14).glass(palette, radius: 22)
    }
}
struct ProfileDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data, .json, .plainText] }
    var data: Data
    init(data: Data = Data()) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}
struct ExportView: View {
    let profile: SavedProfile
    @Environment(\.dismiss) private var dismiss
    @State private var format = 0
    @State private var consent = false
    @State private var save = false
    @State private var result: ExportResult?
    @State private var error: String?
    private let formats = ["JSON", "Endpoint TOML", "CLI TOML", "tt:// / hy2:// / vless://", "Conf"]
    private var suffix: String { ["json", "toml", "toml", "txt", "conf"][format] }
    var body: some View {
        NavigationStack {
            Form {
                Text(profile.name).font(.headline)
                Picker(tr("Format", "Формат"), selection: $format) { ForEach(0..<formats.count, id: \.self) { Text(formats[$0]).tag($0) } }
                if let losses = result?.losses, !losses.isEmpty {
                    Section(tr("Fields lost in this format", "Потери при экспорте")) { ForEach(losses, id: \.self) { Text($0).foregroundStyle(.orange) } }
                }
                Toggle(tr("I understand: the file contains credentials", "Понимаю: файл содержит учётные данные"), isOn: $consent)
                Button(tr("Save file", "Сохранить файл")) { save = true }.disabled(!consent || result?.content == nil)
                if let error { Text(error).foregroundStyle(.red) }
            }.navigationTitle(tr("Export", "Экспорт"))
                .toolbar { Button(tr("Close", "Закрыть")) { dismiss() } }
                .onAppear { generate() }.onChange(of: format) { _ in consent = false; generate() }
                .fileExporter(isPresented: $save, document: ProfileDocument(data: Data((result?.content ?? "").utf8)), contentType: format == 0 ? .json : (format == 3 ? .plainText : .data), defaultFilename: "R-TrustTunnel." + suffix) { response in
                    if case .failure = response { error = tr("Cannot export file", "Не удалось экспортировать файл") }
                    else { result = nil; dismiss() }
                }
        }
    }
    private func generate() {
        do { result = try ProfilePlan.export(profile.content, format: Int32(format)); error = nil }
        catch { result = nil; self.error = (error as? AppError)?.localizedDescription ?? "Export failed" }
    }
}
