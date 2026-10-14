import SwiftUI
import NetworkExtension
import WidgetKit

@MainActor
final class VPNModel: ObservableObject {
    @Published var vault = VaultData()
    @Published var state: NEVPNStatus = .disconnected
    @Published var error: String?
    @Published var busy = true
    @Published var onDemand = false
    @Published var preview: SavedProfile?
    private var manager: NETunnelProviderManager?
    private var observer: NSObjectProtocol?
    private var observationTimer: Timer?
    private var observationEpoch: UInt64 = 0
    @Published private var observations: [String: Any]?
    private var observationReceived = Date.distantPast
    private var observationTick = 0
    /// True after a connection attempt ended before the tunnel came up (or the start call
    /// threw). Cleared by the next toggle or a connected state. Drives the red state only.
    @Published private(set) var attemptFailed = false
    private var attempting = false
    /// Profile this app passed to startTunnel in this session. nil when the tunnel was
    /// started elsewhere (widget, On Demand, an earlier app session): the provider then
    /// loads the default profile itself, so the UI names no profile.
    @Published private(set) var runningProfileID: String?
    var runningProfile: SavedProfile? {
        guard active, let id = runningProfileID else { return nil }
        return vault.profiles.first { $0.id == id }
    }
    /// The provider snapshot if it was received in the last 6 seconds while connected.
    var snapshot: [String: Any]? {
        guard state == .connected, Date().timeIntervalSince(observationReceived) <= 6 else { return nil }
        return observations
    }
    var snapshotReceived: Date? { snapshot == nil ? nil : observationReceived }
    var level: TunnelLevel {
        state == .connected ? ObservationStatus.level(snapshot) : TunnelLevel.transport(state, attemptFailed: attemptFailed)
    }
    private func refreshObservations() {
        observationEpoch &+= 1
        let epoch = observationEpoch
        // Old results are not cleared on every poll (that would flicker); freshness is
        // enforced by the receive time above and each check's own TTL.
        guard active, let session = manager?.connection as? NETunnelProviderSession else { observations = nil; return }
        try? session.sendProviderMessage(Data("observations-v1".utf8)) { [weak self] data in
            Task { @MainActor in
                guard let self, epoch == self.observationEpoch, self.active,
                      let data, data.count <= 65536,
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                      object["schema"] as? Int == 2 else { return }
                self.observations = object
                self.observationReceived = Date()
            }
        }
    }
    @Published var flowWanted = false
    @Published var flowSummary = ""
    private var flowEpoch: UInt64 = 0
    private var flowToken: [String: Any]?
    private func flowMessage(_ operation: UInt8, _ token: [String: Any]?, completion: @escaping ([String: Any]?) -> Void) {
        guard let session = manager?.connection as? NETunnelProviderSession,
              let data = try? JSONSerialization.data(withJSONObject: ["type":"flow-capture-v1", "operation":operation,
                "session":token?["session"] ?? 0, "capture":token?["capture"] ?? 0]) else { completion(nil); return }
        do { try session.sendProviderMessage(data) { data in
            Task { @MainActor in
                guard let data, data.count <= 65536,
                      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { completion(nil); return }
                completion(object)
            }
        } } catch { completion(nil) }
    }
    func startFlowCapture() {
        guard active, !flowWanted else { return }
        flowWanted = true; flowEpoch &+= 1; let epoch = flowEpoch
        flowSummary = tr("Starting local observation", "Запуск локального наблюдения")
        flowMessage(0, nil) { [weak self] identity in
            guard let self, epoch == self.flowEpoch, self.flowWanted else { return }
            guard self.active, let token = identity?["token"] as? [String: Any] else {
                self.stopFlowCapture(); self.error = tr("Flow observation unavailable", "Наблюдение потоков недоступно"); return
            }
            self.flowMessage(1, token) { [weak self] result in
                guard let self else { return }
                guard let accepted = result?["token"] as? [String: Any] else {
                    if epoch == self.flowEpoch { self.stopFlowCapture() }
                    return
                }
                guard epoch == self.flowEpoch, self.flowWanted, self.active else {
                    self.flowMessage(2, accepted) { _ in }; return
                }
                self.flowToken = accepted; self.refreshFlowCapture()
            }
        }
    }
    func stopFlowCapture() {
        flowEpoch &+= 1; flowWanted = false; flowSummary = ""
        let token = flowToken; flowToken = nil
        if let token { flowMessage(2, token) { _ in } }
    }
    private func refreshFlowCapture() {
        guard flowWanted else { return }
        guard active else { stopFlowCapture(); return }
        guard let token = flowToken else { return }
        let epoch = flowEpoch
        flowMessage(3, token) { [weak self] result in
            guard let self, epoch == self.flowEpoch, self.flowWanted else { return }
            guard let result, result["error"] == nil, result["enabled"] as? Bool == true else { self.stopFlowCapture(); return }
            var lines = [tr("Actual flow policy selections, not delivery or OS protection. Addresses are not recorded.", "Реальные решения политики, а не доставка или системная защита. Адреса не записываются.")]
            let lagged = result["lagged"] as? UInt64 ?? 0, stale = result["discarded_stale"] as? UInt64 ?? 0
            if lagged > 0 { lines.append(tr("Events lost: ", "Событий потеряно: ") + String(lagged)) }
            if stale > 0 { lines.append(tr("Old policy events discarded: ", "События прежней политики отброшены: ") + String(stale)) }
            let oversized = result["discarded_oversize"] as? UInt64 ?? 0
            if oversized > 0 { lines.append(tr("Events omitted for size: ", "События пропущены по размеру: ") + String(oversized)) }
            let events = result["events"] as? [[String: Any]] ?? []
            if events.isEmpty { lines.append(tr("No new observed decisions", "Новых решений нет")) }
            for event in events.prefix(32) {
                guard let decision = event["decision"] as? [String: Any], decision["prediction"] as? Bool == false else { continue }
                let action: String
                switch decision["action"] as? String {
                case "tunnel": action = "VPN"
                case "direct": action = tr("Direct", "Напрямую")
                case "block": action = tr("Blocked", "Заблокировано")
                default: action = tr("Unknown", "Неизвестно")
                }
                let reason: String
                switch decision["reason"] as? String {
                case "dns_always_tunneled": reason = tr("DNS uses VPN", "DNS через VPN")
                case "matched_rule": reason = tr("matching rule", "совпало правило")
                case "default_tunnel": reason = tr("default VPN policy", "VPN по умолчанию")
                case "default_direct": reason = tr("default direct policy", "напрямую по умолчанию")
                case "unknown_name_protected": reason = tr("unknown name stays protected", "неизвестное имя защищено")
                case "shared_ip_conflict_protected": reason = tr("conflicting names stay protected", "конфликт имён защищён")
                default: reason = tr("other policy reason", "другая причина политики")
                }
                let source = (decision["context"] as? [String: Any])?["source"] as? String
                let sourceText = source == "embedded_profile" ? tr("profile policy", "политика профиля") : tr("other policy source", "другой источник политики")
                let epoch = (event["version"] as? [String: Any])?["epoch"] as? UInt64 ?? 0
                let age = event["age_ms"] as? UInt64 ?? 0
                let revision = (event["version"] as? [String: Any])?["revision"] as? String ?? ""
                let opaque = revision.count == 64 && revision.allSatisfy({ "0123456789abcdef".contains($0) }) ? String(revision.prefix(12)) : tr("opaque revision", "непрозрачная ревизия")
                lines.append(action + " · " + reason + " · " + sourceText + " · " + tr("policy ", "политика ") + opaque + " / " + String(epoch) + " · " + String(age) + " ms")
            }
            self.flowSummary = lines.joined(separator:"\n")
        }
    }
    var active: Bool { VPNController.isActive(state) }
    var canEdit: Bool { !busy && !active && !onDemand }
    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        // Re-render every second so expired results lose their colour on time;
        // ask the provider every third tick.
        observationTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.observationTick &+= 1
                if self.observationTick % 3 == 0 { self.refreshObservations(); self.refreshFlowCapture() }
                if self.active { self.objectWillChange.send() }
            }
        }
        Task { await refresh(); busy = false }
    }
    deinit { observationTimer?.invalidate() }
    func report(_ error: Error) {
        self.error = (error as? AppError)?.localizedDescription ?? ((error as NSError).domain == "RTrustPortal" ? error.localizedDescription : tr("Operation failed. Saved profiles were preserved.", "Операция не выполнена. Сохранённые профили не изменены."))
    }
    func reloadVault() { do { vault = try ProfileVault.snapshot() } catch { report(error) } }
    func refresh() async {
        reloadVault()
        guard VPNController.supportsVPN else { WidgetState.update(.disconnected); return }
        do {
            manager = try await VPNController.manager()
            track(manager?.connection.status ?? .disconnected)
            onDemand = manager?.isOnDemandEnabled ?? false
            refreshObservations()
            WidgetState.update(state)
        } catch { self.error = tr("Cannot load VPN configuration", "Не удалось загрузить конфигурацию VPN") }
    }
    /// Records whether a connection attempt ended before the tunnel came up.
    /// Only status transitions are used; nothing is probed.
    func track(_ next: NEVPNStatus) {
        let wasUp = state == .connected || state == .reasserting
        switch next {
        // Only a fresh attempt counts; reasserting after a connected session does not.
        case .connecting: if !wasUp && !VPNController.userStopped { attempting = true }
        case .connected: attempting = false; attemptFailed = false
        case .disconnected, .invalid:
            if attempting && !VPNController.userStopped { attemptFailed = true }
            if attempting || VPNController.isActive(state) { runningProfileID = nil }
            attempting = false; VPNController.userStopped = false
        default: break
        }
        // Results from before a reconnect or stop must not reappear afterwards.
        if state == .connected && next != .connected { observations = nil }
        state = next
    }
    /// Records the profile passed by this app to startTunnel (also used by tests).
    func recordStart(_ profileID: String?) { runningProfileID = profileID }
    /// Status chip text; names a profile only if this app started it.
    func homeTag(_ level: TunnelLevel) -> String {
        if level == .off { return loc("v3.tag.off") }
        let state = loc("v3.tag." + level.rawValue)
        guard let profile = runningProfile else { return state }
        return profile.name.uppercased() + " · " + state
    }
    func homeDescription(_ level: TunnelLevel) -> String {
        switch level {
        case .off: return vault.active == nil ? loc("v3.desc.off.none") : loc("v3.desc.off")
        case .connecting:
            if state == .reasserting { return loc("v3.desc.reconnecting") }
            return runningProfile.map { loc("v3.desc.connecting", shownHost($0)) } ?? loc("v3.desc.connecting.unnamed")
        case .disconnecting: return loc("v3.desc.disconnecting")
        case .running: return loc("v3.desc.running")
        case .verified: return loc("v3.desc.verified")
        case .warning: return loc("v3.desc.warning", loc("v3.check." + (ObservationStatus.firstFailed(snapshot) ?? "transport")))
        case .error: return loc("v3.desc.error")
        }
    }
    func previewImport(_ data: Data) {
        guard canEdit else { error = tr("Disconnect and disable On Demand before editing profiles", "Перед изменением профилей отключите VPN и On Demand"); return }
        do { preview = SavedProfile.imported(try ProfilePlan.parse(data)); error = nil } catch { report(error) }
    }
    func acceptImport() {
        guard canEdit, let profile = preview else { return }
        do {
            try ProfileVault.edit { vault in vault.profiles.append(profile); if vault.selected == nil { vault.selected = profile.id } }
            preview = nil; reloadVault()
        } catch { report(error) }
    }
    func select(_ id: String) {
        guard canEdit else { return }
        do { try ProfileVault.edit { $0.selected = id }; reloadVault() } catch { report(error) }
    }
    func makeDefault(_ id: String) {
        guard canEdit else { return }
        do { try ProfileVault.edit { vault in
            guard vault.profiles.contains(where: { $0.id == id }) else { throw AppError.message("Profile no longer exists") }
            vault.defaultProfileID = id
        }; reloadVault() } catch { report(error) }
    }
    func delete(_ id: String) {
        guard canEdit else { return }
        do { try ProfileVault.edit { $0.profiles.removeAll { $0.id == id }; $0.repairSelection() }; reloadVault() } catch { report(error) }
    }
    func rename(_ id: String, name: String) {
        guard canEdit else { return }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 80 else { return }
        do {
            try ProfileVault.edit { vault in if let index = vault.profiles.firstIndex(where: { $0.id == id }) { vault.profiles[index].name = name } }
            reloadVault()
        } catch { report(error) }
    }
    func toggle() async {
        guard !busy, VPNController.supportsVPN else { return }
        busy = true; defer { busy = false }
        attemptFailed = false
        var starting = false
        do {
            let current = try await VPNController.manager()
            if let current, VPNController.isActive(current.connection.status) {
                current.isOnDemandEnabled = false
                try await current.saveToPreferences()
                VPNController.userStopped = true
                current.connection.stopVPNTunnel()
            } else {
                starting = true
                guard let profileID = vault.selected else { throw AppError.message("Select a profile first") }
                _ = try ProfilePlan.parse(ProfileVault.load(profileID: profileID))
                let current = current ?? NETunnelProviderManager()
                let configuration = NETunnelProviderProtocol()
                configuration.providerBundleIdentifier = VPNController.providerID
                configuration.serverAddress = "R-TrustTunnel"
                // Credentials remain in Keychain. Provider reads the selected snapshot.
                current.protocolConfiguration = configuration
                current.localizedDescription = "R-TrustTunnel"
                let rule = NEOnDemandRuleConnect(); rule.interfaceTypeMatch = .any
                current.onDemandRules = [rule]; current.isOnDemandEnabled = onDemand
                recordStart(profileID)
                try await VPNController.start(current, profileID: profileID)
                // A start that fails before .connecting is observed still counts as an attempt.
                attempting = true
                manager = current
            }
            error = nil; await refresh()
        } catch {
            if starting { attemptFailed = true; attempting = false; recordStart(nil) }
            report(error)
        }
    }
    func setOnDemand(_ enabled: Bool) async {
        guard !busy, VPNController.supportsVPN else { return }
        busy = true; defer { busy = false }
        do {
            guard let current = try await VPNController.manager() else { throw AppError.message(tr("Connect once to authorize VPN first", "Сначала подключитесь и разрешите VPN")) }
            if enabled { _ = try ProfilePlan.parse(ProfileVault.load()) }
            let rule = NEOnDemandRuleConnect(); rule.interfaceTypeMatch = .any
            current.onDemandRules = [rule]; current.isOnDemandEnabled = enabled
            try await current.saveToPreferences()
            await refresh()
        } catch { report(error) }
    }
    func portalOperation(_ operation: () async throws -> Void) async {
        guard !busy else { return }
        busy = true; defer { busy = false; reloadVault(); PortalSync.schedule() }
        do { try await operation(); error = nil } catch { report(error) }
    }
}

/// Localized UI string from Resources/<lang>.lproj/Localizable.strings. The language is
/// chosen by the same rule as `tr`, so new and existing strings never mix languages.
func loc(_ key: String, _ arguments: CVarArg...) -> String {
    let language = Locale.preferredLanguages.first?.hasPrefix("ru") == true ? "ru" : "en"
    let bundle = Bundle.main.path(forResource: language, ofType: "lproj").flatMap(Bundle.init(path:)) ?? .main
    let format = bundle.localizedString(forKey: key, value: key, table: nil)
    return arguments.isEmpty ? format : String(format: format, locale: Locale(identifier: language), arguments: arguments)
}

/// Rendering of the Rust core observation snapshot (schema 2), same rules as Android
/// ObservationStatus: only every check passed and fresh is verified.
enum ObservationStatus {
    static let keys = ["transport", "route", "dns", "guard", "connectivity"]
    /// Normalised outcome. Passed/configured results become stale after
    /// min(6 s, valid_for_ms); a missing check is "unknown" (never passed).
    static func outcome(_ observation: Any?, nowMs: Double = Date().timeIntervalSince1970 * 1000) -> String {
        guard let observation = observation as? [String: Any], let outcome = observation["outcome"] as? String else { return "unknown" }
        if outcome == "passed" || outcome == "configured" {
            guard let time = (observation["observed_at_ms"] as? NSNumber)?.doubleValue else { return "stale" }
            let ttl = min(6000, (observation["valid_for_ms"] as? NSNumber)?.doubleValue ?? 0)
            if nowMs < time || nowMs - time > ttl { return "stale" }
        }
        return ["passed", "failed", "configured", "stale", "unsupported"].contains(outcome) ? outcome : "unknown"
    }
    static func valid(_ snapshot: [String: Any]?) -> [String: Any] {
        guard let snapshot, snapshot["schema"] as? Int == 2 else { return [:] }
        return snapshot
    }
    /// Level of a connected tunnel: warning if any check failed, verified only if all
    /// five passed and are fresh, otherwise running.
    static func level(_ snapshot: [String: Any]?, nowMs: Double = Date().timeIntervalSince1970 * 1000) -> TunnelLevel {
        let snapshot = valid(snapshot)
        var verified = true
        for key in keys {
            let value = outcome(snapshot[key], nowMs: nowMs)
            if value == "failed" { return .warning }
            if value != "passed" { verified = false }
        }
        return verified ? .verified : .running
    }
    static func firstFailed(_ snapshot: [String: Any]?, nowMs: Double = Date().timeIntervalSince1970 * 1000) -> String? {
        let snapshot = valid(snapshot)
        return keys.first { outcome(snapshot[$0], nowMs: nowMs) == "failed" }
    }
    static func reason(_ snapshot: [String: Any]?, _ key: String) -> String? {
        (valid(snapshot)[key] as? [String: Any])?["reason"] as? String
    }
}

enum CheckDot: Equatable { case filled(StateTone), ring(StateTone), empty }
struct CheckRow: Identifiable, Equatable {
    let id: String
    let name: String
    let value: String
    let dot: CheckDot
    var tone: StateTone? {
        switch dot {
        case .filled(let tone), .ring(let tone): return tone
        case .empty: return nil
        }
    }
}
extension ObservationStatus {
    /// One row per check. Only a connected tunnel shows snapshot results; otherwise the
    /// transport row follows the system VPN status and every other check is "no data".
    static func rows(status: NEVPNStatus, level: TunnelLevel, snapshot: [String: Any]?,
                     nowMs: Double = Date().timeIntervalSince1970 * 1000) -> [CheckRow] {
        let noData = (loc("v3.value.nodata"), CheckDot.empty)
        return keys.map { key in
            let (value, dot): (String, CheckDot)
            if status == .connected {
                switch outcome(valid(snapshot)[key], nowMs: nowMs) {
                case "passed": (value, dot) = (loc("v3.value.passed"), .filled(.green))
                case "failed": (value, dot) = (loc("v3.value.failed"), .filled(.yellow))
                case "configured": (value, dot) = (loc("v3.value.running"), .filled(.blue))
                case "stale": (value, dot) = (loc("v3.value.stale"), .ring(.grey))
                case "unsupported": (value, dot) = (loc("v3.value.unsupported"), .ring(.grey))
                default: (value, dot) = noData
                }
            } else if key == "transport" {
                switch level {
                case .connecting: (value, dot) = (loc("v3.value.connecting"), .ring(.blue))
                case .disconnecting: (value, dot) = (loc("v3.value.disconnecting"), .ring(.grey))
                case .error: (value, dot) = (loc("v3.value.error"), .filled(.red))
                default: (value, dot) = (loc("v3.value.off"), .empty)
                }
            } else { (value, dot) = noData }
            return CheckRow(id: key, name: loc("v3.check." + key), value: value, dot: dot)
        }
    }
}
