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
    private func observationLabel(_ key: String) -> String {
        guard Date().timeIntervalSince(observationReceived) <= 6,
              let o = observations?[key] as? [String: Any], let outcome = o["outcome"] as? String else { return tr("unchecked", "не проверено") }
        if outcome == "passed" || outcome == "configured" {
            let time = (o["observed_at_ms"] as? NSNumber)?.doubleValue ?? 0
            let age = Date().timeIntervalSince1970 * 1000 - time
            if age < 0 || age > 6000 { return tr("stale", "устарело") }
        }
        switch outcome {
        case "passed": return tr("verified", "проверено")
        case "configured": return tr("running, availability unchecked", "запущен, доступность не проверена")
        case "failed": return tr("failed", "сбой")
        case "stale": return tr("stale", "устарело")
        case "unsupported": return tr("check unsupported", "проверка не поддерживается")
        default: return tr("unchecked", "не проверено")
        }
    }
    private func refreshObservations() {
        observationEpoch &+= 1
        let epoch = observationEpoch
        observations = nil
        guard active, let session = manager?.connection as? NETunnelProviderSession else { return }
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
    var status: String {
        switch state {
        case .connected: return [tr("Transport", "Транспорт") + ": " + observationLabel("transport"),
            tr("route", "маршрут") + ": " + observationLabel("route"), "DNS: " + observationLabel("dns"),
            tr("guard", "защита") + ": " + observationLabel("guard"), tr("connectivity", "доступность") + ": " + observationLabel("connectivity")].joined(separator: " · ")
        case .connecting: return tr("Connecting", "Подключение")
        case .reasserting: return tr("Reconnecting", "Восстановление")
        case .disconnecting: return tr("Disconnecting", "Отключение")
        default: return tr("Disconnected", "Отключено")
        }
    }
    var color: Color { error != nil ? .red : active ? .orange : .gray }
    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        observationTimer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refreshObservations(); self?.refreshFlowCapture() }
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
            state = manager?.connection.status ?? .disconnected
            onDemand = manager?.isOnDemandEnabled ?? false
            refreshObservations()
            WidgetState.update(state)
        } catch { self.error = tr("Cannot load VPN configuration", "Не удалось загрузить конфигурацию VPN") }
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
        do {
            let current = try await VPNController.manager()
            if let current, VPNController.isActive(current.connection.status) {
                current.isOnDemandEnabled = false
                try await current.saveToPreferences()
                current.connection.stopVPNTunnel()
            } else {
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
                try await VPNController.start(current, profileID: profileID)
                manager = current
            }
            error = nil; await refresh()
        } catch { report(error) }
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
