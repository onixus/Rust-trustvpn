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
    var active: Bool { VPNController.isActive(state) }
    var canEdit: Bool { !busy && !active && !onDemand }
    var status: String {
        switch state {
        case .connected: return tr("Connected", "Подключено")
        case .connecting: return tr("Connecting", "Подключение")
        case .reasserting: return tr("Reconnecting", "Восстановление")
        case .disconnecting: return tr("Disconnecting", "Отключение")
        default: return tr("Disconnected", "Отключено")
        }
    }
    var color: Color { error != nil ? .red : state == .connected ? .green : active ? .orange : .gray }
    init() {
        observer = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
        }
        Task { await refresh(); busy = false }
    }
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
                _ = try ProfilePlan.parse(ProfileVault.load())
                let current = current ?? NETunnelProviderManager()
                let configuration = NETunnelProviderProtocol()
                configuration.providerBundleIdentifier = VPNController.providerID
                configuration.serverAddress = "R-TrustTunnel"
                // Credentials remain in Keychain. Provider reads the selected snapshot.
                current.protocolConfiguration = configuration
                current.localizedDescription = "R-TrustTunnel"
                current.isEnabled = true
                let rule = NEOnDemandRuleConnect(); rule.interfaceTypeMatch = .any
                current.onDemandRules = [rule]; current.isOnDemandEnabled = onDemand
                try await current.saveToPreferences()
                try await current.loadFromPreferences()
                manager = current
                try current.connection.startVPNTunnel()
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
