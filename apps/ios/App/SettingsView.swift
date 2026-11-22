import SwiftUI
import UIKit

struct SettingsView: View {
    @ObservedObject var model: VPNModel
    @Environment(\.colorScheme) private var scheme
    @AppStorage(ThemeMode.key) private var theme = ThemeMode.system.rawValue
    @State private var checking = false
    @State private var updateNote: String?
    var body: some View {
        Form {
            Section(loc("v3.theme")) {
                Picker(loc("v3.theme"), selection: $theme) {
                    ForEach(ThemeMode.allCases) { Text(loc("v3.theme." + $0.rawValue)).tag($0.rawValue) }
                }
                .pickerStyle(.segmented)
            }
            Section(tr("Automatic connection", "Автоподключение")) {
                Toggle("On Demand", isOn: Binding(get: { model.onDemand }, set: { enabled in Task { await model.setOnDemand(enabled) } }))
                    .disabled(model.busy || !VPNController.supportsVPN)
                Text(tr("Connect once to authorize VPN. On Demand reconnects when needed; it is not Android lockdown. Disconnect also disables On Demand.", "Сначала подключитесь и разрешите VPN. On Demand подключает VPN по необходимости, но не заменяет Android lockdown. Отключение VPN также выключает On Demand.")).font(.footnote)
            }
            PortalSection(model: model)
            Section(tr("Routing and DNS", "Маршрутизация и DNS")) {
                Text(tr("Import portable general/selective rules, domains, CIDRs, ports, routes and DoH/DoT with the profile. Unsupported fields are rejected.", "Правила general/selective, домены, CIDR, порты, маршруты и DoH/DoT импортируются с профилем. Неподдерживаемые поля отклоняются."))
                Text(tr("Per-app VPN and enforced Always-on require managed-device capabilities on iOS. They are not offered as ordinary switches.", "VPN по приложениям и принудительный Always-on на iOS требуют управления устройством. Обычных переключателей для них здесь нет.")).font(.footnote).foregroundStyle(.secondary)
            }
            Section(tr("GitHub releases", "Релизы GitHub")) {
                Button(tr("Check GitHub", "Проверить GitHub")) { Task { await checkGitHub() } }
                    .disabled(checking)
                if let updateNote { Text(updateNote).font(.footnote) }
                Text(tr("No installable iOS package is published. A newer release only opens its page; nothing is downloaded or installed.", "Установочный пакет iOS не публикуется. Более новый релиз только открывает свою страницу; ничего не скачивается и не устанавливается.")).font(.footnote).foregroundStyle(.secondary)
            }
            Section(tr("Widget", "Виджет")) {
                Text(tr("Add R-TrustTunnel from the Home Screen widget gallery, or the circular Lock Screen widget. On iOS 17+, the power button opens the app and toggles an already authorized VPN. Unlock is required. On iOS 16, tap to open the app.", "Добавьте R-TrustTunnel из галереи виджетов рабочего стола или круглый виджет экрана блокировки. На iOS 17+ кнопка открывает приложение и переключает уже разрешённый VPN. Требуется разблокировка. На iOS 16 нажатие открывает приложение."))
            }
            if model.busy { ProgressView() }
            if let error = model.error { Text(error).foregroundStyle(.red) }
        }
        .scrollContentBackground(.hidden)
        .background(Backdrop(palette: Palette(scheme)))
        .navigationTitle(tr("Settings", "Настройки"))
    }

    /// Latest stable GitHub Release. iOS has no published installer, so a newer
    /// tag only opens the release page. SHA256SUMS is not consulted or trusted.
    private func checkGitHub() async {
        checking = true
        defer { checking = false }
        guard let url = URL(string: "https://api.github.com/repos/onixus/Rust-trustvpn/releases/latest") else { return }
        var request = URLRequest(url: url)
        request.setValue("rtrust-update", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let tag = json["tag_name"] as? String, json["draft"] as? Bool != true,
                  json["prerelease"] as? Bool != true else {
                updateNote = tr("GitHub check failed.", "Проверка GitHub не удалась.")
                return
            }
            let current = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
            let pageURL = "https://github.com/onixus/Rust-trustvpn/releases/tag/\(tag)"
            if GithubVersion(tag) > GithubVersion(current), GithubTag.isSafe(tag),
               let page = URL(string: pageURL), page.absoluteString == pageURL, page.host == "github.com" {
                updateNote = tr("GitHub \(tag) is newer. Opening the release page.", "GitHub \(tag) новее. Открываю страницу релиза.")
                await UIApplication.shared.open(page)
            } else {
                updateNote = tr("GitHub \(tag) is not newer than \(current).", "GitHub \(tag) не новее установленной \(current).")
            }
        } catch {
            updateNote = tr("GitHub check failed.", "Проверка GitHub не удалась.")
        }
    }
}

/// A release tag may only be a version-like token. Anything else is not opened.
private enum GithubTag {
    static func isSafe(_ tag: String) -> Bool {
        let rest = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        return !rest.isEmpty && rest.count <= 64 && rest.allSatisfy {
            $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_"
        }
    }
}

/// `major.minor.patch`, ignoring a leading `v` and a pre-release suffix.
private struct GithubVersion: Comparable {
    let parts: [Int]
    init(_ text: String) {
        let bare = text.hasPrefix("v") ? String(text.dropFirst()) : text
        let cut = bare.firstIndex(where: { $0 == "-" || $0 == "+" }) ?? bare.endIndex
        parts = bare[..<cut].split(separator: ".").compactMap { Int($0) }
    }
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.parts == rhs.parts
    }
    static func < (lhs: Self, rhs: Self) -> Bool {
        guard lhs.parts.count == 3, rhs.parts.count == 3 else { return false }
        return lhs.parts.lexicographicallyPrecedes(rhs.parts)
    }
}

/// Portal enrollment, synchronization, upload and removal (unchanged behaviour);
/// shown in Settings and reachable from Add profile.
struct PortalSection: View {
    @ObservedObject var model: VPNModel
    @State private var origin = ""
    @State private var code = ""
    @State private var deviceName = "iPhone"
    @State private var forget = false
    @State private var upload = false
    var body: some View {
        Section(tr("Server profiles", "Серверные профили")) {
            if let portal = model.vault.portal {
                Text(portal.origin).font(.caption)
                if portal.authExpired { Text(tr("Registration expired. Register again.", "Регистрация истекла. Зарегистрируйтесь заново.")).foregroundStyle(.red) }
                if let date = portal.lastSync { Text(date, style: .date); Text(date, style: .time) }
                Button(tr("Synchronize", "Синхронизировать")) {
                    Task { await model.portalOperation { try await PortalSync.run(background: false) } }
                }.disabled(!model.canEdit)
                Toggle(tr("Background sync", "Фоновая синхронизация"), isOn: Binding(get: { model.vault.portal?.backgroundSync ?? false }, set: { enabled in
                    do { try ProfileVault.edit { $0.portal?.backgroundSync = enabled }; model.reloadVault(); PortalSync.schedule() } catch { model.report(error) }
                })).disabled(model.busy || portal.authExpired)
                Text(tr("iOS chooses when background updates run. There is no guaranteed hourly schedule; the running tunnel keeps its profile until reconnect.", "iOS определяет время фонового обновления. Почасовой запуск не гарантирован; текущий туннель сохраняет профиль до переподключения.")).font(.footnote)
                Button(tr("Upload selected profile", "Загрузить выбранный профиль на сервер")) { upload = true }.disabled(model.busy || model.vault.active == nil)
                Button(tr("Remove registration", "Удалить регистрацию"), role: .destructive) { forget = true }.disabled(!model.canEdit)
            } else {
                TextField("https://vpn.example.com", text: $origin).textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                SecureField(tr("One-time code", "Одноразовый код"), text: $code).textInputAutocapitalization(.never).autocorrectionDisabled()
                TextField(tr("Device name", "Название устройства"), text: $deviceName)
                Button(tr("Register device", "Зарегистрировать устройство")) {
                    let secret = code; code = ""
                    Task { await model.portalOperation {
                        let session = try await PortalClient.enroll(origin: origin, code: secret, name: deviceName)
                        try ProfileVault.edit { vault in
                            guard vault.portal == nil else { throw AppError.message("Already registered") }
                            vault.portal = session
                        }
                    } }
                }.disabled(model.busy || code.isEmpty || origin.isEmpty)
            }
        }
        .alert(tr("Upload credentials?", "Передать учётные данные?"), isPresented: $upload) {
            Button(tr("Upload", "Передать")) {
                guard let session = model.vault.portal, let profile = model.vault.active else { return }
                Task { await model.portalOperation { try await PortalClient(session: session).upload(profile) } }
            }
            Button(tr("Cancel", "Отмена"), role: .cancel) {}
        } message: { Text(tr("The selected profile, including its credentials, will be sent to ", "Выбранный профиль с учётными данными будет передан на ") + (model.vault.portal?.origin ?? "")) }
        .alert(tr("Remove registration?", "Удалить регистрацию?"), isPresented: $forget) {
            Button(tr("Remove", "Удалить"), role: .destructive) {
                guard model.canEdit else { return }
                do {
                    try ProfileVault.edit { $0.profiles.removeAll { $0.remoteID != nil }; $0.portal = nil; $0.repairSelection() }
                    model.reloadVault(); PortalSync.schedule()
                } catch { model.report(error) }
            }
            Button(tr("Cancel", "Отмена"), role: .cancel) {}
        } message: { Text(tr("Downloaded profiles will be removed. Revoke the device in the server UI to invalidate its token.", "Загруженные профили будут удалены. Для отзыва токена отключите устройство на сервере.")) }
    }
}
struct PortalView: View {
    @ObservedObject var model: VPNModel
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        Form {
            PortalSection(model: model)
            if model.busy { ProgressView() }
            if let error = model.error { Text(error).foregroundStyle(.red) }
        }
        .scrollContentBackground(.hidden)
        .background(Backdrop(palette: Palette(scheme)))
        .navigationTitle(tr("Server profiles", "Серверные профили"))
    }
}
