import SwiftUI

struct SettingsView: View {
    @ObservedObject var model: VPNModel
    @State private var origin = ""
    @State private var code = ""
    @State private var deviceName = "iPhone"
    @State private var forget = false
    @State private var upload = false
    var body: some View {
        Form {
            Section(tr("Automatic connection", "Автоподключение")) {
                Toggle("On Demand", isOn: Binding(get: { model.onDemand }, set: { enabled in Task { await model.setOnDemand(enabled) } }))
                    .disabled(model.busy || !VPNController.supportsVPN)
                Text(tr("Connect once to authorize VPN. On Demand reconnects when needed; it is not Android lockdown. Disconnect also disables On Demand.", "Сначала подключитесь и разрешите VPN. On Demand подключает VPN по необходимости, но не заменяет Android lockdown. Отключение VPN также выключает On Demand.")).font(.footnote)
            }
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
            Section(tr("Routing and DNS", "Маршрутизация и DNS")) {
                Text(tr("Import portable general/selective rules, domains, CIDRs, ports, routes and DoH/DoT with the profile. Unsupported fields are rejected.", "Правила general/selective, домены, CIDR, порты, маршруты и DoH/DoT импортируются с профилем. Неподдерживаемые поля отклоняются."))
                Text(tr("Per-app VPN and enforced Always-on require managed-device capabilities on iOS. They are not offered as ordinary switches.", "VPN по приложениям и принудительный Always-on на iOS требуют управления устройством. Обычных переключателей для них здесь нет.")).font(.footnote).foregroundStyle(.secondary)
            }
            Section(tr("Widget", "Виджет")) {
                Text(tr("Add R-TrustTunnel from the Home Screen widget gallery, or the circular Lock Screen widget. On iOS 17+, the power button opens the app and toggles an already authorized VPN. Unlock is required. On iOS 16, tap to open the app.", "Добавьте R-TrustTunnel из галереи виджетов рабочего стола или круглый виджет экрана блокировки. На iOS 17+ кнопка открывает приложение и переключает уже разрешённый VPN. Требуется разблокировка. На iOS 16 нажатие открывает приложение."))
            }
            if model.busy { ProgressView() }
            if let error = model.error { Text(error).foregroundStyle(.red) }
        }.navigationTitle(tr("Settings", "Настройки"))
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
