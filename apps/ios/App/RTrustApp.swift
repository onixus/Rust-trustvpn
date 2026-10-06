import SwiftUI
import PhotosUI
import VisionKit
import UniformTypeIdentifiers
import UIKit

final class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        PortalSync.register(); return true
    }
}
@main
struct RTrustApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var model = VPNModel()
    @Environment(\.scenePhase) private var phase
    @State private var captured = UIScreen.main.isCaptured
    var body: some Scene {
        WindowGroup {
            RootView(model: model)
                .overlay {
                    if phase != .active || captured {
                        ZStack { Color(.systemBackground).ignoresSafeArea(); Label("R-TrustTunnel", systemImage: "lock.shield").font(.title) }
                    }
                }
                .onReceive(NotificationCenter.default.publisher(for: UIScreen.capturedDidChangeNotification)) { _ in captured = UIScreen.main.isCaptured }
                .onChange(of: phase) { state in
                    if state == .active { Task { await model.refresh() } }
                    if state == .background { PortalSync.schedule() }
                }
        }
    }
}
struct RootView: View {
    @ObservedObject var model: VPNModel
    @State private var add = false
    @State private var incoming = ""
    @State private var exported: SavedProfile?
    @State private var deleting: SavedProfile?
    @State private var renaming: SavedProfile?
    @State private var name = ""
    var body: some View {
        TabView {
            NavigationStack {
                List {
                    if let selected = model.vault.active {
                        Section(tr("Default profile", "Основной профиль")) {
                            Label(selected.name, systemImage: "shield.lefthalf.filled").font(.headline)
                            Text(selected.hostname).foregroundStyle(.secondary)
                        }
                    }
                    Section(tr("Profiles", "Профили")) {
                        if model.vault.profiles.isEmpty { Text(tr("Add a profile to get started", "Добавьте профиль для подключения")) }
                        ForEach(model.vault.profiles) { profile in
                            HStack {
                                Button { model.select(profile.id) } label: {
                                    HStack {
                                        Image(systemName: model.vault.selected == profile.id ? "checkmark.circle.fill" : "circle")
                                        VStack(alignment: .leading) {
                                            Text(profile.name).foregroundStyle(.primary)
                                            Text(profile.remoteID == nil ? profile.hostname : tr("Server profile", "Серверный профиль")).font(.caption).foregroundStyle(.secondary)
                                        }
                                    }
                                }.disabled(!model.canEdit)
                                Spacer()
                                Menu {
                                    Button(tr("Export", "Экспорт")) { exported = profile }
                                    Button(tr("Rename", "Переименовать")) { renaming = profile; name = profile.name }.disabled(!model.canEdit)
                                    Button(tr("Delete", "Удалить"), role: .destructive) { deleting = profile }.disabled(!model.canEdit)
                                } label: { Image(systemName: "ellipsis.circle").padding(4) }
                            }
                        }
                    }
                    if !VPNController.supportsVPN { Text(tr("Simulator: import and interface testing. VPN requires a physical iPhone.", "Симулятор: проверка импорта и интерфейса. Для VPN нужен физический iPhone.")).font(.footnote).foregroundStyle(.secondary) }
                    if let error = model.error { Text(error).foregroundStyle(.red) }
                }
                .navigationTitle("R-TrustTunnel")
                .toolbar { Button { incoming = ""; add = true } label: { Image(systemName: "plus") }.disabled(!model.canEdit).accessibilityLabel(tr("Add profile", "Добавить профиль")) }
                .safeAreaInset(edge: .bottom) {
                    VStack(spacing: 8) {
                        Label(model.status, systemImage: "circle.fill").foregroundStyle(model.color).font(.caption)
                        Button { Task { await model.toggle() } } label: {
                            Label(model.active ? tr("Disconnect", "Отключить") : tr("Connect", "Подключить"), systemImage: "power").frame(maxWidth: .infinity).padding(8)
                        }.buttonStyle(.borderedProminent).tint(model.color)
                            .disabled(!VPNController.canToggle(active: model.active, hasProfile: model.vault.active != nil, busy: model.busy, supported: VPNController.supportsVPN))
                    }.padding().background(.ultraThinMaterial)
                }
            }.tabItem { Label(tr("Profiles", "Профили"), systemImage: "shield") }
            NavigationStack { SettingsView(model: model) }.tabItem { Label(tr("Settings", "Настройки"), systemImage: "gearshape") }
        }
        .sheet(isPresented: $add) { ImportView(model: model, initial: incoming) }
        .sheet(item: $exported) { ExportView(profile: $0) }
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
            guard ["tt", "hy2", "hysteria2"].contains(url.scheme?.lowercased() ?? ""), url.absoluteString.utf8.count <= 1_048_576 else { return }
            incoming = url.absoluteString; add = true
        }
    }
}
struct ImportView: View {
    @ObservedObject var model: VPNModel
    let initial: String
    @Environment(\.dismiss) private var dismiss
    @State private var input = ""
    @FocusState private var inputFocused: Bool
    @State private var filePicker = false
    @State private var camera = false
    @State private var photo: PhotosPickerItem?
    var body: some View {
        NavigationStack {
            Form {
                Section(tr("Configuration or link", "Конфигурация или ссылка")) {
                    SecureField("tt:// · hy2:// · TOML · YAML · JSON · conf", text: $input).focused($inputFocused).textInputAutocapitalization(.never).autocorrectionDisabled()
                    Button(tr("Preview", "Предпросмотр")) { inputFocused = false; model.previewImport(Data(input.utf8)); input = "" }.disabled(input.isEmpty || !model.canEdit)
                    Button(tr("Open file", "Открыть файл")) { filePicker = true }
                    PhotosPicker(selection: $photo, matching: .images) { Label(tr("QR from image", "QR из изображения"), systemImage: "photo") }
                    Button { camera = true } label: { Label(tr("Scan QR", "Сканировать QR"), systemImage: "qrcode.viewfinder") }
                        .disabled(!DataScannerViewController.isSupported || !DataScannerViewController.isAvailable)
                }
                if let preview = model.preview {
                    Section(tr("Import preview", "Предпросмотр импорта")) {
                        Text(preview.name).font(.headline); Text(preview.hostname)
                        Text(tr("Routing and DNS policy validated. Credentials are hidden.", "Маршрутизация и DNS проверены. Учётные данные скрыты.")).font(.caption)
                        Button(tr("Add profile", "Добавить профиль")) { model.acceptImport(); if model.preview == nil { dismiss() } }.disabled(!model.canEdit)
                    }
                }
                if let error = model.error { Text(error).foregroundStyle(.red) }
            }.navigationTitle(tr("Add profile", "Добавить профиль"))
                .toolbar { Button(tr("Close", "Закрыть")) { dismiss() } }
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
                }
        }
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
    private let formats = ["JSON", "Endpoint TOML", "CLI TOML", "tt:// / hy2://", "Conf"]
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
