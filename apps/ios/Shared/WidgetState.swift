import Foundation
import NetworkExtension
import WidgetKit

// Shared with the widget; no credentials or profile contents are stored here.
enum WidgetState {
    static let kind = "RTrustVPN"
    static var group: String { Bundle.main.object(forInfoDictionaryKey: "AppGroup") as? String ?? "invalid" }
    static var defaults: UserDefaults? { UserDefaults(suiteName: group) }
    static func update(_ status: NEVPNStatus) {
        defaults?.set(status.rawValue, forKey: "vpnStatus")
        defaults?.set(Date().timeIntervalSince1970, forKey: "statusDate")
        WidgetCenter.shared.reloadTimelines(ofKind: kind)
    }
}
