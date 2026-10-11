// Loaded at runtime by the Rust app (dlopen); WidgetKit has no C/Objective-C API.
import WidgetKit

@_cdecl("rtrust_widget_reload")
public func rtrustWidgetReload() {
    WidgetCenter.shared.reloadTimelines(ofKind: "org.rtrusttunnel.vpn")
    if #available(macOS 26.0, *) {
        ControlCenter.shared.reloadControls(ofKind: "org.rtrusttunnel.vpn.control")
    }
}
