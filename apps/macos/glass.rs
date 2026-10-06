//! Public AppKit materials for the native desktop shell.
//! Called only on the UI thread. AppKit owns the wrapper after installation.
use objc2::{
    msg_send,
    rc::Retained,
    runtime::{AnyClass, AnyObject},
};
use objc2_foundation::{NSRect, NSString};

pub fn transparency_allowed() -> bool {
    unsafe {
        let Some(class) = AnyClass::get(c"NSWorkspace") else {
            return false;
        };
        let workspace: *mut AnyObject = msg_send![class, sharedWorkspace];
        let reduce: bool = msg_send![workspace, accessibilityDisplayShouldReduceTransparency];
        !reduce
    }
}

/// Insert a material behind the content; winit requires its own contentView identity.
pub unsafe fn install(window: *mut AnyObject) -> bool {
    if window.is_null() {
        return false;
    }
    unsafe {
        let content: *mut AnyObject = msg_send![window, contentView];
        if content.is_null() {
            return false;
        }
        let glass = AnyClass::get(c"NSGlassEffectView");
        let Some(class) = glass.or_else(|| AnyClass::get(c"NSVisualEffectView")) else {
            return false;
        };
        let parent: *mut AnyObject = msg_send![content, superview];
        if parent.is_null() {
            return false;
        }
        let bounds: NSRect = msg_send![content, frame];
        let allocated: *mut AnyObject = msg_send![class, alloc];
        let initialized: *mut AnyObject = msg_send![allocated, initWithFrame: bounds];
        let Some(wrapper) = Retained::from_raw(initialized) else {
            return false;
        };
        let _: () = msg_send![&*wrapper, setAutoresizingMask: 18usize]; // width + height
        // The Rust UI uses a dark palette regardless of the system appearance.
        let appearance_class = AnyClass::get(c"NSAppearance").unwrap();
        let name = NSString::from_str("NSAppearanceNameDarkAqua");
        let appearance: *mut AnyObject = msg_send![appearance_class, appearanceNamed: &*name];
        let _: () = msg_send![&*wrapper, setAppearance: appearance];
        if glass.is_some() {
            let _: () = msg_send![&*wrapper, setCornerRadius: 12.0f64];
            let _: () = msg_send![&*wrapper, setStyle: 0isize]; // regular glass preserves text contrast
        } else {
            let _: () = msg_send![&*wrapper, setMaterial: 12isize]; // underWindowBackground
            let _: () = msg_send![&*wrapper, setBlendingMode: 0isize]; // behindWindow
        }
        let _: () =
            msg_send![parent, addSubview: &*wrapper, positioned: -1isize, relativeTo: content];
        let _: () = msg_send![window, setOpaque: false];
        let color = AnyClass::get(c"NSColor").expect("AppKit NSColor");
        let clear: *mut AnyObject = msg_send![color, clearColor];
        let _: () = msg_send![window, setBackgroundColor: clear];
        if std::env::args().any(|arg| arg == "--ci-glass-smoke") {
            println!(
                "AppKit material: {}",
                if glass.is_some() {
                    "NSGlassEffectView"
                } else {
                    "NSVisualEffectView"
                }
            );
        }
        true
    }
}

/// Appearance preferences are separate from the encrypted VPN vault.
pub fn preference() -> bool {
    unsafe {
        let defaults: *mut AnyObject = msg_send![
            AnyClass::get(c"NSUserDefaults").unwrap(),
            standardUserDefaults
        ];
        let key = NSString::from_str("RTrustGlassEnabled");
        let value: *mut AnyObject = msg_send![defaults, objectForKey: &*key];
        value.is_null() || msg_send![defaults, boolForKey: &*key]
    }
}
pub fn save_preference(enabled: bool) {
    if std::env::args().any(|arg| arg.starts_with("--ci-")) {
        return;
    }
    unsafe {
        let defaults: *mut AnyObject = msg_send![
            AnyClass::get(c"NSUserDefaults").unwrap(),
            standardUserDefaults
        ];
        let key = NSString::from_str("RTrustGlassEnabled");
        let _: () = msg_send![defaults, setBool: enabled, forKey: &*key];
    }
}
