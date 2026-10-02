//! macOS delivers tt:// and hy2:// links as a kAEGetURL Apple Event instead of
//! argv, both on cold launch and to an already running instance. The handler
//! only queues the link; the UI drains it on its tick and shows the usual import
//! preview, so opening a link never connects or saves a profile by itself.
use objc2::{
    AllocAnyThread, define_class, msg_send,
    rc::Retained,
    runtime::{AnyObject, NSObject},
    sel,
};
use objc2_foundation::NSString;
use std::sync::Mutex;

const INTERNET_EVENT_CLASS: u32 = u32::from_be_bytes(*b"GURL");
const GET_URL: u32 = u32::from_be_bytes(*b"GURL");
const DIRECT_OBJECT: u32 = u32::from_be_bytes(*b"----");

static PENDING: Mutex<Option<String>> = Mutex::new(None);

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "RTrustOpenURLHandler"]
    struct Handler;

    impl Handler {
        #[unsafe(method(handleGetURL:withReplyEvent:))]
        fn handle_get_url(&self, event: &AnyObject, _reply: &AnyObject) {
            let descriptor: Option<Retained<AnyObject>> =
                unsafe { msg_send![event, paramDescriptorForKeyword: DIRECT_OBJECT] };
            let Some(descriptor) = descriptor else { return };
            let link: Option<Retained<NSString>> = unsafe { msg_send![&*descriptor, stringValue] };
            if let Some(link) = link {
                // Only the most recent link is kept, matching the single import preview.
                *PENDING.lock().unwrap_or_else(|e| e.into_inner()) = Some(link.to_string());
            }
        }
    }
);

/// Must run before the event loop starts so a launch-time link is not lost.
pub fn install() {
    let handler: Retained<Handler> = unsafe { msg_send![Handler::alloc(), init] };
    let manager: Retained<AnyObject> =
        unsafe { msg_send![objc2::class!(NSAppleEventManager), sharedAppleEventManager] };
    let _: () = unsafe {
        msg_send![&*manager, setEventHandler: &*handler,
            andSelector: sel!(handleGetURL:withReplyEvent:),
            forEventClass: INTERNET_EVENT_CLASS,
            andEventID: GET_URL]
    };
    // NSAppleEventManager does not retain the handler; it lives for the process.
    std::mem::forget(handler);
}

pub fn take() -> Option<String> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner()).take()
}
