//! Native power notifications: early wake is not network readiness.
//! See Apple's QA1340 and IOPMLib.h's IORegisterForSystemPower contract.
use core_foundation::{
    base::TCFType,
    runloop::{CFRunLoop, CFRunLoopSource, CFRunLoopSourceRef, kCFRunLoopDefaultMode},
};
use std::{
    ffi::c_void,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;

const CAN_SLEEP: u32 = 0xe0000270;
const WILL_SLEEP: u32 = 0xe0000280;
const POWERED_ON: u32 = 0xe0000300;

#[derive(Clone, Copy, Debug)]
pub(super) struct State {
    pub awake: bool,
    pub generation: u64,
}
impl Default for State {
    fn default() -> Self {
        Self {
            awake: true,
            generation: 0,
        }
    }
}
struct Context {
    port: u32,
    events: watch::Sender<State>,
}
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IORegisterForSystemPower(
        context: *mut c_void,
        port: *mut *mut c_void,
        callback: unsafe extern "C" fn(*mut c_void, u32, u32, *mut c_void),
        notifier: *mut u32,
    ) -> u32;
    fn IOAllowPowerChange(port: u32, notification: isize) -> i32;
    fn IODeregisterForSystemPower(notifier: *mut u32) -> i32;
    fn IOServiceClose(port: u32) -> i32;
    fn IONotificationPortGetRunLoopSource(port: *mut c_void) -> CFRunLoopSourceRef;
    fn IONotificationPortDestroy(port: *mut c_void);
}
unsafe extern "C" fn callback(context: *mut c_void, _: u32, message: u32, argument: *mut c_void) {
    // Context stays boxed on the run-loop thread until the source is removed
    // and IOKit registration destroyed. Only this thread accesses its port.
    let context = unsafe { &*(context as *const Context) };
    match message {
        WILL_SLEEP | POWERED_ON => {
            context.events.send_modify(|s| {
                s.awake = message == POWERED_ON;
                s.generation = s.generation.wrapping_add(1);
            });
        }
        _ => {}
    }
    if message == CAN_SLEEP || message == WILL_SLEEP {
        // Never delay sleep waiting for transport/route cleanup, and never veto.
        unsafe {
            IOAllowPowerChange(context.port, argument as isize);
        }
    }
}

pub(super) struct Monitor {
    pub events: watch::Receiver<State>,
    stopped: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Monitor {
    pub fn new() -> Result<Self, String> {
        let (events, receiver) = watch::channel(State::default());
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("rtrust-power".into())
            .spawn(move || {
                let mut context = Box::new(Context { port: 0, events });
                let mut port = std::ptr::null_mut();
                let mut notifier = 0;
                context.port = unsafe {
                    IORegisterForSystemPower(
                        (&mut *context as *mut Context).cast(),
                        &mut port,
                        callback,
                        &mut notifier,
                    )
                };
                if context.port == 0 {
                    let _ = ready.send(Err("Cannot register macOS power notifications".to_owned()));
                    return;
                }
                let source = unsafe { IONotificationPortGetRunLoopSource(port) };
                if source.is_null() {
                    unsafe {
                        IODeregisterForSystemPower(&mut notifier);
                        IOServiceClose(context.port);
                        IONotificationPortDestroy(port);
                    }
                    let _ = ready.send(Err("Cannot create macOS power run loop".to_owned()));
                    return;
                }
                let source = unsafe { CFRunLoopSource::wrap_under_get_rule(source) };
                let run_loop = CFRunLoop::get_current();
                let mode = unsafe { kCFRunLoopDefaultMode };
                run_loop.add_source(&source, mode);
                let _ = ready.send(Ok(()));
                while !stop.load(Ordering::Acquire) {
                    CFRunLoop::run_in_mode(mode, Duration::from_millis(250), false);
                }
                run_loop.remove_source(&source, mode);
                unsafe {
                    IODeregisterForSystemPower(&mut notifier);
                    IOServiceClose(context.port);
                    IONotificationPortDestroy(port);
                }
            })
            .map_err(|_| "Cannot start macOS power monitor")?;
        let mut monitor = Self {
            events: receiver,
            stopped,
            thread: Some(thread),
        };
        if let Err(error) = started
            .recv()
            .map_err(|_| "macOS power monitor stopped".to_owned())
            .and_then(|r| r)
        {
            monitor.stopped.store(true, Ordering::Release);
            if let Some(thread) = monitor.thread.take() {
                let _ = thread.join();
            }
            return Err(error);
        }
        Ok(monitor)
    }
}
impl Drop for Monitor {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires access to native IOKit outside the sandbox"]
    fn native_registration_and_cleanup() {
        let monitor = Monitor::new().expect("register native power notifications");
        assert!(monitor.events.borrow().awake);
        drop(monitor);
    }
    #[test]
    fn early_wake_does_not_resume_transport() {
        let (events, receiver) = watch::channel(State::default());
        let context = Context { port: 0, events };
        // Invoke only non-acknowledged messages: no kernel operation in unit test.
        let ptr = (&context as *const Context).cast_mut().cast();
        context.events.send_modify(|s| s.awake = false);
        unsafe {
            callback(ptr, 0, 0xe0000320, std::ptr::null_mut());
        }
        assert!(!receiver.borrow().awake);
        unsafe {
            callback(ptr, 0, POWERED_ON, std::ptr::null_mut());
        }
        assert!(receiver.borrow().awake);
        assert_eq!(receiver.borrow().generation, 1);
    }
}
