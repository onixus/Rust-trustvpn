//! Read-only BPF tap for the guard probe: is one probe datagram seen leaving
//! a physical interface, and does the tap see this host's other output there
//! in the same window? Opens `/dev/bpf*` read-only with a filter on the
//! interface's own source MAC; nothing is injected, no interface setting
//! changes.
use crate::sysprobe::{
    Live,
    macos::{SNAPLEN, Seen, filter, scan},
};
use std::{
    ffi::CStr,
    net::{SocketAddr, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};
const BUFFER: u32 = 64 * 1024;
/// Our datagram, if it leaves, shows within this.
const WATCH: Duration = Duration::from_millis(300);
/// Keep watching for a control frame (this host's other output) up to this.
const CONTROL: Duration = Duration::from_millis(1_000);
const DLT_EN10MB: u32 = 1;
// <net/bpf.h>: _IOR/_IOW('B', 118/119, u_int).
const BIOCGSEESENT: libc::c_ulong = 0x4004_4276;
const BIOCSSEESENT: libc::c_ulong = 0x8004_4277;
#[repr(C)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct Program {
    len: libc::c_uint,
    insns: *const Insn,
}
#[repr(C)]
#[derive(Default)]
struct Stat {
    received: libc::c_uint,
    dropped: libc::c_uint,
}

/// The interface's own Ethernet address (AF_LINK, six bytes).
fn mac(interface: &str) -> Option<[u8; 6]> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut found = None;
    let mut entry = list;
    while !entry.is_null() {
        let item = unsafe { &*entry };
        entry = item.ifa_next;
        if item.ifa_addr.is_null() || item.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(item.ifa_name) };
        if name.to_bytes() != interface.as_bytes()
            || i32::from(unsafe { (*item.ifa_addr).sa_family }) != libc::AF_LINK
        {
            continue;
        }
        let link = unsafe { &*(item.ifa_addr as *const libc::sockaddr_dl) };
        let (start, length) = (usize::from(link.sdl_nlen), usize::from(link.sdl_alen));
        if length == 6 && usize::from(link.sdl_len) >= 8 + start + length {
            let data = unsafe {
                std::slice::from_raw_parts(link.sdl_data.as_ptr().cast::<u8>().add(start), 6)
            };
            found = data.try_into().ok();
        }
        break;
    }
    unsafe { libc::freeifaddrs(list) };
    found.filter(|m: &[u8; 6]| m.iter().any(|&b| b != 0))
}
fn open() -> Option<OwnedFd> {
    for n in 0..256 {
        let path = format!("/dev/bpf{n}\0");
        let path = CStr::from_bytes_with_nul(path.as_bytes()).ok()?;
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd >= 0 {
            return Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EBUSY) {
            return None;
        }
    }
    None
}
fn ioctl<T>(fd: &OwnedFd, request: libc::c_ulong, value: &mut T) -> bool {
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), request, value as *mut T) };
    result == 0
}
fn flush(fd: &OwnedFd) -> bool {
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCFLUSH as libc::c_ulong) };
    result == 0
}
/// Arm the tap on `interface` for frames from `mac`: SEESENT on and read
/// back, Ethernet only, buffer length as granted. Returns it with that length.
fn arm(interface: &str, mac: [u8; 6]) -> Option<(OwnedFd, usize)> {
    let name = interface.as_bytes();
    if name.len() >= 16 {
        return None;
    }
    let fd = open()?;
    let mut length = BUFFER;
    let mut request = [0u8; 32];
    request[..name.len()].copy_from_slice(name);
    let mut on: libc::c_uint = 1;
    let mut seesent: libc::c_uint = 0;
    let mut link: libc::c_uint = 0;
    let insns: Vec<Insn> = filter(mac)
        .iter()
        .map(|&(code, jt, jf, k)| Insn { code, jt, jf, k })
        .collect();
    let mut program = Program {
        len: insns.len() as libc::c_uint,
        insns: insns.as_ptr(),
    };
    let ready = ioctl(&fd, libc::BIOCSBLEN, &mut length)
        && ioctl(&fd, libc::BIOCSETIF, &mut request)
        && ioctl(&fd, libc::BIOCGBLEN, &mut length)
        && ioctl(&fd, libc::BIOCIMMEDIATE, &mut on)
        && ioctl(&fd, BIOCSSEESENT, &mut on)
        && ioctl(&fd, BIOCGSEESENT, &mut seesent)
        && ioctl(&fd, libc::BIOCGDLT, &mut link)
        && ioctl(&fd, libc::BIOCSETF, &mut program)
        && flush(&fd);
    let usable = length as usize >= SNAPLEN as usize + 32;
    (ready && usable && seesent == 1 && link == DLT_EN10MB).then_some((fd, length as usize))
}
/// Send one byte from `socket` (already bound to `interface`) to `target`
/// and watch the interface: for our datagram during WATCH, and until CONTROL
/// for any other frame this host sends there. Blocking, at most CONTROL.
/// Nothing is sent once the run that started it is gone.
pub(super) fn watched_send(
    interface: &str,
    socket: UdpSocket,
    target: SocketAddr,
    live: &Live,
) -> Seen {
    let Some(mac) = mac(interface) else {
        return Seen::Unknown;
    };
    let Some((fd, length)) = arm(interface, mac) else {
        return Seen::Unknown;
    };
    let Ok(port) = socket.local_addr().map(|a| a.port()) else {
        return Seen::Unknown;
    };
    if !live.get() {
        return Seen::Unknown;
    }
    let sent = crate::sysprobe::send(&socket, target);
    let started = Instant::now();
    let mut buffer = vec![0u8; length];
    let mut control = false;
    loop {
        let elapsed = started.elapsed();
        if elapsed >= CONTROL || (control && elapsed >= WATCH) {
            break;
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let wait = (CONTROL - elapsed).as_millis().max(1) as libc::c_int;
        let ready = unsafe { libc::poll(&mut poll, 1, wait) };
        if ready < 0 {
            return Seen::Unknown;
        }
        if ready == 0 {
            continue;
        }
        let read = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if read < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
                continue;
            }
            return Seen::Unknown;
        }
        let found = scan(&buffer[..read as usize], port, mac);
        if found.probe {
            return Seen::Captured;
        }
        if found.malformed {
            return Seen::Unknown;
        }
        control |= found.control;
    }
    let mut stat = Stat::default();
    if !ioctl(&fd, libc::BIOCGSTATS, &mut stat) || stat.dropped != 0 {
        return Seen::Unknown;
    }
    Seen::Silent { sent, control }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loopback_has_no_ethernet_address() {
        assert_eq!(mac("lo0"), None);
        assert_eq!(mac("rtrust-absent0"), None);
    }
    /// Lab positive control: without a full-tunnel guard the tap must see a
    /// datagram to the physical default gateway, or silence proves nothing.
    /// `sudo <test binary> --ignored tap_sees` with the VPN disconnected.
    #[test]
    #[ignore = "needs root and an unguarded physical default route"]
    fn tap_sees_an_unguarded_datagram() {
        let table = std::process::Command::new("/usr/sbin/netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            .unwrap();
        let entries =
            super::super::route_table::parse(&String::from_utf8(table.stdout).unwrap()).unwrap();
        let entry = entries
            .into_iter()
            .find(|e| e.destination == "default" && !e.interface.starts_with("utun"))
            .expect("physical default route");
        let gateway = crate::sysprobe::macos::gateway(&entry.gateway, &entry.interface)
            .expect("gateway address");
        let socket = super::super::probe::socket(false, &entry.interface).unwrap();
        let (_fence, live) = crate::sysprobe::fence();
        assert_eq!(
            watched_send(&entry.interface, socket, SocketAddr::new(gateway, 9), &live),
            Seen::Captured
        );
    }
    /// A dropped run sends nothing, even with the tap armed.
    #[test]
    #[ignore = "needs root and an unguarded physical default route"]
    fn tap_sends_nothing_for_a_dropped_run() {
        let table = std::process::Command::new("/usr/sbin/netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            .unwrap();
        let entries =
            super::super::route_table::parse(&String::from_utf8(table.stdout).unwrap()).unwrap();
        let entry = entries
            .into_iter()
            .find(|e| e.destination == "default" && !e.interface.starts_with("utun"))
            .expect("physical default route");
        let gateway = crate::sysprobe::macos::gateway(&entry.gateway, &entry.interface)
            .expect("gateway address");
        let socket = super::super::probe::socket(false, &entry.interface).unwrap();
        let (fence, live) = crate::sysprobe::fence();
        drop(fence);
        assert_eq!(
            watched_send(&entry.interface, socket, SocketAddr::new(gateway, 9), &live),
            Seen::Unknown
        );
    }
}
