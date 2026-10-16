//! Read-only BPF tap for the guard probe: is one probe datagram seen leaving
//! a physical interface? Opens `/dev/bpf*` read-only with a narrow filter;
//! nothing is injected and no interface setting changes.
use crate::sysprobe::macos::{FILTER, Seen, captured};
use std::{
    ffi::CStr,
    net::{SocketAddr, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};
const BUFFER: u32 = 64 * 1024;
const WATCH: Duration = Duration::from_millis(500);
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
/// Arm the tap on `interface`, verify it sees sent Ethernet frames, flush.
fn arm(interface: &str) -> Option<OwnedFd> {
    let fd = open()?;
    let mut length = BUFFER;
    let mut request = [0u8; 32];
    let name = interface.as_bytes();
    if name.len() >= 16 {
        return None;
    }
    request[..name.len()].copy_from_slice(name);
    let mut on: libc::c_uint = 1;
    let mut seesent: libc::c_uint = 0;
    let mut link: libc::c_uint = 0;
    let insns: Vec<Insn> = FILTER
        .iter()
        .map(|&(code, jt, jf, k)| Insn { code, jt, jf, k })
        .collect();
    let mut program = Program {
        len: insns.len() as libc::c_uint,
        insns: insns.as_ptr(),
    };
    let ready = ioctl(&fd, libc::BIOCSBLEN, &mut length)
        && ioctl(&fd, libc::BIOCSETIF, &mut request)
        && ioctl(&fd, libc::BIOCIMMEDIATE, &mut on)
        && ioctl(&fd, BIOCSSEESENT, &mut on)
        && ioctl(&fd, BIOCGSEESENT, &mut seesent)
        && ioctl(&fd, libc::BIOCGDLT, &mut link)
        && ioctl(&fd, libc::BIOCSETF, &mut program)
        && flush(&fd);
    (ready && seesent == 1 && link == DLT_EN10MB).then_some(fd)
}
/// Send one byte from `socket` (already bound to `interface`) to `target`
/// and watch the interface for it. Blocking, at most about WATCH.
pub(super) fn watched_send(interface: &str, socket: UdpSocket, target: SocketAddr) -> Seen {
    let Some(fd) = arm(interface) else {
        return Seen::Unknown;
    };
    let Ok(port) = socket.local_addr().map(|a| a.port()) else {
        return Seen::Unknown;
    };
    let sent = crate::sysprobe::send(&socket, target);
    let mut buffer = vec![0u8; BUFFER as usize];
    let deadline = Instant::now() + WATCH;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut poll, 1, left.as_millis().max(1) as libc::c_int) };
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
        if captured(&buffer[..read as usize], port) {
            return Seen::Captured;
        }
    }
    let mut stat = Stat::default();
    if !ioctl(&fd, libc::BIOCGSTATS, &mut stat) || stat.dropped != 0 {
        return Seen::Unknown;
    }
    Seen::Silent(sent)
}
fn flush(fd: &OwnedFd) -> bool {
    let result = unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCFLUSH as libc::c_ulong) };
    result == 0
}
#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(
            watched_send(&entry.interface, socket, SocketAddr::new(gateway, 9)),
            Seen::Captured
        );
    }
}
#[cfg(test)]
#[test]
fn darwin_errno_constants_match_libc() {
    assert_eq!(crate::sysprobe::macos::EHOSTUNREACH, libc::EHOSTUNREACH);
    assert_eq!(crate::sysprobe::macos::ENETUNREACH, libc::ENETUNREACH);
}
