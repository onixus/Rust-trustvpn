//! Own dynamic DNS entries; never rewrite persistent network-service preferences.
use core_foundation::{
    array::CFArray,
    base::{CFEqual, CFRelease, TCFType},
    dictionary::CFDictionary,
    number::CFNumber,
    string::CFString,
};
use std::{net::Ipv4Addr, ptr};
use system_configuration_sys::dynamic_store::*;

/// Darwin scopes system DNS to the physical interface. If the primary resolver
/// is in the tunnel networks, mirror it without that scope instead of letting
/// PF block the resulting physical bypass. Never select a per-domain resolver.
pub fn routed_system_resolver(
    networks: &[rtrust_control::Ipv4Net],
) -> Result<Option<Ipv4Addr>, String> {
    let config = super::command::run("/usr/sbin/scutil", &["--dns"])?;
    Ok(selected_resolver(&config, networks))
}
fn selected_resolver(config: &str, networks: &[rtrust_control::Ipv4Net]) -> Option<Ipv4Addr> {
    let resolver = config
        .lines()
        .take_while(|line| !line.trim().starts_with("resolver #2"))
        .find_map(|line| {
            let (key, address) = line.trim().split_once(':')?;
            let key = key.trim();
            if !key.starts_with("nameserver[") || !key.ends_with(']') {
                return None;
            }
            address.trim().parse::<Ipv4Addr>().ok()
        })?;
    (rtrust_control::validate_dns(resolver).is_ok()
        && networks.iter().any(|network| network.contains(&resolver)))
    .then_some(resolver)
}

const KEY: &str = "State:/Network/Service/org.rtrusttunnel.VPN/DNS";
struct Store(SCDynamicStoreRef);
impl Store {
    fn open() -> Result<Self, String> {
        let name = CFString::new("R-TrustTunnel VPN");
        let store = unsafe {
            SCDynamicStoreCreate(
                ptr::null(),
                name.as_concrete_TypeRef(),
                None,
                ptr::null_mut(),
            )
        };
        if store.is_null() {
            Err("Cannot access macOS dynamic network configuration".into())
        } else {
            Ok(Self(store))
        }
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0.cast()) };
    }
}
fn value(uid: u32, dns: Ipv4Addr) -> CFDictionary<CFString, core_foundation::base::CFType> {
    CFDictionary::from_CFType_pairs(&[
        (
            CFString::new("ServerAddresses"),
            CFArray::from_CFTypes(&[CFString::new(&dns.to_string())]).as_CFType(),
        ),
        (
            CFString::new("SupplementalMatchDomains"),
            CFArray::from_CFTypes(&[CFString::new("")]).as_CFType(),
        ),
        (
            CFString::new("SupplementalMatchDomainsNoSearch"),
            CFNumber::from(1i32).as_CFType(),
        ),
        (
            CFString::new("SearchOrder"),
            CFNumber::from(0i32).as_CFType(),
        ),
        (
            CFString::new("RTrustOwnerUID"),
            CFNumber::from(i64::from(uid)).as_CFType(),
        ),
    ])
}
pub fn preflight() -> Result<(), String> {
    let store = Store::open()?;
    let key = CFString::new(KEY);
    let existing = unsafe { SCDynamicStoreCopyValue(store.0, key.as_concrete_TypeRef()) };
    if existing.is_null() {
        return Ok(());
    }
    unsafe { CFRelease(existing) };
    Err("R-TrustTunnel DNS state already exists; recover before connecting".into())
}
pub fn install(uid: u32, dns: Ipv4Addr) -> Result<(), String> {
    let store = Store::open()?;
    let key = CFString::new(KEY);
    let value = value(uid, dns);
    if unsafe { SCDynamicStoreAddValue(store.0, key.as_concrete_TypeRef(), value.as_CFTypeRef()) }
        == 0
    {
        Err("Cannot add exclusive VPN DNS configuration".into())
    } else {
        Ok(())
    }
}
pub fn ensure(uid: u32, dns: Ipv4Addr) -> Result<(), String> {
    let store = Store::open()?;
    let key = CFString::new(KEY);
    let existing = unsafe { SCDynamicStoreCopyValue(store.0, key.as_concrete_TypeRef()) };
    if existing.is_null() {
        return install(uid, dns);
    }
    let expected = value(uid, dns);
    let ours = unsafe { CFEqual(existing, expected.as_CFTypeRef()) != 0 };
    unsafe { CFRelease(existing) };
    if ours {
        Ok(())
    } else {
        Err("VPN DNS state changed externally; protection retained".into())
    }
}
pub fn remove(uid: u32, dns: Ipv4Addr) -> Result<(), String> {
    let store = Store::open()?;
    let key = CFString::new(KEY);
    let existing = unsafe { SCDynamicStoreCopyValue(store.0, key.as_concrete_TypeRef()) };
    if existing.is_null() {
        return Ok(());
    }
    let expected = value(uid, dns);
    let ours = unsafe { CFEqual(existing, expected.as_CFTypeRef()) != 0 };
    unsafe { CFRelease(existing) };
    if !ours {
        return Err("VPN DNS state changed externally; recovery refused".into());
    }
    if unsafe { SCDynamicStoreRemoveValue(store.0, key.as_concrete_TypeRef()) } == 0 {
        Err("Cannot remove VPN DNS configuration".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mirrors_primary_system_dns_only_when_its_address_is_tunneled() {
        let config = "resolver #1\n  nameserver[0] : 8.8.8.8\n  nameserver[1] : 1.1.1.1\n  if_index : 15 (en0)\nresolver #2\n  domain : internal\n  nameserver[0] : 203.0.113.53\n";
        assert_eq!(
            selected_resolver(config, &["8.0.0.0/5".parse().unwrap()]),
            Some("8.8.8.8".parse().unwrap())
        );
        assert_eq!(
            selected_resolver(config, &["1.0.0.0/8".parse().unwrap()]),
            None
        );
        assert_eq!(
            selected_resolver(config, &["203.0.113.0/24".parse().unwrap()]),
            None
        );
        assert_eq!(
            selected_resolver("nameserver[0] : 127.0.0.1", &["0.0.0.0/0".parse().unwrap()]),
            None
        );
        assert_eq!(
            selected_resolver(
                "DNS configuration unavailable",
                &["0.0.0.0/0".parse().unwrap()]
            ),
            None
        );
    }
}
