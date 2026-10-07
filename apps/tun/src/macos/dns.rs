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
