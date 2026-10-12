//! Session owner capability issued by the service with an admitted Start.
//!
//! Only its holder may stop a live service-owned session from a new IPC
//! connection (Recover). The value is a secret: Debug is redacted, equality is
//! constant time and the bytes are zeroized on drop.
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

pub const LEN: usize = 32;
/// Service reply when a live session's owner is missing or wrong. Clients
/// match on it to explain the next step; it never contains an owner.
pub const NOT_OWNER: &str =
    "Сессией VPN управляет другое приложение; защита сохранена. Отключите VPN в нём.";

#[derive(Clone)]
pub struct Owner([u8; LEN]);

impl Owner {
    /// `bytes` must come from a CSPRNG.
    pub fn from_bytes(bytes: [u8; LEN]) -> Self {
        Self(bytes)
    }
    /// Constant-time comparison; never short-circuits on the first difference.
    pub fn matches(&self, other: &Self) -> bool {
        let mut difference = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            difference |= a ^ b;
        }
        // Keep the optimizer from turning the fold into an early exit.
        std::hint::black_box(difference) == 0
    }
    /// Lowercase hex; the caller keeps the result zeroized.
    pub fn to_hex(&self) -> Zeroizing<String> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut text = Zeroizing::new(String::with_capacity(LEN * 2));
        for byte in self.0 {
            text.push(DIGITS[(byte >> 4) as usize] as char);
            text.push(DIGITS[(byte & 15) as usize] as char);
        }
        text
    }
    pub fn from_hex(text: &str) -> Result<Self, String> {
        let text = text.as_bytes();
        if text.len() != LEN * 2 {
            return Err("Invalid session owner".into());
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err("Invalid session owner".to_owned()),
        };
        let mut bytes = Zeroizing::new([0; LEN]);
        for (i, pair) in text.as_chunks::<2>().0.iter().enumerate() {
            bytes[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
        }
        Ok(Self(*bytes))
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl std::fmt::Debug for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Owner([REDACTED])")
    }
}
impl Serialize for Owner {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}
impl<'de> Deserialize<'de> for Owner {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        Self::from_hex(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hex_roundtrip_is_strict_and_comparison_is_exact() {
        let owner = Owner::from_bytes([0xa5; LEN]);
        let parsed = Owner::from_hex(&owner.to_hex()).unwrap();
        assert!(owner.matches(&parsed));
        let mut other = [0xa5; LEN];
        other[LEN - 1] ^= 1;
        assert!(!owner.matches(&Owner::from_bytes(other)));
        for bad in [
            "",
            "00",
            &"A5".repeat(LEN),
            &"g0".repeat(LEN),
            &"a5".repeat(LEN + 1),
        ] {
            assert!(Owner::from_hex(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn debug_and_errors_never_contain_the_secret() {
        let owner = Owner::from_bytes([0x5c; LEN]);
        let canary = owner.to_hex();
        assert!(!format!("{owner:?}").contains(canary.as_str()));
        assert!(!format!("{:?}", Some(owner.clone())).contains("5c5c"));
        let mut response = crate::Response::new(crate::State::Connected, "ok");
        response.owner = Some(owner);
        assert!(!format!("{response:?}").contains(canary.as_str()));
        let wire = serde_json::to_string(&response).unwrap();
        assert!(wire.contains(canary.as_str()));
        let mut broken = canary.to_string();
        broken.replace_range(0..1, "Z");
        let error = serde_json::from_value::<Owner>(serde_json::Value::String(broken.clone()))
            .unwrap_err()
            .to_string();
        assert!(!error.contains(&broken[1..]));
    }
    #[test]
    fn recover_without_owner_keeps_the_plain_wire_shape() {
        let plain = serde_json::to_value(crate::Command::Recover { owner: None }).unwrap();
        assert_eq!(plain, serde_json::json!({"op": "Recover"}));
        let parsed: crate::Command = serde_json::from_value(plain).unwrap();
        assert!(matches!(parsed, crate::Command::Recover { owner: None }));
        let owned = serde_json::to_value(crate::Command::Recover {
            owner: Some(Owner::from_bytes([1; LEN])),
        })
        .unwrap();
        assert_eq!(owned["owner"], "01".repeat(LEN));
    }
}
