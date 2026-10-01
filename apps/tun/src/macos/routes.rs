use super::{command, route_table};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Route {
    pub v6: bool,
    pub prefix: String,
    pub gateway: String,
    pub interface: String,
    pub direct: bool,
}
impl Route {
    pub fn validate(&self) -> Result<(), String> {
        if !route_table::valid_interface(&self.interface)
            || route_table::prefix(&self.prefix, self.v6).as_deref() != Some(self.prefix.as_str())
            || (!self.direct && self.gateway.parse::<std::net::Ipv4Addr>().is_err())
            || (self.direct && self.gateway != self.interface)
        {
            return Err("Invalid route in recovery journal".into());
        }
        Ok(())
    }
    fn current(&self) -> Result<Option<route_table::Entry>, String> {
        self.validate()?;
        let mut matching = route_table::read(self.v6)?.into_iter().filter(|row| {
            !row.flags.contains('I')
                && route_table::prefix(&row.destination, self.v6).as_deref()
                    == Some(self.prefix.as_str())
        });
        let row = matching.next();
        if matching.next().is_some() {
            return Err("Ambiguous route ownership; protection retained".into());
        }
        Ok(row)
    }
    fn owns(&self, row: &route_table::Entry) -> bool {
        row.interface == self.interface
            && row.flags.contains('2')
            && if self.direct {
                !row.flags.contains('G')
            } else {
                row.gateway == self.gateway
            }
    }
    pub fn vacant(&self) -> Result<(), String> {
        if self.current()?.is_some() {
            Err(format!("Conflicting route: {}", self.prefix))
        } else {
            Ok(())
        }
    }
    pub fn ensure(&self) -> Result<(), String> {
        match self.current()? {
            Some(row) if self.owns(&row) => Ok(()),
            Some(_) => Err("VPN route changed externally; guard retained".into()),
            None => self.add(),
        }
    }
    pub fn add(&self) -> Result<(), String> {
        self.vacant()?;
        let mut args = vec![
            "-n",
            "add",
            if self.v6 { "-inet6" } else { "-inet" },
            "-net",
            &self.prefix,
            "-proto2",
            "-ifp",
            &self.interface,
        ];
        if self.direct {
            args.push("-interface");
        }
        args.push(&self.gateway);
        command::run("/sbin/route", &args)?;
        if !self.current()?.as_ref().is_some_and(|r| self.owns(r)) {
            return Err("New VPN route could not be verified; protection retained".into());
        }
        Ok(())
    }
    pub fn remove(&self) -> Result<(), String> {
        let Some(row) = self.current()? else {
            return Ok(());
        };
        if !self.owns(&row) {
            return Err(format!(
                "Route {} changed externally; protection retained",
                self.prefix
            ));
        }
        let mut args = vec![
            "-n",
            "delete",
            if self.v6 { "-inet6" } else { "-inet" },
            "-net",
            &self.prefix,
            "-ifp",
            &self.interface,
        ];
        if self.direct {
            args.push("-interface");
        }
        args.push(&self.gateway);
        command::run("/sbin/route", &args)?;
        if self.current()?.is_some() {
            return Err("VPN route removal not confirmed".into());
        }
        Ok(())
    }
}
pub(super) fn physical_interface() -> Result<String, String> {
    let defaults: Vec<_> = route_table::read(false)?
        .into_iter()
        .filter(|r| r.destination == "default" && !r.flags.contains('I'))
        .collect();
    if defaults.len() != 1
        || defaults[0].interface.starts_with("utun")
        || defaults[0].interface == "lo0"
    {
        return Err(
            "A unique physical IPv4 default route is required; disconnect other system VPNs first"
                .into(),
        );
    }
    Ok(defaults[0].interface.clone())
}
pub(super) fn endpoint(ip: std::net::Ipv4Addr, interface: &str) -> Result<Route, String> {
    if !route_table::valid_interface(interface) {
        return Err("Invalid physical interface".into());
    }
    let text = command::run(
        "/sbin/route",
        &["-n", "get", "-inet", "-ifscope", interface, &ip.to_string()],
    )?;
    let fields: std::collections::HashMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once(':').map(|(k, v)| (k.trim(), v.trim())))
        .collect();
    if fields.get("interface") != Some(&interface) {
        return Err("Endpoint would use an unexpected interface".into());
    }
    let gateway = fields
        .get("gateway")
        .ok_or("Endpoint gateway unavailable")?;
    let (gateway, direct) = if gateway.starts_with("link#") {
        (interface.to_owned(), true)
    } else {
        let gateway: std::net::Ipv4Addr = gateway
            .parse()
            .map_err(|_| "Unsupported physical gateway")?;
        (gateway.to_string(), false)
    };
    Ok(Route {
        v6: false,
        prefix: format!("{ip}/32"),
        gateway,
        interface: interface.into(),
        direct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_requires_interface_and_protocol_marker_and_gateway() {
        let route = Route {
            v6: false,
            prefix: "192.0.2.4/32".into(),
            gateway: "192.168.1.1".into(),
            interface: "en0".into(),
            direct: false,
        };
        let mut row = route_table::Entry {
            destination: "192.0.2.4".into(),
            gateway: route.gateway.clone(),
            interface: "en0".into(),
            flags: "UGHS2".into(),
        };
        assert!(route.owns(&row));
        row.flags = "UGHS".into();
        assert!(!route.owns(&row));
        row.flags = "UGHS2".into();
        row.interface = "en1".into();
        assert!(!route.owns(&row));
        row.interface = "en0".into();
        row.gateway = "192.168.1.2".into();
        assert!(!route.owns(&row));
    }
    #[test]
    fn journal_rejects_option_injection_and_family_confusion() {
        let mut route = Route {
            v6: false,
            prefix: "0.0.0.0/1".into(),
            gateway: "utun5254".into(),
            interface: "utun5254".into(),
            direct: true,
        };
        assert!(route.validate().is_ok());
        route.prefix = "::/1".into();
        assert!(route.validate().is_err());
        route.prefix = "0.0.0.0/1".into();
        route.interface = "-ifscope en0".into();
        assert!(route.validate().is_err());
    }
}
