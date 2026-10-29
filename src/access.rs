//! Named access lists and the policy maps that apply a policy to their traffic.
//!
//! A neutral access list `N` is one NX-OS ACL per address family it uses, both
//! named `N`, and a class map `N` matching them. Applying policy `P` to the
//! traffic of `N` on an interface puts class `N`, policed at `P`'s rate, into
//! the policy map `P-<interface>-<direction>` and attaches that map to the
//! interface. The map holds one class per access list on that interface and
//! is removed with its last class.

use crate::client::{complete_class_items, dme_object_exists};
use crate::{BandwidthPolicy as Policer, Client, Direction, Error, EthernetInterface};
use network_device::{AccessEntry, AccessList, AccessListName, IpPrefix};
use reqwest::Method;
use serde_json::{Value, json};
use std::net::IpAddr;

/// Longest NX-OS ACL, class-map or policy-map name.
pub(crate) const MAX_NAME_LENGTH: usize = 39;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    V4,
    V6,
}

impl Family {
    pub(crate) const ALL: [Self; 2] = [Self::V4, Self::V6];

    fn of(entry: &AccessEntry) -> Self {
        if entry.is_ipv4() { Self::V4 } else { Self::V6 }
    }

    fn key(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }

    fn any(self) -> &'static str {
        match self {
            Self::V4 => "0.0.0.0",
            Self::V6 => "::",
        }
    }
}

pub(crate) fn check_name(name: &str) -> Result<(), Error> {
    if name.len() > MAX_NAME_LENGTH {
        return Err(Error::Configuration("name is too long for NX-OS"));
    }
    Ok(())
}

fn acl_path(family: Family) -> String {
    format!("/api/mo/sys/acl/{}.json", family.key())
}

fn named_acl_path(family: Family, name: &str) -> String {
    format!(
        "/api/mo/sys/acl/{}/name-{name}.json?rsp-subtree=children",
        family.key()
    )
}

fn class_map_path(name: &str) -> String {
    format!("/api/mo/sys/ipqos/dflt/c/name-{name}.json")
}

pub(crate) fn policy_map_path(name: &str) -> String {
    format!("/api/mo/sys/ipqos/dflt/p/name-{name}.json")
}

/// The per-interface policy map applying `policy` to access-list traffic.
pub(crate) fn interface_map_name(
    policy: &str,
    interface: &EthernetInterface,
    direction: Direction,
) -> String {
    format!(
        "{policy}-{}-{}",
        interface.as_str().replace('/', "-"),
        match direction {
            Direction::Ingress => "in",
            Direction::Egress => "out",
        }
    )
}

/// One ACE as the switch stores it: `(source, destination)` prefixes, `None`
/// meaning any address.
type Ace = (Option<IpPrefix>, Option<IpPrefix>);

fn ace_attributes(family: Family, sequence: usize, (source, destination): Ace) -> Value {
    let side = |prefix: Option<IpPrefix>| match prefix {
        Some(prefix) => (prefix.address().to_string(), prefix.prefix_length()),
        None => (family.any().to_owned(), 0),
    };
    let (source, source_length) = side(source);
    let (destination, destination_length) = side(destination);
    json!({
        "action": "permit",
        "protocol": match family { Family::V4 => "ip", Family::V6 => "ipv6" },
        "srcPrefix": source,
        "srcPrefixLength": source_length.to_string(),
        "dstPrefix": destination,
        "dstPrefixLength": destination_length.to_string(),
        "seqNum": sequence.to_string(),
    })
}

/// Writes the family's entries as sequence numbers 10, 20, … and deletes the
/// stale sequence numbers in the same request.
fn acl_payload(family: Family, name: &str, wanted: &[Ace], stale: &[usize]) -> Value {
    let (af, acl, ace) = match family {
        Family::V4 => ("ipv4aclAF", "ipv4aclACL", "ipv4aclACE"),
        Family::V6 => ("ipv6aclAF", "ipv6aclACL", "ipv6aclACE"),
    };
    let mut children: Vec<Value> = wanted
        .iter()
        .enumerate()
        .map(|(index, entry)| json!({ (ace): { "attributes": ace_attributes(family, (index + 1) * 10, *entry) } }))
        .collect();
    children.extend(stale.iter().map(|sequence| {
        json!({ (ace): { "attributes": { "seqNum": sequence.to_string(), "status": "deleted" } } })
    }));
    json!({ (af): { "children": [ { (acl): { "attributes": { "name": name }, "children": children } } ] } })
}

fn acl_delete_payload(family: Family, name: &str) -> Value {
    let (af, acl) = match family {
        Family::V4 => ("ipv4aclAF", "ipv4aclACL"),
        Family::V6 => ("ipv6aclAF", "ipv6aclACL"),
    };
    json!({ (af): { "children": [ { (acl): { "attributes": { "name": name, "status": "deleted" } } } ] } })
}

fn class_map_payload(name: &str) -> Value {
    json!({"ipqosCMapInst":{"attributes":{"name":name,"matchType":"match-all"},
        "children":[{"ipqosAcl":{"attributes":{"name":name}}}]}})
}

fn police_attributes(policer: &Policer) -> Value {
    let mut police = json!({"cirRate":policer.rate_bps.to_string(),"cirUnit":"bps",
        "conformAction":"transmit","exceedAction":"unspecified"});
    if let Some(burst) = policer.burst_bytes {
        police["bcRate"] = json!(burst.to_string());
        police["bcUnit"] = json!("bytes");
    }
    police
}

fn class_delete_payload(map: &str, class: &str) -> Value {
    json!({"ipqosPMapEntity":{"children":[{"ipqosPMapInst":{"attributes":{"name":map},
        "children":[{"ipqosMatchCMap":{"attributes":{"name":class,"status":"deleted"}}}]}}]}})
}

fn map_delete_payload(map: &str) -> Value {
    json!({"ipqosPMapEntity":{"children":[{"ipqosPMapInst":{"attributes":{"name":map,"status":"deleted"}}}]}})
}

fn prefix(address: Option<&Value>, length: Option<&Value>) -> Result<Option<IpPrefix>, Error> {
    let length: u8 = length
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
        .ok_or(Error::Response("missing ACE prefix length"))?;
    if length == 0 {
        return Ok(None);
    }
    let address: IpAddr = address
        .and_then(Value::as_str)
        .and_then(|value| value.parse().ok())
        .ok_or(Error::Response("missing ACE prefix"))?;
    IpPrefix::new(address, length)
        .map(Some)
        .map_err(|_| Error::Response("invalid ACE prefix"))
}

impl Client {
    /// The family's ACL entries ordered by sequence number, with those
    /// numbers; `None` when the ACL does not exist.
    async fn read_acl(
        &self,
        family: Family,
        name: &str,
    ) -> Result<Option<Vec<(usize, Ace)>>, Error> {
        let body = self
            .request(Method::GET, &named_acl_path(family, name), None, true)
            .await?;
        let items = body["imdata"]
            .as_array()
            .ok_or(Error::Response("missing ACL data"))?;
        let Some(acl) = items.first() else {
            return Ok(None);
        };
        let key = match family {
            Family::V4 => ("ipv4aclACL", "ipv4aclACE"),
            Family::V6 => ("ipv6aclACL", "ipv6aclACE"),
        };
        let mut entries = Vec::new();
        for child in acl[key.0]["children"].as_array().into_iter().flatten() {
            let Some(attributes) = child.get(key.1).and_then(|ace| ace.get("attributes")) else {
                continue;
            };
            if attributes.get("action").and_then(Value::as_str) != Some("permit") {
                return Err(Error::Configuration("ACL holds a non-permit entry"));
            }
            let sequence = attributes
                .get("seqNum")
                .and_then(Value::as_str)
                .and_then(|value| value.parse().ok())
                .ok_or(Error::Response("missing ACE sequence number"))?;
            let source = prefix(
                attributes.get("srcPrefix"),
                attributes.get("srcPrefixLength"),
            )?;
            let destination = prefix(
                attributes.get("dstPrefix"),
                attributes.get("dstPrefixLength"),
            )?;
            entries.push((sequence, (source, destination)));
        }
        entries.sort_by_key(|(sequence, _)| *sequence);
        Ok(Some(entries))
    }

    /// Makes the ACLs named after the list match its entries; returns writes.
    pub(crate) async fn ensure_access_list(
        &self,
        list: &AccessList,
    ) -> Result<usize, (usize, Error)> {
        let name = list.name().as_str();
        check_name(name).map_err(|error| (0, error))?;
        let mut writes = 0;
        for family in Family::ALL {
            let wanted: Vec<Ace> = list
                .entries()
                .iter()
                .filter(|entry| Family::of(entry) == family)
                .map(|entry| (entry.source(), entry.destination()))
                .collect();
            let existing = self
                .read_acl(family, name)
                .await
                .map_err(|error| (writes, error))?;
            let body = match existing {
                None if wanted.is_empty() => continue,
                Some(_) if wanted.is_empty() => acl_delete_payload(family, name),
                Some(entries)
                    if entries
                        .iter()
                        .map(|(_, ace)| *ace)
                        .eq(wanted.iter().copied())
                        && entries
                            .iter()
                            .enumerate()
                            .all(|(index, (sequence, _))| *sequence == (index + 1) * 10) =>
                {
                    continue;
                }
                existing => {
                    let kept = wanted.len() * 10;
                    let stale: Vec<usize> = existing
                        .into_iter()
                        .flatten()
                        .map(|(sequence, _)| sequence)
                        .filter(|sequence| *sequence > kept || sequence % 10 != 0)
                        .collect();
                    acl_payload(family, name, &wanted, &stale)
                }
            };
            self.request(Method::POST, &acl_path(family), Some(body), true)
                .await
                .map_err(|error| (writes, error))?;
            writes += 1;
        }
        Ok(writes)
    }

    /// Reads the list back from its ACLs; `None` when neither exists.
    pub(crate) async fn read_access_list(
        &self,
        name: &AccessListName,
    ) -> Result<Option<AccessList>, Error> {
        let mut entries = Vec::new();
        let mut found = false;
        for family in Family::ALL {
            if let Some(acl) = self.read_acl(family, name.as_str()).await? {
                found = true;
                for (_, (source, destination)) in acl {
                    entries.push(
                        AccessEntry::new(source, destination)
                            .map_err(|_| Error::Response("ACE matches any traffic"))?,
                    );
                }
            }
        }
        if !found {
            return Ok(None);
        }
        AccessList::new(name.clone(), entries)
            .map(Some)
            .map_err(|_| Error::Response("ACL has no entries"))
    }

    /// Removes the list's class map and ACLs, refusing while a policy map
    /// still uses the class; returns writes.
    pub(crate) async fn remove_access_list(
        &self,
        name: &AccessListName,
    ) -> Result<usize, (usize, Error)> {
        let name = name.as_str();
        let body = self
            .request(Method::GET, "/api/class/ipqosMatchCMap.json", None, true)
            .await
            .map_err(|error| (0, error))?;
        let items = complete_class_items(&body, "missing class reference data")
            .map_err(|error| (0, error))?;
        if items.iter().any(|item| {
            item.pointer("/ipqosMatchCMap/attributes/name")
                .and_then(Value::as_str)
                == Some(name)
        }) {
            return Err((
                0,
                Error::Configuration("refusing to remove an access list in use by a policy"),
            ));
        }
        let mut writes = 0;
        let class = self
            .request(Method::GET, &class_map_path(name), None, true)
            .await
            .map_err(|error| (writes, error))?;
        if dme_object_exists(&class).map_err(|error| (writes, error))? {
            self.request(
                Method::POST,
                "/api/mo/sys/ipqos/dflt/c.json",
                Some(json!({"ipqosCMapEntity":{"children":[{"ipqosCMapInst":{"attributes":{"name":name,"status":"deleted"}}}]}})),
                true,
            )
            .await
            .map_err(|error| (writes, error))?;
            writes += 1;
        }
        for family in Family::ALL {
            if self
                .read_acl(family, name)
                .await
                .map_err(|error| (writes, error))?
                .is_some()
            {
                self.request(
                    Method::POST,
                    &acl_path(family),
                    Some(acl_delete_payload(family, name)),
                    true,
                )
                .await
                .map_err(|error| (writes, error))?;
                writes += 1;
            }
        }
        Ok(writes)
    }

    /// The classes of a policy map with their policers; `None` when absent.
    pub(crate) async fn map_classes(
        &self,
        map: &str,
    ) -> Result<Option<Vec<(String, Option<Value>)>>, Error> {
        let body = self
            .request(
                Method::GET,
                &format!("{}?rsp-subtree=full", policy_map_path(map)),
                None,
                true,
            )
            .await?;
        let items = body["imdata"]
            .as_array()
            .ok_or(Error::Response("missing policy data"))?;
        let Some(item) = items.first() else {
            return Ok(None);
        };
        let mut classes = Vec::new();
        for child in item["ipqosPMapInst"]["children"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let Some(class) = child.get("ipqosMatchCMap") else {
                continue;
            };
            let name = class
                .pointer("/attributes/name")
                .and_then(Value::as_str)
                .ok_or(Error::Response("missing class name"))?;
            let police = class.pointer("/children/0/ipqosPolice/attributes").cloned();
            classes.push((name.to_owned(), police));
        }
        Ok(Some(classes))
    }

    /// Puts class `list` policed at `policer` into the interface map and
    /// attaches the map; returns writes.
    pub(crate) async fn attach_list(
        &self,
        map: &str,
        list: &str,
        policer: &Policer,
        interface: &EthernetInterface,
        direction: Direction,
    ) -> Result<usize, (usize, Error)> {
        check_name(map).map_err(|error| (0, error))?;
        check_name(list).map_err(|error| (0, error))?;
        let mut writes = 0;
        let class = self
            .request(Method::GET, &class_map_path(list), None, true)
            .await
            .map_err(|error| (writes, error))?;
        if !dme_object_exists(&class).map_err(|error| (writes, error))? {
            self.request(
                Method::POST,
                &class_map_path(list),
                Some(class_map_payload(list)),
                true,
            )
            .await
            .map_err(|error| (writes, error))?;
            writes += 1;
        }
        let wanted = police_attributes(policer);
        let classes = self
            .map_classes(map)
            .await
            .map_err(|error| (writes, error))?
            .unwrap_or_default();
        let current = classes
            .iter()
            .find(|(name, _)| name == list)
            .and_then(|(_, police)| police.clone());
        if !current.is_some_and(|police| police_matches(&police, &wanted)) {
            let request = crate::dme::named_policer(map, list, wanted);
            self.request(Method::POST, &request.path, Some(request.body), true)
                .await
                .map_err(|error| (writes, error))?;
            writes += 1;
        }
        let path = format!(
            "{}/pmap.json",
            Client::assignment_path(interface, direction)
        );
        if !self
            .owns_attachment(&path, map)
            .await
            .map_err(|error| (writes, error))?
        {
            let name: crate::PolicyName = map
                .parse()
                .map_err(|_| (writes, Error::Configuration("invalid policy map name")))?;
            self.write_assignment(&name, interface, direction, false)
                .await
                .map_err(|error| (writes, error))?;
            writes += 1;
        }
        Ok(writes)
    }

    /// Removes class `list` from the interface map, and the map itself with
    /// its last class; returns writes.
    pub(crate) async fn detach_list(
        &self,
        map: &str,
        list: &str,
        interface: &EthernetInterface,
        direction: Direction,
    ) -> Result<usize, (usize, Error)> {
        let mut writes = 0;
        let Some(classes) = self
            .map_classes(map)
            .await
            .map_err(|error| (writes, error))?
        else {
            return Ok(0);
        };
        if classes.iter().any(|(name, _)| name == list) {
            self.request(
                Method::POST,
                "/api/mo/sys/ipqos/dflt/p.json",
                Some(class_delete_payload(map, list)),
                true,
            )
            .await
            .map_err(|error| (writes, error))?;
            writes += 1;
        }
        if classes.iter().any(|(name, _)| name != list) {
            return Ok(writes);
        }
        let path = format!(
            "{}/pmap.json",
            Client::assignment_path(interface, direction)
        );
        if self
            .owns_attachment(&path, map)
            .await
            .map_err(|error| (writes, error))?
        {
            let name: crate::PolicyName = map
                .parse()
                .map_err(|_| (writes, Error::Configuration("invalid policy map name")))?;
            self.write_assignment(&name, interface, direction, true)
                .await
                .map_err(|error| (writes, error))?;
            writes += 1;
        }
        self.request(
            Method::POST,
            "/api/mo/sys/ipqos/dflt/p.json",
            Some(map_delete_payload(map)),
            true,
        )
        .await
        .map_err(|error| (writes, error))?;
        Ok(writes + 1)
    }

    /// Brings every class of `policy`'s interface maps in `direction` to the
    /// policy's current rate; returns writes.
    pub(crate) async fn sync_interface_maps(
        &self,
        policy: &str,
        direction: Direction,
        policer: &Policer,
    ) -> Result<usize, (usize, Error)> {
        let body = self
            .request(Method::GET, "/api/class/ipqosPMapInst.json", None, true)
            .await
            .map_err(|error| (0, error))?;
        let items =
            complete_class_items(&body, "missing policy map data").map_err(|error| (0, error))?;
        let suffix = match direction {
            Direction::Ingress => "-in",
            Direction::Egress => "-out",
        };
        let prefix = format!("{policy}-eth");
        let maps: Vec<String> = items
            .iter()
            .filter_map(|item| {
                item.pointer("/ipqosPMapInst/attributes/name")
                    .and_then(Value::as_str)
            })
            .filter(|name| name.starts_with(&prefix) && name.ends_with(suffix))
            .map(str::to_owned)
            .collect();
        let wanted = police_attributes(policer);
        let mut writes = 0;
        for map in maps {
            let classes = self
                .map_classes(&map)
                .await
                .map_err(|error| (writes, error))?
                .unwrap_or_default();
            for (class, police) in classes {
                if police.is_some_and(|police| police_matches(&police, &wanted)) {
                    continue;
                }
                let request = crate::dme::named_policer(&map, &class, wanted.clone());
                self.request(Method::POST, &request.path, Some(request.body), true)
                    .await
                    .map_err(|error| (writes, error))?;
                writes += 1;
            }
        }
        Ok(writes)
    }
}

/// Whether a policer as read matches the wanted attributes.
fn police_matches(current: &Value, wanted: &Value) -> bool {
    [
        "cirRate",
        "cirUnit",
        "bcRate",
        "conformAction",
        "exceedAction",
    ]
    .iter()
    .all(|key| {
        current.get(*key).and_then(Value::as_str) == wanted.get(*key).and_then(Value::as_str)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(value: &str) -> IpPrefix {
        value.parse().unwrap()
    }

    #[test]
    fn acl_payload_writes_entries_in_order_and_deletes_stale_ones() {
        let body = acl_payload(
            Family::V4,
            "list-1",
            &[
                (Some(prefix("192.0.2.20/32")), None),
                (None, Some(prefix("192.0.2.20/32"))),
            ],
            &[30],
        );
        let children = &body["ipv4aclAF"]["children"][0]["ipv4aclACL"]["children"];
        let first = &children[0]["ipv4aclACE"]["attributes"];
        assert_eq!(first["srcPrefix"], "192.0.2.20");
        assert_eq!(first["srcPrefixLength"], "32");
        assert_eq!(first["dstPrefix"], "0.0.0.0");
        assert_eq!(first["dstPrefixLength"], "0");
        assert_eq!(first["seqNum"], "10");
        assert_eq!(
            children[1]["ipv4aclACE"]["attributes"]["dstPrefix"],
            "192.0.2.20"
        );
        assert_eq!(children[1]["ipv4aclACE"]["attributes"]["seqNum"], "20");
        assert_eq!(children[2]["ipv4aclACE"]["attributes"]["status"], "deleted");
        assert_eq!(children[2]["ipv4aclACE"]["attributes"]["seqNum"], "30");
    }

    #[test]
    fn ipv6_entries_use_the_ipv6_acl_objects() {
        let body = acl_payload(
            Family::V6,
            "list-1",
            &[(None, Some(prefix("2001:db8::1/128")))],
            &[],
        );
        let ace = &body["ipv6aclAF"]["children"][0]["ipv6aclACL"]["children"][0]["ipv6aclACE"]["attributes"];
        assert_eq!(ace["protocol"], "ipv6");
        assert_eq!(ace["srcPrefix"], "::");
        assert_eq!(ace["dstPrefixLength"], "128");
    }

    #[test]
    fn interface_maps_are_named_per_policy_interface_and_direction() {
        let interface: EthernetInterface = "Ethernet1/2".parse().unwrap();
        assert_eq!(
            interface_map_name("rate-10m", &interface, Direction::Ingress),
            "rate-10m-eth1-2-in"
        );
        assert_eq!(
            interface_map_name("rate-10m", &interface, Direction::Egress),
            "rate-10m-eth1-2-out"
        );
        assert!(check_name(&"x".repeat(40)).is_err());
    }

    #[test]
    fn police_comparison_ignores_other_attributes() {
        let wanted = police_attributes(&Policer {
            rate_bps: std::num::NonZeroU64::new(10).unwrap(),
            burst_bytes: None,
        });
        let mut current = wanted.clone();
        current["dn"] = json!("sys/ipqos/dflt/p/name-x");
        assert!(police_matches(&current, &wanted));
        current["cirRate"] = json!("20");
        assert!(!police_matches(&current, &wanted));
    }
}
