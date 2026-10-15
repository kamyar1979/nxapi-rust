//! Validated IP classifiers for Nexus QoS policy planning.
//!
//! Nexus attaches a policy-map to an interface or VLAN; an IP address is a
//! classifier expressed through an IPv4/IPv6 ACL and a QoS class-map. This
//! module models the DME objects used by NX-OS 7.x and later.
use serde_json::{Value, json};
use std::{net::IpAddr, str::FromStr};

/// Which packet endpoint an ACL classifier constrains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpEndpoint {
    /// Source address.
    Source,
    /// Destination address.
    Destination,
}

/// A validated IPv4 or IPv6 address used by a QoS classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddress(IpAddr);

impl IpAddress {
    /// Return the parsed address.
    pub fn as_std(&self) -> IpAddr {
        self.0
    }
}

/// An IP address could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid IPv4/IPv6 address")]
pub struct InvalidIpAddress;

impl FromStr for IpAddress {
    type Err = InvalidIpAddress;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self).map_err(|_| InvalidIpAddress)
    }
}

/// An address match in an IPv4/IPv6 ACL used by a QoS class-map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpMatch {
    /// Source or destination.
    pub endpoint: IpEndpoint,
    /// Address to match.
    pub address: IpAddress,
}

impl IpMatch {
    /// Construct a source-address match.
    pub fn source(address: IpAddress) -> Self {
        Self {
            endpoint: IpEndpoint::Source,
            address,
        }
    }
    /// Construct a destination-address match.
    pub fn destination(address: IpAddress) -> Self {
        Self {
            endpoint: IpEndpoint::Destination,
            address,
        }
    }
}

/// Release-independent plan for classifying IP traffic before policing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpQosClassifier {
    /// ACL/class-map name to provision.
    pub name: String,
    /// Address criterion.
    pub address: IpMatch,
    /// Optional second endpoint criterion. When present it must be the
    /// opposite endpoint and the same address family as `address`.
    pub secondary: Option<IpMatch>,
}

impl IpQosClassifier {
    /// Create a classifier plan. Names are constrained like DME class maps.
    pub fn new(name: impl Into<String>, address: IpMatch) -> Result<Self, InvalidClassifierName> {
        let name = name.into();
        if name.is_empty()
            || name.len() > 39
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(InvalidClassifierName);
        }
        Ok(Self {
            name,
            address,
            secondary: None,
        })
    }

    /// Add a destination/source criterion to this classifier. IPv4 and IPv6
    /// ACLs cannot mix families, so mismatches are rejected.
    pub fn with_match(mut self, extra: IpMatch) -> Result<Self, InvalidClassifierMatch> {
        if extra.endpoint == self.address.endpoint
            || extra.address.as_std().is_ipv4() != self.address.address.as_std().is_ipv4()
        {
            return Err(InvalidClassifierMatch);
        }
        self.secondary = Some(extra);
        Ok(self)
    }
}

/// A second classifier criterion has the wrong endpoint or address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("classifier criteria must use opposite endpoints in the same IP family")]
pub struct InvalidClassifierMatch;

/// A classifier name is empty, too long, or contains unsupported characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("classifier name must be 1-39 ASCII letters, digits, hyphens or underscores")]
pub struct InvalidClassifierName;

pub(crate) fn acl_path(address: IpAddress) -> &'static str {
    match address.as_std() {
        IpAddr::V4(_) => "/api/mo/sys/acl/ipv4.json",
        IpAddr::V6(_) => "/api/mo/sys/acl/ipv6.json",
    }
}

pub(crate) fn named_acl_path(classifier: &IpQosClassifier) -> String {
    let family = match classifier.address.address.as_std() {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    };
    format!("/api/mo/sys/acl/{family}/name-{}.json", classifier.name)
}

pub(crate) fn acl_payload(classifier: &IpQosClassifier) -> Value {
    let (af, acl, ace, any, bits, protocol) = match classifier.address.address.as_std() {
        IpAddr::V4(address) => (
            "ipv4aclAF",
            "ipv4aclACL",
            "ipv4aclACE",
            IpAddr::V4(address),
            32,
            "ip",
        ),
        IpAddr::V6(address) => (
            "ipv6aclAF",
            "ipv6aclACL",
            "ipv6aclACE",
            IpAddr::V6(address),
            128,
            "ipv6",
        ),
    };
    let unspecified = match any {
        IpAddr::V4(_) => "0.0.0.0",
        IpAddr::V6(_) => "::",
    };
    let matched = any.to_string();
    let (mut src, mut src_len, mut dst, mut dst_len) = match classifier.address.endpoint {
        IpEndpoint::Source => (matched.clone(), bits, unspecified.to_owned(), 0),
        IpEndpoint::Destination => (unspecified.to_owned(), 0, matched.clone(), bits),
    };
    if let Some(extra) = classifier.secondary {
        let value = extra.address.as_std().to_string();
        match extra.endpoint {
            IpEndpoint::Source => {
                src = value;
                src_len = bits;
            }
            IpEndpoint::Destination => {
                dst = value;
                dst_len = bits;
            }
        }
    }
    json!({(af):{"children":[{(acl):{"attributes":{"name":classifier.name},"children":[
        {(ace):{"attributes":{"action":"permit","srcPrefix":src,"srcPrefixLength":src_len.to_string(),
        "dstPrefix":dst,"dstPrefixLength":dst_len.to_string(),"protocol":protocol,"seqNum":"10"}}}
    ]}}]}})
}

pub(crate) fn acl_delete_payload(classifier: &IpQosClassifier) -> Value {
    let (family, acl) = if classifier.address.address.as_std().is_ipv4() {
        ("ipv4aclAF", "ipv4aclACL")
    } else {
        ("ipv6aclAF", "ipv6aclACL")
    };
    json!({(family):{"children":[{(acl):{"attributes":{
        "name":classifier.name,"status":"deleted"
    }}}]}})
}

pub(crate) fn class_map_payload(classifier: &IpQosClassifier) -> Value {
    json!({"ipqosCMapInst":{"attributes":{"name":classifier.name,"matchType":"match-all"},
        "children":[{"ipqosAcl":{"attributes":{"name":classifier.name}}}]}})
}

pub(crate) fn class_map_path(classifier: &IpQosClassifier) -> String {
    format!("/api/mo/sys/ipqos/dflt/c/name-{}.json", classifier.name)
}

pub(crate) fn policy_path(name: &crate::PolicyName) -> String {
    format!("/api/mo/sys/ipqos/dflt/p/name-{}.json", name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_both_families_and_endpoints() {
        let v4: IpAddress = "192.0.2.1".parse().unwrap();
        let v6: IpAddress = "2001:db8::1".parse().unwrap();
        assert_eq!(IpMatch::source(v4).endpoint, IpEndpoint::Source);
        assert_eq!(IpMatch::destination(v6).endpoint, IpEndpoint::Destination);
    }
    #[test]
    fn rejects_bad_names_and_addresses() {
        assert!("not-an-ip".parse::<IpAddress>().is_err());
        assert!(
            IpQosClassifier::new("bad/name", IpMatch::source("192.0.2.1".parse().unwrap()))
                .is_err()
        );
    }

    #[test]
    fn renders_dual_source_destination_acl() {
        let src = IpMatch::source("192.0.2.1".parse().unwrap());
        let dst = IpMatch::destination("192.0.2.2".parse().unwrap());
        let classifier = IpQosClassifier::new("both", src)
            .unwrap()
            .with_match(dst)
            .unwrap();
        let ace = &acl_payload(&classifier)["ipv4aclAF"]["children"][0]["ipv4aclACL"]["children"]
            [0]["ipv4aclACE"]["attributes"];
        assert_eq!(ace["srcPrefix"], "192.0.2.1");
        assert_eq!(ace["dstPrefix"], "192.0.2.2");
    }

    #[test]
    fn rejects_mixed_family_or_duplicate_endpoint() {
        let src = IpMatch::source("192.0.2.1".parse().unwrap());
        assert!(
            IpQosClassifier::new("x", src)
                .unwrap()
                .with_match(IpMatch::destination("2001:db8::1".parse().unwrap()))
                .is_err()
        );
        assert!(
            IpQosClassifier::new("x", src)
                .unwrap()
                .with_match(IpMatch::source("192.0.2.2".parse().unwrap()))
                .is_err()
        );
    }
}
