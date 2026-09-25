//! Interface-scoped operations, independent of OSS events and message routing.

use std::{fmt, num::NonZeroU64, str::FromStr};

/// Direction relative to the customer-facing switch port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Customer upload: traffic entering the switch.
    Ingress,
    /// Customer download: traffic leaving the switch.
    Egress,
}

/// A validated Ethernet interface identifier in NX-API form, e.g. `eth1/1`.
///
/// Only physical and breakout Ethernet identifiers are accepted in this profile.
/// Parsing does not establish that the interface exists or supports policing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetInterface(String);

impl EthernetInterface {
    /// Return the normalized NX-API identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An identifier is not a physical or breakout Ethernet interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidInterface;

impl fmt::Display for InvalidInterface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected Ethernet<slot>/<port> or Ethernet<slot>/<port>/<breakout>")
    }
}

impl std::error::Error for InvalidInterface {}

impl FromStr for EthernetInterface {
    type Err = InvalidInterface;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let lower = value.to_ascii_lowercase();
        let suffix = lower
            .strip_prefix("ethernet")
            .or_else(|| lower.strip_prefix("eth"))
            .ok_or(InvalidInterface)?;
        let parts: Vec<&str> = suffix.split('/').collect();
        if !(2..=3).contains(&parts.len())
            || parts.iter().any(|part| {
                part.is_empty()
                    || part.starts_with('0')
                    || !part.bytes().all(|b| b.is_ascii_digit())
                    || part.parse::<u32>().is_err()
            })
        {
            return Err(InvalidInterface);
        }
        Ok(Self(format!("eth{suffix}")))
    }
}

/// Desired operation on a dedicated customer interface.
///
/// Pass these operations to [crate::Client::apply]. The caller must ensure
/// the port is dedicated and supports the requested policing direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementOperation {
    /// Set the interface administrative state. Does not remove policing.
    SetAdminState {
        /// Dedicated customer interface.
        interface: EthernetInterface,
        /// Whether the interface should be administratively enabled.
        enabled: bool,
    },
    /// Create/update a policer and attach it in one direction.
    Throttle {
        /// Dedicated customer interface whose QoS attachment the caller owns.
        interface: EthernetInterface,
        /// Ingress or egress; support must be checked independently.
        direction: Direction,
        /// Committed information rate in bits per second, never zero.
        rate_bps: NonZeroU64,
        /// Optional committed burst in bytes, never zero when supplied.
        burst_bytes: Option<NonZeroU64>,
    },
    /// Remove SDK-owned policing in one direction; leave link state unchanged.
    RemoveThrottle {
        /// Dedicated customer interface.
        interface: EthernetInterface,
        /// Direction whose SDK-owned restriction should be removed.
        direction: Direction,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_ethernet_identifiers() {
        for (input, expected) in [
            ("Ethernet1/1", "eth1/1"),
            ("ETH1/10", "eth1/10"),
            ("Ethernet1/1/2", "eth1/1/2"),
        ] {
            assert_eq!(
                input.parse::<EthernetInterface>().unwrap().as_str(),
                expected
            );
        }
    }

    #[test]
    fn rejects_unsupported_or_unsafe_identifiers() {
        for input in [
            "",
            "mgmt0",
            "port-channel1",
            "eth1",
            "eth1/0",
            "eth1/01",
            "eth1//1",
            "eth1/../1",
            "eth1/1?x=1",
            "eth1/1/1/1",
        ] {
            assert!(input.parse::<EthernetInterface>().is_err(), "{input}");
        }
    }
}
