//! Named, reusable QoS policies, independent of interface assignment.
use std::{num::NonZeroU64, str::FromStr};

/// A safe DME policy-map name: 1–39 ASCII letters, digits, `_` or `-`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyName(String);

impl PolicyName {
    /// Return the device policy-map name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A policy name is empty, too long, or contains unsupported characters.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("policy name must be 1-39 ASCII letters, digits, hyphens or underscores")]
pub struct InvalidPolicyName;

impl FromStr for PolicyName {
    type Err = InvalidPolicyName;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty()
            || value.len() > 39
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(InvalidPolicyName);
        }
        Ok(Self(value.into()))
    }
}

/// Bandwidth policing for the policy's class-default traffic.
/// Other existing classes/settings are not replaced by an edit.
#[derive(Debug, Clone, Copy)]
pub struct BandwidthPolicy {
    /// Committed rate in bits per second.
    pub rate_bps: NonZeroU64,
    /// Burst in bytes. None preserves the current/device-default burst.
    pub burst_bytes: Option<NonZeroU64>,
}
