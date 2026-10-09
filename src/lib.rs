//! Cisco Nexus NX-API REST (DME) enforcement client.
//!
//! Execute typed interface administration and bandwidth policing operations.
//! Callers own customer identity, inventory resolution and OSS event mapping.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod client;
mod dme;
pub mod enforcement;
pub mod policy;
mod session;
pub use policy::{BandwidthPolicy, InvalidPolicyName, PolicyName};

pub use client::{
    ApplyError, ApplyReport, Client, ClientBuilder, Error, SessionMetadata, TransportError,
};
pub use session::{SessionStore, SessionStoreError, StoredSession};

pub use enforcement::{Direction, EnforcementOperation, EthernetInterface, InvalidInterface};
