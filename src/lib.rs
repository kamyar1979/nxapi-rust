//! Cisco Nexus NX-API REST (DME) enforcement client.
//!
//! Execute typed interface administration and bandwidth policing operations.
//! Callers decide what to configure; this crate only talks to the switch.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod access;
mod client;
mod connector;
mod dme;
pub mod enforcement;
pub mod ipqos;
mod neutral;
mod operation;
pub mod policy;
mod session;
pub use policy::{BandwidthPolicy, InvalidPolicyName, PolicyName};

pub use client::{
    ApplyError, ApplyReport, Client, ClientBuilder, Error, SessionMetadata, TransportError,
};
pub use connector::{NxapiAuthentication, NxapiConnector};
pub use session::{SessionStore, SessionStoreError, StoredSession};

pub use enforcement::{Direction, EnforcementOperation, EthernetInterface, InvalidInterface};
pub use ipqos::{
    InvalidClassifierMatch, InvalidClassifierName, InvalidIpAddress, IpAddress, IpEndpoint,
    IpMatch, IpQosClassifier,
};
pub use operation::{
    AssignBandwidthPolicy, DefineBandwidthPolicy, DefineIpBandwidthPolicy, DriverError,
    EditBandwidthPolicy, EditIpBandwidthPolicy, RemoveBandwidthPolicy, RemoveIpBandwidthPolicy,
    UnassignBandwidthPolicy,
};
