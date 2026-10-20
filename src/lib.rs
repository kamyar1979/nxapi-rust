//! Cisco Nexus NX-API REST (DME) enforcement client.
//!
//! Execute typed interface administration and bandwidth policing operations.
//! Callers own customer identity, inventory resolution and OSS event mapping.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod client;
mod connector;
mod dme;
pub mod enforcement;
pub mod ipqos;
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
    EditBandwidthPolicy, EditIpBandwidthPolicy, GetInterfaceState, RemoveBandwidthPolicy,
    RemoveIpBandwidthPolicy, UnassignBandwidthPolicy,
};
