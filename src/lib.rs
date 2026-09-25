//! Cisco NX-API enforcement SDK scaffold.
//!
//! This initial crate defines vendor-facing enforcement intent. HTTP transport,
//! authentication, DME serialization and readback are not implemented yet.
//! Callers own customer identity, inventory resolution and OSS event mapping.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod enforcement;

pub use enforcement::{Direction, EnforcementOperation, EthernetInterface, InvalidInterface};
