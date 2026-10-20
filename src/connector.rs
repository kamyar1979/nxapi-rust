//! Construction and authentication through the `network-device` connector contract.

#![allow(clippy::manual_async_fn)]

use crate::{Client, ClientBuilder, Error};
use network_device::DriverConnector;
use std::future::Future;

/// Authentication material accepted by [`NxapiConnector`].
///
/// Applications should resolve secrets through their credential provider and
/// convert the result into this owned value before connecting.
pub struct NxapiAuthentication {
    username: String,
    password: String,
}

impl NxapiAuthentication {
    /// Creates username/password authentication for Cisco `aaaLogin`.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

impl std::fmt::Debug for NxapiAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NxapiAuthentication")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Builds and authenticates NX-API clients from reusable client configuration.
#[derive(Clone, Copy, Debug, Default)]
pub struct NxapiConnector;

impl DriverConnector for NxapiConnector {
    type Driver = Client;
    type Target = ClientBuilder;
    type Authentication = NxapiAuthentication;
    type Error = Error;

    fn connect<'a>(
        &'a self,
        target: &'a Self::Target,
        authentication: Self::Authentication,
    ) -> impl Future<Output = Result<Self::Driver, Self::Error>> + Send + 'a {
        async move {
            let NxapiAuthentication { username, password } = authentication;
            let mut client = target.clone().build()?;
            client.ensure_authenticated(&username, &password).await?;
            Ok(client)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_debug_output_redacts_password() {
        let authentication = NxapiAuthentication::new("operator", "do-not-log-this");
        let output = format!("{authentication:?}");

        assert!(output.contains("operator"));
        assert!(!output.contains("do-not-log-this"));
    }
}
