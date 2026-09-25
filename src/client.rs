use crate::{EnforcementOperation, EthernetInterface, dme};
use reqwest::{
    Method, Url,
    header::{COOKIE, HeaderValue},
};
use serde_json::{Value, json};
use std::time::Duration;
use thiserror::Error;

/// Failures from configuration, authentication or a single device request.
/// Raw response bodies and authentication secrets are never included.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid endpoint, cookie or client options.
    #[error("invalid NX-API configuration: {0}")]
    Configuration(&'static str),
    /// Network or TLS failure, with the request URL stripped.
    #[error("NX-API transport failed: {0}")]
    Transport(#[source] reqwest::Error),
    /// HTTP status outside the successful range.
    #[error("NX-API returned HTTP {0}")]
    Http(u16),
    /// A Cisco DME error, including errors inside HTTP 200 responses.
    #[error("NX-API DME error (code {code})")]
    Device {
        /// Cisco numeric code, if supplied.
        code: String,
    },
    /// JSON or response structure did not match the DME protocol.
    #[error("invalid NX-API response: {0}")]
    Response(&'static str),
    /// The authenticated session is missing.
    #[error("NX-API authentication required; call login or set_session_cookie")]
    Unauthenticated,
}

/// Failure during an operation. Requests before this failure may have applied.
#[derive(Debug, Error)]
#[error("NX-API operation failed after {requests_completed} completed requests: {source}")]
pub struct ApplyError {
    /// Number of prior requests acknowledged by the device.
    pub requests_completed: usize,
    /// Underlying request failure. A transport failure can have an unknown outcome.
    #[source]
    pub source: Error,
}

/// Successful device acknowledgements, not proof of hardware forwarding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyReport {
    /// Number of successfully acknowledged requests.
    pub requests_completed: usize,
}

/// Connection and policy naming options.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Per-request deadline, including reading the response body.
    pub timeout: Duration,
    /// Explicit lab opt-in to plain HTTP. Defaults to false.
    pub allow_http: bool,
    /// Explicit lab opt-in to invalid TLS certificates. Defaults to false.
    pub insecure_skip_tls_verify: bool,
    /// Prefix for SDK-owned per-interface policy maps. Defaults to "nxapi".
    /// Set to "pcef" when taking over existing PCEF-generated policies.
    pub policy_prefix: String,
    /// Maximum response size in bytes.
    pub max_response_bytes: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            allow_http: false,
            insecure_skip_tls_verify: false,
            policy_prefix: "nxapi".into(),
            max_response_bytes: 1024 * 1024,
        }
    }
}

/// Async NX-API REST DME client. Reuses its HTTP connection pool and session.
/// Redirects are refused. No automatic retries or rollback are performed.
pub struct Client {
    http: reqwest::Client,
    origin: Url,
    cookie: Option<HeaderValue>,
    options: ClientOptions,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("origin", &self.origin)
            .field("authenticated", &self.cookie.is_some())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Construct a client for an HTTPS origin, e.g. https://192.0.2.10.
    pub fn new(endpoint: &str) -> Result<Self, Error> {
        Self::with_options(endpoint, ClientOptions::default())
    }

    /// Construct a client with explicit transport settings.
    /// Endpoint must be an origin with no credentials, query, fragment or path.
    pub fn with_options(endpoint: &str, options: ClientOptions) -> Result<Self, Error> {
        let origin = Url::parse(endpoint).map_err(|_| Error::Configuration("invalid endpoint"))?;
        if origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !(origin.scheme() == "https" || (origin.scheme() == "http" && options.allow_http))
        {
            return Err(Error::Configuration(
                "expected an HTTPS origin (HTTP requires allow_http)",
            ));
        }
        if options.timeout.is_zero() || options.max_response_bytes == 0 {
            return Err(Error::Configuration(
                "timeout and response size must be positive",
            ));
        }
        if options.policy_prefix.is_empty()
            || options.policy_prefix.len() > 16
            || !options
                .policy_prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Configuration(
                "policy prefix must be 1-16 letters, digits, hyphens or underscores",
            ));
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(options.timeout)
            .tls_danger_accept_invalid_certs(options.insecure_skip_tls_verify)
            .build()
            .map_err(transport)?;
        Ok(Self {
            http,
            origin,
            options,
            cookie: None,
        })
    }

    /// Set a preauthenticated cookie, e.g. APIC-cookie=<token>.
    /// The caller owns session expiration and renewal.
    pub fn set_session_cookie(&mut self, cookie: &str) -> Result<(), Error> {
        if cookie.trim().is_empty() || !cookie.contains('=') {
            return Err(Error::Configuration("expected a nonempty session cookie"));
        }
        let mut header = HeaderValue::from_str(cookie)
            .map_err(|_| Error::Configuration("invalid cookie header"))?;
        header.set_sensitive(true);
        self.cookie = Some(header);
        Ok(())
    }

    /// Authenticate via aaaLogin and retain the returned APIC session cookie.
    /// A failed login clears any previous session. Passwords are not stored.
    pub async fn login(&mut self, username: &str, password: &str) -> Result<(), Error> {
        self.cookie = None;
        if username.is_empty() || password.is_empty() {
            return Err(Error::Configuration(
                "username and password must be nonempty",
            ));
        }
        let body = self
            .request(
                Method::POST,
                "/api/aaaLogin.json",
                Some(json!({"aaaUser":{"attributes":{"name":username,"pwd":password}}})),
                false,
            )
            .await?;
        let login = body.get("aaaLogin").or_else(|| {
            body.get("imdata")
                .and_then(Value::as_array)
                .and_then(|items| items.iter().find_map(|i| i.get("aaaLogin")))
        });
        let token = login
            .and_then(|v| v.pointer("/attributes/token"))
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && !v.contains(';') && !v.chars().any(char::is_whitespace))
            .ok_or(Error::Response("missing or invalid login token"))?;
        self.set_session_cookie(&format!("APIC-cookie={token}"))
    }

    /// Apply one operation on a dedicated, caller-owned customer interface.
    /// Throttle creates the policer before attaching it. On error, no later
    /// request is sent; earlier changes remain. No automatic retry is attempted.
    pub async fn apply(&self, operation: &EnforcementOperation) -> Result<ApplyReport, ApplyError> {
        let requests = dme::requests(operation, &self.options.policy_prefix);
        let mut completed = 0;
        for request in requests {
            let result = self
                .request(Method::POST, &request.path, Some(request.body), true)
                .await;
            result.map_err(|source| ApplyError {
                requests_completed: completed,
                source,
            })?;
            completed += 1;
        }
        Ok(ApplyReport {
            requests_completed: completed,
        })
    }

    /// Read back the configured administrative state (not physical link state).
    pub async fn admin_state(&self, interface: &EthernetInterface) -> Result<bool, Error> {
        let body = self
            .request(Method::GET, &dme::interface_path(interface), None, true)
            .await?;
        let state = body["imdata"]
            .as_array()
            .and_then(|items| {
                items
                    .iter()
                    .find_map(|item| item.pointer("/l1PhysIf/attributes/adminSt"))
            })
            .and_then(Value::as_str);
        match state {
            Some("up") => Ok(true),
            Some("down") => Ok(false),
            _ => Err(Error::Response("missing interface administrative state")),
        }
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        authenticated: bool,
    ) -> Result<Value, Error> {
        let url = self
            .origin
            .join(path)
            .map_err(|_| Error::Configuration("invalid generated path"))?;
        let mut request = self
            .http
            .request(method, url)
            .header("accept", "application/json");
        if authenticated {
            request = request.header(
                COOKIE,
                self.cookie.as_ref().ok_or(Error::Unauthenticated)?.clone(),
            );
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request.send().await.map_err(transport)?;
        if !response.status().is_success() {
            return Err(Error::Http(response.status().as_u16()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if chunk.len() > self.options.max_response_bytes.saturating_sub(bytes.len()) {
                return Err(Error::Response("response exceeded size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::Response("malformed JSON"))?;
        check_device_error(&value)?;
        if authenticated && !value.get("imdata").is_some_and(Value::is_array) {
            return Err(Error::Response("missing imdata array"));
        }
        Ok(value)
    }
}

fn transport(error: reqwest::Error) -> Error {
    Error::Transport(error.without_url())
}

fn check_device_error(value: &Value) -> Result<(), Error> {
    // Walk children as well: an error MO must never be interpreted as success.
    match value {
        Value::Object(object) => {
            if let Some(error) = object.get("error") {
                let code = error
                    .pointer("/attributes/code")
                    .map(|c| {
                        c.as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| c.to_string())
                    })
                    .unwrap_or_else(|| "unknown".into());
                return Err(Error::Device { code });
            }
            for child in object.values() {
                check_device_error(child)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                check_device_error(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}
