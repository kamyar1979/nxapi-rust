use crate::{BandwidthPolicy, Direction, EnforcementOperation, EthernetInterface, PolicyName, dme};
use reqwest::{
    Method, Url,
    header::{COOKIE, HeaderValue},
};
use serde_json::{Value, json};
use std::{
    error::Error as StdError,
    fmt,
    time::{Duration, Instant},
};
use thiserror::Error;

/// Failures from configuration, authentication or a single device request.
/// Raw response bodies and authentication secrets are never included.
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid endpoint, cookie or client options.
    #[error("invalid NX-API configuration: {0}")]
    Configuration(&'static str),
    /// Network or TLS failure with safe request context and the URL stripped
    /// from the underlying HTTP error.
    #[error("NX-API transport failed: {0}")]
    Transport(#[source] TransportError),
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

/// A network, TLS, timeout, or response-body failure with safe request context.
///
/// Credentials, cookies, request bodies, and response bodies are never retained.
#[derive(Debug)]
pub struct TransportError {
    kind: &'static str,
    operation: String,
    detail: String,
    source: reqwest::Error,
}

impl TransportError {
    /// Broad category suitable for logs and metrics.
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// Safe operation description containing only method, sanitized origin and path.
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} while {}: {}",
            self.kind, self.operation, self.detail
        )
    }
}

impl StdError for TransportError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.source)
    }
}

/// Failure during an operation. Requests before this failure may have applied.
#[derive(Debug, Error)]
#[error("NX-API operation failed after {requests_completed} completed requests: {source}")]
pub struct ApplyError {
    /// Number of prior mutation requests acknowledged by the device (excludes reads).
    pub requests_completed: usize,
    /// Underlying request failure. A transport failure can have an unknown outcome.
    #[source]
    pub source: Error,
}

/// Successful device acknowledgements, not proof of hardware forwarding state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyReport {
    /// Number of successfully acknowledged mutation requests (excludes reads).
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
    session: Option<SessionMetadata>,
    options: ClientOptions,
}

/// Non-secret timing and identity metadata returned by Cisco `aaaLogin`.
///
/// The refresh deadline is calculated from a monotonic clock when the response
/// is received; it is a local renewal hint, not proof the device still accepts
/// the session. Session tokens and session IDs are intentionally not exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMetadata {
    /// Monotonic instant at which the successful login response was received.
    pub received_at: Instant,
    /// Monotonic deadline derived from `refreshTimeoutSeconds`.
    pub refresh_deadline: Instant,
    /// Device-provided refresh timeout, in seconds.
    pub refresh_timeout_seconds: u64,
    /// Optional GUI idle timeout, in seconds.
    pub gui_idle_timeout_seconds: Option<u64>,
    /// Optional REST timeout, in seconds (`0` is retained as reported).
    pub rest_timeout_seconds: Option<u64>,
    /// Optional device session creation time (Unix seconds).
    pub creation_time: Option<u64>,
    /// Optional first-login time (Unix seconds).
    pub first_login_time: Option<u64>,
    /// Optional username reported by the device.
    pub user_name: Option<String>,
    /// Optional device software version.
    pub version: Option<String>,
    /// Optional device build timestamp.
    pub build_time: Option<String>,
    /// Whether the device marked this as a remote user session, when reported.
    pub remote_user: Option<bool>,
}

impl SessionMetadata {
    /// Whether the locally calculated refresh deadline has passed.
    pub fn refresh_due(&self) -> bool {
        Instant::now() >= self.refresh_deadline
    }

    /// Remaining time until the local refresh deadline, saturating at zero.
    pub fn refresh_in(&self) -> Duration {
        self.refresh_deadline
            .saturating_duration_since(Instant::now())
    }

    /// Whether the local refresh deadline is within `margin` of now.
    pub fn refresh_due_within(&self, margin: Duration) -> bool {
        self.refresh_in() <= margin
    }
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
            .map_err(|error| transport(error, "building the HTTP client".into()))?;
        Ok(Self {
            http,
            origin,
            options,
            cookie: None,
            session: None,
        })
    }

    /// Set a preauthenticated cookie, e.g. `APIC-cookie=token`.
    /// The caller owns session expiration and renewal.
    pub fn set_session_cookie(&mut self, cookie: &str) -> Result<(), Error> {
        if cookie.trim().is_empty() || !cookie.contains('=') {
            return Err(Error::Configuration("expected a nonempty session cookie"));
        }
        let mut header = HeaderValue::from_str(cookie)
            .map_err(|_| Error::Configuration("invalid cookie header"))?;
        header.set_sensitive(true);
        self.cookie = Some(header);
        self.session = None;
        Ok(())
    }

    /// Authenticate via aaaLogin and retain the returned APIC session cookie.
    /// A failed login clears any previous session. Passwords are not stored.
    pub async fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<SessionMetadata, Error> {
        self.cookie = None;
        self.session = None;
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
        let (token, metadata) = parse_login_response(&body)?;
        self.set_session_cookie(&format!("APIC-cookie={token}"))?;
        self.session = Some(metadata.clone());
        Ok(metadata)
    }

    /// Refresh the current device session using its existing cookie.
    ///
    /// Transient or malformed responses preserve the current cookie and
    /// metadata. An explicit HTTP 401/403 clears them. Successful refresh
    /// atomically replaces the cookie and timing metadata.
    pub async fn refresh(&mut self) -> Result<SessionMetadata, Error> {
        if self.cookie.is_none() {
            return Err(Error::Unauthenticated);
        }
        let body = match self
            .request(Method::POST, "/api/aaaRefresh.json", None, true)
            .await
        {
            Ok(body) => body,
            Err(error @ Error::Http(401 | 403)) => {
                self.cookie = None;
                self.session = None;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        let (token, metadata) = parse_login_response(&body)?;
        let mut cookie = HeaderValue::from_str(&format!("APIC-cookie={token}"))
            .map_err(|_| Error::Response("invalid refreshed login token"))?;
        cookie.set_sensitive(true);
        self.cookie = Some(cookie);
        self.session = Some(metadata.clone());
        Ok(metadata)
    }

    /// Metadata for a login-established session, if available.
    /// Manually supplied cookies have no device timing metadata.
    pub fn session_metadata(&self) -> Option<&SessionMetadata> {
        self.session.as_ref()
    }

    /// Define a new named class-default bandwidth policy without assigning it.
    /// Fails if the name exists. Existence checks are not atomic: callers must
    /// serialize policy management with other writers.
    pub async fn define_policy(
        &self,
        name: &PolicyName,
        policy: &BandwidthPolicy,
    ) -> Result<(), Error> {
        if self.policy_exists(name).await? {
            return Err(Error::Configuration(
                "policy already exists; use edit_policy",
            ));
        }
        self.write_policy(name, policy).await
    }

    /// Edit an existing policy's class-default policer without changing assignments.
    /// This affects every interface using the policy. None for burst preserves it.
    /// Fails if absent; callers must serialize edits with other policy writers.
    pub async fn edit_policy(
        &self,
        name: &PolicyName,
        policy: &BandwidthPolicy,
    ) -> Result<(), Error> {
        if !self.policy_exists(name).await? {
            return Err(Error::Configuration("policy does not exist"));
        }
        self.write_policy(name, policy).await
    }

    /// Delete a named policy definition, never implicitly unassigning interfaces.
    /// Caller must first unassign it everywhere and must own the definition.
    /// Device rejection (including an in-use policy) is propagated unchanged.
    pub async fn remove_policy(&self, name: &PolicyName) -> Result<(), Error> {
        self.request(
            Method::POST,
            "/api/mo/sys/ipqos/dflt/p.json",
            Some(json!({
                "ipqosPMapEntity":{"children":[{"ipqosPMapInst":{"attributes":{
                    "name":name.as_str(),"status":"deleted"
                }}}]}
            })),
            true,
        )
        .await?;
        Ok(())
    }

    /// Assign an existing policy without creating or editing its definition.
    /// Replaces this direction's existing attachment; caller must own the port.
    pub async fn assign_policy(
        &self,
        name: &PolicyName,
        interface: &EthernetInterface,
        direction: Direction,
    ) -> Result<(), Error> {
        if !self.policy_exists(name).await? {
            return Err(Error::Configuration("policy does not exist"));
        }
        self.write_assignment(name, interface, direction, false)
            .await
    }

    /// Detach the expected policy, preserving its definition and other ports.
    /// An absent attachment is a no-op; a different attached name is an error.
    /// The read/check/write is not atomic; callers must serialize port changes.
    pub async fn unassign_policy(
        &self,
        name: &PolicyName,
        interface: &EthernetInterface,
        direction: Direction,
    ) -> Result<(), Error> {
        let path = format!("{}/pmap.json", Self::assignment_path(interface, direction));
        if self.owns_attachment(&path, name.as_str()).await? {
            self.write_assignment(name, interface, direction, true)
                .await?;
        }
        Ok(())
    }

    async fn policy_exists(&self, name: &PolicyName) -> Result<bool, Error> {
        let path = format!("/api/mo/sys/ipqos/dflt/p/name-{}.json", name.as_str());
        let body = self.request(Method::GET, &path, None, true).await?;
        let items = body["imdata"]
            .as_array()
            .ok_or(Error::Response("missing policy data"))?;
        if items.is_empty() {
            return Ok(false);
        }
        if items.len() != 1
            || items[0]
                .pointer("/ipqosPMapInst/attributes/name")
                .and_then(Value::as_str)
                != Some(name.as_str())
        {
            return Err(Error::Response("unexpected policy data"));
        }
        Ok(true)
    }

    async fn write_policy(&self, name: &PolicyName, policy: &BandwidthPolicy) -> Result<(), Error> {
        let mut attrs = json!({"cirRate":policy.rate_bps.to_string(),"cirUnit":"bps", "conformAction":"transmit","exceedAction":"unspecified"});
        if let Some(burst) = policy.burst_bytes {
            attrs["bcRate"] = json!(burst.to_string());
            attrs["bcUnit"] = json!("bytes");
        }
        let request = dme::policer(name.as_str(), attrs);
        self.request(Method::POST, &request.path, Some(request.body), true)
            .await?;
        Ok(())
    }

    fn assignment_path(interface: &EthernetInterface, direction: Direction) -> String {
        let direction = match direction {
            Direction::Ingress => "in",
            Direction::Egress => "out",
        };
        format!(
            "/api/mo/sys/ipqos/dflt/policy/{direction}/intf-[{}]",
            interface.as_str()
        )
    }

    async fn write_assignment(
        &self,
        name: &PolicyName,
        interface: &EthernetInterface,
        direction: Direction,
        remove: bool,
    ) -> Result<(), Error> {
        let attrs = if remove {
            json!({"name":name.as_str(),"status":"deleted"})
        } else {
            json!({"name":name.as_str(),"stats":"yes"})
        };
        self.request(Method::POST, &format!("{}.json", Self::assignment_path(interface, direction)), Some(json!({
            "ipqosIf":{"attributes":{"name":interface.as_str()},"children":[{"ipqosInst":{"attributes":attrs}}]}
        })), true).await?;
        Ok(())
    }

    /// Apply one operation on a dedicated, caller-owned customer interface.
    /// Throttle creates the policer before attaching it. On error, no later
    /// request is sent; earlier changes remain. No automatic retry is attempted.
    /// RemoveThrottle checks attachment ownership, detaches it, then deletes
    /// the owned policy map. It never changes interface administrative state.
    pub async fn apply(&self, operation: &EnforcementOperation) -> Result<ApplyReport, ApplyError> {
        let requests = dme::requests(operation, &self.options.policy_prefix);
        let skip_detach = if let EnforcementOperation::RemoveThrottle {
            interface,
            direction,
        } = operation
        {
            let (direction, name) = dme::policy(interface, *direction, &self.options.policy_prefix);
            let path = format!(
                "/api/mo/sys/ipqos/dflt/policy/{direction}/intf-[{}]/pmap.json",
                interface.as_str()
            );
            !self
                .owns_attachment(&path, &name)
                .await
                .map_err(|source| ApplyError {
                    requests_completed: 0,
                    source,
                })?
        } else {
            false
        };
        let mut completed = 0;
        for request in requests.into_iter().skip(usize::from(skip_detach)) {
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

    // ipqosInst is a singleton: its name is not part of its DN. Never delete
    // that slot without checking which policy is currently attached.
    async fn owns_attachment(&self, path: &str, expected: &str) -> Result<bool, Error> {
        let body = self.request(Method::GET, path, None, true).await?;
        let items = body["imdata"]
            .as_array()
            .ok_or(Error::Response("missing attachment data"))?;
        if items.is_empty() {
            return Ok(false);
        }
        if items.len() != 1 {
            return Err(Error::Response("ambiguous interface policy attachment"));
        }
        let name = items[0]
            .pointer("/ipqosInst/attributes/name")
            .and_then(Value::as_str)
            .ok_or(Error::Response("missing attached policy name"))?;
        if name.is_empty() {
            return Ok(false);
        }
        if name != expected {
            return Err(Error::Configuration(
                "refusing to detach a policy not owned by this operation",
            ));
        }
        Ok(true)
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
        let operation = format!(
            "sending {method} {}{path}",
            self.origin.as_str().trim_end_matches('/')
        );
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
        let mut response = request
            .send()
            .await
            .map_err(|error| transport(error, operation.clone()))?;
        if !response.status().is_success() {
            return Err(Error::Http(response.status().as_u16()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| transport(error, format!("reading the response to {operation}")))?
        {
            if chunk.len() > self.options.max_response_bytes.saturating_sub(bytes.len()) {
                return Err(Error::Response("response exceeded size limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|_| Error::Response("malformed JSON"))?;
        check_device_error(&value)?;
        if authenticated
            && path != "/api/aaaRefresh.json"
            && !value.get("imdata").is_some_and(Value::is_array)
        {
            return Err(Error::Response("missing imdata array"));
        }
        Ok(value)
    }
}

fn transport(error: reqwest::Error, operation: String) -> Error {
    let source = error.without_url();
    let kind = if source.is_timeout() {
        "timeout"
    } else if source.is_connect() {
        "connection failure"
    } else if source.is_body() {
        "response body failure"
    } else if source.is_decode() {
        "response decoding failure"
    } else if source.is_builder() {
        "request construction failure"
    } else if source.is_request() {
        "request failure"
    } else {
        "transport failure"
    };
    let mut causes = Vec::new();
    let mut current = source.source();
    while let Some(cause) = current {
        causes.push(cause.to_string());
        current = cause.source();
    }
    let detail = if causes.is_empty() {
        source.to_string()
    } else {
        causes.join(": ")
    };
    Error::Transport(TransportError {
        kind,
        operation,
        detail,
        source,
    })
}

fn parse_login_response(value: &Value) -> Result<(String, SessionMetadata), Error> {
    let login = value
        .get("aaaLogin")
        .or_else(|| value.get("aaaRefresh"))
        .or_else(|| {
            value
                .get("imdata")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items
                        .iter()
                        .find_map(|item| item.get("aaaLogin").or_else(|| item.get("aaaRefresh")))
                })
        });
    let attributes = login
        .and_then(|entry| entry.get("attributes"))
        .and_then(Value::as_object)
        .ok_or(Error::Response("missing login attributes"))?;
    let token = attributes
        .get("token")
        .and_then(value_as_text)
        .filter(|text| {
            !text.is_empty() && !text.contains(';') && !text.chars().any(char::is_whitespace)
        })
        .ok_or(Error::Response("missing or invalid login token"))?
        .to_owned();
    let refresh_timeout_seconds = required_seconds(attributes, "refreshTimeoutSeconds")?;
    if refresh_timeout_seconds == 0 {
        return Err(Error::Response("invalid refreshTimeoutSeconds"));
    }
    let received_at = Instant::now();
    let refresh_deadline = received_at
        .checked_add(Duration::from_secs(refresh_timeout_seconds))
        .ok_or(Error::Response("refreshTimeoutSeconds is out of range"))?;
    let metadata = SessionMetadata {
        received_at,
        refresh_deadline,
        refresh_timeout_seconds,
        gui_idle_timeout_seconds: optional_seconds(attributes, "guiIdleTimeoutSeconds")?,
        rest_timeout_seconds: optional_seconds(attributes, "restTimeoutSeconds")?,
        creation_time: optional_seconds(attributes, "creationTime")?,
        first_login_time: optional_seconds(attributes, "firstLoginTime")?,
        user_name: optional_text(attributes, "userName")?,
        version: optional_text(attributes, "version")?,
        build_time: optional_text(attributes, "buildTime")?,
        remote_user: optional_bool(attributes, "remoteUser")?,
    };
    Ok((token, metadata))
}

fn value_as_text(value: &Value) -> Option<&str> {
    value.as_str()
}

fn required_seconds(
    attributes: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<u64, Error> {
    optional_seconds(attributes, key)?.ok_or(Error::Response("missing refreshTimeoutSeconds"))
}

fn optional_seconds(
    attributes: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<u64>, Error> {
    let Some(value) = attributes.get(key) else {
        return Ok(None);
    };
    let parsed = value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or(Error::Response("invalid login timing attribute"))?;
    Ok(Some(parsed))
}

fn optional_text(
    attributes: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<String>, Error> {
    let Some(value) = attributes.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or(Error::Response("invalid login metadata attribute"))?;
    Ok((!text.is_empty()).then(|| text.to_owned()))
}

fn optional_bool(
    attributes: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<Option<bool>, Error> {
    let Some(value) = attributes.get(key) else {
        return Ok(None);
    };
    let parsed = value
        .as_bool()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .ok_or(Error::Response("invalid login metadata attribute"))?;
    Ok(Some(parsed))
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
