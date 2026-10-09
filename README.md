# nxapi

Async Cisco Nexus **NX-API REST/DME** client for dedicated-interface enforcement.
Version 0.6.0 adds a builder and an optional session-store contract.
This is not the NX-API CLI/JSON-RPC interface.

## Install

Version 0.6.0 provides Cisco `aaaLogin` timing metadata, explicit refresh,
and optional persistence of session cookies through the `SessionStore` trait.
The builder configures transport and policy options individually.

After publishing 0.6.0:

```toml
[dependencies]
nxapi = "0.6.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Reusable policy lifecycle

Use these methods for pre-provisioned policies shared by multiple interfaces:

| Method | Behavior |
| --- | --- |
| `define_policy` | Create a named class-default policer; reject an existing name |
| `edit_policy` | Update an existing policer; reject a missing name |
| `remove_policy` | Delete the definition only; caller must unassign it everywhere first |
| `assign_policy` | Attach an existing policy to an interface/direction, replacing that slot |
| `unassign_policy` | Detach the expected policy without deleting its definition |

```rust,no_run
use nxapi::{Client, BandwidthPolicy, Direction};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut client = Client::builder("https://192.0.2.10:443")
    .timeout(std::time::Duration::from_secs(5))
    .policy_prefix("pcef")
    .build()?;
client.login(&std::env::var("NXAPI_USERNAME")?,
             &std::env::var("NXAPI_PASSWORD")?).await?;
let name = "quota-10m".parse()?;
let interface = "Ethernet1/10".parse()?;
let mut policy = BandwidthPolicy {
    rate_bps: 10_000_000.try_into()?,
    burst_bytes: Some(65_536.try_into()?),
};
client.define_policy(&name, &policy).await?;
client.assign_policy(&name, &interface, Direction::Ingress).await?;
policy.rate_bps = 20_000_000.try_into()?;
client.edit_policy(&name, &policy).await?;
client.unassign_policy(&name, &interface, Direction::Ingress).await?;
client.remove_policy(&name).await?;
# Ok(())
# }
```

Names accept 1–39 ASCII letters, digits, underscores or hyphens. Edits affect
every interface using the policy, update only its class-default policer, and
leave other classes intact. `burst_bytes: None` preserves the existing/default
burst rather than resetting it. Unassign is a no-op if already detached and
refuses to detach a different policy. Remove does not discover or detach users
of a policy: the caller must ensure all references are removed first; device
errors are propagated. All methods return `Result<(), Error>`.

Existence/ownership checks are not atomic with writes. Serialize management
operations with other writers. These methods never alter interface admin state.
Login retains the returned APIC cookie and returns `SessionMetadata`. Cisco
requires `refreshTimeoutSeconds`; the client records its monotonic refresh
deadline and parses optional GUI/REST timeouts, creation/first-login times,
username and software version. Use `refresh_due_within(margin)` to schedule
renewal before expiry, inspect the non-secret data via `session_metadata()`, or
call `refresh()` to POST `aaaRefresh` without a body using the existing cookie.
A successful refresh replaces cookie and metadata together; transient
or malformed refresh failures preserve the current session, while HTTP 401/403
clears it. A manually supplied cookie has no timing metadata. The deadline is a
renewal hint, not proof that the device still accepts the session. Session
tokens and IDs are never included in metadata/debug output. Passwords are not
stored.

To persist a session, implement `SessionStore` and attach it with
`Client::builder(endpoint).session_store(store, key).build()`. The key must
identify the device and login account. The store receives a sensitive cookie
and a wall-clock refresh deadline. Call `ensure_authenticated(username,
password)` to restore a saved cookie, refresh it near the deadline, or log in.
For an already shared `Arc<dyn SessionStore>`, use `shared_session_store`.
Storage alone does not serialize simultaneous logins across processes; a
distributed coordinator is required if that guarantee is needed.

## Legacy per-interface convenience operations

```rust,no_run
use std::num::NonZeroU64;
use nxapi::{Client, Direction, EnforcementOperation, EthernetInterface};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new("https://192.0.2.10")?;
    client.login(&std::env::var("NXAPI_USERNAME")?,
                 &std::env::var("NXAPI_PASSWORD")?).await?;
    let interface: EthernetInterface = "Ethernet1/10".parse()?;

    // Block the dedicated customer port.
    client.apply(&EnforcementOperation::SetAdminState {
        interface: interface.clone(), enabled: false,
    }).await?;

    // Unblock it. This does not change policing.
    client.apply(&EnforcementOperation::SetAdminState {
        interface: interface.clone(), enabled: true,
    }).await?;
    assert!(client.admin_state(&interface).await?);

    // Customer upload: create a policer and attach the ingress policy.
    client.apply(&EnforcementOperation::Throttle {
        interface: interface.clone(),
        direction: Direction::Ingress,
        rate_bps: NonZeroU64::new(10_000_000).unwrap(),
        burst_bytes: NonZeroU64::new(65_536),
    }).await?;

    // Remove this restriction. Repeat with Egress for customer download.
    client.apply(&EnforcementOperation::RemoveThrottle {
        interface, direction: Direction::Ingress,
    }).await?;
    Ok(())
}
```

Alternatively, provide an existing session with
`client.set_session_cookie("APIC-cookie=<token>")?`. Passwords are not stored.
The caller handles expiration/renewal; failed login clears the previous session.
Authentication failures are returned, not retried.

## Behavior and ownership

| Operation | Device requests |
| --- | --- |
| SetAdminState | POST l1PhysIf adminSt=up/down |
| Throttle | POST ipqosPolice configuration, then POST interface policy attachment |
| RemoveThrottle | GET current attachment; POST its deletion; POST owned policy-map deletion |
| admin_state | GET interface administrative state |

Rates are bits per second; explicit bursts are bytes. A missing burst leaves the
device's current/default burst unchanged. Each operation affects one direction:
ingress is customer upload, egress is customer download. Removal detaches the
owned service-policy, then deletes the entire owned policy map (including its
class and policer). It does not enable a disabled interface. Already-detached
policies skip the detach step, so empty maps left by 0.2.0 can still be cleaned up.

The attachment is read before deletion. An unexpected policy name or malformed
response fails before any write. This check is not atomic: the caller must
serialize changes to the dedicated port and prevent other writers racing it.
The SDK does not delete default policies or unrelated named maps. SDK-owned
maps must not be shared with other ports. Mutation counts exclude the ownership
read. A failed detach prevents map deletion; a failed map deletion leaves the
port detached and reports partial progress. No automatic rollback is performed.

This request sequence is covered by mock HTTP tests; verify it on the target
NX-OS release before production rollout. No live-switch verification is implied.

Policy names are `nxapi-eth1-10-in` / `nxapi-eth1-10-out`. Set
`.policy_prefix("pcef")` on the client builder when adopting existing PCEF
policers so removal/update addresses the same objects.

The caller must own a dedicated customer port and its QoS attachment; applying
a policy can replace an existing attachment. This profile uses class-default,
not per-IP filtering on shared ports. It does not discover switch capabilities.
Actual rate limits, direction support (particularly egress), burst granularity,
and forwarding behavior depend on the Nexus hardware and NX-OS release.

The DME policer uses `conformAction=transmit` and
`exceedAction=unspecified`, matching the existing PCEF lab configuration.
Device default exceed behavior and effective hardware policing must be checked
in the target lab; an HTTP acknowledgement alone does not prove traffic limiting.

## Transport and errors

The client reuses its connection pool. HTTPS certificate verification is enabled
by default; redirects are always rejected to avoid forwarding credentials.
The client builder allows a per-request timeout (30s default), response size limit
(1 MiB default), explicit plain HTTP for labs, and explicit TLS verification
bypass. A device endpoint must be an origin; paths, embedded credentials,
queries and fragments are rejected.

`Client::apply` sends requests sequentially and returns `ApplyReport` on device
acknowledgement. HTTP failures, malformed responses, and Cisco DME error objects
even inside HTTP 200 fail the operation. `ApplyError.requests_completed` tells
the caller how many prior requests were acknowledged. The failed request may
have applied if its response was lost; changes are not transactional and there
is no automatic retry or rollback. Transport errors include a category, HTTP
method, sanitized device origin, relative API path and the underlying network or
TLS cause chain. Error messages omit credentials, cookies, request/response
bodies and URLs captured internally by the HTTP client. Cisco error codes are
retained.

`admin_state` reads configuration back, not operational link state. Automatic
QoS readback, traffic validation, login renewal and persistence across device
reboots are not provided by this release.

OSS events, inventory resolution and broker routing remain caller concerns.
No dependency on PCEF or Qanat is required.

## Verification

```text
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo package --locked
```

Integration tests run actual HTTP calls against local mock servers. They cover
authentication, request order/payloads, both directions, reverse operations,
HTTP/DME failures, partial application, redirects, timeouts, response size limits
and administrative readback. These do not substitute for a live Nexus lab test.

## Cisco references

- [Login](https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference/latest/logging-in/)
- [Interface state](https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference-release-9-2x/configuring-an-ethernet-interface/)
- [Policing and removal](https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference/latest/configuring-qos-policy-maps/)
- [Policy attachment](https://developer.cisco.com/docs/nx-os-n3k-n9k-api-ref-7-x/configuring-qos/)

## License

Apache-2.0. See [LICENSE](LICENSE).
