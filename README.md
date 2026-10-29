# nxapi

Async Cisco Nexus **NX-API REST/DME** client for dedicated-interface enforcement.
This is not the NX-API CLI/JSON-RPC interface.

The client implements the operational eDSL from
[`network-device`](https://crates.io/crates/network-device). Authentication,
session restoration, and transport configuration remain client lifecycle;
authenticated clients can execute and compose standard and NX-API-specific
device operations.

## Install

The crate provides Cisco `aaaLogin` timing metadata, explicit refresh, and
optional persistence of session cookies through the `SessionStore` trait. The
builder configures transport and policy options individually.

```toml
[dependencies]
network-device = "0.5.0"
nxapi = "0.9.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Vendor-neutral driver

`Client` implements every `network-device` operation, so it is a
`network_device::NeutralDriver` and, through it, a `DynDriver` that callers
can select at run time. The neutral operations map onto the switch like this:

| Neutral operation | On the switch |
| --- | --- |
| `EnsureBandwidthPolicy` (policy `P`) | Policy maps `P-in` and `P-out`, each one `class-default` policer; only a direction that differs is written, and a direction without a limit is removed |
| `RemoveBandwidthPolicy` | Both maps removed; refused while attached |
| `AttachBandwidthPolicy` / `DetachBandwidthPolicy`, interface scope | `P-in`/`P-out` attached to (detached from) the interface; another policy already attached is refused |
| `SetInterfaceBandwidthLimit` / `RemoveInterfaceBandwidthLimit` | The per-interface throttle (`<prefix>-<interface>-in`/`-out`) |
| `GetInterfaceState`, `GetBandwidthPolicy`, `GetInterfacePolicies`, `GetAccessList` | Read back from the DME |
| `EnsureAccessList` / `RemoveAccessList` (list `N`) | One ACL `N` per address family it uses, plus class map `N` when attached; written in one request per family, only when it differs. Removal refuses while a policy map uses `N` |
| `AttachBandwidthPolicy` / `DetachBandwidthPolicy`, access-list scope `N` | Class `N`, policed at `P`'s rate, in the policy map `P-<interface>-in`/`-out`, which is attached to the interface; the map holds one class per list and is removed with its last class. Ensuring `P` keeps these rates in sync |
| `SetInterfaceDescription`, static routes | Not implemented yet: `ErrorKind::Unsupported` |

A neutral policy name must leave room for the `-in`/`-out` suffix within the
39 characters NX-OS allows. Every write reads first and writes only what
differs. `DriverError` implements `network_device::DeviceError`: transport and
retryable HTTP failures are `Transient` (every neutral write converges, so a
retry is safe), 401/403 are `Authentication`, and device or configuration
errors are `Rejected`, each with the number of writes acknowledged before the
failure.

## Operational eDSL

A caller can retrieve credentials from its secret store, authenticate the
client, and then execute a credential-free operation program. The eDSL delegates
to the same tested NX-API methods as the direct API:

```rust,no_run
use network_device::{
    AdministrativeState, DriverConnector, InterfaceName, Run, SetInterfaceState, operation,
};
use nxapi::{
    Client, Direction, EnforcementOperation, NxapiAuthentication, NxapiConnector,
};
use std::num::NonZeroU64;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
// The caller obtains these values from its secret store.
let username = std::env::var("NXAPI_USERNAME")?;
let password = std::env::var("NXAPI_PASSWORD")?;

let target = Client::builder("https://192.0.2.10:443");
let client = NxapiConnector
    .connect(&target, NxapiAuthentication::new(username, password))
    .await?;

let interface = InterfaceName::try_from("Ethernet1/10")?;
let nx_interface = "Ethernet1/10".parse()?;

operation(SetInterfaceState::new(
    interface,
    AdministrativeState::Enabled,
))
.then(operation(EnforcementOperation::Throttle {
    interface: nx_interface,
    direction: Direction::Ingress,
    rate_bps: NonZeroU64::new(10_000_000).expect("non-zero rate"),
    burst_bytes: NonZeroU64::new(65_536),
}))
.run(&client)
.await?;
# Ok(())
# }
```

Shared operations such as `SetInterfaceState` come from `network-device`.
NX-API policy types remain in this crate because they encode Cisco DME
ownership and attachment semantics. Policy definition, editing, assignment,
unassignment, and IP-classified policy operations are also available as typed
eDSL operations. Existing direct methods remain backward compatible.

IP-address throttling uses the same typed operation path for IPv4 and IPv6:
define the ACL-classified policy, then assign it to the interface and traffic
direction. `IpMatch::source` and `IpMatch::destination` select the address side
used by the generated ACL.

```rust,no_run
use network_device::{Run, operation};
use nxapi::{
    AssignBandwidthPolicy, BandwidthPolicy, DefineIpBandwidthPolicy, Direction,
    IpAddress, IpMatch, IpQosClassifier, PolicyName,
};
use std::num::NonZeroU64;

# async fn example(client: &nxapi::Client) -> Result<(), Box<dyn std::error::Error>> {
let name: PolicyName = "rate-10m".parse()?;
let classifier = IpQosClassifier::new(
    "classifier-42",
    IpMatch::source("192.0.2.42".parse::<IpAddress>()?),
)?;
let policy = BandwidthPolicy {
    rate_bps: NonZeroU64::new(10_000_000).expect("non-zero rate"),
    burst_bytes: NonZeroU64::new(65_536),
};
let interface: nxapi::EthernetInterface = "Ethernet1/10".parse()?;

operation(DefineIpBandwidthPolicy::new(classifier, name.clone(), policy))
    .then(operation(AssignBandwidthPolicy::new(
        name,
        interface,
        Direction::Ingress,
    )))
    .run(client)
    .await?;
# Ok(())
# }
```

Use an IPv6 string instead of `192.0.2.42` to generate the corresponding IPv6
ACL. The same `AssignBandwidthPolicy` operation supports ingress and egress.

## Reusable policy lifecycle

Use these methods for pre-provisioned policies shared by multiple interfaces:

| Method | Behavior |
| --- | --- |
| `define_policy` | Create a named class-default policer; reject an existing name |
| `edit_policy` | Update an existing policer; reject a missing name |
| `remove_policy` | Delete the definition only after a switch-wide attachment check confirms it is unused |
| `assign_policy` | Attach an existing policy to an interface/direction, replacing that slot |
| `unassign_policy` | Detach the expected policy without deleting its definition |
| `remove_ip_policy` | After ownership and reference checks, delete an IP policy-map, class-map, and ACL |

```rust,no_run
use nxapi::{Client, BandwidthPolicy, Direction};

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let mut client = Client::builder("https://192.0.2.10:443")
    .timeout(std::time::Duration::from_secs(5))
    .policy_prefix("edge")
    .build()?;
client.login(&std::env::var("NXAPI_USERNAME")?,
             &std::env::var("NXAPI_PASSWORD")?).await?;
let name = "rate-10m".parse()?;
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

    // Shut the interface down.
    client.apply(&EnforcementOperation::SetAdminState {
        interface: interface.clone(), enabled: false,
    }).await?;

    // Unblock it. This does not change policing.
    client.apply(&EnforcementOperation::SetAdminState {
        interface: interface.clone(), enabled: true,
    }).await?;
    assert!(client.admin_state(&interface).await?);

    // Received traffic: create a policer and attach the ingress policy.
    client.apply(&EnforcementOperation::Throttle {
        interface: interface.clone(),
        direction: Direction::Ingress,
        rate_bps: NonZeroU64::new(10_000_000).unwrap(),
        burst_bytes: NonZeroU64::new(65_536),
    }).await?;

    // Remove this restriction. Repeat with Egress for sent traffic.
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
ingress is traffic received on the interface, egress is traffic sent out of it. Removal detaches the
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
`.policy_prefix(...)` on the client builder when adopting policers created
under another prefix, so removal and update address the same objects.

The caller must own the interface and its QoS attachment; applying
a policy can replace an existing attachment. This profile uses class-default,
not per-IP filtering on shared ports. It does not discover switch capabilities.
Actual rate limits, direction support (particularly egress), burst granularity,
and forwarding behavior depend on the Nexus hardware and NX-OS release.

The DME policer uses `conformAction=transmit` and
`exceedAction=unspecified`, matching the configuration verified in the lab.
Device default exceed behavior and effective hardware policing must be checked
in the target lab; an HTTP acknowledgement alone does not prove traffic limiting.

For shared-port IP classification, `define_ip_policy` creates a host ACL, a QoS
class-map referencing it, and a policy-map with a policer on that named class.
`edit_ip_policy` verifies that exact single-class relationship before changing
the named-class policer. The policy must still be attached to an interface with
`assign_policy`; defining it alone does not affect traffic. A source-address
classifier matches packets whose source is the given IP, while a
destination-address classifier matches packets whose destination is that IP.
The optional second match can constrain both source and destination, provided
both addresses use the same IP family. These packet semantics are independent
of interface ingress/egress: callers must choose both the endpoint and
attachment direction for their topology.

`remove_ip_policy` checks the exact policy, class-map, and ACL and queries
switch-wide references before deleting them in that order. It refuses deletion
when the policy is attached, a classifier is shared, or the reference query is
incomplete or malformed. Checks and writes are not atomic; serialize writers
and reconcile partial failures. These DME reads and deletion payloads require
validation against the target NX-OS release in a Nexus lab.

Only one QoS policy-map can occupy an interface/direction attachment slot;
calling `assign_policy` for another policy replaces that slot. The neutral
access-list-scoped attachment combines several access lists on one interface
in a single policy map, one class per list.

Classifier deletion is intentionally not automated. Cisco documents the named
ACL and class-map DNs and DME deletion convention, but the SDK cannot prove that
another policy does not reference those globally named objects. Safely stop
enforcement with `unassign_policy`; remove classifier objects only through a
separate configuration owner that can perform complete reference discovery.

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

Deciding what to configure, and naming access lists, are caller concerns.

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
- [IPv4 and IPv6 ACLs](https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference/latest/configuring-ipv4-and-ipv6-acls/)
- [QoS class maps](https://developer.cisco.com/docs/cisco-nexus-3000-and-9000-series-nx-api-rest-sdk-user-guide-and-api-reference/latest/configuring-qos-class-maps/)

## License

Apache-2.0. See [LICENSE](LICENSE).
