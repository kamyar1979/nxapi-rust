# nxapi

Async Cisco Nexus **NX-API REST/DME** client for dedicated-interface enforcement.
Version 0.2.0 adds real HTTPS execution, authentication, Cisco response checking,
and administrative-state readback. This is not the NX-API CLI/JSON-RPC interface.

## Install

After publishing 0.2.0:

```toml
[dependencies]
nxapi = "0.2.0"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Apply operations

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
| RemoveThrottle | POST status=deleted on the owned ipqosPolice |
| admin_state | GET interface administrative state |

Rates are bits per second; explicit bursts are bytes. A missing burst leaves the
device's current/default burst unchanged. Each operation affects one direction:
ingress is customer upload, egress is customer download. Removal leaves an empty
policy map/attachment for reuse and does not enable a disabled interface.

Policy names are `nxapi-eth1-10-in` / `nxapi-eth1-10-out`. Set
`ClientOptions.policy_prefix = "pcef".into()` when adopting existing PCEF
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
`ClientOptions` allows a per-request timeout (30s default), response size limit
(1 MiB default), explicit plain HTTP for labs, and explicit TLS verification
bypass. A device endpoint must be an origin; paths, embedded credentials,
queries and fragments are rejected.

`Client::apply` sends requests sequentially and returns `ApplyReport` on device
acknowledgement. HTTP failures, malformed responses, and Cisco DME error objects
even inside HTTP 200 fail the operation. `ApplyError.requests_completed` tells
the caller how many prior requests were acknowledged. The failed request may
have applied if its response was lost; changes are not transactional and there
is no automatic retry or rollback. Error messages omit raw response text and
credentials. Cisco error codes are retained.

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
