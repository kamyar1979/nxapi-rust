# nxapi

A Rust library for describing interface enforcement operations on Cisco
NX-OS devices: administrative state changes and bandwidth policing.

**Current status:** the crate provides validated Ethernet identifiers and typed
operation descriptions. It does not yet send NX-API requests. Authentication,
HTTP transport, device configuration and readback verification are not implemented.
The examples below construct operations locally; they do not modify a switch.

## Installation

Add the Git dependency to your `Cargo.toml`:

```toml
[dependencies]
nxapi = { git = "https://github.com/kamyar1979/nxapi-rust" }
```

## Validate an interface

Physical and breakout Ethernet identifiers are normalized to NX-API form.

```rust
use nxapi::EthernetInterface;

fn main() -> Result<(), nxapi::InvalidInterface> {
    let interface: EthernetInterface = "Ethernet1/1".parse()?;
    assert_eq!(interface.as_str(), "eth1/1");

    let breakout: EthernetInterface = "Ethernet1/1/2".parse()?;
    assert_eq!(breakout.as_str(), "eth1/1/2");

    assert!("mgmt0".parse::<EthernetInterface>().is_err());
    assert!("eth1/../1".parse::<EthernetInterface>().is_err());
    Ok(())
}
```

Validation checks the identifier's syntax, not whether the port exists on the
device. Management interfaces, port channels and subinterfaces are not supported.

## Describe bandwidth limits

Create separate operations for each direction. Rates are in **bits per second**;
an optional burst is in **bytes**. `NonZeroU64` prevents zero-valued rates or
explicit bursts.

```rust
use std::num::NonZeroU64;
use nxapi::{Direction, EnforcementOperation, EthernetInterface};

fn main() -> Result<(), nxapi::InvalidInterface> {
    let interface: EthernetInterface = "Ethernet1/1".parse()?;

    let upload = EnforcementOperation::Throttle {
        interface: interface.clone(),
        direction: Direction::Ingress,
        rate_bps: NonZeroU64::new(10_000_000).unwrap(), // 10 Mbps
        burst_bytes: None,
    };

    let download = EnforcementOperation::Throttle {
        interface,
        direction: Direction::Egress,
        rate_bps: NonZeroU64::new(20_000_000).unwrap(), // 20 Mbps
        burst_bytes: NonZeroU64::new(65_536),
    };

    println!("{upload:?}");
    println!("{download:?}");
    Ok(())
}
```

On a customer-facing switch port, ingress is customer upload and egress is
customer download. This model targets a dedicated customer interface, not
individual IP addresses on a shared port. Policing support and valid rate/burst
values depend on the device and NX-OS version; constructing an operation does
not establish support.

## Describe an administrative state change

```rust
use nxapi::EnforcementOperation;

fn main() -> Result<(), nxapi::InvalidInterface> {
    let disable = EnforcementOperation::SetAdminState {
        interface: "Ethernet1/1".parse()?,
        enabled: false,
    };
    println!("{disable:?}");
    Ok(())
}
```

Use `enabled: true` to describe enabling the interface. Administrative state
and throttling are separate operations: enabling a port does not remove a policer.

## Describe removal of throttling

```rust
use nxapi::{Direction, EnforcementOperation};

fn main() -> Result<(), nxapi::InvalidInterface> {
    let remove = EnforcementOperation::RemoveThrottle {
        interface: "Ethernet1/1".parse()?,
        direction: Direction::Ingress,
    };
    println!("{remove:?}");
    Ok(())
}
```

The intended removal scope is SDK-owned policing in the selected direction,
without changing the interface administrative state. Describe a second operation
with `Direction::Egress` to remove the restriction in both directions.

## License

Apache-2.0. See [LICENSE](LICENSE).
