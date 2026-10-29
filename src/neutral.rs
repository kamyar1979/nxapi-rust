//! The vendor-neutral `network-device` operations on NX-API.
//!
//! A neutral policy `P` is two policy maps on the switch, `P-in` and `P-out`,
//! each a single `class-default` policer; a direction without a limit has no
//! map. Attaching `P` to an interface attaches those maps. The direct rate
//! limit for devices enforcing without policies is the per-interface throttle
//! (`<prefix>-<interface>-in`/`-out`). Every write converges: an operation
//! reads first and writes only what differs.
//!
//! Access lists and access-list-scoped attachment are described in
//! `access.rs`. Interface descriptions and static routes are not implemented
//! yet and answer [`network_device::ErrorKind::Unsupported`].

#![allow(clippy::manual_async_fn)]

use crate::access::interface_map_name;
use crate::operation::parse_interface;
use crate::{
    ApplyError, BandwidthPolicy as Policer, Client, Direction, DriverError, EnforcementOperation,
    Error, EthernetInterface, PolicyName as CiscoName,
};
use network_device::{
    AccessList, AdministrativeState, AttachBandwidthPolicy, BandwidthLimit, BandwidthLimits,
    BandwidthPolicy, BitsPerSecond, BurstBytes, Change, DetachBandwidthPolicy, DeviceError,
    EnsureAccessList, EnsureBandwidthPolicy, EnsureStaticRoute, ErrorKind, Execute, GetAccessList,
    GetBandwidthPolicy, GetInterfacePolicies, GetInterfaceState, InterfacePolicies,
    PolicyAttachment, PolicyName, PolicyScope, RemoveAccessList, RemoveBandwidthPolicy,
    RemoveInterfaceBandwidthLimit, RemoveStaticRoute, SetInterfaceBandwidthLimit,
    SetInterfaceDescription, SetInterfaceState, Unsupported,
};
use std::future::Future;

const DIRECTIONS: [Direction; 2] = [Direction::Ingress, Direction::Egress];

fn suffix(direction: Direction) -> &'static str {
    match direction {
        Direction::Ingress => "in",
        Direction::Egress => "out",
    }
}

/// The switch policy map realizing one direction of a neutral policy.
fn map_name(name: &PolicyName, direction: Direction) -> Result<CiscoName, DriverError> {
    format!("{}-{}", name.as_str(), suffix(direction))
        .parse()
        .map_err(|_| {
            DriverError::Request(Error::Configuration(
                "policy name is too long for an NX-OS policy map",
            ))
        })
}

fn limit_in(limits: BandwidthLimits, direction: Direction) -> Option<BandwidthLimit> {
    match direction {
        Direction::Ingress => limits.ingress(),
        Direction::Egress => limits.egress(),
    }
}

fn policer(limit: BandwidthLimit) -> Policer {
    Policer {
        rate_bps: std::num::NonZeroU64::new(limit.rate.get()).expect("rates are positive"),
        burst_bytes: limit
            .burst
            .and_then(|burst| std::num::NonZeroU64::new(burst.get())),
    }
}

fn limit_of(policer: Policer) -> BandwidthLimit {
    let limit = BandwidthLimit::new(BitsPerSecond::new(policer.rate_bps));
    match policer.burst_bytes {
        Some(burst) => limit.burst(BurstBytes::new(burst)),
        None => limit,
    }
}

/// Wraps a failure after `writes` acknowledged writes.
fn after(writes: usize, source: Error) -> DriverError {
    DriverError::Apply(ApplyError {
        requests_completed: writes,
        source,
    })
}

/// Wraps an `(acknowledged writes, error)` failure.
fn partial((writes, source): (usize, Error)) -> DriverError {
    after(writes, source)
}

fn unsupported(operation: &'static str) -> DriverError {
    DriverError::Unsupported(Unsupported::new(operation))
}

impl DeviceError for DriverError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::InvalidInterface(_) => ErrorKind::Rejected,
            Self::Unsupported(_) => ErrorKind::Unsupported,
            Self::Apply(error) => error_kind(&error.source),
            Self::Request(error) => error_kind(error),
        }
    }

    fn completed_writes(&self) -> usize {
        match self {
            Self::Apply(error) => error.requests_completed,
            _ => 0,
        }
    }
}

/// Every neutral write converges, so a failure that may be momentary is safe
/// to retry.
fn error_kind(error: &Error) -> ErrorKind {
    match error {
        Error::Transport(_) | Error::SessionStorage(_) => ErrorKind::Transient,
        Error::Http(401 | 403) | Error::Unauthenticated => ErrorKind::Authentication,
        Error::Http(408 | 429) | Error::Http(500..=599) => ErrorKind::Transient,
        Error::Http(_) | Error::Device { .. } | Error::Configuration(_) | Error::Response(_) => {
            ErrorKind::Rejected
        }
    }
}

impl Client {
    /// Attaches or detaches the policy maps of `name` on `interface`.
    async fn attachment(
        &self,
        name: &PolicyName,
        interface: &EthernetInterface,
        attach: bool,
    ) -> Result<Change, DriverError> {
        let mut writes = 0;
        let mut defined = false;
        for direction in DIRECTIONS {
            let map = map_name(name, direction)?;
            let path = format!(
                "{}/pmap.json",
                Client::assignment_path(interface, direction)
            );
            if attach {
                if !self
                    .policy_exists(&map)
                    .await
                    .map_err(|error| after(writes, error))?
                {
                    continue;
                }
                defined = true;
                if self
                    .owns_attachment(&path, map.as_str())
                    .await
                    .map_err(|error| after(writes, error))?
                {
                    continue;
                }
            } else if !self
                .owns_attachment(&path, map.as_str())
                .await
                .map_err(|error| after(writes, error))?
            {
                continue;
            }
            self.write_assignment(&map, interface, direction, !attach)
                .await
                .map_err(|error| after(writes, error))?;
            writes += 1;
        }
        if attach && !defined {
            return Err(DriverError::Request(Error::Configuration(
                "policy is not defined on the device",
            )));
        }
        Ok(Change::from_writes(writes))
    }

    async fn throttle(
        &self,
        interface: EthernetInterface,
        limits: Option<BandwidthLimits>,
    ) -> Result<Change, DriverError> {
        let mut writes = 0;
        for direction in DIRECTIONS {
            let operation = match limits.and_then(|limits| limit_in(limits, direction)) {
                Some(limit) => {
                    let policer = policer(limit);
                    EnforcementOperation::Throttle {
                        interface: interface.clone(),
                        direction,
                        rate_bps: policer.rate_bps,
                        burst_bytes: policer.burst_bytes,
                    }
                }
                None => EnforcementOperation::RemoveThrottle {
                    interface: interface.clone(),
                    direction,
                },
            };
            let report = self.apply(&operation).await.map_err(|error| {
                DriverError::Apply(ApplyError {
                    requests_completed: writes + error.requests_completed,
                    source: error.source,
                })
            })?;
            writes += report.requests_completed;
        }
        Ok(Change::from_writes(writes))
    }
}

impl Execute<SetInterfaceState> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: SetInterfaceState,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            let report = self
                .apply(&EnforcementOperation::SetAdminState {
                    interface,
                    enabled: operation.state == AdministrativeState::Enabled,
                })
                .await
                .map_err(DriverError::Apply)?;
            Ok(Change::from_writes(report.requests_completed))
        }
    }
}

impl Execute<EnsureBandwidthPolicy> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: EnsureBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let policy = operation.policy;
            let mut writes = 0;
            for direction in DIRECTIONS {
                let map = map_name(&policy.name, direction)?;
                let exists = self
                    .policy_exists(&map)
                    .await
                    .map_err(|error| after(writes, error))?;
                match limit_in(policy.limits, direction) {
                    Some(limit) => {
                        let wanted = policer(limit);
                        if !exists
                            || !self
                                .policy_matches(&map, &wanted)
                                .await
                                .map_err(|error| after(writes, error))?
                        {
                            self.write_policy(&map, &wanted)
                                .await
                                .map_err(|error| after(writes, error))?;
                            writes += 1;
                        }
                        // Access-list classes carry a copy of the rate.
                        writes += self
                            .sync_interface_maps(policy.name.as_str(), direction, &wanted)
                            .await
                            .map_err(|(done, error)| after(writes + done, error))?;
                    }
                    None if exists => {
                        // Refuses while attached, so a narrowed policy never
                        // leaves an interface half enforced.
                        self.remove_policy(&map)
                            .await
                            .map_err(|error| after(writes, error))?;
                        writes += 1;
                    }
                    None => {}
                }
            }
            Ok(Change::from_writes(writes))
        }
    }
}

impl Execute<RemoveBandwidthPolicy> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: RemoveBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let mut writes = 0;
            for direction in DIRECTIONS {
                let map = map_name(&operation.name, direction)?;
                if self
                    .policy_exists(&map)
                    .await
                    .map_err(|error| after(writes, error))?
                {
                    self.remove_policy(&map)
                        .await
                        .map_err(|error| after(writes, error))?;
                    writes += 1;
                }
            }
            Ok(Change::from_writes(writes))
        }
    }
}

impl Execute<AttachBandwidthPolicy> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: AttachBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            match operation.scope {
                PolicyScope::Interface => self.attachment(&operation.name, &interface, true).await,
                PolicyScope::AccessList(list) => {
                    let mut writes = 0;
                    let mut defined = false;
                    for direction in DIRECTIONS {
                        let source = map_name(&operation.name, direction)?;
                        let Some(rate) = self
                            .read_policer(&source)
                            .await
                            .map_err(|error| after(writes, error))?
                        else {
                            continue;
                        };
                        defined = true;
                        let map =
                            interface_map_name(operation.name.as_str(), &interface, direction);
                        writes += self
                            .attach_list(&map, list.as_str(), &rate, &interface, direction)
                            .await
                            .map_err(|(done, error)| after(writes + done, error))?;
                    }
                    if !defined {
                        return Err(DriverError::Request(Error::Configuration(
                            "policy is not defined on the device",
                        )));
                    }
                    Ok(Change::from_writes(writes))
                }
            }
        }
    }
}

impl Execute<DetachBandwidthPolicy> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: DetachBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            match operation.scope {
                PolicyScope::Interface => self.attachment(&operation.name, &interface, false).await,
                PolicyScope::AccessList(list) => {
                    let mut writes = 0;
                    for direction in DIRECTIONS {
                        let map =
                            interface_map_name(operation.name.as_str(), &interface, direction);
                        writes += self
                            .detach_list(&map, list.as_str(), &interface, direction)
                            .await
                            .map_err(|(done, error)| after(writes + done, error))?;
                    }
                    Ok(Change::from_writes(writes))
                }
            }
        }
    }
}

impl Execute<SetInterfaceBandwidthLimit> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: SetInterfaceBandwidthLimit,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            self.throttle(interface, Some(operation.limits)).await
        }
    }
}

impl Execute<RemoveInterfaceBandwidthLimit> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: RemoveInterfaceBandwidthLimit,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            self.throttle(interface, None).await
        }
    }
}

impl Execute<GetInterfaceState> for Client {
    type Output = AdministrativeState;

    fn execute<'a>(
        &'a self,
        operation: GetInterfaceState,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            let enabled = self
                .admin_state(&interface)
                .await
                .map_err(DriverError::Request)?;
            Ok(if enabled {
                AdministrativeState::Enabled
            } else {
                AdministrativeState::Disabled
            })
        }
    }
}

impl Execute<GetBandwidthPolicy> for Client {
    type Output = Option<BandwidthPolicy>;

    fn execute<'a>(
        &'a self,
        operation: GetBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let mut limits = [None, None];
            for (slot, direction) in limits.iter_mut().zip(DIRECTIONS) {
                let map = map_name(&operation.name, direction)?;
                *slot = self
                    .read_policer(&map)
                    .await
                    .map_err(DriverError::Request)?
                    .map(limit_of);
            }
            let [ingress, egress] = limits;
            Ok(BandwidthLimits::new(ingress, egress)
                .ok()
                .map(|limits| BandwidthPolicy::new(operation.name, limits)))
        }
    }
}

impl Execute<GetInterfacePolicies> for Client {
    type Output = InterfacePolicies;

    fn execute<'a>(
        &'a self,
        operation: GetInterfacePolicies,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            let mut observed = InterfacePolicies::default();
            let mut throttle = [None, None];
            for (index, direction) in DIRECTIONS.into_iter().enumerate() {
                let Some(name) = self
                    .attached_policy(&interface, direction)
                    .await
                    .map_err(DriverError::Request)?
                else {
                    continue;
                };
                let (_, throttle_name) =
                    crate::dme::policy(&interface, direction, self.policy_prefix());
                if name == throttle_name {
                    let map: CiscoName = name.parse().map_err(|_| {
                        DriverError::Request(Error::Response("unexpected throttle name"))
                    })?;
                    throttle[index] = self
                        .read_policer(&map)
                        .await
                        .map_err(DriverError::Request)?
                        .map(limit_of);
                    continue;
                }
                let slug = format!(
                    "-{}-{}",
                    interface.as_str().replace('/', "-"),
                    suffix(direction)
                );
                if let Some(policy) = name
                    .strip_suffix(&slug)
                    .and_then(|base| PolicyName::new(base).ok())
                {
                    let classes = self
                        .map_classes(&name)
                        .await
                        .map_err(DriverError::Request)?
                        .unwrap_or_default();
                    for (class, _) in classes {
                        let Ok(list) = network_device::AccessListName::new(class) else {
                            continue;
                        };
                        let attachment = PolicyAttachment {
                            name: policy.clone(),
                            scope: PolicyScope::AccessList(list),
                        };
                        if !observed.attachments.contains(&attachment) {
                            observed.attachments.push(attachment);
                        }
                    }
                    continue;
                }
                let neutral = name
                    .strip_suffix(&format!("-{}", suffix(direction)))
                    .and_then(|base| PolicyName::new(base).ok());
                if let Some(neutral) = neutral
                    && !observed.attachments.iter().any(|attachment| {
                        attachment.name == neutral && attachment.scope == PolicyScope::Interface
                    })
                {
                    observed.attachments.push(PolicyAttachment {
                        name: neutral,
                        scope: PolicyScope::Interface,
                    });
                }
            }
            let [ingress, egress] = throttle;
            observed.bandwidth_limit = BandwidthLimits::new(ingress, egress).ok();
            Ok(observed)
        }
    }
}

impl Execute<EnsureAccessList> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: EnsureAccessList,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.ensure_access_list(&operation.list)
                .await
                .map(Change::from_writes)
                .map_err(partial)
        }
    }
}

impl Execute<RemoveAccessList> for Client {
    type Output = Change;

    fn execute<'a>(
        &'a self,
        operation: RemoveAccessList,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.remove_access_list(&operation.name)
                .await
                .map(Change::from_writes)
                .map_err(partial)
        }
    }
}

impl Execute<GetAccessList> for Client {
    type Output = Option<AccessList>;

    fn execute<'a>(
        &'a self,
        operation: GetAccessList,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.read_access_list(&operation.name)
                .await
                .map_err(DriverError::Request)
        }
    }
}

macro_rules! unsupported_operation {
    ($operation:ty, $name:literal) => {
        impl Execute<$operation> for Client {
            type Output = Change;

            fn execute<'a>(
                &'a self,
                _operation: $operation,
            ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
                async move { Err(unsupported($name)) }
            }
        }
    };
}

unsupported_operation!(SetInterfaceDescription, "set_interface_description");
unsupported_operation!(EnsureStaticRoute, "ensure_static_route");
unsupported_operation!(RemoveStaticRoute, "remove_static_route");

#[cfg(test)]
mod tests {
    use super::*;
    use network_device::BurstBytes;
    use std::num::NonZeroU64;

    fn name(value: &str) -> PolicyName {
        PolicyName::new(value).unwrap()
    }

    #[test]
    fn a_neutral_policy_maps_to_one_switch_map_per_direction() {
        assert_eq!(
            map_name(&name("rate-limit-10m"), Direction::Ingress)
                .unwrap()
                .as_str(),
            "rate-limit-10m-in"
        );
        assert_eq!(
            map_name(&name("rate-limit-10m"), Direction::Egress)
                .unwrap()
                .as_str(),
            "rate-limit-10m-out"
        );
        // NX-OS policy maps hold at most 39 characters, suffix included.
        assert!(map_name(&name(&"p".repeat(36)), Direction::Ingress).is_ok());
        assert!(map_name(&name(&"p".repeat(37)), Direction::Egress).is_err());
    }

    #[test]
    fn limits_and_policers_round_trip() {
        let limit = BandwidthLimit::new(BitsPerSecond::new(NonZeroU64::new(10_000_000).unwrap()))
            .burst(BurstBytes::new(NonZeroU64::new(1_500).unwrap()));
        let switch = policer(limit);
        assert_eq!(switch.rate_bps.get(), 10_000_000);
        assert_eq!(switch.burst_bytes.map(NonZeroU64::get), Some(1_500));
        assert_eq!(limit_of(switch), limit);
    }

    #[test]
    fn errors_are_classified_for_neutral_callers() {
        assert_eq!(error_kind(&Error::Http(401)), ErrorKind::Authentication);
        assert_eq!(
            error_kind(&Error::Unauthenticated),
            ErrorKind::Authentication
        );
        assert_eq!(error_kind(&Error::Http(503)), ErrorKind::Transient);
        assert_eq!(error_kind(&Error::Http(404)), ErrorKind::Rejected);
        assert_eq!(
            error_kind(&Error::Device { code: "103".into() }),
            ErrorKind::Rejected
        );
        let partial = after(2, Error::Configuration("refused"));
        assert_eq!(partial.kind(), ErrorKind::Rejected);
        assert_eq!(partial.completed_writes(), 2);
        assert_eq!(
            unsupported("ensure_static_route").kind(),
            ErrorKind::Unsupported
        );
    }
}
