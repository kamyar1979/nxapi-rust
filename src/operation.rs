//! Integration with the `network-device` operational eDSL.
//!
//! Authentication and session management remain part of [`crate::Client`]
//! lifecycle. Once authenticated, the client executes both shared semantic
//! operations and NX-API-specific policy operations.

#![allow(clippy::manual_async_fn)]

use crate::{
    ApplyError, ApplyReport, BandwidthPolicy, Client, Direction, EnforcementOperation, Error,
    EthernetInterface, InvalidInterface, IpQosClassifier, PolicyName,
};
use network_device::{AdministrativeState, Driver, Execute, InterfaceName, SetInterfaceState};
use std::future::Future;

/// Error returned while executing a network-device operation through NX-API.
#[derive(Debug, thiserror::Error)]
pub enum DriverError {
    /// A neutral interface name cannot be represented as an NX-API Ethernet interface.
    #[error("interface is not supported by this NX-API driver")]
    InvalidInterface(#[source] InvalidInterface),
    /// A multi-request NX-API operation failed after zero or more acknowledged writes.
    #[error("NX-API operation failed")]
    Apply(#[source] ApplyError),
    /// A single NX-API request failed.
    #[error("NX-API request failed")]
    Request(#[source] Error),
}

impl Driver for Client {
    type Error = DriverError;
}

impl Execute<EnforcementOperation> for Client {
    type Output = ApplyReport;

    fn execute<'a>(
        &'a self,
        operation: EnforcementOperation,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            Client::apply(self, &operation)
                .await
                .map_err(DriverError::Apply)
        }
    }
}

impl Execute<SetInterfaceState> for Client {
    type Output = ApplyReport;

    fn execute<'a>(
        &'a self,
        operation: SetInterfaceState,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            let interface = parse_interface(&operation.interface)?;
            let operation = EnforcementOperation::SetAdminState {
                interface,
                enabled: operation.state == AdministrativeState::Enabled,
            };
            Client::apply(self, &operation)
                .await
                .map_err(DriverError::Apply)
        }
    }
}

/// Reads the configured administrative state of an interface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GetInterfaceState {
    /// Interface whose configured state should be read.
    pub interface: InterfaceName,
}

impl GetInterfaceState {
    /// Creates an interface-state query.
    pub fn new(interface: InterfaceName) -> Self {
        Self { interface }
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
            self.admin_state(&interface)
                .await
                .map(|enabled| {
                    if enabled {
                        AdministrativeState::Enabled
                    } else {
                        AdministrativeState::Disabled
                    }
                })
                .map_err(DriverError::Request)
        }
    }
}

/// Defines a reusable class-default bandwidth policy.
#[derive(Debug, Clone)]
pub struct DefineBandwidthPolicy {
    /// Name of the policy to define.
    pub name: PolicyName,
    /// Desired policer settings.
    pub policy: BandwidthPolicy,
}

impl DefineBandwidthPolicy {
    /// Creates a policy-definition operation.
    pub fn new(name: PolicyName, policy: BandwidthPolicy) -> Self {
        Self { name, policy }
    }
}

impl Execute<DefineBandwidthPolicy> for Client {
    type Output = ();

    fn execute<'a>(
        &'a self,
        operation: DefineBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.define_policy(&operation.name, &operation.policy)
                .await
                .map_err(DriverError::Request)
        }
    }
}

/// Updates an existing class-default bandwidth policy.
#[derive(Debug, Clone)]
pub struct EditBandwidthPolicy {
    /// Name of the policy to update.
    pub name: PolicyName,
    /// New policer settings.
    pub policy: BandwidthPolicy,
}

impl EditBandwidthPolicy {
    /// Creates a policy-edit operation.
    pub fn new(name: PolicyName, policy: BandwidthPolicy) -> Self {
        Self { name, policy }
    }
}

impl Execute<EditBandwidthPolicy> for Client {
    type Output = ();

    fn execute<'a>(
        &'a self,
        operation: EditBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.edit_policy(&operation.name, &operation.policy)
                .await
                .map_err(DriverError::Request)
        }
    }
}

/// Removes an unattached class-default bandwidth policy.
#[derive(Debug, Clone)]
pub struct RemoveBandwidthPolicy {
    /// Name of the policy to remove.
    pub name: PolicyName,
}

impl RemoveBandwidthPolicy {
    /// Creates a policy-removal operation.
    pub fn new(name: PolicyName) -> Self {
        Self { name }
    }
}

impl Execute<RemoveBandwidthPolicy> for Client {
    type Output = ();

    fn execute<'a>(
        &'a self,
        operation: RemoveBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.remove_policy(&operation.name)
                .await
                .map_err(DriverError::Request)
        }
    }
}

/// Assigns an existing bandwidth policy to an interface and direction.
#[derive(Debug, Clone)]
pub struct AssignBandwidthPolicy {
    /// Policy to assign.
    pub name: PolicyName,
    /// Interface that owns the attachment slot.
    pub interface: EthernetInterface,
    /// Traffic direction of the attachment.
    pub direction: Direction,
}

impl AssignBandwidthPolicy {
    /// Creates a policy-assignment operation.
    pub fn new(name: PolicyName, interface: EthernetInterface, direction: Direction) -> Self {
        Self {
            name,
            interface,
            direction,
        }
    }
}

impl Execute<AssignBandwidthPolicy> for Client {
    type Output = ();

    fn execute<'a>(
        &'a self,
        operation: AssignBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.assign_policy(&operation.name, &operation.interface, operation.direction)
                .await
                .map_err(DriverError::Request)
        }
    }
}

/// Removes an expected policy assignment while preserving its definition.
#[derive(Debug, Clone)]
pub struct UnassignBandwidthPolicy {
    /// Policy expected in the attachment slot.
    pub name: PolicyName,
    /// Interface that owns the attachment slot.
    pub interface: EthernetInterface,
    /// Traffic direction of the attachment.
    pub direction: Direction,
}

impl UnassignBandwidthPolicy {
    /// Creates a policy-unassignment operation.
    pub fn new(name: PolicyName, interface: EthernetInterface, direction: Direction) -> Self {
        Self {
            name,
            interface,
            direction,
        }
    }
}

impl Execute<UnassignBandwidthPolicy> for Client {
    type Output = ();

    fn execute<'a>(
        &'a self,
        operation: UnassignBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.unassign_policy(&operation.name, &operation.interface, operation.direction)
                .await
                .map_err(DriverError::Request)
        }
    }
}

/// Defines an ACL-classified bandwidth policy.
#[derive(Debug, Clone)]
pub struct DefineIpBandwidthPolicy {
    /// ACL and class-map classifier to create.
    pub classifier: IpQosClassifier,
    /// Name of the policy map to create.
    pub name: PolicyName,
    /// Desired policer settings.
    pub policy: BandwidthPolicy,
}

impl DefineIpBandwidthPolicy {
    /// Creates an IP-policy-definition operation.
    pub fn new(classifier: IpQosClassifier, name: PolicyName, policy: BandwidthPolicy) -> Self {
        Self {
            classifier,
            name,
            policy,
        }
    }
}

impl Execute<DefineIpBandwidthPolicy> for Client {
    type Output = ApplyReport;

    fn execute<'a>(
        &'a self,
        operation: DefineIpBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.define_ip_policy(&operation.classifier, &operation.name, &operation.policy)
                .await
                .map_err(DriverError::Apply)
        }
    }
}

/// Updates the policer of an existing ACL-classified policy.
#[derive(Debug, Clone)]
pub struct EditIpBandwidthPolicy {
    /// Existing ACL and class-map classifier.
    pub classifier: IpQosClassifier,
    /// Existing policy-map name.
    pub name: PolicyName,
    /// New policer settings.
    pub policy: BandwidthPolicy,
}

impl EditIpBandwidthPolicy {
    /// Creates an IP-policy-edit operation.
    pub fn new(classifier: IpQosClassifier, name: PolicyName, policy: BandwidthPolicy) -> Self {
        Self {
            classifier,
            name,
            policy,
        }
    }
}

impl Execute<EditIpBandwidthPolicy> for Client {
    type Output = ();

    fn execute<'a>(
        &'a self,
        operation: EditIpBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.edit_ip_policy(&operation.classifier, &operation.name, &operation.policy)
                .await
                .map_err(DriverError::Request)
        }
    }
}

/// Removes an unattached ACL-classified policy and its owned classifier objects.
#[derive(Debug, Clone)]
pub struct RemoveIpBandwidthPolicy {
    /// Classifier expected to belong to the policy.
    pub classifier: IpQosClassifier,
    /// Policy-map name to remove.
    pub name: PolicyName,
}

impl RemoveIpBandwidthPolicy {
    /// Creates an IP-policy-removal operation.
    pub fn new(classifier: IpQosClassifier, name: PolicyName) -> Self {
        Self { classifier, name }
    }
}

impl Execute<RemoveIpBandwidthPolicy> for Client {
    type Output = ApplyReport;

    fn execute<'a>(
        &'a self,
        operation: RemoveIpBandwidthPolicy,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + 'a {
        async move {
            self.remove_ip_policy(&operation.classifier, &operation.name)
                .await
                .map_err(DriverError::Apply)
        }
    }
}

fn parse_interface(interface: &InterfaceName) -> Result<EthernetInterface, DriverError> {
    interface
        .as_str()
        .parse()
        .map_err(DriverError::InvalidInterface)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_execute<Operation>()
    where
        Operation: Send,
        Client: Execute<Operation>,
    {
    }

    #[test]
    fn client_exposes_every_existing_device_operation() {
        assert_execute::<EnforcementOperation>();
        assert_execute::<SetInterfaceState>();
        assert_execute::<GetInterfaceState>();
        assert_execute::<DefineBandwidthPolicy>();
        assert_execute::<EditBandwidthPolicy>();
        assert_execute::<RemoveBandwidthPolicy>();
        assert_execute::<AssignBandwidthPolicy>();
        assert_execute::<UnassignBandwidthPolicy>();
        assert_execute::<DefineIpBandwidthPolicy>();
        assert_execute::<EditIpBandwidthPolicy>();
        assert_execute::<RemoveIpBandwidthPolicy>();
    }
}
