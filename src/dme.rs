use crate::{Direction, EnforcementOperation};
use serde_json::{Value, json};

pub(crate) struct Request {
    pub path: String,
    pub body: Value,
}

pub(crate) fn interface_path(interface: &crate::EthernetInterface) -> String {
    format!("/api/mo/sys/intf/phys-[{}].json", interface.as_str())
}

pub(crate) fn requests(operation: &EnforcementOperation, prefix: &str) -> Vec<Request> {
    match operation {
        EnforcementOperation::SetAdminState { interface, enabled } => vec![Request {
            path: interface_path(interface),
            body: json!({"l1PhysIf":{"attributes":{
                "id": interface.as_str(), "adminSt": if *enabled { "up" } else { "down" },
                "userCfgdFlags":"admin_state"
            }}}),
        }],
        EnforcementOperation::Throttle {
            interface,
            direction,
            rate_bps,
            burst_bytes,
        } => {
            let (direction, name) = policy(interface, *direction, prefix);
            // Matches the lab-tested NX-OS default exceed behavior. Explicit
            // "drop" is rejected by some NX-OS images; unspecified resets it.
            let mut police = json!({"cirRate":rate_bps.to_string(),"cirUnit":"bps",
                "conformAction":"transmit","exceedAction":"unspecified"});
            if let Some(burst) = burst_bytes {
                police["bcRate"] = json!(burst.to_string());
                police["bcUnit"] = json!("bytes");
            }
            vec![
                policer(&name, police),
                Request {
                    path: format!(
                        "/api/mo/sys/ipqos/dflt/policy/{direction}/intf-[{}].json",
                        interface.as_str()
                    ),
                    body: json!({"ipqosIf":{"attributes":{"name":interface.as_str()},"children":[
                        {"ipqosInst":{"attributes":{"name":name,"stats":"yes"}}}
                    ]}}),
                },
            ]
        }
        EnforcementOperation::RemoveThrottle {
            interface,
            direction,
        } => {
            let (_, name) = policy(interface, *direction, prefix);
            vec![policer(&name, json!({"status":"deleted"}))]
        }
    }
}

fn policy(
    interface: &crate::EthernetInterface,
    direction: Direction,
    prefix: &str,
) -> (&'static str, String) {
    let direction = match direction {
        Direction::Ingress => "in",
        Direction::Egress => "out",
    };
    (
        direction,
        format!(
            "{prefix}-{}-{direction}",
            interface.as_str().replace('/', "-")
        ),
    )
}

fn policer(name: &str, attributes: Value) -> Request {
    Request {
        path: "/api/mo/sys/ipqos/dflt/p.json".into(),
        body: json!({"ipqosPMapEntity":{"children":[
            {"ipqosPMapInst":{"attributes":{"name":name,"matchType":"match-all"},"children":[
                {"ipqosMatchCMap":{"attributes":{"name":"class-default","userSetBit":"1"},
                    "children":[{"ipqosPolice":{"attributes":attributes}}]}}
            ]}}
        ]}}),
    }
}
