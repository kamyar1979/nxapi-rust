use nxapi::{Client, ClientOptions, Direction, EnforcementOperation as Op, Error};
use serde_json::{Value, json};
use std::{num::NonZeroU64, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

#[derive(Debug)]
struct Recorded {
    head: String,
    body: Value,
}

async fn server(responses: Vec<(u16, String)>) -> (String, JoinHandle<Vec<Recorded>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut records = vec![];
        for (status, body) in responses {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut data = Vec::new();
            let header_end = loop {
                let byte = socket.read_u8().await.unwrap();
                data.push(byte);
                if data.ends_with(b"\r\n\r\n") {
                    break data.len();
                }
            };
            let head = String::from_utf8(data).unwrap();
            let length = head
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let mut payload = vec![0; length];
            socket.read_exact(&mut payload).await.unwrap();
            records.push(Recorded {
                head,
                body: if length == 0 {
                    Value::Null
                } else {
                    serde_json::from_slice(&payload).unwrap()
                },
            });
            let redirect = if status == 302 {
                "Location: http://127.0.0.1:1/leak\r\n"
            } else {
                ""
            };
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{redirect}\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            assert!(header_end > 0);
        }
        records
    });
    (origin, task)
}

fn options() -> ClientOptions {
    ClientOptions {
        allow_http: true,
        policy_prefix: "pcef".into(),
        ..Default::default()
    }
}
fn client(origin: &str) -> Client {
    let mut c = Client::with_options(origin, options()).unwrap();
    c.set_session_cookie("APIC-cookie=test-token").unwrap();
    c
}
fn interface() -> nxapi::EthernetInterface {
    "Ethernet1/10".parse().unwrap()
}
fn throttle(direction: Direction) -> Op {
    Op::Throttle {
        interface: interface(),
        direction,
        rate_bps: NonZeroU64::new(10_000_000).unwrap(),
        burst_bytes: NonZeroU64::new(8192),
    }
}
fn success() -> (u16, String) {
    (200, r#"{"imdata":[]}"#.into())
}

#[tokio::test]
async fn login_block_unblock_and_readback_use_real_http() {
    let (url, task) = server(vec![
        (
            200,
            json!({"imdata":[{"aaaLogin":{"attributes":{"token":"secret"}}}]}).to_string(),
        ),
        success(),
        success(),
        (
            200,
            json!({"imdata":[{"l1PhysIf":{"attributes":{"adminSt":"up"}}}]}).to_string(),
        ),
    ])
    .await;
    let mut c = Client::with_options(&url, options()).unwrap();
    c.login("operator", "password").await.unwrap();
    for enabled in [false, true] {
        assert_eq!(
            c.apply(&Op::SetAdminState {
                interface: interface(),
                enabled
            })
            .await
            .unwrap()
            .requests_completed,
            1
        );
    }
    assert!(c.admin_state(&interface()).await.unwrap());
    let requests = task.await.unwrap();
    assert!(requests[0].head.starts_with("POST /api/aaaLogin.json "));
    assert_eq!(
        requests[0].body,
        json!({"aaaUser":{"attributes":{"name":"operator","pwd":"password"}}})
    );
    assert!(!requests[0].head.to_lowercase().contains("cookie:"));
    for (index, state) in [(1, "down"), (2, "up")] {
        assert!(
            requests[index]
                .head
                .starts_with("POST /api/mo/sys/intf/phys-[eth1/10].json ")
        );
        assert!(requests[index].head.contains("APIC-cookie=secret"));
        assert_eq!(
            requests[index].body["l1PhysIf"]["attributes"]["adminSt"],
            state
        );
    }
    assert!(requests[3].head.starts_with("GET "));
    assert!(!format!("{c:?}").contains("secret"));
}

#[tokio::test]
async fn direct_login_response_is_supported() {
    let (url, task) = server(vec![(
        200,
        json!({"aaaLogin":{"attributes":{"token":"abc"}}}).to_string(),
    )])
    .await;
    Client::with_options(&url, options())
        .unwrap()
        .login("user", "pass")
        .await
        .unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn policing_payload_and_attachment_are_generated_for_both_directions() {
    for (direction, suffix) in [(Direction::Ingress, "in"), (Direction::Egress, "out")] {
        let (url, task) = server(vec![success(), success()]).await;
        assert_eq!(
            client(&url)
                .apply(&throttle(direction))
                .await
                .unwrap()
                .requests_completed,
            2
        );
        let requests = task.await.unwrap();
        assert!(
            requests[0]
                .head
                .starts_with("POST /api/mo/sys/ipqos/dflt/p.json ")
        );
        let policy = &requests[0].body["ipqosPMapEntity"]["children"][0]["ipqosPMapInst"];
        assert_eq!(
            policy["attributes"]["name"],
            format!("pcef-eth1-10-{suffix}")
        );
        assert_eq!(
            policy["children"][0]["ipqosMatchCMap"]["children"][0]["ipqosPolice"]["attributes"],
            json!({"cirRate":"10000000","cirUnit":"bps","bcRate":"8192","bcUnit":"bytes",
                "conformAction":"transmit","exceedAction":"unspecified"})
        );
        assert!(
            requests[1]
                .head
                .contains(&format!("/policy/{suffix}/intf-[eth1/10].json"))
        );
    }
}

#[tokio::test]
async fn removal_only_deletes_owned_policer() {
    for direction in [Direction::Ingress, Direction::Egress] {
        let (url, task) = server(vec![success()]).await;
        client(&url)
            .apply(&Op::RemoveThrottle {
                interface: interface(),
                direction,
            })
            .await
            .unwrap();
        let records = task.await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].body["ipqosPMapEntity"]["children"][0]["ipqosPMapInst"]["children"][0]["ipqosMatchCMap"]
                ["children"][0]["ipqosPolice"]["attributes"],
            json!({"status":"deleted"})
        );
        assert!(!records[0].body.to_string().contains("adminSt"));
    }
}

#[tokio::test]
async fn dme_error_stops_before_attachment_even_on_http_200() {
    let (url, task) = server(vec![(
        200,
        json!({"imdata":[{"error":{"attributes":{"code":"400","text":"secret"}}}]}).to_string(),
    )])
    .await;
    let error = client(&url)
        .apply(&throttle(Direction::Ingress))
        .await
        .unwrap_err();
    assert_eq!(error.requests_completed, 0);
    assert!(matches!(error.source, Error::Device { .. }));
    assert!(!format!("{error:?}").contains("secret"));
    assert_eq!(task.await.unwrap().len(), 1);
}

#[tokio::test]
async fn attachment_failure_reports_partial_application() {
    let (url, task) = server(vec![success(), (500, "error".into())]).await;
    let error = client(&url)
        .apply(&throttle(Direction::Ingress))
        .await
        .unwrap_err();
    assert_eq!(error.requests_completed, 1);
    assert!(matches!(error.source, Error::Http(500)));
    task.await.unwrap();
}

#[tokio::test]
async fn malformed_missing_and_oversized_responses_fail() {
    for body in ["not json", "{}", r#"{"imdata":{}}"#] {
        let (url, task) = server(vec![(200, body.into())]).await;
        assert!(matches!(
            client(&url)
                .apply(&throttle(Direction::Ingress))
                .await
                .unwrap_err()
                .source,
            Error::Response(_)
        ));
        task.await.unwrap();
    }
    let (url, task) = server(vec![success()]).await;
    let mut c = Client::with_options(
        &url,
        ClientOptions {
            max_response_bytes: 2,
            ..options()
        },
    )
    .unwrap();
    c.set_session_cookie("APIC-cookie=abc").unwrap();
    assert!(matches!(
        c.apply(&throttle(Direction::Ingress))
            .await
            .unwrap_err()
            .source,
        Error::Response(_)
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn redirect_and_unauthorized_are_not_retried() {
    for status in [302, 401] {
        let (url, task) = server(vec![(status, "{}".into())]).await;
        assert!(
            matches!(client(&url).apply(&throttle(Direction::Ingress)).await.unwrap_err().source, Error::Http(s) if s == status)
        );
        task.await.unwrap();
    }
}

#[tokio::test]
async fn failed_login_clears_previous_session() {
    let (url, task) = server(vec![(401, "{}".into())]).await;
    let mut c = client(&url);
    assert!(c.login("user", "wrong").await.is_err());
    assert!(matches!(
        c.apply(&throttle(Direction::Ingress))
            .await
            .unwrap_err()
            .source,
        Error::Unauthenticated
    ));
    task.await.unwrap();
}

#[tokio::test]
async fn request_timeout_is_returned() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut c = Client::with_options(
        &url,
        ClientOptions {
            timeout: Duration::from_millis(50),
            ..options()
        },
    )
    .unwrap();
    c.set_session_cookie("APIC-cookie=abc").unwrap();
    assert!(matches!(
        c.apply(&throttle(Direction::Ingress))
            .await
            .unwrap_err()
            .source,
        Error::Transport(_)
    ));
}

#[test]
fn rejects_unsafe_configuration_and_headers() {
    for endpoint in [
        "http://192.0.2.1",
        "https://user:pass@192.0.2.1",
        "https://example.com/api",
        "https://example.com/?x=1",
    ] {
        assert!(Client::new(endpoint).is_err());
    }
    let mut c = Client::new("https://192.0.2.1").unwrap();
    assert!(
        c.set_session_cookie("APIC-cookie=a\r\nInjected: value")
            .is_err()
    );
    assert!(
        Client::with_options(
            "https://192.0.2.1",
            ClientOptions {
                policy_prefix: "../x".into(),
                ..Default::default()
            }
        )
        .is_err()
    );
}
