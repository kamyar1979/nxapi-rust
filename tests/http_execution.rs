use async_trait::async_trait;
use nxapi::{
    Client, ClientBuilder, Direction, EnforcementOperation as Op, Error, SessionStore,
    SessionStoreError, StoredSession,
};
use serde_json::{Value, json};
use std::{num::NonZeroU64, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::JoinHandle,
};

#[derive(Clone)]
struct TestSessionStore(watch::Sender<Option<StoredSession>>);

impl TestSessionStore {
    fn new() -> Self {
        let (sender, _) = watch::channel(None);
        Self(sender)
    }

    fn saved(&self) -> Option<StoredSession> {
        self.0.borrow().clone()
    }
}

#[async_trait]
impl SessionStore for TestSessionStore {
    async fn load(&self, _: &str) -> Result<Option<StoredSession>, SessionStoreError> {
        Ok(self.saved())
    }

    async fn save(&self, _: &str, session: &StoredSession) -> Result<(), SessionStoreError> {
        self.0.send_replace(Some(session.clone()));
        Ok(())
    }

    async fn delete(&self, _: &str) -> Result<(), SessionStoreError> {
        self.0.send_replace(None);
        Ok(())
    }
}

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

fn client_builder(origin: &str) -> ClientBuilder {
    Client::builder(origin)
        .allow_http(true)
        .policy_prefix("pcef")
}
fn client(origin: &str) -> Client {
    let mut c = client_builder(origin).build().unwrap();
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

fn named_policy() -> (nxapi::PolicyName, nxapi::BandwidthPolicy) {
    (
        "quota-10m".parse().unwrap(),
        nxapi::BandwidthPolicy {
            rate_bps: NonZeroU64::new(10_000_000).unwrap(),
            burst_bytes: NonZeroU64::new(8192),
        },
    )
}

fn policy_present() -> (u16, String) {
    (
        200,
        json!({"imdata":[{"ipqosPMapInst":{"attributes":{"name":"quota-10m"}}}]}).to_string(),
    )
}

#[tokio::test]
async fn separate_policy_lifecycle() {
    for (direction, path_direction) in [(Direction::Ingress, "in"), (Direction::Egress, "out")] {
        let (url, task) = server(vec![
            success(),
            success(),
            policy_present(),
            success(),
            policy_present(),
            success(),
            attachment("quota-10m"),
            success(),
            success(),
        ])
        .await;
        let c = client(&url);
        let (name, mut policy) = named_policy();
        c.define_policy(&name, &policy).await.unwrap();
        policy.rate_bps = NonZeroU64::new(20_000_000).unwrap();
        policy.burst_bytes = None;
        c.edit_policy(&name, &policy).await.unwrap();
        c.assign_policy(&name, &interface(), direction)
            .await
            .unwrap();
        c.unassign_policy(&name, &interface(), direction)
            .await
            .unwrap();
        c.remove_policy(&name).await.unwrap();
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 9);
        assert!(
            requests[0]
                .head
                .starts_with("GET /api/mo/sys/ipqos/dflt/p/name-quota-10m.json ")
        );
        for (index, rate) in [(1, "10000000"), (3, "20000000")] {
            assert!(
                requests[index]
                    .head
                    .starts_with("POST /api/mo/sys/ipqos/dflt/p.json ")
            );
            let map = &requests[index].body["ipqosPMapEntity"]["children"][0]["ipqosPMapInst"];
            assert_eq!(map["attributes"]["name"], "quota-10m");
            let attrs =
                &map["children"][0]["ipqosMatchCMap"]["children"][0]["ipqosPolice"]["attributes"];
            assert_eq!(attrs["cirRate"], rate);
            assert_eq!(attrs["cirUnit"], "bps");
            if index == 1 {
                assert_eq!(attrs["bcRate"], "8192");
            } else {
                assert!(attrs.get("bcRate").is_none());
            }
        }
        for index in [5, 7] {
            assert!(requests[index].head.starts_with(&format!(
                "POST /api/mo/sys/ipqos/dflt/policy/{path_direction}/intf-[eth1/10].json "
            )));
            let attrs = &requests[index].body["ipqosIf"]["children"][0]["ipqosInst"]["attributes"];
            assert_eq!(attrs["name"], "quota-10m");
            if index == 7 {
                assert_eq!(attrs["status"], "deleted");
            } else {
                assert_eq!(attrs["stats"], "yes");
            }
            assert!(requests[index].body.get("ipqosPMapEntity").is_none());
        }
        assert_eq!(
            requests[8].body,
            json!({"ipqosPMapEntity":{"children":[{"ipqosPMapInst":{"attributes":{"name":"quota-10m","status":"deleted"}}}]}})
        );
    }
}

#[tokio::test]
async fn separate_policy_preconditions_prevent_writes() {
    let (name, policy) = named_policy();
    let (url, task) = server(vec![
        policy_present(),
        success(),
        success(),
        attachment("unrelated"),
        success(),
        (200, json!({"imdata":[{}]}).to_string()),
    ])
    .await;
    let c = client(&url);
    assert!(matches!(
        c.define_policy(&name, &policy).await,
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        c.edit_policy(&name, &policy).await,
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        c.assign_policy(&name, &interface(), Direction::Ingress)
            .await,
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        c.unassign_policy(&name, &interface(), Direction::Ingress)
            .await,
        Err(Error::Configuration(_))
    ));
    c.unassign_policy(&name, &interface(), Direction::Ingress)
        .await
        .unwrap();
    assert!(matches!(
        c.edit_policy(&name, &policy).await,
        Err(Error::Response(_))
    ));
    assert!(
        task.await
            .unwrap()
            .iter()
            .all(|r| r.head.starts_with("GET "))
    );
}

#[tokio::test]
async fn separate_policy_mutation_errors_are_returned() {
    let failure = || {
        (
            200,
            json!({"imdata":[{"error":{"attributes":{"code":"400","text":"rejected"}}}]})
                .to_string(),
        )
    };
    let (url, task) = server(vec![
        success(),
        failure(),
        policy_present(),
        failure(),
        policy_present(),
        failure(),
        attachment("quota-10m"),
        failure(),
        failure(),
    ])
    .await;
    let c = client(&url);
    let (name, policy) = named_policy();
    assert!(matches!(
        c.define_policy(&name, &policy).await,
        Err(Error::Device { .. })
    ));
    assert!(matches!(
        c.edit_policy(&name, &policy).await,
        Err(Error::Device { .. })
    ));
    assert!(matches!(
        c.assign_policy(&name, &interface(), Direction::Ingress)
            .await,
        Err(Error::Device { .. })
    ));
    assert!(matches!(
        c.unassign_policy(&name, &interface(), Direction::Ingress)
            .await,
        Err(Error::Device { .. })
    ));
    assert!(matches!(
        c.remove_policy(&name).await,
        Err(Error::Device { .. })
    ));
    assert_eq!(task.await.unwrap().len(), 9);
}

#[test]
fn policy_names_are_validated() {
    for name in ["", "../foo", "a/b", "a b", "a?b", "é", &"a".repeat(40)] {
        assert!(name.parse::<nxapi::PolicyName>().is_err(), "{name}");
    }
    for name in ["quota-10m", "customer_1", &"a".repeat(39)] {
        assert_eq!(name.parse::<nxapi::PolicyName>().unwrap().as_str(), name);
    }
}

#[tokio::test]
async fn invalid_login_tokens_clear_session() {
    for token in ["", "bad;cookie=x", "bad token", "bad\r\ntoken"] {
        let (url, task) = server(vec![(
            200,
            json!({"aaaLogin":{"attributes":{"token":token,"refreshTimeoutSeconds":"600"}}})
                .to_string(),
        )])
        .await;
        let mut c = client(&url);
        assert!(c.login("user", "password").await.is_err());
        assert!(matches!(
            c.remove_policy(&named_policy().0).await,
            Err(Error::Unauthenticated)
        ));
        assert_eq!(task.await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn login_block_unblock_and_readback_use_real_http() {
    let (url, task) = server(vec![
        (
            200,
            json!({"imdata":[{"aaaLogin":{"attributes":{"token":"secret","refreshTimeoutSeconds":"600"}}}]}).to_string(),
        ),
        success(),
        success(),
        (
            200,
            json!({"imdata":[{"l1PhysIf":{"attributes":{"adminSt":"up"}}}]}).to_string(),
        ),
    ])
    .await;
    let mut c = client_builder(&url).build().unwrap();
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
async fn login_parses_timing_metadata_and_hides_secrets() {
    let attrs = json!({
        "token":"do-not-log-this-token",
        "refreshTimeoutSeconds":"600",
        "guiIdleTimeoutSeconds":"1200",
        "restTimeoutSeconds":"0",
        "creationTime":"1435631774",
        "firstLoginTime":1435631775,
        "userName":"operator",
        "version":"10.6(1)",
        "buildTime":"Tue Jun 23 04:05:41 PDT 2015",
        "remoteUser":"false"
    });
    let (url, task) = server(vec![(
        200,
        json!({"imdata":[{"aaaLogin":{"attributes":attrs}}]}).to_string(),
    )])
    .await;
    let mut c = client_builder(&url).build().unwrap();
    let metadata = c
        .login("operator", "do-not-log-this-password")
        .await
        .unwrap();
    assert_eq!(metadata.refresh_timeout_seconds, 600);
    assert_eq!(metadata.gui_idle_timeout_seconds, Some(1200));
    assert_eq!(metadata.rest_timeout_seconds, Some(0));
    assert_eq!(metadata.creation_time, Some(1_435_631_774));
    assert_eq!(metadata.first_login_time, Some(1_435_631_775));
    assert_eq!(metadata.user_name.as_deref(), Some("operator"));
    assert_eq!(metadata.version.as_deref(), Some("10.6(1)"));
    assert_eq!(
        metadata.build_time.as_deref(),
        Some("Tue Jun 23 04:05:41 PDT 2015")
    );
    assert_eq!(metadata.remote_user, Some(false));
    assert!(metadata.refresh_deadline > metadata.received_at);
    assert!(!metadata.refresh_due());
    assert!(!metadata.refresh_due_within(Duration::from_secs(30)));
    assert!(format!("{metadata:?}").find("do-not-log-this").is_none());
    assert!(format!("{c:?}").find("do-not-log-this").is_none());
    task.await.unwrap();
}

#[tokio::test]
async fn login_requires_valid_refresh_timeout() {
    for attributes in [
        json!({"token":"abc"}),
        json!({"token":"abc","refreshTimeoutSeconds":"soon"}),
        json!({"token":"abc","refreshTimeoutSeconds":0}),
    ] {
        let (url, task) = server(vec![(
            200,
            json!({"aaaLogin":{"attributes":attributes}}).to_string(),
        )])
        .await;
        let mut c = client_builder(&url).build().unwrap();
        assert!(matches!(
            c.login("user", "password").await,
            Err(Error::Response(_))
        ));
        assert!(c.session_metadata().is_none());
        task.await.unwrap();
    }
}

#[tokio::test]
async fn refresh_replaces_cookie_and_metadata_only_after_success() {
    let (url, task) = server(vec![
        (200, json!({"aaaLogin":{"attributes":{"token":"old-secret","refreshTimeoutSeconds":"60"}}}).to_string()),
        (200, json!({"aaaRefresh":{"attributes":{"token":"new-secret","refreshTimeoutSeconds":"900","userName":"operator"}}}).to_string()),
        (200, json!({"imdata":[{"l1PhysIf":{"attributes":{"adminSt":"up"}}}]}).to_string()),
    ]).await;
    let mut c = client_builder(&url).build().unwrap();
    c.login("user", "password").await.unwrap();
    let refreshed = c.refresh().await.unwrap();
    assert_eq!(refreshed.refresh_timeout_seconds, 900);
    assert_eq!(c.session_metadata(), Some(&refreshed));
    assert!(c.admin_state(&interface()).await.unwrap());
    let requests = task.await.unwrap();
    assert!(requests[1].head.starts_with("POST /api/aaaRefresh.json "));
    assert!(requests[1].head.contains("APIC-cookie=old-secret"));
    assert!(requests[1].body.is_null());
    assert!(requests[2].head.contains("APIC-cookie=new-secret"));
    assert!(!format!("{c:?}").contains("new-secret"));
}

#[tokio::test]
async fn builder_restores_saved_session_without_another_login() {
    let (url, task) = server(vec![
        (
            200,
            json!({"aaaLogin":{"attributes":{"token":"saved-secret","refreshTimeoutSeconds":"600"}}}).to_string(),
        ),
        success(),
    ])
    .await;
    let store = TestSessionStore::new();
    let mut first = Client::builder(&url)
        .allow_http(true)
        .timeout(Duration::from_secs(5))
        .policy_prefix("pcef")
        .max_response_bytes(1024 * 1024)
        .session_store(store.clone(), "switch-1/operator")
        .build()
        .unwrap();
    first.login("operator", "password").await.unwrap();
    let saved = store.saved().unwrap();
    assert_eq!(saved.cookie, "APIC-cookie=saved-secret");
    assert!(!format!("{saved:?}").contains("saved-secret"));

    let mut second = Client::builder(&url)
        .allow_http(true)
        .session_store(store, "switch-1/operator")
        .build()
        .unwrap();
    second
        .ensure_authenticated("operator", "password")
        .await
        .unwrap();
    assert!(second.session_metadata().is_none());
    second
        .apply(&Op::SetAdminState {
            interface: interface(),
            enabled: false,
        })
        .await
        .unwrap();
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].head.contains("APIC-cookie=saved-secret"));
}

#[tokio::test]
async fn stored_session_is_refreshed_and_replaced() {
    let (url, task) = server(vec![
        (
            200,
            json!({"aaaLogin":{"attributes":{"token":"old-secret","refreshTimeoutSeconds":"1"}}}).to_string(),
        ),
        (
            200,
            json!({"aaaRefresh":{"attributes":{"token":"new-secret","refreshTimeoutSeconds":"600"}}}).to_string(),
        ),
        success(),
    ])
    .await;
    let store = TestSessionStore::new();
    let mut first = Client::builder(&url)
        .allow_http(true)
        .session_store(store.clone(), "switch-1/operator")
        .build()
        .unwrap();
    first.login("operator", "password").await.unwrap();

    let mut second = Client::builder(&url)
        .allow_http(true)
        .session_store(store.clone(), "switch-1/operator")
        .build()
        .unwrap();
    second
        .ensure_authenticated("operator", "password")
        .await
        .unwrap();
    assert_eq!(store.saved().unwrap().cookie, "APIC-cookie=new-secret");
    second
        .apply(&Op::SetAdminState {
            interface: interface(),
            enabled: false,
        })
        .await
        .unwrap();
    let requests = task.await.unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[1].head.contains("APIC-cookie=old-secret"));
    assert!(requests[2].head.contains("APIC-cookie=new-secret"));
}

#[tokio::test]
async fn failed_refresh_preserves_session_but_explicit_unauthorized_clears_it() {
    let (url, task) = server(vec![
        (
            200,
            json!({"aaaLogin":{"attributes":{"token":"still-valid","refreshTimeoutSeconds":"60"}}})
                .to_string(),
        ),
        (
            200,
            json!({"aaaLogin":{"attributes":{"token":"replacement"}}}).to_string(),
        ),
        (403, "{}".into()),
    ])
    .await;
    let mut c = client_builder(&url).build().unwrap();
    c.login("user", "password").await.unwrap();
    let prior = c.session_metadata().unwrap().clone();
    assert!(matches!(c.refresh().await, Err(Error::Response(_))));
    assert_eq!(c.session_metadata(), Some(&prior));
    assert!(matches!(c.refresh().await, Err(Error::Http(403))));
    assert!(c.session_metadata().is_none());
    assert!(!format!("{c:?}").contains("still-valid"));
    let requests = task.await.unwrap();
    assert!(requests[1].head.contains("APIC-cookie=still-valid"));
    assert!(requests[2].head.contains("APIC-cookie=still-valid"));
}

#[tokio::test]
async fn refresh_without_session_fails_without_request() {
    let mut c = client_builder("http://127.0.0.1:1").build().unwrap();
    assert!(matches!(c.refresh().await, Err(Error::Unauthenticated)));
}

#[tokio::test]
async fn direct_login_response_is_supported() {
    let (url, task) = server(vec![(
        200,
        json!({"aaaLogin":{"attributes":{"token":"abc","refreshTimeoutSeconds":600}}}).to_string(),
    )])
    .await;
    client_builder(&url)
        .build()
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

fn attachment(name: &str) -> (u16, String) {
    (
        200,
        json!({"imdata":[{"ipqosInst":{"attributes":{"name":name}}}]}).to_string(),
    )
}

fn removal(direction: Direction) -> Op {
    Op::RemoveThrottle {
        interface: interface(),
        direction,
    }
}

#[tokio::test]
async fn removal_detaches_then_deletes_owned_map_in_both_directions() {
    for (direction, suffix) in [(Direction::Ingress, "in"), (Direction::Egress, "out")] {
        let name = format!("pcef-eth1-10-{suffix}");
        let (url, task) = server(vec![attachment(&name), success(), success()]).await;
        let report = client(&url).apply(&removal(direction)).await.unwrap();
        assert_eq!(report.requests_completed, 2);
        let records = task.await.unwrap();
        assert_eq!(records.len(), 3);
        assert!(records[0].head.starts_with(&format!(
            "GET /api/mo/sys/ipqos/dflt/policy/{suffix}/intf-[eth1/10]/pmap.json "
        )));
        assert!(records[1].head.starts_with(&format!(
            "POST /api/mo/sys/ipqos/dflt/policy/{suffix}/intf-[eth1/10].json "
        )));
        assert_eq!(
            records[1].body,
            json!({"ipqosIf":{"attributes":{"name":"eth1/10"},"children":[
                {"ipqosInst":{"attributes":{"name":name,"status":"deleted"}}}
            ]}})
        );
        assert!(
            records[2]
                .head
                .starts_with("POST /api/mo/sys/ipqos/dflt/p.json ")
        );
        assert_eq!(
            records[2].body,
            json!({"ipqosPMapEntity":{"children":[
                {"ipqosPMapInst":{"attributes":{"name":name,"status":"deleted"}}}
            ]}})
        );
        for record in &records {
            assert!(!record.body.to_string().contains("adminSt"));
            assert!(!record.body.to_string().contains("ipqosPolice"));
            assert!(record.head.contains("APIC-cookie=test-token"));
        }
    }
}

#[tokio::test]
async fn removal_cleans_up_already_detached_map_without_touching_attachment() {
    for absent in [success(), attachment("")] {
        let (url, task) = server(vec![absent, success()]).await;
        assert_eq!(
            client(&url)
                .apply(&removal(Direction::Ingress))
                .await
                .unwrap()
                .requests_completed,
            1
        );
        let records = task.await.unwrap();
        assert_eq!(records.len(), 2);
        assert!(
            records[1]
                .head
                .starts_with("POST /api/mo/sys/ipqos/dflt/p.json ")
        );
    }
}

#[tokio::test]
async fn removal_rejects_unowned_or_malformed_attachment_before_any_write() {
    for response in [
        attachment("MANUAL-POLICY"),
        (
            200,
            json!({"imdata":[{"ipqosInst":{"attributes":{}}}]}).to_string(),
        ),
        (200, json!({"imdata":[{},{}]}).to_string()),
        (403, "{}".into()),
        (
            200,
            json!({"imdata":[{"error":{"attributes":{"code":"400"}}}]}).to_string(),
        ),
    ] {
        let (url, task) = server(vec![response]).await;
        let error = client(&url)
            .apply(&removal(Direction::Ingress))
            .await
            .unwrap_err();
        assert_eq!(error.requests_completed, 0);
        let records = task.await.unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].head.starts_with("GET "));
    }
}

#[tokio::test]
async fn removal_stops_on_detach_or_delete_failure_and_reports_write_progress() {
    for failed_step in [0, 1] {
        for failure in [
            (500, "{}".into()),
            (
                200,
                json!({"imdata":[{"error":{"attributes":{"code":"400"}}}]}).to_string(),
            ),
        ] {
            let mut responses = vec![attachment("pcef-eth1-10-in")];
            if failed_step == 1 {
                responses.push(success());
            }
            responses.push(failure);
            let (url, task) = server(responses).await;
            let error = client(&url)
                .apply(&removal(Direction::Ingress))
                .await
                .unwrap_err();
            assert_eq!(error.requests_completed, failed_step);
            assert!(matches!(
                error.source,
                Error::Http(500) | Error::Device { .. }
            ));
            assert_eq!(task.await.unwrap().len(), failed_step + 2);
        }
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
    let mut c = client_builder(&url).max_response_bytes(2).build().unwrap();
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
    let mut c = client_builder(&url)
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
    c.set_session_cookie("APIC-cookie=abc").unwrap();
    let error = c
        .apply(&throttle(Direction::Ingress))
        .await
        .unwrap_err()
        .source;
    let message = error.to_string();
    let Error::Transport(context) = error else {
        panic!("expected transport error, got {message}");
    };
    assert_eq!(context.kind(), "timeout");
    assert!(context.operation().contains("sending POST"));
    assert!(context.operation().contains(&url));
    assert!(message.contains("operation timed out"));
    assert!(!message.contains("APIC-cookie"));
    assert!(!message.contains("abc"));
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
        Client::builder("https://192.0.2.1")
            .policy_prefix("../x")
            .build()
            .is_err()
    );
}
