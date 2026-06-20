use base64::{engine::general_purpose::STANDARD as B64, Engine};
use naboscale_coord::AppState;
use naboscale_crypto::{Identity, Keypair};
use serde_json::{json, Value};

struct TestClient {
    identity: Identity,
    wg: Keypair,
    base: String,
    auth_token: Option<String>,
    auth_token_expires_at: Option<i64>,
    node_id: Option<String>,
    ip: Option<String>,
}

impl TestClient {
    fn new(base: String) -> Self {
        Self {
            identity: Identity::generate(),
            wg: Keypair::generate(),
            base,
            auth_token: None,
            auth_token_expires_at: None,
            node_id: None,
            ip: None,
        }
    }

    fn identity_pub_b64(&self) -> String {
        B64.encode(self.identity.public())
    }

    fn wg_pub_b64(&self) -> String {
        B64.encode(self.wg.public())
    }

    async fn register(&mut self) -> reqwest::Response {
        let timestamp = now_ts();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"register");
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(&self.identity.public());
        msg.extend_from_slice(self.wg.public());
        let sig = self.identity.sign(&msg);
        let body = json!({
            "identity_pubkey": self.identity_pub_b64(),
            "wg_pubkey": self.wg_pub_b64(),
            "timestamp": timestamp,
            "signature": B64.encode(sig),
        });
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/register", self.base))
            .json(&body)
            .send()
            .await
            .expect("register request");
        assert!(
            resp.status().is_success(),
            "register failed: {}",
            resp.status()
        );
        let body: Value = resp.json().await.expect("register response json");
        self.auth_token = Some(body["auth_token"].as_str().unwrap().to_string());
        self.auth_token_expires_at = body["auth_token_expires_at"].as_i64();
        self.node_id = Some(body["node_id"].as_str().unwrap().to_string());
        self.ip = Some(body["ip"].as_str().unwrap().to_string());
        reqwest::Client::new()
            .get(format!("{}/v1/health", self.base))
            .send()
            .await
            .unwrap()
    }

    /// Returns the HTTP status code. On 2xx, mutates `self.auth_token` to
    /// the freshly issued token.
    async fn refresh_token(&mut self) -> reqwest::StatusCode {
        let timestamp = now_ts();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"token_refresh");
        msg.extend_from_slice(&timestamp.to_be_bytes());
        let sig = self.identity.sign(&msg);
        let body = json!({
            "timestamp": timestamp,
            "signature": B64.encode(sig),
        });
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/token/refresh", self.base))
            .bearer_auth(self.auth_token.as_ref().unwrap())
            .json(&body)
            .send()
            .await
            .expect("refresh_token request");
        let status = resp.status();
        if status.is_success() {
            let body: Value = resp.json().await.expect("refresh_token json");
            self.auth_token = Some(body["auth_token"].as_str().unwrap().to_string());
            self.auth_token_expires_at = body["auth_token_expires_at"].as_i64();
        }
        status
    }

    async fn delete_node_status(&self) -> reqwest::StatusCode {
        let timestamp = now_ts();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"delete_node");
        msg.extend_from_slice(&timestamp.to_be_bytes());
        let sig = self.identity.sign(&msg);
        let body = json!({
            "timestamp": timestamp,
            "signature": B64.encode(sig),
        });
        let resp = reqwest::Client::new()
            .delete(format!("{}/v1/node", self.base))
            .bearer_auth(self.auth_token.as_ref().unwrap())
            .json(&body)
            .send()
            .await
            .expect("delete_node request");
        resp.status()
    }

    fn bearer(&self) -> &str {
        self.auth_token.as_ref().expect("test client has no token")
    }

    async fn heartbeat(&self, endpoint: &str) -> reqwest::Response {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut msg = Vec::new();
        msg.extend_from_slice(b"heartbeat");
        msg.extend_from_slice(&timestamp.to_be_bytes());
        msg.extend_from_slice(endpoint.as_bytes());
        // Matches `auth::build_heartbeat_message(_, _, None)`: push 0x01
        // (the "no relay" discriminator) so the signature covers the same
        // bytes the server reconstructs.
        msg.push(1);
        let sig = self.identity.sign(&msg);
        let body = json!({
            "endpoint": endpoint,
            "timestamp": timestamp,
            "signature": B64.encode(sig),
        });
        reqwest::Client::new()
            .post(format!("{}/v1/heartbeat", self.base))
            .bearer_auth(self.auth_token.as_ref().unwrap())
            .json(&body)
            .send()
            .await
            .expect("heartbeat request")
    }

    async fn peers(&self) -> Vec<Value> {
        let resp = reqwest::Client::new()
            .get(format!("{}/v1/peers", self.base))
            .bearer_auth(self.auth_token.as_ref().unwrap())
            .send()
            .await
            .expect("peers request");
        assert!(
            resp.status().is_success(),
            "peers failed: {}",
            resp.status()
        );
        let body: Value = resp.json().await.expect("peers response json");
        body["peers"].as_array().unwrap().clone()
    }
}

async fn spawn_server() -> String {
    let state = AppState::in_memory().expect("app state");
    let app = naboscale_coord::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://127.0.0.1:{}", addr.port())
}

async fn spawn_server_with_ttl(ttl_secs: i64) -> String {
    let state = AppState::in_memory_with_ttl(ttl_secs).expect("app state");
    let app = naboscale_coord::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    format!("http://127.0.0.1:{}", addr.port())
}

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let base = spawn_server().await;
    let resp = reqwest::get(format!("{}/v1/health", base)).await.unwrap();
    assert!(resp.status().is_success());
    assert_eq!(resp.text().await.unwrap(), "ok");
}

#[tokio::test]
async fn two_clients_register_and_see_each_other() {
    let base = spawn_server().await;
    let mut alice = TestClient::new(base.clone());
    let mut bob = TestClient::new(base.clone());

    alice.register().await;
    bob.register().await;

    assert_eq!(alice.ip.as_deref(), Some("100.100.0.1"));
    assert_eq!(bob.ip.as_deref(), Some("100.100.0.2"));

    let alice_peers = alice.peers().await;
    assert_eq!(alice_peers.len(), 1);
    assert_eq!(alice_peers[0]["wg_pubkey"], bob.wg_pub_b64());
    assert_eq!(alice_peers[0]["ip"], "100.100.0.2");

    let bob_peers = bob.peers().await;
    assert_eq!(bob_peers.len(), 1);
    assert_eq!(bob_peers[0]["wg_pubkey"], alice.wg_pub_b64());
}

#[tokio::test]
async fn heartbeat_updates_endpoint() {
    let base = spawn_server().await;
    let mut alice = TestClient::new(base.clone());
    let mut bob = TestClient::new(base.clone());
    alice.register().await;
    bob.register().await;

    let resp = bob.heartbeat("203.0.113.10:51820").await;
    assert!(
        resp.status().is_success(),
        "heartbeat failed: {}",
        resp.status()
    );

    let peers = alice.peers().await;
    assert_eq!(peers[0]["last_endpoint"], "203.0.113.10:51820");
    assert!(peers[0]["last_seen"].as_i64().is_some());
}

#[tokio::test]
async fn register_rejects_bad_signature() {
    let base = spawn_server().await;
    let alice_identity = Identity::generate();
    let alice_wg = Keypair::generate();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let sig = [0u8; 64];
    let body = json!({
        "identity_pubkey": B64.encode(alice_identity.public()),
        "wg_pubkey": B64.encode(alice_wg.public()),
        "timestamp": timestamp,
        "signature": B64.encode(sig),
    });
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/register", base))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn heartbeat_rejects_missing_token() {
    let base = spawn_server().await;
    let mut alice = TestClient::new(base.clone());
    alice.register().await;
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/heartbeat", base))
        .json(&json!({
            "endpoint": "1.2.3.4:51820",
            "timestamp": 0,
            "signature": B64.encode([0u8; 64]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn register_returns_expiry_in_future() {
    let base = spawn_server().await;
    let mut alice = TestClient::new(base);
    alice.register().await;
    let exp = alice.auth_token_expires_at.expect("expiry set");
    assert!(exp > now_ts(), "expiry {exp} must be > now {}", now_ts());
}

#[tokio::test]
async fn expired_token_is_rejected() {
    // 1-second TTL, sleep past it.
    let base = spawn_server_with_ttl(1).await;
    let mut alice = TestClient::new(base.clone());
    alice.register().await;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let resp = alice.heartbeat("1.2.3.4:51820").await;
    assert_eq!(
        resp.status(),
        401,
        "expired token must be rejected (got {})",
        resp.status()
    );
}

#[tokio::test]
async fn refresh_token_replaces_old_and_revokes_it() {
    let base = spawn_server().await;
    let mut alice = TestClient::new(base.clone());
    alice.register().await;
    let old_token = alice.auth_token.clone().expect("token");
    let status = alice.refresh_token().await;
    assert!(status.is_success(), "refresh failed: {status}");
    let new_token = alice.auth_token.clone().expect("new token");
    assert_ne!(old_token, new_token, "refresh must issue a new token");

    // Old token must now be revoked → heartbeat with it returns 401.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/heartbeat", base))
        .bearer_auth(&old_token)
        .json(&json!({
            "endpoint": "1.2.3.4:51820",
            "timestamp": now_ts(),
            "signature": B64.encode([0u8; 64]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "old (revoked) token must be rejected");

    // New token must still work.
    let resp = alice.heartbeat("1.2.3.4:51820").await;
    assert!(
        resp.status().is_success(),
        "new token must be accepted, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn delete_node_removes_node_and_releases_ip() {
    let base = spawn_server().await;
    let mut alice = TestClient::new(base.clone());
    alice.register().await;
    let alice_token = alice.bearer().to_string();
    let status = alice.delete_node_status().await;
    assert_eq!(status, 204, "delete_node must return 204");

    // Subsequent requests with the now-revoked token return 401.
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/heartbeat", base))
        .bearer_auth(&alice_token)
        .json(&json!({
            "endpoint": "1.2.3.4:51820",
            "timestamp": now_ts(),
            "signature": B64.encode([0u8; 64]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // The freed IP must be re-assigned to the next registrant. Bob should
    // get 100.100.0.1 (alice's old IP) since she's gone.
    let mut bob = TestClient::new(base);
    bob.register().await;
    assert_eq!(
        bob.ip.as_deref(),
        Some("100.100.0.1"),
        "alice's IP must be recycled after delete_node"
    );
}

#[tokio::test]
async fn refresh_token_rejects_wrong_signature() {
    let base = spawn_server().await;
    let mut alice = TestClient::new(base.clone());
    alice.register().await;
    let bad_sig = [0u8; 64];
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/token/refresh", base))
        .bearer_auth(alice.bearer())
        .json(&json!({
            "timestamp": now_ts(),
            "signature": B64.encode(bad_sig),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn register_rate_limited_after_threshold() {
    let base = spawn_server().await;
    // First 5 successful registers (different identities). The 6th is the
    // first one that should hit the register rate-limit (5/min/IP).
    let mut last_status = None;
    for i in 0..7 {
        let id = Identity::generate();
        let wg = Keypair::generate();
        let ts = now_ts();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"register");
        msg.extend_from_slice(&ts.to_be_bytes());
        msg.extend_from_slice(&id.public());
        msg.extend_from_slice(wg.public());
        let sig = id.sign(&msg);
        let body = json!({
            "identity_pubkey": B64.encode(id.public()),
            "wg_pubkey": B64.encode(wg.public()),
            "timestamp": ts,
            "signature": B64.encode(sig),
        });
        let resp = reqwest::Client::new()
            .post(format!("{}/v1/register", base))
            .json(&body)
            .send()
            .await
            .unwrap();
        last_status = Some(resp.status());
        if last_status.unwrap().as_u16() == 429 {
            // Verify Retry-After is set.
            let retry = resp.headers().get("Retry-After");
            assert!(retry.is_some(), "429 must include Retry-After");
            return;
        }
        assert!(
            resp.status().is_success(),
            "register {i} unexpectedly failed: {}",
            resp.status()
        );
    }
    panic!(
        "expected 429 within 7 registers from one IP, last_status={:?}",
        last_status
    );
}

#[tokio::test]
async fn oversize_body_rejected() {
    let base = spawn_server().await;
    let huge = "x".repeat(8192);
    let resp = reqwest::Client::new()
        .post(format!("{}/v1/register", base))
        .header("content-type", "application/json")
        .body(huge)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        413,
        "expected 413 Payload Too Large for oversized body, got {}",
        resp.status()
    );
}
