use base64::{engine::general_purpose::STANDARD as B64, Engine};
use naboscale_coord::AppState;
use naboscale_crypto::{Identity, Keypair};
use serde_json::{json, Value};

struct TestClient {
    identity: Identity,
    wg: Keypair,
    base: String,
    auth_token: Option<String>,
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
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
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
        assert!(resp.status().is_success(), "register failed: {}", resp.status());
        let body: Value = resp.json().await.expect("register response json");
        self.auth_token = Some(body["auth_token"].as_str().unwrap().to_string());
        self.node_id = Some(body["node_id"].as_str().unwrap().to_string());
        self.ip = Some(body["ip"].as_str().unwrap().to_string());
        reqwest::Client::new()
            .get(format!("{}/v1/health", self.base))
            .send()
            .await
            .unwrap()
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
        assert!(resp.status().is_success(), "peers failed: {}", resp.status());
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
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{}", addr.port())
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
    assert!(resp.status().is_success(), "heartbeat failed: {}", resp.status());

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
