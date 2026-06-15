use crate::auth;
use crate::db::{self, NodeRecord};
use crate::error::Result;
use crate::state::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

const DERP_URL_DEFAULT: &str = "";

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub identity_pubkey: String,
    pub wg_pubkey: String,
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub node_id: String,
    pub ip: String,
    pub auth_token: String,
    pub derp_url: String,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    let identity_pubkey = decode_pubkey(&req.identity_pubkey)?;
    let wg_pubkey = decode_pubkey(&req.wg_pubkey)?;
    let signature = decode_signature(&req.signature)?;

    let now = auth::current_timestamp();
    auth::validate_timestamp(req.timestamp, now)?;
    auth::verify_register_signature(&identity_pubkey, &wg_pubkey, req.timestamp, &signature)?;

    let ip_bytes = state.ip_alloc.allocate()?;
    let ip = format!(
        "{}.{}.{}.{}",
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]
    );
    let node_id = Uuid::new_v4().to_string();
    let auth_token = generate_token();

    let record = NodeRecord {
        node_id: node_id.clone(),
        identity_pubkey: identity_pubkey.to_vec(),
        wg_pubkey: wg_pubkey.to_vec(),
        ip: ip.clone(),
        last_endpoint: None,
        last_seen: None,
        created_at: now,
    };
    db::insert_node(&state.db, &record, &auth_token)?;

    Ok(Json(RegisterResponse {
        node_id,
        ip,
        auth_token,
        derp_url: DERP_URL_DEFAULT.to_string(),
    }))
}

#[derive(Serialize)]
pub struct PeerEntry {
    pub node_id: String,
    pub wg_pubkey: String,
    pub ip: String,
    pub last_endpoint: Option<String>,
    pub last_seen: Option<i64>,
}

#[derive(Serialize)]
pub struct PeersResponse {
    pub peers: Vec<PeerEntry>,
}

pub async fn peers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<PeersResponse>> {
    let token = extract_bearer(&headers)?;
    let caller = db::get_node_by_token(&state.db, &token)?.ok_or(crate::Error::InvalidAuthToken)?;
    let peers = db::list_peers(&state.db, Some(&caller.node_id))?;
    let response = PeersResponse {
        peers: peers
            .into_iter()
            .map(|p| PeerEntry {
                node_id: p.node_id,
                wg_pubkey: B64.encode(p.wg_pubkey),
                ip: p.ip,
                last_endpoint: p.last_endpoint,
                last_seen: p.last_seen,
            })
            .collect(),
    };
    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub endpoint: String,
    pub timestamp: i64,
    pub signature: String,
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<StatusCode> {
    let token = extract_bearer(&headers)?;
    let caller = db::get_node_by_token(&state.db, &token)?.ok_or(crate::Error::InvalidAuthToken)?;

    let signature = decode_signature(&req.signature)?;
    let now = auth::current_timestamp();
    auth::validate_timestamp(req.timestamp, now)?;

    let mut identity_pubkey = [0u8; 32];
    identity_pubkey.copy_from_slice(&caller.identity_pubkey);
    auth::verify_heartbeat_signature(&identity_pubkey, &req.endpoint, req.timestamp, &signature)?;

    db::update_endpoint(&state.db, &caller.node_id, &req.endpoint, now)?;
    Ok(StatusCode::OK)
}

pub async fn health() -> &'static str {
    "ok"
}

fn decode_pubkey(s: &str) -> Result<[u8; 32]> {
    let bytes = B64.decode(s)?;
    if bytes.len() != 32 {
        return Err(crate::Error::InvalidPubkey);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_signature(s: &str) -> Result<[u8; 64]> {
    let bytes = B64.decode(s)?;
    if bytes.len() != 64 {
        return Err(crate::Error::InvalidRequest("invalid signature length".into()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn extract_bearer(headers: &HeaderMap) -> Result<String> {
    let auth = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(crate::Error::InvalidAuthToken)?;
    let token = auth.strip_prefix("Bearer ").ok_or(crate::Error::InvalidAuthToken)?;
    Ok(token.to_string())
}

fn generate_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64.encode(bytes)
}

impl IntoResponse for crate::Error {
    fn into_response(self) -> axum::response::Response {
        use crate::Error::*;
        let (status, message) = match &self {
            InvalidSignature => (StatusCode::UNAUTHORIZED, self.to_string()),
            InvalidAuthToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            NodeNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            InvalidPubkey => (StatusCode::BAD_REQUEST, self.to_string()),
            InvalidTimestamp(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            IpPoolExhausted => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}
