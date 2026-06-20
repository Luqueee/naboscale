use crate::auth;
use crate::db::{self, NodeRecord};
use crate::error::Result;
use crate::rate_limit::Bucket;
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

const DERP_URL_DEFAULT: &str = "";

/// Maximum JSON body size we accept on any route. Enough for two base64
/// pubkeys + signature + endpoint string. Anything larger is rejected
/// before the handler ever runs.
pub const MAX_BODY_BYTES: usize = 4 * 1024;

fn check_rate_limit(state: &AppState, peer: SocketAddr, bucket: Bucket) -> Result<()> {
    if let Err(retry) = state.rate_limiter.check(peer.ip(), bucket) {
        Err(crate::Error::RateLimited(retry.as_secs().max(1)))
    } else {
        Ok(())
    }
}

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
    /// Seconds until this token expires (UTC epoch seconds).
    pub auth_token_expires_at: i64,
    pub derp_url: String,
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    check_rate_limit(&state, peer, Bucket::Register)?;
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
    let ttl = state.token_ttl_secs;
    let expires_at = now + ttl;

    let record = NodeRecord {
        node_id: node_id.clone(),
        identity_pubkey: identity_pubkey.to_vec(),
        wg_pubkey: wg_pubkey.to_vec(),
        ip: ip.clone(),
        last_endpoint: None,
        via_relay: None,
        last_seen: None,
        created_at: now,
    };
    db::insert_node(&state.db, &record, &auth_token, ttl)?;

    Ok(Json(RegisterResponse {
        node_id,
        ip,
        auth_token,
        auth_token_expires_at: expires_at,
        derp_url: DERP_URL_DEFAULT.to_string(),
    }))
}

#[derive(Serialize)]
pub struct PeerEntry {
    pub node_id: String,
    pub wg_pubkey: String,
    pub ip: String,
    pub last_endpoint: Option<String>,
    pub via_relay: Option<String>,
    pub last_seen: Option<i64>,
}

#[derive(Serialize)]
pub struct PeersResponse {
    pub peers: Vec<PeerEntry>,
}

pub async fn peers(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<PeersResponse>> {
    check_rate_limit(&state, peer, Bucket::Default)?;
    let token = extract_bearer(&headers)?;
    let now = auth::current_timestamp();
    let caller =
        db::get_node_by_token(&state.db, &token, now)?.ok_or(crate::Error::InvalidAuthToken)?;
    let peers = db::list_peers(&state.db, Some(&caller.node_id))?;
    let response = PeersResponse {
        peers: peers
            .into_iter()
            .map(|p| PeerEntry {
                node_id: p.node_id,
                wg_pubkey: B64.encode(p.wg_pubkey),
                ip: p.ip,
                last_endpoint: p.last_endpoint,
                via_relay: p.via_relay,
                last_seen: p.last_seen,
            })
            .collect(),
    };
    Ok(Json(response))
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub endpoint: String,
    pub via_relay: Option<String>,
    pub timestamp: i64,
    pub signature: String,
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> Result<StatusCode> {
    check_rate_limit(&state, peer, Bucket::Heartbeat)?;
    let token = extract_bearer(&headers)?;
    let now = auth::current_timestamp();
    let caller =
        db::get_node_by_token(&state.db, &token, now)?.ok_or(crate::Error::InvalidAuthToken)?;

    let signature = decode_signature(&req.signature)?;
    auth::validate_timestamp(req.timestamp, now)?;

    let mut identity_pubkey = [0u8; 32];
    identity_pubkey.copy_from_slice(&caller.identity_pubkey);
    auth::verify_heartbeat_signature(
        &identity_pubkey,
        &req.endpoint,
        req.via_relay.as_deref(),
        req.timestamp,
        &signature,
    )?;

    // Validate via_relay format if provided (must be ip:port).
    if let Some(ref r) = req.via_relay {
        if r.parse::<std::net::SocketAddr>().is_err() {
            return Err(crate::Error::InvalidRequest(format!(
                "via_relay {r:?} is not a valid ip:port"
            )));
        }
    }
    db::update_heartbeat(
        &state.db,
        &caller.node_id,
        &req.endpoint,
        req.via_relay.as_deref(),
        now,
    )?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct SignedRequest {
    pub timestamp: i64,
    pub signature: String,
}

#[derive(Serialize)]
pub struct RefreshResponse {
    pub auth_token: String,
    pub auth_token_expires_at: i64,
    /// When the OLD token expires (informational; useful for clients that
    /// want to keep it alive during a grace window — currently we revoke
    /// immediately, so this is just the same as the new expires_at).
    pub old_token_expires_at: i64,
}

/// Issue a fresh token, revoking any prior non-expired tokens belonging to
/// the caller. Signed with the caller's identity key over "token_refresh" +
/// timestamp to prove possession.
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SignedRequest>,
) -> Result<Json<RefreshResponse>> {
    check_rate_limit(&state, peer, Bucket::Token)?;
    let old_token = extract_bearer(&headers)?;
    let now = auth::current_timestamp();
    let caller =
        db::get_node_by_token(&state.db, &old_token, now)?.ok_or(crate::Error::InvalidAuthToken)?;

    let signature = decode_signature(&req.signature)?;
    auth::validate_timestamp(req.timestamp, now)?;
    let mut identity_pubkey = [0u8; 32];
    identity_pubkey.copy_from_slice(&caller.identity_pubkey);
    let msg = auth::build_refresh_message(req.timestamp);
    if !naboscale_crypto::Identity::verify(&identity_pubkey, &msg, &signature) {
        return Err(crate::Error::InvalidSignature);
    }

    // Revoke old tokens (so even an attacker that captured one can't keep
    // using it after the legitimate owner refreshes).
    let _ = db::revoke_all_tokens_for_node(&state.db, &caller.node_id)?;
    let new_token = generate_token();
    let ttl = state.token_ttl_secs;
    db::create_token(&state.db, &caller.node_id, &new_token, now, ttl)?;

    Ok(Json(RefreshResponse {
        auth_token: new_token,
        auth_token_expires_at: now + ttl,
        old_token_expires_at: now + ttl,
    }))
}

/// Self-de-register: delete the calling node, revoke its tokens, return the
/// IP to the pool. After this the caller will receive 401 on every endpoint
/// until it registers a fresh identity.
pub async fn delete_node(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SignedRequest>,
) -> Result<StatusCode> {
    check_rate_limit(&state, peer, Bucket::Token)?;
    let token = extract_bearer(&headers)?;
    let now = auth::current_timestamp();
    let caller =
        db::get_node_by_token(&state.db, &token, now)?.ok_or(crate::Error::InvalidAuthToken)?;

    let signature = decode_signature(&req.signature)?;
    auth::validate_timestamp(req.timestamp, now)?;
    let mut identity_pubkey = [0u8; 32];
    identity_pubkey.copy_from_slice(&caller.identity_pubkey);
    let msg = auth::build_delete_node_message(req.timestamp);
    if !naboscale_crypto::Identity::verify(&identity_pubkey, &msg, &signature) {
        return Err(crate::Error::InvalidSignature);
    }

    if let Some(ip) = db::delete_node(&state.db, &caller.node_id)? {
        if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
            state.ip_alloc.release(&addr.octets());
        }
    }
    tracing::info!(node_id = %caller.node_id, "node self-de-registered");
    Ok(StatusCode::NO_CONTENT)
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
        return Err(crate::Error::InvalidRequest(
            "invalid signature length".into(),
        ));
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
    let token = auth
        .strip_prefix("Bearer ")
        .ok_or(crate::Error::InvalidAuthToken)?;
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
        if let crate::Error::RateLimited(secs) = &self {
            let mut headers = HeaderMap::new();
            headers.insert("Retry-After", secs.to_string().parse().unwrap());
            let body = serde_json::json!({
                "error": self.to_string(),
                "retry_after_seconds": secs,
            });
            return (StatusCode::TOO_MANY_REQUESTS, headers, axum::Json(body)).into_response();
        }
        use crate::Error::*;
        let (status, message) = match &self {
            InvalidSignature => (StatusCode::UNAUTHORIZED, self.to_string()),
            InvalidAuthToken => (StatusCode::UNAUTHORIZED, self.to_string()),
            TokenExpired(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            NodeNotFound => (StatusCode::NOT_FOUND, self.to_string()),
            InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            InvalidPubkey => (StatusCode::BAD_REQUEST, self.to_string()),
            InvalidTimestamp(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            IpPoolExhausted => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            RateLimited(_) => unreachable!("handled above"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        let body = serde_json::json!({ "error": message });
        (status, axum::Json(body)).into_response()
    }
}
