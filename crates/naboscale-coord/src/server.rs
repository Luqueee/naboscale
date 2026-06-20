use crate::routes;
use crate::state::AppState;
use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post};
use axum::Router;
use std::sync::Arc;

pub fn build_router(state: AppState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/v1/register", post(routes::register))
        .route("/v1/peers", get(routes::peers))
        .route("/v1/heartbeat", post(routes::heartbeat))
        .route("/v1/token/refresh", post(routes::refresh_token))
        .route("/v1/node", delete(routes::delete_node))
        .route("/v1/health", get(routes::health))
        // Reject any body larger than 4 KiB with 413 Payload Too Large
        // before the handler runs. Signatures + base64 pubkeys fit in
        // ~250 bytes so 4 KiB is plenty of headroom.
        .layer(DefaultBodyLimit::max(routes::MAX_BODY_BYTES))
        .with_state(state)
}
