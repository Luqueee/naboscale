use crate::routes;
use crate::state::AppState;
use axum::routing::{get, post};
use axum::Router;
use std::sync::Arc;

pub fn build_router(state: AppState) -> Router {
    let state = Arc::new(state);
    Router::new()
        .route("/v1/register", post(routes::register))
        .route("/v1/peers", get(routes::peers))
        .route("/v1/heartbeat", post(routes::heartbeat))
        .route("/v1/health", get(routes::health))
        .with_state(state)
}
