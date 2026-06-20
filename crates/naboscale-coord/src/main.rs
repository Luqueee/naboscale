//! naboscale-coord binary: runs the coordination server.

use naboscale_coord::AppState;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let db_path =
        std::env::var("NABOSCALE_COORD_DB").unwrap_or_else(|_| "naboscale-coord.sqlite".into());
    let state = AppState::open(&db_path)?;

    let bind: SocketAddr = std::env::var("NABOSCALE_COORD_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()
        .expect("NABOSCALE_COORD_ADDR must be a valid socket address");

    let app = naboscale_coord::build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "naboscale-coord listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
