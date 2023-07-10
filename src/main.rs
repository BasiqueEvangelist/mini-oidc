use std::net::SocketAddr;

use axum::{middleware, routing::get, Router};

use crate::{auth::session::AuthSession, model::auth_codes::AuthorizationCode};

pub mod auth;
pub mod error;
pub mod links;
pub mod model;
pub mod oauth;
pub mod oidc;
pub mod server_info;
pub mod state;
pub mod util;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv()?;

    tracing_subscriber::fmt::init();

    let state = state::init().await?;

    tokio::spawn(AuthorizationCode::cleanup_job(state.pool.clone()));
    tokio::spawn(AuthSession::cleanup_job(state.pool.clone()));

    let app = Router::new()
        .route("/", get(server_info::index))
        .route("/api/", get(server_info::server_info))
        .merge(oauth::router())
        .merge(oidc::router())
        .merge(auth::router())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::session::layer,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            util::csrf::layer,
        ))
        .with_state(state.clone());

    let server = axum::Server::try_bind(&state.bind_addr)?
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    tracing::info!("listening on {}", server.local_addr());

    server.await?;

    Ok(())
}
