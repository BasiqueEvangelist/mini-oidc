use axum::{
    routing::{get, post},
    Router,
};

use crate::state::ServerState;

mod oidc_config;
mod oidc_register;

pub fn router() -> Router<ServerState> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(oidc_config::configuration),
        )
        .route("/api/oidc/jwks", get(oidc_config::keyset))
        .route("/api/oidc/register", post(oidc_register::register_client))
}
