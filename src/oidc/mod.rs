use axum::{
    routing::{get, post},
    Router,
};

use crate::state::ServerState;

pub mod claim_gatherer;
mod oidc_config;
mod oidc_register;
mod oidc_userinfo;

pub fn router() -> Router<ServerState> {
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(oidc_config::configuration),
        )
        .route("/api/oidc/jwks", get(oidc_config::keyset))
        .route("/api/oidc/register", post(oidc_register::register_client))
        .route("/api/oidc/userinfo", get(oidc_userinfo::userinfo))
}
