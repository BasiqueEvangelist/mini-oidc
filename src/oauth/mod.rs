use axum::{
    routing::{get, post},
    Router,
};

use crate::state::ServerState;

mod oauth_authorize;
mod oauth_token;

pub fn router() -> Router<ServerState> {
    Router::new()
        .route(
            "/api/oauth2/auth",
            get(oauth_authorize::authorization_code).post(oauth_authorize::authorization_code_post),
        )
        .route("/api/oauth2/token", post(oauth_token::oauth_token))
}
