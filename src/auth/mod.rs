use std::convert::Infallible;

use axum::{
    async_trait,
    extract::{FromRequestParts, Query},
    http::request::Parts,
    routing::{get, post},
    Router,
};
use serde::Deserialize;

use crate::state::ServerState;

mod login;
pub mod logout;
mod register;
pub mod session;

#[derive(Deserialize)]
pub struct RedirectQuery {
    pub redirect_uri: String,
}

#[async_trait]
impl FromRequestParts<ServerState> for RedirectQuery {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        Ok(
            Option::<Query<RedirectQuery>>::from_request_parts(parts, state)
                .await
                .unwrap()
                .map(|x| x.0)
                .unwrap_or_else(|| RedirectQuery {
                    redirect_uri: state.links.issuer.to_string(),
                }),
        )
    }
}

pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/login", get(login::login_view).post(login::login))
        .route(
            "/register",
            get(register::register_view).post(register::register),
        )
        .route("/logout", post(logout::logout))
}
