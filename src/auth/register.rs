use std::net::SocketAddr;

use argon2::Argon2;
use askama::Template;
use axum::extract::ConnectInfo;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::response::Response;
use axum::Form;
use axum_extra::extract::CookieJar;
use password_hash::PasswordHasher;
use password_hash::SaltString;
use serde::Deserialize;

use crate::auth::session::AuthSession;
use crate::error::ApiError;
use crate::state::ServerState;
use crate::util::csrf::CsrfNonce;
use crate::util::id::EntityId;
use crate::util::template::TemplateBase;

use super::RedirectQuery;

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterTemplate {
    base: TemplateBase,
    error: Option<String>,
}

pub async fn register_view(base: TemplateBase) -> impl IntoResponse {
    RegisterTemplate { base, error: None }
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub csrf: CsrfNonce,
}

pub async fn register(
    base: TemplateBase,
    state: ServerState,
    redir: RedirectQuery,
    from: ConnectInfo<SocketAddr>,
    req: Form<RegisterRequest>,
) -> Result<Response, ApiError> {
    base.csrf.verify(&req.csrf)?;

    let salt = SaltString::generate(&mut rand::thread_rng());
    let alg = Argon2::default();
    let hash = alg.hash_password(req.password.as_bytes(), &salt)?;
    let uid = EntityId::generate(&mut rand::thread_rng());

    let hash_q = hash.to_string();

    sqlx::query!(
        "
        INSERT INTO users
        (id, username, email, password_hash)
        VALUES
        ($1, $2, $3, $4)
        ",
        uid,
        req.username,
        req.email,
        hash_q
    )
    .execute(&state.pool)
    .await?;

    Ok((
        CookieJar::new().add(AuthSession::create(uid, from.0, &state.pool).await?),
        Redirect::to(&redir.redirect_uri),
    )
        .into_response())
}
