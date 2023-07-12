use std::net::SocketAddr;

use argon2::Argon2;
use argon2::PasswordHash;
use argon2::PasswordVerifier;
use askama::Template;
use axum::extract::ConnectInfo;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::response::Response;
use axum::Form;

use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::error::ApiError;
use crate::state::ServerState;
use crate::util::csrf::CsrfNonce;
use crate::util::id::EntityId;
use crate::util::template::TemplateBase;

use super::session::AuthSession;
use super::RedirectQuery;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    base: TemplateBase,
    register_url: String,
    error: Option<String>,
}

pub async fn login_view(redir: RedirectQuery, base: TemplateBase) -> impl IntoResponse {
    LoginTemplate {
        base: base.clone(),
        register_url: base.links.register_from(redir.redirect_uri),
        error: None,
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub csrf: CsrfNonce,
}

pub async fn login(
    base: TemplateBase,
    redir: RedirectQuery,
    state: ServerState,
    from: ConnectInfo<SocketAddr>,
    req: Form<LoginRequest>,
) -> Result<Response, ApiError> {
    base.csrf.verify(&req.csrf)?;

    let Some(user) = sqlx::query!(
        "
        SELECT u.id as `id:EntityId`, u.password_hash as `password_hash:String`
        FROM users u
        WHERE u.username = $1
        ",
        req.username
    )
    .fetch_optional(&state.pool)
    .await?
    else {
        return Ok(
            LoginTemplate {
                base: base.clone(),
                error: Some("No such user".to_string()),
                register_url: state.links.register_from(redir.redirect_uri),
            }
        
            .into_response());
    };

    let hash = PasswordHash::new(&user.password_hash)?;

    let res = Argon2::default().verify_password(req.password.as_bytes(), &hash);

    if let Err(password_hash::Error::Password) = res {
        return Ok(
            LoginTemplate {
                base: base.clone(),
                error: Some("Wrong password".to_string()),
                register_url: state.links.register_from(redir.redirect_uri),
            }
        
            .into_response());
    } else {
        res?;
    }

    Ok((
        CookieJar::new().add(AuthSession::create(user.id, from.0, &state.pool).await?),
        Redirect::to(&redir.redirect_uri),
    )
        .into_response())
}
