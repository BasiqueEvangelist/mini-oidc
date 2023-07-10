use axum::{
    response::{IntoResponse, Redirect},
    Form,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    error::ApiError,
    state::ServerState,
    util::{csrf::CsrfNonce, template::TemplateBase},
};

use super::{session::AuthSession, RedirectQuery};

#[derive(Deserialize)]
pub struct LogoutRequest {
    pub csrf: CsrfNonce,
}

pub async fn logout(
    base: TemplateBase,
    state: ServerState,
    redir: RedirectQuery,
    session: AuthSession,
    req: Form<LogoutRequest>,
) -> Result<impl IntoResponse, ApiError> {
    base.csrf.verify(&req.csrf)?;

    let cookie = session.destroy(&state.pool).await?;

    Ok((
        CookieJar::new().add(cookie),
        Redirect::to(&redir.redirect_uri),
    ))
}
