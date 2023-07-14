use askama::Template;
use axum::{response::IntoResponse, Form};

use openidconnect::core::CoreAuthErrorResponseType;
use serde::Deserialize;

use crate::{
    auth::session::AuthSession,
    error::ApiError,
    model::auth_codes::{AuthorizationCode, AuthorizationCodeBody},
    state::ServerState,
    util::{
        csrf::CsrfNonce, extract::OidcAuthRequestHead, id::EntityId, scopes::Scopes,
        template::TemplateBase,
    },
};

#[derive(Template)]
#[template(path = "authorize.html")]
struct AuthorizeTemplate {
    client_name: String,
    logo_uri: String,
    scopes: Scopes,
    base: TemplateBase,
}

pub async fn authorization_code(
    req: OidcAuthRequestHead,
    base: TemplateBase,
    _auth: AuthSession,
    state: ServerState,
) -> Result<impl IntoResponse, ApiError> {
    let redirect_uri_q = req.redirect_uri.as_str();
    let Some(record) = sqlx::query!(
        "
        SELECT c.client_name, c.logo_uri as `logo_uri:String`
        FROM clients c
        INNER JOIN client_redirect_uris cru ON cru.client_id = c.id
        WHERE c.id = $1 AND cru.redirect_uri = $2
        ",
        req.client_id,
        redirect_uri_q
    )
    .fetch_optional(&state.pool)
    .await?
    else {
        // TODO: display this to user properly.
        return Err(crate::error::not_found()
            .with_detail(format!("'{}' is not a valid client.", req.client_id))
            .into());
    };

    let req = req.next()?;

    Ok(AuthorizeTemplate {
        client_name: record.client_name,
        logo_uri: record.logo_uri,
        scopes: req.scope,
        base,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizeAction {
    Allow,
    Deny,
}

#[derive(Deserialize)]
pub struct AuthorizeRequest {
    pub csrf: CsrfNonce,
    pub action: AuthorizeAction,
}

pub async fn authorization_code_post(
    req: OidcAuthRequestHead,
    base: TemplateBase,
    auth: AuthSession,
    state: ServerState,
    req_f: Form<AuthorizeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    base.csrf.verify(&req_f.csrf)?;

    let redirect_uri_q = req.redirect_uri.as_str();
    let redirect_uri_valid = sqlx::query!(
        "
        SELECT EXISTS(
            SELECT 1 FROM client_redirect_uris
            WHERE client_id=$1 AND redirect_uri=$2
        ) AS `valid:bool`
        ",
        req.client_id,
        redirect_uri_q,
    )
    .fetch_one(&state.pool)
    .await?
    .valid
    .unwrap_or(false);

    if !redirect_uri_valid {
        // TODO: display this to user properly.
        return Err(crate::error::not_found()
            .with_detail(format!(
                "'{}' is not a valid redirect URI.",
                req.redirect_uri
            ))
            .into());
    }

    let req = req.next()?;

    if let AuthorizeAction::Deny = req_f.action {
        return Err(req.error(
            CoreAuthErrorResponseType::AccessDenied,
            "User denied access.",
        ));
    }

    let code = AuthorizationCode::insert(
        auth.user_id,
        req.client_id,
        AuthorizationCodeBody {
            scope: req.scope.clone(),
            state: req.state.clone(),
            nonce: req.nonce.clone(),
        },
        &state.pool,
    )
    .await?;

    Ok(req.proceed(&code))
}
