use askama::Template;
use axum::{
    extract::Query,
    response::{IntoResponse, Redirect},
    Form,
};

use serde::Deserialize;
use url::Url;

use crate::{
    auth::session::AuthSession,
    error::ApiError,
    model::auth_codes::{AuthorizationCode, AuthorizationCodeBody},
    state::ServerState,
    util::{csrf::CsrfNonce, id::EntityId, scopes::Scopes, template::TemplateBase},
};

#[derive(Deserialize)]
pub struct AuthorizationCodeRequest {
    pub client_id: EntityId,
    pub redirect_uri: Url,
    pub scope: Scopes,
    pub state: String,
    pub nonce: Option<String>,
}

#[derive(Template)]
#[template(path = "authorize.html")]
struct AuthorizeTemplate {
    client_name: String,
    logo_uri: String,
    scopes: Scopes,
    base: TemplateBase,
}

pub async fn authorization_code(
    Query(req): Query<AuthorizationCodeRequest>,
    base: TemplateBase,
    _auth: AuthSession,
    state: ServerState,
) -> Result<impl IntoResponse, ApiError> {
    let Some(record) = sqlx::query!(
        "
        SELECT client_name, logo_uri as `logo_uri:String`
        FROM clients
        WHERE id = $1
        ",
        req.client_id
    )
    .fetch_optional(&state.pool)
    .await?
    else {
        // TODO: display this to user properly.
        return Err(crate::error::not_found()
            .with_detail(format!("'{}' is not a valid client.", req.client_id))
            .into());
    };

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
    Query(req): Query<AuthorizationCodeRequest>,
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

    if let AuthorizeAction::Deny = req_f.action {
        let redirect_to = {
            let mut redirect_to = req.redirect_uri.clone();

            redirect_to
                .query_pairs_mut()
                .append_pair("state", &req.state)
                .append_pair("error", "access_denied");

            redirect_to
        };

        return Ok(Redirect::to(redirect_to.as_str()));
    }

    let code = AuthorizationCode::insert(
        auth.user_id,
        req.client_id,
        AuthorizationCodeBody {
            scope: req.scope,
            state: req.state.clone(),
            nonce: req.nonce,
        },
        &state.pool,
    )
    .await?;

    let redirect_to = {
        let mut redirect_to = req.redirect_uri.clone();

        redirect_to
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &req.state);

        redirect_to
    };

    Ok(Redirect::to(redirect_to.as_str()))
}
