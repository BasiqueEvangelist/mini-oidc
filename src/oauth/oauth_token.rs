use axum::headers::authorization::Basic;
use axum::headers::Authorization;
use axum::response::IntoResponse;
use axum::{Form, Json, TypedHeader};
use chrono::{Duration, Utc};
use openidconnect::core::{
    CoreErrorResponseType, CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields,
    CoreJwsSigningAlgorithm, CoreTokenResponse,
};
use openidconnect::{
    Audience, EmptyAdditionalClaims, EmptyExtraTokenFields, IssuerUrl,
    StandardErrorResponse,
};
use serde::Deserialize;

use crate::error::ApiError;
use crate::model::access_tokens::{AccessToken, AccessTokenBody};
use crate::model::auth_codes::AuthorizationCode;
use crate::model::signing_keys::SigningKey;
use crate::oidc::claim_gatherer;
use crate::state::ServerState;
use crate::util::id::EntityId;

#[derive(Deserialize)]
pub struct TokenRequestBody {
    pub code: String,
    pub redirect_uri: String,
}

pub async fn oauth_token(
    auth: TypedHeader<Authorization<Basic>>,
    state: ServerState,
    req: Form<TokenRequestBody>,
) -> Result<impl IntoResponse, ApiError> {
    let Some(flow) = AuthorizationCode::get(&req.code, &state.pool).await? else {
        return Err(StandardErrorResponse::<CoreErrorResponseType>::new(
            CoreErrorResponseType::InvalidGrant,
            None,
            None,
        )
        .into());
    };

    let Ok(client_id) = EntityId::try_from(auth.username()) else {
        return Err(StandardErrorResponse::<CoreErrorResponseType>::new(
            CoreErrorResponseType::InvalidClient,
            None,
            None,
        )
        .into());
    };
    let client_secret = auth.password();

    let Some(..) = sqlx::query!(
        "
        SELECT 1 as `ae`
        FROM clients
        WHERE id = $1 AND client_secret = $2
        ",
        client_id,
        client_secret
    )
    .fetch_optional(&state.pool)
    .await?
    else {
        return Err(StandardErrorResponse::<CoreErrorResponseType>::new(
            CoreErrorResponseType::InvalidClient,
            None,
            None,
        )
        .into());
    };

    let claims = CoreIdTokenClaims::new(
        IssuerUrl::from_url(state.links.issuer.clone()),
        vec![Audience::new(client_id.to_string())],
        Utc::now() + Duration::minutes(30),
        Utc::now(),
        claim_gatherer::gather(flow.user_id, &flow.body.scope, &state.pool).await?,
        EmptyAdditionalClaims {},
    );

    let keys = SigningKey::get_all(&state.pool).await?;
    let key = keys.values().next().unwrap();

    let id_token = CoreIdToken::new(
        claims,
        &key.key,
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        None,
        Some(&openidconnect::AuthorizationCode::new(req.code.clone())),
    )
    .unwrap();

    let access_token = AccessToken::insert(
        flow.user_id,
        flow.client_id,
        AccessTokenBody {
            scope: flow.body.scope,
        },
        &state.pool,
    )
    .await?;

    let res = CoreTokenResponse::new(
        openidconnect::AccessToken::new(access_token),
        openidconnect::core::CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );

    Ok(Json(res))
}
