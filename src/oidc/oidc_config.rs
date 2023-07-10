use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, Json};

use openidconnect::{
    core::{
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType,
    },
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySet, JsonWebKeySetUrl,
    RegistrationUrl, ResponseTypes, TokenUrl, UserInfoUrl,
};

use crate::{
    error::ApiError, links::ServerLinks, model::signing_keys::SigningKey, state::ServerState,
};

pub async fn configuration(links: State<Arc<ServerLinks>>) -> impl IntoResponse {
    let metadata = CoreProviderMetadata::new(
        IssuerUrl::from_url(links.issuer.clone()),
        AuthUrl::from_url(links.oauth_authorize.clone()),
        JsonWebKeySetUrl::from_url(links.oidc_jwks.clone()),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::from_url(links.oauth_token.clone())))
    .set_userinfo_endpoint(Some(UserInfoUrl::from_url(links.oidc_userinfo.clone())))
    .set_registration_endpoint(Some(RegistrationUrl::from_url(links.oidc_register.clone())));

    Json(metadata)
}

pub async fn keyset(state: ServerState) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(JsonWebKeySet::new(
        SigningKey::get_all(&state.pool)
            .await?
            .values()
            .map(|x| x.into_jwk())
            .collect(),
    )))
}
