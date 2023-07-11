use askama_axum::IntoResponse;
use axum::Json;
use openidconnect::{
    core::CoreUserInfoClaims, EmptyAdditionalClaims,
};

use crate::{error::ApiError, model::access_tokens::AccessToken, state::ServerState};

use super::claim_gatherer;

pub async fn userinfo(
    token: AccessToken,
    state: ServerState,
) -> Result<impl IntoResponse, ApiError> {
    Ok(Json(CoreUserInfoClaims::new(
        claim_gatherer::gather(token.user_id, &token.body.scope, &state.pool).await?,
        EmptyAdditionalClaims {},
    )))
}
