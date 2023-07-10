use std::sync::Arc;

use axum::extract::OriginalUri;

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};

use crate::error::ApiError;
use crate::links::ServerLinks;
use crate::{auth::session::AuthSession, state::ServerState};

use super::csrf::CsrfNonce;

#[derive(Clone)]
pub struct TemplateBase {
    pub auth: Option<AuthSession>,
    pub links: Arc<ServerLinks>,
    pub path: String,
    pub csrf: CsrfNonce,
}

#[async_trait]
impl FromRequestParts<ServerState> for TemplateBase {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let session: Option<AuthSession> = parts.extensions.get().cloned();
        let links = state.links.clone();
        let path = parts
            .extensions
            .get::<OriginalUri>()
            .map(|x| &x.0)
            .unwrap_or(&parts.uri)
            .path_and_query()
            .map(|x| x.to_string())
            .unwrap_or("/".to_string());
        let csrf = CsrfNonce::from_request_parts(parts, state).await.unwrap();

        Ok(TemplateBase {
            auth: session,
            links,
            path,
            csrf,
        })
    }
}
