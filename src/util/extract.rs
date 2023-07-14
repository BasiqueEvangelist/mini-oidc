use axum::response::IntoResponse;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::Redirect,
};
use openidconnect::{
    core::{
        CoreAuthDisplay, CoreAuthErrorResponseType, CoreAuthPrompt, CoreIdToken, CoreResponseMode,
        CoreResponseType,
    },
    LanguageTag,
};
use serde::{de::Visitor, Deserialize, Deserializer};
use time::Duration;
use url::Url;

use crate::error::ApiError;

use super::id::EntityId;
use super::scopes::Scopes;

#[derive(Deserialize, Debug)]
pub struct OidcAuthRequestHead {
    pub client_id: EntityId,
    pub redirect_uri: url::Url,
    pub state: String,
    #[serde(skip)]
    query_remaining: String,
}

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for OidcAuthRequestHead {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or_default();
        let mut req: OidcAuthRequestHead = serde_urlencoded::from_str(query).map_err(|x| {
            problemdetails::new(StatusCode::BAD_REQUEST)
                .with_type("https://basique.top/mini-oidc/error/invalid_auth_request")
                .with_detail(x.to_string())
        })?;

        req.query_remaining = query.to_string();

        Ok(req)
    }
}

impl OidcAuthRequestHead {
    pub fn next(self) -> Result<OidcAuthRequest, ApiError> {
        let query = &self.query_remaining;

        Ok(serde_urlencoded::from_str(query).map_err(|x| {
            error_redirect(
                &self.redirect_uri,
                &self.state,
                CoreAuthErrorResponseType::InvalidRequest,
                &x.to_string(),
            )
        })?)
    }
}

impl OidcAuthRequest {
    pub fn proceed(&self, code: &str) -> impl IntoResponse {
        let mut redirect_to = self.redirect_uri.clone();

        redirect_to
            .query_pairs_mut()
            .append_pair("code", code)
            .append_pair("state", &self.state);

        Redirect::to(redirect_to.as_str())
    }

    pub fn error(&self, error: CoreAuthErrorResponseType, error_desc: &str) -> ApiError {
        error_redirect(&self.redirect_uri, &self.state, error, error_desc)
    }
}

fn error_redirect(
    redirect_uri: &Url,
    state: &str,
    error: CoreAuthErrorResponseType,
    error_desc: &str,
) -> ApiError {
    let mut redirect_to = redirect_uri.clone();

    redirect_to
        .query_pairs_mut()
        .append_pair("error", error.as_ref())
        .append_pair("error_description", error_desc)
        .append_pair("state", &state);

    ApiError::FromAxum(Redirect::to(redirect_to.as_str()).into_response())
}

#[derive(Deserialize, Debug)]
pub struct OidcAuthRequest {
    pub scope: Scopes,
    pub response_type: CoreResponseType,
    pub client_id: EntityId,
    pub redirect_uri: Url,
    pub state: String,
    pub response_mode: Option<CoreResponseMode>,
    pub nonce: Option<String>,
    pub display: Option<CoreAuthDisplay>,
    pub prompt: Option<CoreAuthPrompt>,
    #[serde(deserialize_with = "deserialize_max_age")]
    #[serde(default)]
    pub max_age: Option<Duration>,
    #[serde(deserialize_with = "deserialize_ui_locales")]
    #[serde(default)]
    pub ui_locales: Vec<LanguageTag>,
    pub id_token_hint: Option<CoreIdToken>,
    pub login_hint: Option<String>,
    // acr_values
}

fn deserialize_max_age<'de, D: Deserializer<'de>>(
    deserialize: D,
) -> Result<Option<Duration>, D::Error> {
    struct MaxAgeVisitor;

    impl<'de> Visitor<'de> for MaxAgeVisitor {
        type Value = Option<Duration>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("max age in seconds")
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Some(Duration::seconds(v)))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(None)
        }
    }

    deserialize.deserialize_i64(MaxAgeVisitor)
}

fn deserialize_ui_locales<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<LanguageTag>, D::Error> {
    struct LocalesVisitor;

    impl<'de> Visitor<'de> for LocalesVisitor {
        type Value = Vec<LanguageTag>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("space separated language tags")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(v.split(' ')
                .map(|x| LanguageTag::new(x.to_string()))
                .collect())
        }
    }

    deserializer.deserialize_str(LocalesVisitor)
}
