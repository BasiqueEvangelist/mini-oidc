use std::{convert::Infallible, fmt::Display};

use askama_axum::IntoResponse;
use axum::{
    async_trait,
    body::Body,
    extract::FromRequestParts,
    http::request::Parts,
    middleware::Next,
    response::{IntoResponseParts, Response, ResponseParts},
};
use axum_extra::extract::{
    cookie::{Cookie, Expiration},
    CookieJar,
};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

pub async fn layer(
    csrf: CsrfNonce,
    request: axum::http::Request<Body>,
    next: Next<Body>,
) -> Response {
    (csrf, next.run(request).await).into_response()
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct CsrfNonce(pub String);

impl CsrfNonce {
    pub fn verify(&self, other: &CsrfNonce) -> Result<(), ApiError> {
        if self != other {
            Err(ApiError::CsrfFailure)
        } else {
            Ok(())
        }
    }
}

impl Display for CsrfNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// TODO: use signed cookies for this.

#[async_trait]
impl<S> FromRequestParts<S> for CsrfNonce
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);

        Ok(CsrfNonce(
            jar.get("csrf")
                .map(|x| x.value().to_string())
                .unwrap_or_else(crate::util::gen_secret),
        ))
    }
}

impl IntoResponseParts for CsrfNonce {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        CookieJar::new()
            .add(
                Cookie::build("csrf", self.0)
                    .expires(Expiration::Session)
                    .secure(true)
                    .http_only(true)
                    .finish(),
            )
            .into_response_parts(res)
    }
}
