use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use openidconnect::{
    core::{CoreErrorResponseType, CoreRegisterErrorResponseType},
    StandardErrorResponse,
};
use problemdetails::Problem;

pub enum ApiError {
    ProblemDetails(Problem),
    PasswordHash(password_hash::Error),
    Sqlx(sqlx::Error),
    OidcRegistration(StandardErrorResponse<CoreRegisterErrorResponseType>),
    OauthToken(StandardErrorResponse<CoreErrorResponseType>),
    CsrfFailure,
    Url(url::ParseError),
    Rsa(rsa::Error),
    FromAxum(Response),
}

macro_rules! from_err {
    ($from_type:ty, $variant:ident) => {
        impl From<$from_type> for ApiError {
            fn from(value: $from_type) -> Self {
                ApiError::$variant(value)
            }
        }
    };
}

from_err!(problemdetails::Problem, ProblemDetails);
from_err!(sqlx::Error, Sqlx);
from_err!(
    StandardErrorResponse<CoreRegisterErrorResponseType>,
    OidcRegistration
);
from_err!(StandardErrorResponse<CoreErrorResponseType>, OauthToken);
from_err!(password_hash::Error, PasswordHash);
from_err!(url::ParseError, Url);
from_err!(rsa::Error, Rsa);

pub trait IntoApiResult {
    type Value;

    fn into_api(self) -> Result<Self::Value, ApiError>;
}

impl<V, E: IntoResponse> IntoApiResult for Result<V, E> {
    type Value = V;

    fn into_api(self) -> Result<Self::Value, ApiError> {
        self.map_err(|x| ApiError::FromAxum(x.into_response()))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        match self {
            ApiError::Sqlx(err) => problemdetails::new(StatusCode::INTERNAL_SERVER_ERROR)
                .with_type("https://basique.top/mini-oidc/error/database")
                .with_title("Database error")
                .with_detail(err.to_string())
                .into_response(),
            ApiError::ProblemDetails(problem) => problem.into_response(),
            ApiError::OidcRegistration(err) => (StatusCode::BAD_REQUEST, Json(err)).into_response(),
            ApiError::OauthToken(err) => (StatusCode::BAD_REQUEST, Json(err)).into_response(),
            ApiError::CsrfFailure => problemdetails::new(StatusCode::BAD_REQUEST)
                .with_type("https://basique.top/mini-oidc/error/csrf")
                .with_title("CSRF token invalid")
                .into_response(),
            ApiError::PasswordHash(_) => problemdetails::new(StatusCode::INTERNAL_SERVER_ERROR)
                .with_type("https://basique.top/mini-oidc/error/password_hash")
                .with_title("Password hash error")
                .into_response(),
            ApiError::Url(_) => problemdetails::new(StatusCode::INTERNAL_SERVER_ERROR)
                .with_type("https://basique.top/mini-oidc/error/url_parse")
                .with_title("URL parsing")
                .into_response(),
            ApiError::Rsa(_) => problemdetails::new(StatusCode::INTERNAL_SERVER_ERROR)
                .with_type("https://basique.top/mini-oidc/error/rsa")
                .with_title("RSA error")
                .into_response(),
            ApiError::FromAxum(res) => res,
        }
    }
}

pub fn not_found() -> Problem {
    problemdetails::new(StatusCode::NOT_FOUND)
        .with_type("about:blank")
        .with_title("Not Found")
}
