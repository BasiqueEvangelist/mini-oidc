use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use openidconnect::core::{
    CoreClientMetadata, CoreClientRegistrationResponse, CoreRegisterErrorResponseType,
};
use openidconnect::registration::{
    EmptyAdditionalClientMetadata, EmptyAdditionalClientRegistrationResponse,
};
use openidconnect::{ClientId, ClientSecret, RegistrationAccessToken, StandardErrorResponse};
use sqlx::Connection;

use crate::error::ApiError;
use crate::state::ServerState;
use crate::util::id::EntityId;

pub async fn register_client(
    state: ServerState,
    Json(req): Json<CoreClientMetadata>,
) -> Result<impl IntoResponse, ApiError> {
    let mut conn = state.pool.acquire().await?;

    conn.transaction::<_, _, ApiError>(|tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>| {
        Box::pin(async move {
            let Some(client_name) = req
                .client_name()
                .and_then(|x| x.get(None))
                .map(|x| (**x).clone())
            else {
                return Err(StandardErrorResponse::new(
                    CoreRegisterErrorResponseType::InvalidClientMetadata,
                    Some("client_name is required for registration".to_string()),
                    None,
                )
                .into());
            };

            let app_type = req
                .application_type()
                .cloned()
                .unwrap_or(openidconnect::core::CoreApplicationType::Web);

            let client_uri = req
                .client_uri()
                .and_then(|x| x.get(None))
                .map(|x| x.url().to_string());

            let logo_uri = req
                .logo_uri()
                .and_then(|x| x.get(None))
                .map(|x| x.url().to_string())
                .unwrap_or_else(|| format!("{}/static/default_icon.png", state.links.issuer));

            let client_id = EntityId::generate(&mut rand::thread_rng());
            let registration_token = crate::util::gen_secret();
            let client_secret = crate::util::gen_secret();

            let app_type_q = app_type.as_ref();
            let client_secret_q = &client_secret;
            let reg_token_q = &registration_token;

            sqlx::query!(
                "
                INSERT INTO clients
                (id, client_name, app_type, client_uri, logo_uri, registration_token, client_secret)
                VALUES
                ($1, $2, $3, $4, $5, $6, $7)
                ",
                client_id,
                client_name,
                app_type_q,
                client_uri,
                logo_uri,
                reg_token_q,
                client_secret_q
            )
            .execute(&mut **tx)
            .await?;

            for redirect_uri in req.redirect_uris() {
                let uri_q = redirect_uri.as_str();

                sqlx::query!(
                    "
                    INSERT INTO client_redirect_uris
                    (client_id, redirect_uri)
                    VALUES
                    ($1, $2)
                    ",
                    client_id,
                    uri_q
                )
                .execute(&mut **tx)
                .await?;
            }

            for contact in req.contacts().iter().flat_map(|x| x.iter()) {
                let email_q = contact.as_str();

                sqlx::query!(
                    "
                    INSERT INTO client_contacts
                    (client_id, email)
                    VALUES
                    ($1, $2)
                    ",
                    client_id,
                    email_q
                )
                .execute(&mut **tx)
                .await?;
            }

            Ok((
                StatusCode::CREATED,
                Json(
                    CoreClientRegistrationResponse::new(
                        ClientId::new(client_id.to_string()),
                        req.redirect_uris().clone(),
                        EmptyAdditionalClientMetadata {},
                        EmptyAdditionalClientRegistrationResponse {},
                    )
                    .set_client_secret(Some(ClientSecret::new(client_secret.clone())))
                    .set_client_secret_expires_at(None)
                    .set_registration_access_token(Some(RegistrationAccessToken::new(
                        registration_token.clone(),
                    )))
                    .set_registration_client_uri(Some(state.links.oidc_config_client(client_id)))
                    .set_application_type(Some(app_type))
                    .set_redirect_uris(req.redirect_uris().clone())
                    .set_contacts(req.contacts().cloned()),
                ),
            ))
        })
    })
    .await
}
