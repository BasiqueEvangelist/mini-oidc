use askama_axum::IntoResponse;
use axum::{
    async_trait,
    extract::FromRequestParts,
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
    response::{AppendHeaders, Response},
    TypedHeader,
};
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::Sqlite;
use time::{Duration, OffsetDateTime};

use crate::{
    error::ApiError,
    state::ServerState,
    util::{id::EntityId, scopes::Scopes},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenBody {
    pub scope: Scopes,
}

pub struct AccessToken {
    pub uid: String,
    pub user_id: EntityId,
    pub client_id: EntityId,
    pub expires: OffsetDateTime,

    pub body: AccessTokenBody,
}

impl AccessToken {
    pub async fn get<'e, E>(uid: &str, executor: E) -> Result<Option<AccessToken>, ApiError>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        Ok(sqlx::query!(
            "
            SELECT uid as `uid:String`, user_id as `user_id:EntityId`, client_id as `client_id:EntityId`, body as `body:Json<AccessTokenBody>`, expires as `expires:OffsetDateTime`
            FROM access_tokens
            WHERE uid = $1
            ",
            uid
        )
        .fetch_optional(executor)
        .await?
        .map(|x| AccessToken {
            uid: x.uid,
            user_id: x.user_id,
            client_id: x.client_id,
            body: x.body.0,
            expires: x.expires
        }))
    }

    pub async fn insert<'e, E>(
        user_id: EntityId,
        client_id: EntityId,
        body: AccessTokenBody,
        executor: E,
    ) -> Result<String, ApiError>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        let uid = crate::util::gen_secret();

        let uid_q = &uid;
        let body_q = Json(body);
        let expires_q = OffsetDateTime::now_utc() + Duration::minutes(30);

        sqlx::query!(
            "
            INSERT INTO access_tokens
            (uid, user_id, client_id, body, expires)
            VALUES
            ($1, $2, $3, $4, $5)
            ",
            uid_q,
            user_id,
            client_id,
            body_q,
            expires_q
        )
        .execute(executor)
        .await?;

        Ok(uid)
    }

    pub async fn cleanup_job(pool: sqlx::Pool<Sqlite>) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5 * 60)).await;

            let now_q = OffsetDateTime::now_utc();
            match sqlx::query!(
                "
                DELETE FROM access_tokens
                WHERE expires < $1
                ",
                now_q
            )
            .execute(&pool)
            .await
            {
                Ok(res) => {
                    if res.rows_affected() > 0 {
                        tracing::debug!("Cleaned up {} access tokens", res.rows_affected());
                    }
                }
                Err(err) => {
                    tracing::error!("Failed to clean up access tokens: {err}");
                }
            };
        }
    }
}

#[async_trait]
impl FromRequestParts<ServerState> for AccessToken {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(header) = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
            .await
            .ok()
        {
            if let Some(token) = AccessToken::get(header.token(), &state.pool)
                .await
                .map_err(|x| x.into_response())?
            {
                return Ok(token);
            }
        }

        Err((
            StatusCode::UNAUTHORIZED,
            AppendHeaders([(
                axum::http::header::WWW_AUTHENTICATE,
                "Bearer error=\"invalid_token\"",
            )]),
            "",
        )
            .into_response())
    }
}
