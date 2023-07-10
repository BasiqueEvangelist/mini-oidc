use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::Sqlite;
use time::{Duration, OffsetDateTime};

use crate::{
    error::ApiError,
    util::{id::EntityId, scopes::Scopes},
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationCodeBody {
    pub scope: Scopes,
    pub state: String,
    pub nonce: Option<String>,
}

pub struct AuthorizationCode {
    pub uid: String,
    pub user_id: EntityId,
    pub client_id: EntityId,
    pub expires: OffsetDateTime,

    pub body: AuthorizationCodeBody,
}

impl AuthorizationCode {
    pub async fn get<'e, E>(uid: &str, executor: E) -> Result<Option<AuthorizationCode>, ApiError>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        Ok(sqlx::query!(
            "
            SELECT uid as `uid:String`, user_id as `user_id:EntityId`, client_id as `client_id:EntityId`, body as `body:Json<AuthorizationCodeBody>`, expires as `expires:OffsetDateTime`
            FROM authorization_codes
            WHERE uid = $1
            ",
            uid
        )
        .fetch_optional(executor)
        .await?
        .map(|x| AuthorizationCode {
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
        body: AuthorizationCodeBody,
        executor: E,
    ) -> Result<String, ApiError>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        let uid = crate::util::gen_secret();

        let uid_q = &uid;
        let body_q = Json(body);
        let expires_q = OffsetDateTime::now_utc() + Duration::minutes(2);

        sqlx::query!(
            "
            INSERT INTO authorization_codes
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
                DELETE FROM authorization_codes
                WHERE expires < $1
                ",
                now_q
            )
            .execute(&pool)
            .await
            {
                Ok(res) => {
                    if res.rows_affected() > 0 {
                        tracing::debug!("Cleaned up {} auth codes", res.rows_affected());
                    }
                }
                Err(err) => {
                    tracing::error!("Failed to clean up authorization codes: {err}");
                }
            };
        }
    }
}
