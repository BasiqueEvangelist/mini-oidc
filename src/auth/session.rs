use std::borrow::Cow;
use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect};
use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::request::Parts,
    response::Response,
};
use axum_extra::extract::{
    cookie::{Cookie, Expiration},
    CookieJar,
};
use sqlx::Sqlite;
use time::{Duration, OffsetDateTime};

use crate::error::ApiError;
use crate::{state::ServerState, util::id::EntityId};

#[derive(Clone)]
pub struct AuthSession {
    pub sid: String,
    pub user_id: EntityId,
    pub username: String,
    pub last_ip: SocketAddr,
    pub expires: OffsetDateTime,
}

pub async fn layer(
    State(state): State<ServerState>,
    jar: CookieJar,
    from: ConnectInfo<SocketAddr>,
    mut request: Request<Body>,
    next: Next<Body>,
) -> Result<Response, ApiError> {
    if let Some(session_cookie) = jar.get(AuthSession::COOKIE_NAME) {
        let sid = session_cookie.value();
        if let Some(session_rec) = sqlx::query!(
            "
            SELECT s.user_id as `user_id:EntityId`, u.username, s.last_ip, s.expires
            FROM sessions s
            INNER JOIN users u ON s.user_id = u.id
            WHERE s.uid = $1
            ",
            sid
        )
        .fetch_optional(&state.pool)
        .await?
        {
            let from_q = from.to_string();
            let new_expires = OffsetDateTime::now_utc() + Duration::minutes(30);

            sqlx::query!(
                "
                UPDATE sessions
                SET last_ip = $1, expires = $2
                WHERE uid = $3
                ",
                from_q,
                new_expires,
                sid
            )
            .execute(&state.pool)
            .await?;

            let session = AuthSession {
                user_id: session_rec.user_id,
                sid: sid.to_string(),
                username: session_rec.username,
                last_ip: from.0,
                expires: new_expires,
            };

            request.extensions_mut().insert(session);
        };
    }

    Ok(next.run(request).await)
}

impl AuthSession {
    pub const COOKIE_NAME: &str = "session_id";

    pub async fn create<'e, E>(
        user_id: EntityId,
        ip: SocketAddr,
        exec: E,
    ) -> Result<Cookie<'static>, ApiError>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        let uid = crate::util::gen_secret();
        let expires = OffsetDateTime::now_utc() + Duration::minutes(30);

        let uid_q = &uid;
        let from_q = ip.to_string();

        sqlx::query!(
            "
            INSERT INTO sessions
            (uid, user_id, last_ip, expires)
            VALUES
            ($1, $2, $3, $4)
            ",
            uid_q,
            user_id,
            from_q,
            expires
        )
        .execute(exec)
        .await?;

        Ok(Cookie::build(AuthSession::COOKIE_NAME, Cow::Owned(uid))
            .expires(Expiration::DateTime(expires))
            .secure(true)
            .http_only(true)
            .finish())
    }

    pub async fn destroy<'e, E>(&self, exec: E) -> Result<Cookie<'static>, ApiError>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        let uid_q = self.sid.clone();

        sqlx::query!(
            "
            DELETE from sessions
            WHERE uid = $1
            ",
            uid_q,
        )
        .execute(exec)
        .await?;

        Ok(Cookie::build(AuthSession::COOKIE_NAME, Cow::Borrowed(""))
            .expires(Expiration::DateTime(OffsetDateTime::UNIX_EPOCH))
            .secure(true)
            .http_only(true)
            .finish())
    }

    pub async fn cleanup_job(pool: sqlx::Pool<Sqlite>) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5 * 60)).await;

            let now_q = OffsetDateTime::now_utc();
            match sqlx::query!(
                "
                DELETE FROM sessions
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

#[async_trait]
impl FromRequestParts<ServerState> for AuthSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let Some(session) = parts.extensions.get::<AuthSession>() else {
            let orig_uri = OriginalUri::from_request_parts(parts, state).await.unwrap();

            return Err(
                Redirect::to(state.links.login_from(&orig_uri.to_string()).as_str())
                    .into_response(),
            );
        };

        Ok(session.clone())
    }
}
