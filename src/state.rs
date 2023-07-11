use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{async_trait, extract::FromRequestParts, http::request::Parts};

use rsa::pkcs1::EncodeRsaPrivateKey;
use sqlx::{sqlite::SqlitePoolOptions, Sqlite};
use url::Url;

use crate::{links::ServerLinks, util::id::EntityId};

#[derive(Clone)]
pub struct ServerState {
    pub pool: sqlx::Pool<Sqlite>,
    pub bind_addr: SocketAddr,
    pub links: Arc<ServerLinks>,
}

#[async_trait]
impl FromRequestParts<ServerState> for ServerState {
    type Rejection = Infallible;

    async fn from_request_parts(
        _parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        Ok(state.clone())
    }
}

#[tracing::instrument]
pub async fn init() -> anyhow::Result<ServerState> {
    let bind_addr = dotenvy::var("BIND_ADDR")
        .with_context(|| "reading BIND_ADDR variable")?
        .parse::<SocketAddr>()
        .with_context(|| "parsing BIND_ADDR variable")?;

    let db_url = dotenvy::var("DATABASE_URL")
        .with_context(|| "reading DATABASE_URL environment variable")?;

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect(&db_url)
        .await
        .with_context(|| "connecting to database")?;

    tracing::info!("connected to {db_url}");

    let links = Arc::new(ServerLinks::from(Url::parse(
        dotenvy::var("ISSUER_URL")
            .with_context(|| "reading ISSUER_URL environment variable")?
            .trim_end_matches('/'),
    )?)?);

    let has_keys = sqlx::query!("SELECT EXISTS(SELECT id from jwt_keys WHERE id=id) AS has_keys")
        .fetch_one(&pool)
        .await?
        .has_keys
        == Some(1);

    if !has_keys {
        tracing::info!("no signing keys in DB; generating key");

        generate_and_add_key(&pool).await?;
    }

    Ok(ServerState {
        pool,
        bind_addr,
        links,
    })
}

#[tracing::instrument]
async fn generate_and_add_key(pool: &sqlx::Pool<Sqlite>) -> anyhow::Result<()> {
    let key = tokio::task::spawn_blocking(|| {
        let _enter = tracing::info_span!("generating RSA key").entered();

        rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
    })
    .await??;

    tracing::info!("generated key, inserting into DB");

    let key_pem = key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)?;
    let pem_ref: &str = &key_pem;
    let id = EntityId::generate(&mut rand::thread_rng());

    sqlx::query!(
        "
            INSERT INTO jwt_keys
            (id, pem_body)
            VALUES
            ($1, $2)
            ",
        id,
        pem_ref
    )
    .execute(pool)
    .await?;

    Ok(())
}
