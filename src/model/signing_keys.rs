use std::collections::HashMap;

use openidconnect::{
    core::{CoreJsonWebKey, CoreRsaPrivateSigningKey},
    JsonWebKeyId, PrivateSigningKey,
};
use sqlx::Sqlite;

use crate::{error::ApiError, util::id::EntityId};

pub struct SigningKey {
    pub id: EntityId,
    pub key: CoreRsaPrivateSigningKey,
}

impl SigningKey {
    pub async fn get_all<'e, E>(executor: E) -> Result<HashMap<EntityId, SigningKey>, ApiError>
    where
        E: sqlx::Executor<'e, Database = Sqlite>,
    {
        Ok(sqlx::query!(
            "
                SELECT id as `id:EntityId`, pem_body
                FROM jwt_keys
                "
        )
        .fetch_all(executor)
        .await?
        .into_iter()
        .map(|x| {
            let key = CoreRsaPrivateSigningKey::from_pem(
                &x.pem_body,
                Some(JsonWebKeyId::new(x.id.to_string())),
            )
            .unwrap();

            (x.id, SigningKey { id: x.id, key })
        })
        .collect::<HashMap<_, _>>())
    }

    pub fn into_jwk(&self) -> CoreJsonWebKey {
        self.key.as_verification_key()
    }
}
