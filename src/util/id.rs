use std::{fmt::Display, ops::Range};

use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sqlx::{
    database::{HasArguments, HasValueRef},
    encode::IsNull,
    error::BoxDynError,
    Database, Decode, Encode, Type,
};
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(try_from = "&str")]
#[serde(into = "String")]
pub struct EntityId(u64);

impl EntityId {
    pub const RANGE: Range<u64> = 62u64.pow(7)..62u64.pow(8);

    pub fn generate<R: RngCore + ?Sized>(rng: &mut R) -> EntityId {
        EntityId(rng.gen_range(EntityId::RANGE))
    }

    pub fn raw(&self) -> u64 {
        self.0
    }
}

#[derive(Error, Debug, Clone)]
pub enum GenericIdError {
    #[error("id needs to be 8 characters long, not {0}")]
    WrongLength(usize),
    #[error("id needs to be in 62**7..62**8")]
    OutOfBounds,
    #[error("invalid base62 id")]
    Decode(base62::DecodeError),
}

impl TryFrom<&str> for EntityId {
    type Error = GenericIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() == 8 {
            Ok(EntityId(
                base62::decode(&value).map_err(GenericIdError::Decode)? as u64,
            ))
        } else {
            Err(GenericIdError::WrongLength(value.len()))
        }
    }
}

impl TryFrom<u64> for EntityId {
    type Error = GenericIdError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if EntityId::RANGE.contains(&value) {
            Ok(EntityId(value))
        } else {
            Err(GenericIdError::OutOfBounds)
        }
    }
}

impl From<EntityId> for String {
    fn from(value: EntityId) -> String {
        base62::encode(value.0)
    }
}

impl Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&String::from(*self))
    }
}

impl<DB> Type<DB> for EntityId
where
    DB: Database,
    i64: Type<DB>,
{
    fn type_info() -> <DB as Database>::TypeInfo {
        <i64 as Type<DB>>::type_info()
    }

    fn compatible(ty: &<DB as Database>::TypeInfo) -> bool {
        <i64 as Type<DB>>::compatible(ty)
    }
}

impl<'q, DB> Encode<'q, DB> for EntityId
where
    DB: Database,
    i64: Encode<'q, DB>,
{
    fn encode_by_ref(&self, buf: &mut <DB as HasArguments<'q>>::ArgumentBuffer) -> IsNull {
        <i64 as Encode<DB>>::encode(self.0 as i64, buf)
    }
}

impl<'r, DB> Decode<'r, DB> for EntityId
where
    DB: Database,
    i64: Decode<'r, DB>,
{
    fn decode(value: <DB as HasValueRef<'r>>::ValueRef) -> Result<Self, BoxDynError> {
        Ok(EntityId::try_from(
            <i64 as Decode<DB>>::decode(value)? as u64
        )?)
    }
}
