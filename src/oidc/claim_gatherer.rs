use openidconnect::{
    core::CoreGenderClaim, EndUserEmail, EndUserUsername, StandardClaims, SubjectIdentifier,
};
use sqlx::Sqlite;

use crate::{
    error::ApiError,
    util::{id::EntityId, scopes::Scopes},
};

pub async fn gather<'e, E>(
    user_id: EntityId,
    scope: &Scopes,
    exec: E,
) -> Result<StandardClaims<CoreGenderClaim>, ApiError>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    let mut claims = StandardClaims::new(SubjectIdentifier::new(user_id.to_string()));

    let user = sqlx::query!(
        "
        SELECT username, email
        FROM users
        WHERE id = $1
        ",
        user_id,
    )
    .fetch_one(exec)
    .await?;

    if scope.iter().any(|x| x == "profile") {
        // name
        // family_name
        // given_name
        // middle_name
        // nickname
        claims = claims.set_preferred_username(Some(EndUserUsername::new(user.username)));
        // profile
        // picture
        // website
        // gender
        // birthdate
        // zoneinfo
        // locale
        // updated_at
    }

    if scope.iter().any(|x| x == "email") {
        claims = claims
            .set_email_verified(user.email.as_ref().map(|_x| true))
            .set_email(user.email.map(EndUserEmail::new))
    }

    Ok(claims)
}
