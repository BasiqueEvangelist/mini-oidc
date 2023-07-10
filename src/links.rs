use std::sync::Arc;

use axum::extract::FromRef;
use openidconnect::ClientConfigUrl;
use url::Url;

use crate::{state::ServerState, util::id::EntityId};

pub struct ServerLinks {
    pub issuer: Url,
    pub oauth_authorize: Url,
    pub oauth_token: Url,
    pub oidc_jwks: Url,
    pub oidc_register: Url,
    pub oidc_userinfo: Url,
    pub login: Url,
    pub register: Url,
    pub logout: Url,
    pub user: Url,

    _private: (),
}

impl ServerLinks {
    pub fn from(issuer: Url) -> anyhow::Result<ServerLinks> {
        Ok(ServerLinks {
            oauth_authorize: issuer.join("/api/oauth2/auth")?,
            oauth_token: issuer.join("/api/oauth2/token")?,
            oidc_jwks: issuer.join("/api/oidc/jwks")?,
            oidc_register: issuer.join("/api/oidc/register")?,
            oidc_userinfo: issuer.join("/api/oidc/userinfo")?,
            login: issuer.join("/login")?,
            register: issuer.join("/register")?,
            logout: issuer.join("/logout")?,
            user: issuer.join("/user")?,
            issuer,
            _private: (),
        })
    }

    pub fn oidc_config_client(&self, client_id: EntityId) -> ClientConfigUrl {
        ClientConfigUrl::new(format!("{}/api/oidc/config/{}", self.issuer, client_id)).unwrap()
    }

    pub fn login_from(&self, redirect_to: impl AsRef<str>) -> String {
        let mut uri = self.login.clone();

        uri.query_pairs_mut()
            .append_pair("redirect_uri", redirect_to.as_ref());

        uri.into()
    }

    pub fn register_from(&self, redirect_to: impl AsRef<str>) -> String {
        let mut uri = self.register.clone();

        uri.query_pairs_mut()
            .append_pair("redirect_uri", redirect_to.as_ref());

        uri.into()
    }

    pub fn user_page(&self, user_id: impl AsRef<str>) -> String {
        let mut uri = self.user.clone();

        uri.path_segments_mut().unwrap().push(user_id.as_ref());

        uri.into()
    }
}

impl FromRef<ServerState> for Arc<ServerLinks> {
    fn from_ref(input: &ServerState) -> Self {
        input.links.clone()
    }
}
