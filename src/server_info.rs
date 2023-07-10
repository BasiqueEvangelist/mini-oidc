use askama::Template;
use axum::{response::IntoResponse, Json};
use serde::Serialize;

use crate::util::template::TemplateBase;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    pub base: TemplateBase,
}

pub async fn index(base: TemplateBase) -> impl IntoResponse {
    IndexTemplate { base }
}

pub async fn server_info() -> impl IntoResponse {
    #[derive(Serialize)]
    struct ServerInfo {
        pub name: &'static str,
        pub version: &'static str,
        pub note: &'static str,
    }

    Json(ServerInfo {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        note: "This is the API directory.",
    })
}
