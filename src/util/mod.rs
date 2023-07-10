use rand::{distributions::Alphanumeric, Rng};

pub mod csrf;
pub mod id;
pub mod scopes;
pub mod template;

pub fn gen_secret() -> String {
    rand::thread_rng()
        .sample_iter(Alphanumeric)
        .take(64)
        .map(char::from)
        .collect::<String>()
}
