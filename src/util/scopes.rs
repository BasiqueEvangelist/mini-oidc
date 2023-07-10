use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::ops::Deref;

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(from = "&str")]
pub struct Scopes(pub Vec<String>);

impl Deref for Scopes {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for Scopes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for scope in self.0.iter() {
            if !first {
                f.write_str(" ")?;
            }

            f.write_str(scope.as_str())?;
            first = false;
        }

        Ok(())
    }
}

impl From<&str> for Scopes {
    fn from(value: &str) -> Self {
        Self(value.split(" ").map(|x| x.to_string()).collect::<Vec<_>>())
    }
}

impl Serialize for Scopes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}
