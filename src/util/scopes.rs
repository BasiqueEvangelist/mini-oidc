use serde::{de::Visitor, Deserialize, Serialize};
use std::convert::Infallible;
use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

#[derive(Clone, Debug, PartialEq, Eq)]
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

impl FromStr for Scopes {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            s.split(' ').map(|x| x.to_string()).collect::<Vec<_>>(),
        ))
    }
}

impl<'de> Deserialize<'de> for Scopes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ScopesVisitor;

        impl<'de> Visitor<'de> for ScopesVisitor {
            type Value = Scopes;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("space delimited OAuth2.0 scopes")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Scopes::from_str(v).unwrap())
            }
        }

        deserializer.deserialize_str(ScopesVisitor)
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
