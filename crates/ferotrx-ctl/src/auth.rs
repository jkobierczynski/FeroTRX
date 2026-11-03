//! Logins: tokens and the roles they give.

use std::path::Path;

use serde::Deserialize;

use crate::protocol::Role;

/// A token clients log in with (`auth`), and the role it gives.
#[derive(Clone)]
pub struct Token {
    /// Who logs in with it, for the audit log and `server.info`.
    pub name: String,
    pub role: Role,
    secret: Secret,
}

#[derive(Clone)]
enum Secret {
    Plain(Vec<u8>),
    Sha256([u8; 32]),
}

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Token")
            .field("name", &self.name)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// Error reading a tokens file.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TokenError(String);

impl Token {
    /// A token with the secret itself.
    pub fn new(name: impl Into<String>, role: Role, secret: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            role,
            secret: Secret::Plain(secret.into().into_bytes()),
        }
    }

    /// A token known only by the SHA-256 of its secret, written in hex
    /// (what `sha256sum` prints for the secret without a newline).
    pub fn from_sha256(name: impl Into<String>, role: Role, hex: &str) -> Result<Self, TokenError> {
        let hex = hex.trim();
        let bad = || TokenError(format!("'{hex}' is not a SHA-256 in hex (64 digits)"));
        if hex.len() != 64 {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2).ok_or_else(bad)?, 16)
                .map_err(|_| bad())?;
        }
        Ok(Self {
            name: name.into(),
            role,
            secret: Secret::Sha256(out),
        })
    }

    /// Whether `given` is this token's secret, in time that does not depend
    /// on where they differ.
    pub fn matches(&self, given: &str) -> bool {
        match &self.secret {
            Secret::Plain(s) => same(s, given.as_bytes()),
            Secret::Sha256(h) => {
                let d = ring::digest::digest(&ring::digest::SHA256, given.as_bytes());
                same(h, d.as_ref())
            }
        }
    }

    /// Reads tokens from a TOML file:
    ///
    /// ```toml
    /// [[token]]
    /// name = "ci"
    /// role = "operator"
    /// secret = "a long random string"
    ///
    /// [[token]]
    /// name = "dashboard"
    /// role = "read"
    /// sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    /// ```
    pub fn from_file(path: &Path) -> Result<Vec<Token>, TokenError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| TokenError(format!("cannot read {}: {e}", path.display())))?;
        Self::from_toml(&text).map_err(|e| TokenError(format!("{}: {e}", path.display())))
    }

    /// Reads tokens from TOML text (see [`from_file`](Token::from_file)).
    pub fn from_toml(text: &str) -> Result<Vec<Token>, TokenError> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct File {
            #[serde(default)]
            token: Vec<Entry>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Entry {
            name: String,
            role: String,
            secret: Option<String>,
            sha256: Option<String>,
        }
        let f: File = toml::from_str(text).map_err(|e| TokenError(e.to_string()))?;
        let mut out = Vec::new();
        for e in f.token {
            let role: Role = e.role.parse().map_err(TokenError)?;
            let t = match (e.secret, e.sha256) {
                (Some(s), None) if !s.is_empty() => Token::new(&e.name, role, s),
                (None, Some(h)) => Token::from_sha256(&e.name, role, &h)?,
                _ => {
                    return Err(TokenError(format!(
                        "token '{}' needs exactly one of secret or sha256",
                        e.name
                    )))
                }
            };
            out.push(t);
        }
        Ok(out)
    }
}

/// Compares two secrets in time that depends only on their lengths.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_and_hashed_tokens() {
        let t = Token::new("a", Role::Read, "s3cret");
        assert!(t.matches("s3cret"));
        assert!(!t.matches("s3cre"));
        let h = Token::from_sha256(
            "b",
            Role::Operator,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        )
        .unwrap();
        assert!(h.matches("test"));
        assert!(!h.matches("test2"));
        assert!(Token::from_sha256("c", Role::Read, "abc").is_err());
    }

    #[test]
    fn tokens_file() {
        let list = Token::from_toml(
            r#"
            [[token]]
            name = "ci"
            role = "operator"
            secret = "one"
            [[token]]
            name = "dash"
            role = "read"
            sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            "#,
        )
        .unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].role, Role::Operator);
        assert!(list[1].matches("test"));
        assert!(Token::from_toml("[[token]]\nname='x'\nrole='admin'\nsecret='s'").is_err());
        assert!(Token::from_toml("[[token]]\nname='x'\nrole='read'").is_err());
    }
}
