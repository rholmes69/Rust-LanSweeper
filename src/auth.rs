//! API tokens for machine clients (the MCP HTTP endpoint).
//!
//! Tokens are random 256-bit values shown once at creation; only their SHA-256 hash is stored.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};

use crate::db::Db;

pub const TOKEN_PREFIX: &str = "rsw_";

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("OS random number generator failed: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn hash_token(token: &str) -> String {
    Sha256::digest(token.trim().as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// An authenticated API caller.
#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    pub name: String,
    /// None = all sites; Some(ids) = only these sites.
    pub sites: Option<Vec<i64>>,
}

/// Create a named token, optionally limited to some sites.
/// Returns (id, plaintext token) — the plaintext is never stored.
pub fn create(db: &Db, name: &str, sites: Option<&[i64]>) -> Result<(i64, String)> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(anyhow!("token name must be 1–64 characters"));
    }
    let token = format!("{TOKEN_PREFIX}{}", random_hex(32)?);
    let prefix: String = token.chars().take(TOKEN_PREFIX.len() + 6).collect();
    let id = db
        .create_token(name, &hash_token(&token), &prefix, sites)
        .map_err(|e| if e.to_string().contains("UNIQUE") { anyhow!("a token named '{name}' already exists") } else { e })?;
    Ok((id, token))
}

/// Validate a presented bearer token.
pub fn verify(db: &Db, presented: &str) -> Result<Option<Principal>> {
    let t = presented.trim();
    if !t.starts_with(TOKEN_PREFIX) || t.len() != TOKEN_PREFIX.len() + 64 {
        return Ok(None);
    }
    Ok(db.token_by_hash(&hash_token(t))?.map(|(_, name, sites)| Principal { name, sites }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_verify_revoke() {
        let db = Db::open(":memory:").unwrap();
        let (_, tok) = create(&db, "claude-desktop", None).unwrap();
        assert!(tok.starts_with("rsw_") && tok.len() == 68);
        assert_eq!(verify(&db, &tok).unwrap(), Some(Principal { name: "claude-desktop".into(), sites: None }));
        assert!(verify(&db, "rsw_nope").unwrap().is_none());
        assert!(create(&db, "claude-desktop", None).is_err(), "names are unique");
        let (_, scoped) = create(&db, "dental-only", Some(&[2, 5])).unwrap();
        assert_eq!(verify(&db, &scoped).unwrap().unwrap().sites, Some(vec![2, 5]));
        let stored = db.list_tokens().unwrap();
        assert!(!stored[0].prefix.is_empty() && stored[0].last_used.is_some());
        assert!(db.revoke_token("claude-desktop").unwrap());
        assert!(verify(&db, &tok).unwrap().is_none());
        assert_ne!(random_hex(32).unwrap(), random_hex(32).unwrap());
    }
}
