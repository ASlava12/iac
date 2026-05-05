//! Token generation and verification.
//!
//! The token is a 256-bit cryptographically random value, serialized as
//! base64url. The server stores `hex(sha256(token))`. A bearer token from a
//! request is hashed with the same scheme and compared in constant time to
//! the stored value.
//!
//! TLS / mTLS is NOT in Phase 2a — that's Phase 6. Until then, deploy the
//! control-plane behind a TLS-terminating reverse proxy (or only run on
//! trusted networks).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Returns `(token, hash)` where the token is what we hand to the client and
/// the hash is what we persist server-side.
pub fn issue_token() -> (String, String) {
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    let token = URL_SAFE_NO_PAD.encode(buf);
    let hash = hash_token(&token);
    (token, hash)
}

pub fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

/// Constant-time equality of two equal-length byte strings.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_verify() {
        let (token, hash) = issue_token();
        assert_eq!(hash_token(&token), hash);
        assert!(ct_eq(hash_token(&token).as_bytes(), hash.as_bytes()));
    }

    #[test]
    fn distinct_tokens_distinct_hashes() {
        let (t1, h1) = issue_token();
        let (t2, h2) = issue_token();
        assert_ne!(t1, t2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn ct_eq_rejects_mismatch() {
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"a", b"ab"));
    }
}
