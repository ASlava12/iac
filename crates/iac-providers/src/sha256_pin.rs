//! Phase 10: SHA-256 pin helpers extracted from `wasm::spec`.
//!
//! Originally co-located with the WASM provider (Phase 7dh.4) because
//! the wasm runtime was the first user. Both `process` (Phase 7dh.4)
//! and `wasm` rely on the same byte-pattern check + verify pattern,
//! so the helpers live here as a shared utility — no wasmtime
//! dependency, available even when `--no-default-features` strips
//! the WASM provider for MIPS / OpenWrt cross-compiles.

/// Phase 7dh.4: a SHA-256 pin must be exactly 64 lowercase
/// hex chars. Reject mixed-case / leading `"sha256:"` prefixes /
/// whitespace upfront.
pub(crate) fn validate_sha256_hex(s: &str, field: &'static str) -> Result<(), String> {
    if s.len() != 64 {
        return Err(format!(
            "{field} must be 64 lowercase hex chars (got {})",
            s.len()
        ));
    }
    if !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!(
            "{field} must be lowercase hex (a-f / 0-9); got {s:?}"
        ));
    }
    Ok(())
}

/// Phase 7dh.4: compute the SHA-256 of `bytes` and compare to
/// `expected` (which must already be format-validated). Returns
/// the actual hex hash on mismatch so the operator can update
/// their config if the expected change is legitimate.
pub(crate) fn verify_sha256(
    bytes: &[u8],
    expected: &str,
    label: &str,
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let actual = hex::encode(Sha256::digest(bytes));
    if actual != expected {
        return Err(format!(
            "{label} hash mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_accepts_canonical_hex() {
        let h = "0".repeat(64);
        assert!(validate_sha256_hex(&h, "test").is_ok());
        let h = "abcdef0123456789".repeat(4);
        assert!(validate_sha256_hex(&h, "test").is_ok());
    }

    #[test]
    fn validate_rejects_short() {
        assert!(validate_sha256_hex("abc", "test").is_err());
    }

    #[test]
    fn validate_rejects_uppercase() {
        let h = "A".repeat(64);
        assert!(validate_sha256_hex(&h, "test").is_err());
    }

    #[test]
    fn validate_rejects_non_hex() {
        let mut h: String = "0".repeat(63);
        h.push('z');
        assert!(validate_sha256_hex(&h, "test").is_err());
    }

    #[test]
    fn verify_round_trip() {
        let bytes = b"hello, world";
        // Compute expected
        use sha2::{Digest, Sha256};
        let expected = hex::encode(Sha256::digest(bytes));
        assert!(verify_sha256(bytes, &expected, "test").is_ok());
    }

    #[test]
    fn verify_rejects_mismatch() {
        let bytes = b"hello, world";
        let bogus = "0".repeat(64);
        let err = verify_sha256(bytes, &bogus, "test").unwrap_err();
        assert!(err.contains("expected"), "err: {err}");
    }
}
