use sha2::{Digest, Sha256};
use std::io::{self, Read};

/// Returns a lowercase hex sha256 digest of the input bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// Streaming sha256-hex digest for large inputs (e.g. binaries, log
/// files) where holding the whole input in memory would be wasteful.
/// Phase 7cz.10 — replaces inline duplicates in `ssh_dispatch.rs` and
/// `gitops.rs`.
pub fn sha256_hex_reader<R: Read>(mut reader: R) -> io::Result<String> {
    let mut hasher = Sha256::new();
    io::copy(&mut reader, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streaming_matches_buffered() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let buffered = sha256_hex(data);
        let streamed = sha256_hex_reader(&data[..]).unwrap();
        assert_eq!(buffered, streamed);
    }
}
