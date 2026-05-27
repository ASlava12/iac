//! Phase 7ak: TLS + mTLS termination for the control-plane.
//!
//! Three operating modes:
//!
//! * `none` — plain HTTP. Default for tests + dev-loop deployments
//!   that already trust the network. Existing Phase 2-7 behavior.
//! * `server` — server presents a cert, agents/CLI verify it.
//!   Closes the "anyone on-path can read the bearer token" gap.
//! * `mutual` — server presents a cert AND requires the client to
//!   present its own cert signed by a configured CA. Agents are
//!   provisioned with per-agent client certs; revoking an agent
//!   becomes "invalidate the client cert" instead of "delete the
//!   server-side bearer token row".
//!
//! Cert / key files are PEM-encoded on disk; operators bring their
//! own (or use [`generate_self_signed_pki`] to bootstrap a test stand
//! — same shape as production, but signed by a CA we just made up).
//!
//! Loading is fail-closed: if any of the configured paths can't be
//! parsed the server refuses to start instead of silently falling
//! back to HTTP.

use crate::error::{ApiError, ApiResult};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig as RustlsServerConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// `"none" | "server" | "mutual"`. Default `"none"` (existing
    /// plain-HTTP behavior).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// PEM file with the server's leaf cert (or the full chain
    /// cert+intermediates concatenated). Required for `server` and
    /// `mutual` modes.
    #[serde(default)]
    pub cert_file: Option<std::path::PathBuf>,
    /// PEM file with the server's private key. Required for `server`
    /// and `mutual` modes.
    #[serde(default)]
    pub key_file: Option<std::path::PathBuf>,
    /// PEM file with the trusted client-CA bundle. Required for
    /// `mutual` mode; ignored otherwise.
    #[serde(default)]
    pub client_ca_file: Option<std::path::PathBuf>,
}

fn default_mode() -> String {
    "none".into()
}

impl TlsConfig {
    pub fn is_enabled(&self) -> bool {
        matches!(self.mode.as_str(), "server" | "mutual")
    }
    pub fn requires_client_cert(&self) -> bool {
        self.mode == "mutual"
    }
}

/// Load the rustls `ServerConfig` for `mode = server | mutual`.
/// Fails closed: any IO/parse error becomes `ApiError::Internal`,
/// which `main.rs` propagates and the process exits without binding.
pub fn build_rustls_config(cfg: &TlsConfig) -> ApiResult<Arc<RustlsServerConfig>> {
    let cert_path = cfg
        .cert_file
        .as_deref()
        .ok_or_else(|| ApiError::Internal("tls.cert_file required when mode != none".into()))?;
    let key_path = cfg
        .key_file
        .as_deref()
        .ok_or_else(|| ApiError::Internal("tls.key_file required when mode != none".into()))?;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    // rustls' default builder uses ring as the cryptographic
    // provider. We installed it via the workspace `rustls` feature.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let builder = if cfg.requires_client_cert() {
        let ca_path = cfg.client_ca_file.as_deref().ok_or_else(|| {
            ApiError::Internal("tls.client_ca_file required when mode = mutual".into())
        })?;
        let ca_certs = load_certs(ca_path)?;
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .map_err(|e| ApiError::Internal(format!("client CA add: {e}")))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| ApiError::Internal(format!("client verifier: {e}")))?;
        RustlsServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        RustlsServerConfig::builder().with_no_client_auth()
    };

    let server_config = builder
        .with_single_cert(certs, key)
        .map_err(|e| ApiError::Internal(format!("rustls with_single_cert: {e}")))?;

    Ok(Arc::new(server_config))
}

fn load_certs(path: &Path) -> ApiResult<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path)
        .map_err(|e| ApiError::Internal(format!("read cert {}: {e}", path.display())))?;
    let mut reader = std::io::BufReader::new(&bytes[..]);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ApiError::Internal(format!("parse cert {}: {e}", path.display())))
}

fn load_private_key(path: &Path) -> ApiResult<PrivateKeyDer<'static>> {
    let bytes = std::fs::read(path)
        .map_err(|e| ApiError::Internal(format!("read key {}: {e}", path.display())))?;
    let mut reader = std::io::BufReader::new(&bytes[..]);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| ApiError::Internal(format!("parse key {}: {e}", path.display())))?
        .ok_or_else(|| ApiError::Internal(format!("no key in {}", path.display())))
}

/// Phase 7ak: bootstrap a self-signed PKI for tests + first-run dev.
///
/// Generates one CA, one server cert (with the supplied DNS names
/// and IP SANs), and N client certs. Returns the PEM-encoded bundle.
///
/// In production, operators bring their own CA / certs (typically
/// from cert-manager / Vault PKI / AWS PCA). This helper exists so
/// integration tests don't need an external CA infrastructure and so
/// `iac-controlplane bootstrap-tls` can hand out a working set on a
/// fresh stand.
pub struct GeneratedPki {
    pub ca_cert_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    /// One per `client_names` entry, in order.
    pub client_certs: Vec<GeneratedClientCert>,
}

pub struct GeneratedClientCert {
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn generate_self_signed_pki(
    server_dns_names: &[&str],
    server_ips: &[std::net::IpAddr],
    client_names: &[&str],
) -> Result<GeneratedPki, String> {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        SanType,
    };

    // 1. CA. Self-signed; signs the leaf certs below.
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "iac-test-ca");
        dn
    };
    let ca_key = KeyPair::generate().map_err(|e| format!("ca keypair: {e}"))?;
    let ca = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("ca self-sign: {e}"))?;
    let ca_pem = ca.pem();
    // The Issuer holds the CA's DN/key for signing the leaves below.
    // `from_params` borrows ca_params; we constructed it locally so
    // it lives long enough.
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    // 2. Server cert.
    let mut srv_params = CertificateParams::default();
    // Phase 7cz.16: rcgen's Ia5String::try_into errors only for non-
    // ASCII; callers only pass DNS-spec compliant ASCII names. Tag.
    #[allow(clippy::unwrap_used)]
    {
        srv_params.subject_alt_names = server_dns_names
            .iter()
            .map(|n| SanType::DnsName((*n).to_string().try_into().unwrap()))
            .chain(server_ips.iter().map(|ip| SanType::IpAddress(*ip)))
            .collect();
    }
    srv_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "iac-test-server");
        dn
    };
    let srv_key = KeyPair::generate().map_err(|e| format!("server keypair: {e}"))?;
    let srv = srv_params
        .signed_by(&srv_key, &issuer)
        .map_err(|e| format!("server sign: {e}"))?;

    // 3. Per-client certs.
    let mut client_certs = Vec::with_capacity(client_names.len());
    for name in client_names {
        let mut cl_params = CertificateParams::default();
        cl_params.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, *name);
            dn
        };
        let cl_key = KeyPair::generate().map_err(|e| format!("client {name} keypair: {e}"))?;
        let cl = cl_params
            .signed_by(&cl_key, &issuer)
            .map_err(|e| format!("client {name} sign: {e}"))?;
        client_certs.push(GeneratedClientCert {
            name: (*name).into(),
            cert_pem: cl.pem(),
            key_pem: cl_key.serialize_pem(),
        });
    }

    Ok(GeneratedPki {
        ca_cert_pem: ca_pem,
        server_cert_pem: srv.pem(),
        server_key_pem: srv_key.serialize_pem(),
        client_certs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pki_round_trips_through_rustls() {
        let pki = generate_self_signed_pki(
            &["localhost", "iac-test"],
            &["127.0.0.1".parse().unwrap()],
            &["agent-a", "agent-b"],
        )
        .expect("pki gen");

        // Two clients requested → two client cert bundles produced,
        // each named after the input.
        assert_eq!(pki.client_certs.len(), 2);
        assert_eq!(pki.client_certs[0].name, "agent-a");
        assert_eq!(pki.client_certs[1].name, "agent-b");

        // Round-trip: write to a tempdir, point TlsConfig at the
        // files, build a RustlsServerConfig in mutual mode. Failure
        // here would catch a mismatch between rcgen's PEM output and
        // rustls-pemfile's parser.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("ca.pem"), &pki.ca_cert_pem).unwrap();
        std::fs::write(dir.path().join("srv.pem"), &pki.server_cert_pem).unwrap();
        std::fs::write(dir.path().join("srv.key"), &pki.server_key_pem).unwrap();

        let cfg = TlsConfig {
            mode: "mutual".into(),
            cert_file: Some(dir.path().join("srv.pem")),
            key_file: Some(dir.path().join("srv.key")),
            client_ca_file: Some(dir.path().join("ca.pem")),
        };
        build_rustls_config(&cfg).expect("rustls config");
    }

    #[test]
    fn missing_cert_file_fails_closed() {
        let cfg = TlsConfig {
            mode: "server".into(),
            cert_file: Some("/nonexistent/cert.pem".into()),
            key_file: Some("/nonexistent/key.pem".into()),
            client_ca_file: None,
        };
        let err = build_rustls_config(&cfg).unwrap_err();
        match err {
            ApiError::Internal(msg) => assert!(msg.contains("read cert"), "msg: {msg}"),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn mutual_mode_requires_client_ca() {
        // Generate just the server bits; deliberately omit the
        // client CA file path. Build should fail with a clear
        // message.
        let pki = generate_self_signed_pki(&["localhost"], &[], &[]).expect("pki gen");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("srv.pem"), &pki.server_cert_pem).unwrap();
        std::fs::write(dir.path().join("srv.key"), &pki.server_key_pem).unwrap();

        let cfg = TlsConfig {
            mode: "mutual".into(),
            cert_file: Some(dir.path().join("srv.pem")),
            key_file: Some(dir.path().join("srv.key")),
            client_ca_file: None,
        };
        let err = build_rustls_config(&cfg).unwrap_err();
        match err {
            ApiError::Internal(msg) => {
                assert!(msg.contains("client_ca_file"), "msg: {msg}")
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn enabled_and_requires_client_cert_flags() {
        let none = TlsConfig::default();
        assert!(!none.is_enabled());
        assert!(!none.requires_client_cert());

        let server = TlsConfig {
            mode: "server".into(),
            ..Default::default()
        };
        assert!(server.is_enabled());
        assert!(!server.requires_client_cert());

        let mutual = TlsConfig {
            mode: "mutual".into(),
            ..Default::default()
        };
        assert!(mutual.is_enabled());
        assert!(mutual.requires_client_cert());
    }
}
