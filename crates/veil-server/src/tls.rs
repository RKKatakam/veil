//! TLS for every connection (`docs/HUB.md` §4.1): a certificate and key in
//! PEM files, or a self-signed certificate for local development.

use std::{path::Path, sync::Arc};

use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

/// Where the certificate comes from.
#[derive(Clone, Debug)]
pub enum TlsSource {
    /// PEM files: the certificate chain and its private key.
    Files { cert: std::path::PathBuf, key: std::path::PathBuf },
    /// A self-signed certificate for `localhost` and `127.0.0.1`, created
    /// in the data directory on first start (`self-signed-cert.pem`, which
    /// `vl login --ca` is given) and reused after.
    SelfSigned,
}

/// The server's TLS configuration, the certificate's PEM and its leaf
/// certificate (DER).
pub fn server_config(source: &TlsSource, data_dir: &Path) -> Result<(Arc<rustls::ServerConfig>, String, CertificateDer<'static>)> {
    let (cert_pem, key_pem) = match source {
        TlsSource::Files { cert, key } => (
            std::fs::read_to_string(cert).with_context(|| format!("reading {}", cert.display()))?,
            std::fs::read_to_string(key).with_context(|| format!("reading {}", key.display()))?,
        ),
        TlsSource::SelfSigned => {
            let cert_path = data_dir.join("self-signed-cert.pem");
            let key_path = data_dir.join("self-signed-key.pem");
            if !cert_path.exists() || !key_path.exists() {
                let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                    .map_err(|e| anyhow!("creating a self-signed certificate: {e}"))?;
                write_private(&key_path, ck.signing_key.serialize_pem().as_bytes())?;
                std::fs::write(&cert_path, ck.cert.pem())?;
            }
            (std::fs::read_to_string(&cert_path)?, std::fs::read_to_string(&key_path)?)
        }
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("certificate PEM: {e}"))?;
    let leaf = certs.first().cloned().ok_or_else(|| anyhow!("no certificate in the certificate PEM"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| anyhow!("private key PEM: {e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok((Arc::new(config), cert_pem, leaf))
}

/// Is the certificate `leaf` valid for the host of `authority`
/// (`host[:port]`, `[v6]:port`)? This is the check a client made before it
/// signed in: a name the certificate does not cover is another server's.
pub fn names(leaf: &CertificateDer<'_>, authority: &str) -> bool {
    let a = authority.trim();
    let host = match a.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => a.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(a, |(h, _)| h),
    };
    let Ok(name) = rustls::pki_types::ServerName::try_from(host) else {
        return false;
    };
    webpki::EndEntityCert::try_from(leaf).is_ok_and(|c| c.verify_is_valid_for_subject_name(&name).is_ok())
}

/// Write a file only its owner can read.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_the_certificates_own() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _, leaf) = server_config(&TlsSource::SelfSigned, dir.path()).unwrap();
        for ok in ["127.0.0.1:8443", "localhost:1", "LOCALHOST", "127.0.0.1"] {
            assert!(names(&leaf, ok), "{ok}");
        }
        for bad in ["evil.example:443", "evil.example", "127.0.0.2:8443", "[::1]:8443", "", "localhost.evil.example", "local host"] {
            assert!(!names(&leaf, bad), "{bad}");
        }
    }
}
