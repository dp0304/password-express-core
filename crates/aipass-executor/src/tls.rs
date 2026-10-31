// SPDX-License-Identifier: Apache-2.0
//! rustls client configurations (single crypto provider: aws-lc-rs, see the workspace
//! TLS rule).
//!
//! * [`webpki_config`] — certificate chain **and** host name verification against the
//!   Mozilla roots (`webpki-roots`) plus optional extra roots (enterprise CA for GHES or a
//!   private API). Used by the egress guard and postgres `sslmode=verify-full`.
//! * [`verify_ca_config`] — chain verification without host-name check (postgres
//!   `sslmode=require` when a root certificate is configured, like libpq's `verify-ca`).
//! * [`encrypt_only_config`] — encryption without certificate verification (postgres
//!   `sslmode=prefer|require` without a root certificate, matching libpq). This protects
//!   against passive eavesdropping only; handshake signatures are still checked. The
//!   README states the limitation and recommends `verify-full`.

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Errors building a TLS configuration (never contain key material).
#[derive(Debug, thiserror::Error)]
pub enum TlsSetupError {
    /// PEM did not contain a usable certificate.
    #[error("invalid PEM certificate")]
    InvalidPem,
    /// rustls rejected the configuration.
    #[error("TLS configuration rejected: {0}")]
    Rustls(String),
}

/// The process-wide crypto provider (aws-lc-rs).
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Parse every certificate in a PEM bundle.
pub fn parse_pem_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, TlsSetupError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|_| TlsSetupError::InvalidPem)?;
    if certs.is_empty() {
        return Err(TlsSetupError::InvalidPem);
    }
    Ok(certs)
}

/// Root store: Mozilla roots plus `extra`.
pub fn root_store(
    include_webpki: bool,
    extra: &[CertificateDer<'static>],
) -> Result<RootCertStore, TlsSetupError> {
    let mut roots = RootCertStore::empty();
    if include_webpki {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    for c in extra {
        roots
            .add(c.clone())
            .map_err(|e| TlsSetupError::Rustls(e.to_string()))?;
    }
    Ok(roots)
}

fn base_builder()
-> Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>, TlsSetupError> {
    ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsSetupError::Rustls(e.to_string()))
}

/// Full verification (chain + host name).
pub fn webpki_config(
    include_webpki: bool,
    extra: &[CertificateDer<'static>],
    alpn_http: bool,
) -> Result<ClientConfig, TlsSetupError> {
    let roots = root_store(include_webpki, extra)?;
    let mut cfg = base_builder()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    if alpn_http {
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    Ok(cfg)
}

/// Chain verification only (no host-name check) against `roots`.
pub fn verify_ca_config(roots: &[CertificateDer<'static>]) -> Result<ClientConfig, TlsSetupError> {
    let store = Arc::new(root_store(false, roots)?);
    let inner = WebPkiServerVerifier::builder_with_provider(store, provider())
        .build()
        .map_err(|e| TlsSetupError::Rustls(e.to_string()))?;
    let verifier = Arc::new(CaOnlyVerifier { inner });
    Ok(base_builder()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// Encryption without certificate verification (libpq `prefer` / `require` semantics).
pub fn encrypt_only_config() -> Result<ClientConfig, TlsSetupError> {
    let algs = provider().signature_verification_algorithms;
    Ok(base_builder()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(EncryptOnlyVerifier { algs }))
        .with_no_client_auth())
}

#[derive(Debug)]
struct CaOnlyVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for CaOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(v) => Ok(v),
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(e),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct EncryptOnlyVerifier {
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for EncryptOnlyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configs_build_with_single_provider() {
        webpki_config(true, &[], true).unwrap();
        encrypt_only_config().unwrap();
        assert!(parse_pem_certs("not pem").is_err());
    }
}
