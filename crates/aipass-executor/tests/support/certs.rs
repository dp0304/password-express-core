// SPDX-License-Identifier: Apache-2.0
//! Test CA + leaf certificates (rcgen, aws-lc-rs).

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A CA with one leaf certificate.
pub struct TestPki {
    /// CA certificate PEM (what clients trust).
    pub ca_pem: String,
    /// Leaf certificate DER.
    pub leaf_der: CertificateDer<'static>,
    /// Leaf certificate PEM.
    pub leaf_pem: String,
    /// Leaf key PEM (PKCS#8).
    pub key_pem: String,
    key_der: Vec<u8>,
}

impl TestPki {
    /// CA + leaf for `names` (DNS names and/or IP strings).
    pub fn new(names: &[&str]) -> Self {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "aipass executor test CA");
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let issuer = Issuer::new(ca_params, ca_key);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
                .expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, names.first().copied().unwrap_or("test"));
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");
        Self {
            ca_pem: ca_cert.pem(),
            leaf_der: leaf.der().clone(),
            leaf_pem: leaf.pem(),
            key_pem: leaf_key.serialize_pem(),
            key_der: leaf_key.serialize_der(),
        }
    }

    /// Leaf private key DER.
    pub fn key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()))
    }
}
