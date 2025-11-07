//! TLS configuration for mTLS connections.
//!
//! This module provides configuration builders for Rustls-based mTLS connections.

use crate::crypto::ed25519::Keypair;
use crate::error::{DeTlsError, Result};
use rcgen::Certificate;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ClientConfig;
use std::sync::Arc;

/// Build a TLS configuration from raw DER-encoded certificates.
///
/// This is useful when loading certificates from PEM files.
///
/// # Arguments
///
/// * `client_cert_der` - Client certificate in DER format
/// * `client_key` - Client's private keypair  
/// * `ca_certs_der` - Trusted CA certificates in DER format
pub fn build_mtls_config_from_der(
    client_cert_der: Vec<u8>,
    client_key: &Keypair,
    ca_certs_der: Vec<Vec<u8>>,
) -> Result<TlsConfig> {
    // Convert private key to PKCS#8 DER format
    let key_bytes = client_key.secret_bytes();
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING (34 bytes)
        0x04, 0x20, // OCTET STRING (32 bytes) - the actual key
    ];
    pkcs8_der.extend_from_slice(&key_bytes);

    let private_key = PrivateKeyDer::try_from(pkcs8_der).map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to parse private key: {:?}", e))
    })?;

    // Build root certificate store
    let mut root_store = rustls::RootCertStore::empty();
    for ca_der in ca_certs_der {
        root_store
            .add(CertificateDer::from(ca_der))
            .map_err(|e| DeTlsError::CertificateError(format!("Failed to add CA cert: {:?}", e)))?;
    }

    // Install default crypto provider if not already set
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build client config with mTLS
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(vec![CertificateDer::from(client_cert_der)], private_key)
        .map_err(|e| DeTlsError::NetworkError(format!("Failed to build client config: {}", e)))?;

    Ok(TlsConfig {
        client_config: Arc::new(config),
    })
}

/// TLS configuration for mTLS.
pub struct TlsConfig {
    /// Rustls client configuration
    pub client_config: Arc<ClientConfig>,
}

/// Build a TLS configuration for mTLS.
///
/// # Arguments
///
/// * `client_cert` - The client's certificate
/// * `client_key` - The client's private keypair
/// * `ca_certs` - Trusted CA certificates for server verification
///
/// # Example
///
/// ```rust,no_run
/// use detls::net::config::build_mtls_config;
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::ca::create_root_ca;
///
/// # fn example() -> detls::error::Result<()> {
/// let keypair = generate_ed25519_keypair()?;
/// let cert = create_root_ca(&keypair, "CN=Client", 365)?;
/// let ca_cert = create_root_ca(&keypair, "CN=CA", 365)?;
/// let config = build_mtls_config(&cert, &keypair, &[ca_cert])?;
/// # Ok(())
/// # }
/// ```
pub fn build_mtls_config(
    client_cert: &Certificate,
    client_key: &Keypair,
    ca_certs: &[Certificate],
) -> Result<TlsConfig> {
    // Convert client certificate to DER
    let cert_der = client_cert.serialize_der().map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to serialize certificate: {}", e))
    })?;

    // Convert private key to PKCS#8 DER format
    let key_bytes = client_key.secret_bytes();
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING (34 bytes)
        0x04, 0x20, // OCTET STRING (32 bytes) - the actual key
    ];
    pkcs8_der.extend_from_slice(&key_bytes);

    let private_key = PrivateKeyDer::try_from(pkcs8_der).map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to parse private key: {:?}", e))
    })?;

    // Build root certificate store
    let mut root_store = rustls::RootCertStore::empty();
    for ca_cert in ca_certs {
        let ca_der = ca_cert.serialize_der().map_err(|e| {
            DeTlsError::CertificateError(format!("Failed to serialize CA cert: {}", e))
        })?;

        root_store
            .add(CertificateDer::from(ca_der))
            .map_err(|e| DeTlsError::CertificateError(format!("Failed to add CA cert: {:?}", e)))?;
    }

    // Install default crypto provider if not already set
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build client config with mTLS
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(vec![CertificateDer::from(cert_der)], private_key)
        .map_err(|e| DeTlsError::NetworkError(format!("Failed to build client config: {}", e)))?;

    Ok(TlsConfig {
        client_config: Arc::new(config),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::ca::create_root_ca;
    use crate::crypto::ed25519::generate_ed25519_keypair;

    #[test]
    fn test_build_mtls_config() {
        let keypair = generate_ed25519_keypair().unwrap();
        let cert = create_root_ca(&keypair, "CN=Test", 365).unwrap();

        let ca_keypair = generate_ed25519_keypair().unwrap();
        let ca_cert = create_root_ca(&ca_keypair, "CN=CA", 365).unwrap();

        let result = build_mtls_config(&cert, &keypair, &[ca_cert]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_mtls_config_with_multiple_cas() {
        let keypair = generate_ed25519_keypair().unwrap();
        let cert = create_root_ca(&keypair, "CN=Client", 365).unwrap();

        let ca_keypair = generate_ed25519_keypair().unwrap();
        let ca_cert = create_root_ca(&ca_keypair, "CN=CA", 365).unwrap();

        let result = build_mtls_config(&cert, &keypair, &[ca_cert]);
        assert!(result.is_ok());
    }
}
