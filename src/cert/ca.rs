//! Root CA certificate operations.
//!
//! This module provides functions for creating self-signed Root CA certificates.

use crate::cert::builder::{keypair_to_rcgen, parse_subject, set_validity};
use crate::crypto::ed25519::Keypair;
use crate::error::{DeTlsError, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};

/// Create a self-signed Root CA certificate.
///
/// # Arguments
///
/// * `keypair` - The Ed25519 keypair for the CA
/// * `subject` - The subject distinguished name (e.g., "CN=My Root CA,O=My Org")
/// * `validity_days` - Number of days the certificate is valid for
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::ca::create_root_ca;
///
/// # fn example() -> detls::error::Result<()> {
/// let keypair = generate_ed25519_keypair()?;
/// let cert = create_root_ca(&keypair, "CN=My Root CA", 3650)?;
/// let pem = cert.serialize_pem().map_err(|e| detls::error::DeTlsError::CertificateError(e.to_string()))?;
/// assert!(pem.contains("BEGIN CERTIFICATE"));
/// # Ok(())
/// # }
/// ```
pub fn create_root_ca(keypair: &Keypair, subject: &str, validity_days: u32) -> Result<Certificate> {
    // Parse subject
    let distinguished_name = parse_subject(subject)?;

    // Convert keypair
    let key_pair = keypair_to_rcgen(keypair)?;

    // Create certificate parameters
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.alg = &rcgen::PKCS_ED25519;

    // Set validity
    set_validity(&mut params, validity_days);

    // Generate self-signed certificate
    params.key_pair = Some(key_pair);

    Certificate::from_params(params)
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to create Root CA: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519_keypair;

    #[test]
    fn test_create_root_ca_success() {
        let keypair = generate_ed25519_keypair().unwrap();
        let result = create_root_ca(&keypair, "CN=Test Root CA", 365);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_root_ca_pem_format() {
        let keypair = generate_ed25519_keypair().unwrap();
        let cert = create_root_ca(&keypair, "CN=Test Root CA", 365).unwrap();
        let pem = cert.serialize_pem().unwrap();

        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_create_root_ca_invalid_subject() {
        let keypair = generate_ed25519_keypair().unwrap();
        let result = create_root_ca(&keypair, "invalid", 365);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_root_ca_complex_subject() {
        let keypair = generate_ed25519_keypair().unwrap();
        let subject = "CN=Test Root CA,O=Test Org,C=US";
        let result = create_root_ca(&keypair, subject, 365);
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_root_ca_different_validity() {
        let keypair = generate_ed25519_keypair().unwrap();

        let cert1 = create_root_ca(&keypair, "CN=Test CA", 365).unwrap();
        let cert2 = create_root_ca(&keypair, "CN=Test CA", 730).unwrap();

        // Both should succeed
        assert!(cert1.serialize_pem().is_ok());
        assert!(cert2.serialize_pem().is_ok());
    }

    #[test]
    fn test_root_ca_is_ca() {
        let keypair = generate_ed25519_keypair().unwrap();
        let cert = create_root_ca(&keypair, "CN=Test Root CA", 365).unwrap();
        let params = cert.get_params();

        // Verify it's marked as a CA
        assert!(matches!(params.is_ca, IsCa::Ca(_)));
    }
}
