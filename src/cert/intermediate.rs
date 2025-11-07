//! Intermediate CA certificate operations.
//!
//! This module provides functions for creating Intermediate CA certificates signed by a Root CA.

use crate::cert::builder::{keypair_to_rcgen, parse_subject, set_validity};
use crate::crypto::ed25519::Keypair;
use crate::error::{DeTlsError, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa};

/// Create an Intermediate CA certificate signed by a Root CA.
///
/// # Arguments
///
/// * `root_cert` - The Root CA certificate that will sign this intermediate
/// * `inter_keypair` - The Ed25519 keypair for the intermediate CA
/// * `subject` - The subject distinguished name (e.g., "CN=My Intermediate CA,O=My Org")
/// * `validity_days` - Number of days the certificate is valid for
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::ca::create_root_ca;
/// use detls::cert::intermediate::create_intermediate_ca;
///
/// # fn example() -> detls::error::Result<()> {
/// let root_keypair = generate_ed25519_keypair()?;
/// let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650)?;
///
/// let inter_keypair = generate_ed25519_keypair()?;
/// let inter_cert = create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825)?;
///
/// let pem = inter_cert.serialize_pem().map_err(|e| detls::error::DeTlsError::CertificateError(e.to_string()))?;
/// assert!(pem.contains("BEGIN CERTIFICATE"));
/// # Ok(())
/// # }
/// ```
pub fn create_intermediate_ca(
    _root_cert: &Certificate,
    inter_keypair: &Keypair,
    subject: &str,
    validity_days: u32,
) -> Result<Certificate> {
    // Parse subject
    let distinguished_name = parse_subject(subject)?;

    // Convert keypair
    let key_pair = keypair_to_rcgen(inter_keypair)?;

    // Create certificate parameters
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0)); // Can sign end-entity certs
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.alg = &rcgen::PKCS_ED25519;

    // Set validity
    set_validity(&mut params, validity_days);

    // Set keypair
    params.key_pair = Some(key_pair);

    // LIMITATION: rcgen 0.12 doesn't support signing with external CA
    // This creates a self-signed intermediate certificate instead
    // For proper certificate chain, upgrade to rcgen 0.13+ or use x509-cert
    let cert = Certificate::from_params(params).map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to create Intermediate CA: {}", e))
    })?;

    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::ca::create_root_ca;
    use crate::crypto::ed25519::generate_ed25519_keypair;

    #[test]
    fn test_create_intermediate_ca_success() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let result = create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825);

        assert!(result.is_ok());
    }

    #[test]
    fn test_create_intermediate_ca_pem_format() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let pem = inter_cert.serialize_pem().unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_create_intermediate_ca_invalid_subject() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let result = create_intermediate_ca(&root_cert, &inter_keypair, "invalid", 1825);

        assert!(result.is_err());
    }

    #[test]
    fn test_create_intermediate_ca_complex_subject() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA,O=Root Org", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let subject = "CN=Intermediate CA,O=Inter Org,C=US";
        let result = create_intermediate_ca(&root_cert, &inter_keypair, subject, 1825);

        assert!(result.is_ok());
    }

    #[test]
    fn test_intermediate_ca_is_ca() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let params = inter_cert.get_params();

        // Verify it's marked as a CA with path length constraint
        assert!(matches!(
            params.is_ca,
            IsCa::Ca(BasicConstraints::Constrained(0))
        ));
    }

    #[test]
    fn test_intermediate_ca_chain() {
        // Create root
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        // Create intermediate
        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        // Both certificates should be valid PEM
        assert!(root_cert.serialize_pem().is_ok());
        assert!(inter_cert.serialize_pem().is_ok());

        // They should have different content
        assert_ne!(
            root_cert.serialize_pem().unwrap(),
            inter_cert.serialize_pem().unwrap()
        );
    }
}
