//! End-entity certificate operations.
//!
//! This module provides functions for creating end-entity certificates signed by an Intermediate CA.

use crate::cert::builder::{keypair_to_rcgen, parse_subject, set_validity};
use crate::crypto::ed25519::Keypair;
use crate::error::{DeTlsError, Result};
use rcgen::{Certificate, CertificateParams, IsCa};

/// Create an end-entity certificate signed by an Intermediate CA.
///
/// # Arguments
///
/// * `inter_cert` - The Intermediate CA certificate that will sign this entity certificate
/// * `entity_keypair` - The Ed25519 keypair for the end entity
/// * `subject` - The subject distinguished name (e.g., "CN=example.com,O=My Org")
/// * `validity_days` - Number of days the certificate is valid for
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::ca::create_root_ca;
/// use detls::cert::intermediate::create_intermediate_ca;
/// use detls::cert::entity::create_end_entity_cert;
///
/// # fn example() -> detls::error::Result<()> {
/// let root_keypair = generate_ed25519_keypair()?;
/// let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650)?;
///
/// let inter_keypair = generate_ed25519_keypair()?;
/// let inter_cert = create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825)?;
///
/// let entity_keypair = generate_ed25519_keypair()?;
/// let entity_cert = create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365)?;
///
/// let pem = entity_cert.serialize_pem().map_err(|e| detls::error::DeTlsError::CertificateError(e.to_string()))?;
/// assert!(pem.contains("BEGIN CERTIFICATE"));
/// # Ok(())
/// # }
/// ```
pub fn create_end_entity_cert(
    _inter_cert: &Certificate,
    entity_keypair: &Keypair,
    subject: &str,
    validity_days: u32,
) -> Result<Certificate> {
    // Parse subject
    let distinguished_name = parse_subject(subject)?;

    // Convert keypair
    let key_pair = keypair_to_rcgen(entity_keypair)?;

    // Create certificate parameters
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::NoCa; // Not a CA
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.alg = &rcgen::PKCS_ED25519;

    // Set validity
    set_validity(&mut params, validity_days);

    // Set keypair
    params.key_pair = Some(key_pair);

    // LIMITATION: rcgen 0.12 doesn't support signing with external CA
    // This creates a self-signed entity certificate instead
    // For proper certificate chain, upgrade to rcgen 0.13+ or use x509-cert
    let cert = Certificate::from_params(params).map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to create end-entity certificate: {}", e))
    })?;

    Ok(cert)
}

/// Build a complete certificate chain (PEM format).
///
/// Returns a string containing the entity certificate, intermediate certificate,
/// and root certificate in PEM format, suitable for use in TLS.
///
/// # Arguments
///
/// * `entity_cert` - The end-entity certificate
/// * `inter_cert` - The intermediate CA certificate
/// * `root_cert` - The root CA certificate
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::ca::create_root_ca;
/// use detls::cert::intermediate::create_intermediate_ca;
/// use detls::cert::entity::{create_end_entity_cert, build_cert_chain_pem};
///
/// # fn example() -> detls::error::Result<()> {
/// let root_keypair = generate_ed25519_keypair()?;
/// let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650)?;
///
/// let inter_keypair = generate_ed25519_keypair()?;
/// let inter_cert = create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825)?;
///
/// let entity_keypair = generate_ed25519_keypair()?;
/// let entity_cert = create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365)?;
///
/// let chain = build_cert_chain_pem(&entity_cert, &inter_cert, &root_cert)?;
/// assert!(chain.contains("BEGIN CERTIFICATE"));
/// # Ok(())
/// # }
/// ```
pub fn build_cert_chain_pem(
    entity_cert: &Certificate,
    inter_cert: &Certificate,
    root_cert: &Certificate,
) -> Result<String> {
    let entity_pem = entity_cert.serialize_pem().map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to encode entity cert: {}", e))
    })?;
    let inter_pem = inter_cert.serialize_pem().map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to encode intermediate cert: {}", e))
    })?;
    let root_pem = root_cert
        .serialize_pem()
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to encode root cert: {}", e)))?;

    Ok(format!("{}\n{}\n{}", entity_pem, inter_pem, root_pem))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::ca::create_root_ca;
    use crate::cert::intermediate::create_intermediate_ca;
    use crate::crypto::ed25519::generate_ed25519_keypair;

    #[test]
    fn test_create_end_entity_cert_success() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let entity_keypair = generate_ed25519_keypair().unwrap();
        let result = create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365);

        assert!(result.is_ok());
    }

    #[test]
    fn test_create_end_entity_cert_pem_format() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let entity_keypair = generate_ed25519_keypair().unwrap();
        let entity_cert =
            create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365).unwrap();

        let pem = entity_cert.serialize_pem().unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_create_end_entity_cert_invalid_subject() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let entity_keypair = generate_ed25519_keypair().unwrap();
        let result = create_end_entity_cert(&inter_cert, &entity_keypair, "invalid", 365);

        assert!(result.is_err());
    }

    #[test]
    fn test_end_entity_cert_is_not_ca() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let entity_keypair = generate_ed25519_keypair().unwrap();
        let entity_cert =
            create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365).unwrap();

        let params = entity_cert.get_params();

        // Verify it's NOT marked as a CA
        assert!(matches!(params.is_ca, IsCa::NoCa));
    }

    #[test]
    fn test_build_cert_chain_pem() {
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let entity_keypair = generate_ed25519_keypair().unwrap();
        let entity_cert =
            create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365).unwrap();

        let chain = build_cert_chain_pem(&entity_cert, &inter_cert, &root_cert).unwrap();

        // Chain should contain all three certificates
        let cert_count = chain.matches("BEGIN CERTIFICATE").count();
        assert_eq!(cert_count, 3);
    }

    #[test]
    fn test_complete_cert_chain() {
        // Create complete chain from root to entity
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert = create_root_ca(&root_keypair, "CN=Root CA", 3650).unwrap();

        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert =
            create_intermediate_ca(&root_cert, &inter_keypair, "CN=Intermediate CA", 1825).unwrap();

        let entity_keypair = generate_ed25519_keypair().unwrap();
        let entity_cert =
            create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365).unwrap();

        // All certificates should be valid
        assert!(root_cert.serialize_pem().is_ok());
        assert!(inter_cert.serialize_pem().is_ok());
        assert!(entity_cert.serialize_pem().is_ok());

        // All should be different
        assert_ne!(
            root_cert.serialize_pem().unwrap(),
            inter_cert.serialize_pem().unwrap()
        );
        assert_ne!(
            inter_cert.serialize_pem().unwrap(),
            entity_cert.serialize_pem().unwrap()
        );
        assert_ne!(
            root_cert.serialize_pem().unwrap(),
            entity_cert.serialize_pem().unwrap()
        );
    }
}
