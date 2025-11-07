//! Certificate builder utilities.
//!
//! This module provides functional utilities for building X.509 certificates.

use crate::error::{DeTlsError, Result};
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair};
use std::time::Duration;

/// Parse a subject string (e.g., "CN=example.com,O=Example Org") into a DistinguishedName.
///
/// # Example
///
/// ```
/// use detls::cert::builder::parse_subject;
///
/// let dn = parse_subject("CN=example.com,O=Example Org").unwrap();
/// ```
pub fn parse_subject(subject: &str) -> Result<DistinguishedName> {
    let mut dn = DistinguishedName::new();

    for part in subject.split(',') {
        let part = part.trim();
        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim();

            let dn_type = match key.to_uppercase().as_str() {
                "CN" => DnType::CommonName,
                "C" => DnType::CountryName,
                "O" => DnType::OrganizationName,
                "OU" => DnType::OrganizationalUnitName,
                "ST" => DnType::StateOrProvinceName,
                "L" => DnType::LocalityName,
                _ => return Err(DeTlsError::ParseError(format!("Unknown DN type: {}", key))),
            };

            dn.push(dn_type, value);
        } else {
            return Err(DeTlsError::ParseError(format!(
                "Invalid subject format: {}",
                part
            )));
        }
    }

    if dn.iter().next().is_none() {
        return Err(DeTlsError::ParseError(
            "Subject cannot be empty".to_string(),
        ));
    }

    Ok(dn)
}

/// Convert an Ed25519 keypair to an rcgen KeyPair.
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::builder::keypair_to_rcgen;
///
/// let keypair = generate_ed25519_keypair().unwrap();
/// let rcgen_keypair = keypair_to_rcgen(&keypair).unwrap();
/// ```
pub fn keypair_to_rcgen(keypair: &crate::crypto::ed25519::Keypair) -> Result<KeyPair> {
    let secret_bytes = keypair.secret_bytes();
    let keypair_pem = ed25519_to_pkcs8_pem(&secret_bytes)?;

    KeyPair::from_pem(&keypair_pem)
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to convert keypair: {}", e)))
}

/// Convert Ed25519 secret key bytes to PKCS#8 PEM format.
fn ed25519_to_pkcs8_pem(secret_bytes: &[u8; 32]) -> Result<String> {
    // PKCS#8 header for Ed25519 private key
    // This is a fixed sequence defined in RFC 8410
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE (46 bytes)
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING (34 bytes)
        0x04, 0x20, // OCTET STRING (32 bytes) - the actual key
    ];
    pkcs8_der.extend_from_slice(secret_bytes);

    // Convert to PEM
    let pem_obj = pem::Pem::new("PRIVATE KEY", pkcs8_der);
    let pem = pem::encode(&pem_obj);

    Ok(pem)
}

/// Set validity period for a certificate.
pub fn set_validity(params: &mut CertificateParams, days: u32) {
    let duration = Duration::from_secs((days as u64) * 24 * 60 * 60);
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = params.not_before + duration;
}

/// Convert an rcgen Certificate to PEM format.
pub fn cert_to_pem(cert: &Certificate) -> Result<String> {
    cert.serialize_pem()
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to convert to PEM: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519_keypair;

    #[test]
    fn test_parse_subject_single_field() {
        let dn = parse_subject("CN=example.com").unwrap();
        assert_eq!(dn.iter().count(), 1);
    }

    #[test]
    fn test_parse_subject_multiple_fields() {
        let dn = parse_subject("CN=example.com,O=Example Org,C=US").unwrap();
        assert_eq!(dn.iter().count(), 3);
    }

    #[test]
    fn test_parse_subject_with_spaces() {
        let dn = parse_subject("CN = example.com , O = Example Org").unwrap();
        assert_eq!(dn.iter().count(), 2);
    }

    #[test]
    fn test_parse_subject_empty() {
        let result = parse_subject("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subject_invalid_format() {
        let result = parse_subject("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_subject_unknown_type() {
        let result = parse_subject("XX=value");
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_to_rcgen() {
        let keypair = generate_ed25519_keypair().unwrap();
        let result = keypair_to_rcgen(&keypair);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_to_pkcs8_pem() {
        let keypair = generate_ed25519_keypair().unwrap();
        let pem = ed25519_to_pkcs8_pem(&keypair.secret_bytes()).unwrap();

        assert!(pem.contains("BEGIN PRIVATE KEY"));
        assert!(pem.contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_set_validity() {
        let mut params = CertificateParams::default();
        set_validity(&mut params, 365);

        let duration = params.not_after - params.not_before;
        assert_eq!(duration.whole_seconds(), 365 * 24 * 60 * 60);
    }
}
