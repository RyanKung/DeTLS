//! Certificate loading from PEM files.
//!
//! This module provides utilities to load rcgen certificates from PEM files
//! by converting them through DER format.

use crate::error::{DeTlsError, Result};
use rustls_pemfile::Item;
use std::io::Cursor;

/// Load an rcgen Certificate from a PEM file.
///
/// This works by:
/// 1. Parsing the PEM file to extract the DER-encoded certificate
/// 2. Converting it to rcgen's internal format
///
/// Note: This creates a certificate without the private key.
/// It's suitable for verification but not for signing.
///
/// # Arguments
///
/// * `pem_str` - PEM-encoded certificate string
///
/// # Example
///
/// ```rust,no_run
/// use detls::cert::loader::load_certificate_from_pem;
///
/// # fn example() -> detls::error::Result<()> {
/// let pem = std::fs::read_to_string("cert.pem")?;
/// let cert = load_certificate_from_pem(&pem)?;
/// # Ok(())
/// # }
/// ```
pub fn load_certificate_from_pem(pem_str: &str) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(pem_str.as_bytes());

    match rustls_pemfile::read_one(&mut cursor)
        .map_err(|e| DeTlsError::PemError(format!("Failed to read PEM: {}", e)))?
    {
        Some(Item::X509Certificate(cert_der)) => Ok(cert_der.to_vec()),
        Some(_) => Err(DeTlsError::PemError(
            "PEM file does not contain a certificate".to_string(),
        )),
        None => Err(DeTlsError::PemError("Empty PEM file".to_string())),
    }
}

/// Load multiple certificates from a PEM file.
///
/// # Arguments
///
/// * `pem_str` - PEM-encoded certificates string (can contain multiple certificates)
///
/// # Example
///
/// ```rust,no_run
/// use detls::cert::loader::load_certificates_from_pem;
///
/// # fn example() -> detls::error::Result<()> {
/// let pem = std::fs::read_to_string("chain.pem")?;
/// let certs = load_certificates_from_pem(&pem)?;
/// println!("Loaded {} certificates", certs.len());
/// # Ok(())
/// # }
/// ```
pub fn load_certificates_from_pem(pem_str: &str) -> Result<Vec<Vec<u8>>> {
    let mut cursor = Cursor::new(pem_str.as_bytes());
    let mut certificates = Vec::new();

    loop {
        match rustls_pemfile::read_one(&mut cursor)
            .map_err(|e| DeTlsError::PemError(format!("Failed to read PEM: {}", e)))?
        {
            Some(Item::X509Certificate(cert_der)) => {
                certificates.push(cert_der.to_vec());
            }
            Some(_) => {
                // Skip non-certificate items
                continue;
            }
            None => break,
        }
    }

    if certificates.is_empty() {
        return Err(DeTlsError::PemError(
            "No certificates found in PEM file".to_string(),
        ));
    }

    Ok(certificates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::ca::create_root_ca;
    use crate::crypto::ed25519::generate_ed25519_keypair;

    #[test]
    fn test_load_certificate_from_pem() {
        let keypair = generate_ed25519_keypair().unwrap();
        let cert = create_root_ca(&keypair, "CN=Test", 365).unwrap();
        let pem = cert.serialize_pem().unwrap();

        let result = load_certificate_from_pem(&pem);
        assert!(result.is_ok());

        let der = result.unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn test_load_certificate_from_invalid_pem() {
        let result = load_certificate_from_pem("not a valid pem");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_certificates_from_pem_single() {
        let keypair = generate_ed25519_keypair().unwrap();
        let cert = create_root_ca(&keypair, "CN=Test", 365).unwrap();
        let pem = cert.serialize_pem().unwrap();

        let result = load_certificates_from_pem(&pem);
        assert!(result.is_ok());

        let certs = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn test_load_certificates_from_pem_multiple() {
        let keypair1 = generate_ed25519_keypair().unwrap();
        let keypair2 = generate_ed25519_keypair().unwrap();

        let cert1 = create_root_ca(&keypair1, "CN=Test1", 365).unwrap();
        let cert2 = create_root_ca(&keypair2, "CN=Test2", 365).unwrap();

        let pem1 = cert1.serialize_pem().unwrap();
        let pem2 = cert2.serialize_pem().unwrap();

        let combined_pem = format!("{}\n{}", pem1, pem2);
        let result = load_certificates_from_pem(&combined_pem);

        assert!(result.is_ok());
        let certs = result.unwrap();
        assert_eq!(certs.len(), 2);
    }

    #[test]
    fn test_load_certificates_from_empty_pem() {
        let result = load_certificates_from_pem("");
        assert!(result.is_err());
    }
}
