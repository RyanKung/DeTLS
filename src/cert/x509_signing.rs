//! Proper X.509 certificate signing using x509-cert.
//!
//! This module implements correct certificate signing where a CA can sign
//! subordinate certificates, creating a proper chain of trust.

use crate::crypto::ed25519::Keypair;
use crate::error::{DeTlsError, Result};
use der::asn1::{BitString, Utf8StringRef};
use der::{Decode, Encode};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::certificate::Certificate;
use x509_cert::name::{RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;
use x509_cert::TbsCertificate;

/// Create a self-signed Root CA certificate.
///
/// # Arguments
///
/// * `keypair` - The Ed25519 keypair for the Root CA
/// * `subject_cn` - Common Name for the certificate (e.g., "My Root CA")
/// * `validity_days` - Number of days the certificate is valid
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::x509_signing::create_self_signed_ca;
///
/// # fn example() -> detls::error::Result<()> {
/// let keypair = generate_ed25519_keypair()?;
/// let cert_pem = create_self_signed_ca(&keypair, "My Root CA", 3650)?;
/// assert!(cert_pem.contains("BEGIN CERTIFICATE"));
/// # Ok(())
/// # }
/// ```
pub fn create_self_signed_ca(
    keypair: &Keypair,
    subject_cn: &str,
    validity_days: u32,
) -> Result<String> {
    let serial = generate_serial_number()?;
    let subject = create_rdn_sequence(subject_cn)?;
    let issuer = subject.clone(); // Self-signed
    let validity = create_validity(validity_days)?;
    let spki = create_subject_public_key_info(&keypair.public)?;
    let signature_algorithm = ed25519_algorithm();

    // Build TBS certificate
    let tbs = TbsCertificate {
        version: x509_cert::certificate::Version::V3,
        serial_number: serial,
        signature: signature_algorithm.clone(),
        issuer,
        validity,
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None, // Simplified for now
    };

    // Sign the certificate
    let signature = sign_tbs(&tbs, &keypair.secret)?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm,
        signature,
    };

    cert_to_pem(&cert)
}

/// Sign a certificate using a CA certificate and key.
///
/// This creates a properly signed certificate where the issuer is the CA.
///
/// # Arguments
///
/// * `subject_keypair` - The keypair for the certificate being created
/// * `subject_cn` - Common Name for the subject
/// * `ca_keypair` - The CA's keypair (used for signing)
/// * `ca_cert_pem` - The CA's certificate in PEM format
/// * `is_ca` - Whether the new certificate is a CA
/// * `validity_days` - Number of days the certificate is valid
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use detls::cert::x509_signing::{create_self_signed_ca, sign_certificate};
///
/// # fn example() -> detls::error::Result<()> {
/// // Create Root CA
/// let ca_keypair = generate_ed25519_keypair()?;
/// let ca_cert_pem = create_self_signed_ca(&ca_keypair, "Root CA", 3650)?;
///
/// // Create client certificate signed by Root CA
/// let client_keypair = generate_ed25519_keypair()?;
/// let client_cert_pem = sign_certificate(
///     &client_keypair,
///     "Client 1",
///     &ca_keypair,
///     &ca_cert_pem,
///     false,  // Not a CA
///     365,
/// )?;
/// assert!(client_cert_pem.contains("BEGIN CERTIFICATE"));
/// # Ok(())
/// # }
/// ```
pub fn sign_certificate(
    subject_keypair: &Keypair,
    subject_cn: &str,
    ca_keypair: &Keypair,
    ca_cert_pem: &str,
    _is_ca: bool,
    validity_days: u32,
) -> Result<String> {
    let ca_cert = cert_from_pem(ca_cert_pem)?;

    let serial = generate_serial_number()?;
    let subject = create_rdn_sequence(subject_cn)?;
    let issuer = ca_cert.tbs_certificate.subject.clone(); // Issuer is the CA
    let validity = create_validity(validity_days)?;
    let spki = create_subject_public_key_info(&subject_keypair.public)?;
    let signature_algorithm = ed25519_algorithm();

    // Build TBS certificate
    let tbs = TbsCertificate {
        version: x509_cert::certificate::Version::V3,
        serial_number: serial,
        signature: signature_algorithm.clone(),
        issuer,
        validity,
        subject,
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None, // Simplified for now
    };

    // Sign with CA's key (not subject's key!)
    let signature = sign_tbs(&tbs, &ca_keypair.secret)?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm,
        signature,
    };

    cert_to_pem(&cert)
}

/// Convert a Certificate to PEM format.
pub fn cert_to_pem(cert: &Certificate) -> Result<String> {
    let der = cert.to_der().map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to encode certificate: {}", e))
    })?;

    Ok(pem::encode(&pem::Pem::new("CERTIFICATE", der)))
}

/// Load a Certificate from PEM format.
pub fn cert_from_pem(pem_str: &str) -> Result<Certificate> {
    let pem = pem::parse(pem_str)
        .map_err(|e| DeTlsError::PemError(format!("Failed to parse PEM: {}", e)))?;

    if pem.tag() != "CERTIFICATE" {
        return Err(DeTlsError::PemError(format!(
            "Expected CERTIFICATE, got {}",
            pem.tag()
        )));
    }

    Certificate::from_der(pem.contents())
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to decode certificate: {}", e)))
}

// Helper functions

fn generate_serial_number() -> Result<SerialNumber> {
    let mut bytes = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    bytes[0] &= 0x7F; // Ensure positive

    SerialNumber::new(&bytes)
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to create serial number: {}", e)))
}

fn create_rdn_sequence(cn: &str) -> Result<RdnSequence> {
    // Parse simple CN-only DN for now
    let cn_only = if cn.starts_with("CN=") {
        cn.strip_prefix("CN=").unwrap().split(',').next().unwrap()
    } else {
        cn
    };

    let cn_attr = AttributeTypeAndValue {
        oid: const_oid::db::rfc4519::CN,
        value: Utf8StringRef::new(cn_only)
            .map_err(|e| DeTlsError::ParseError(format!("Invalid CN: {}", e)))?
            .into(),
    };

    // Create a set containing the CN attribute
    let mut attr_set = der::asn1::SetOfVec::new();
    attr_set
        .insert_ordered(cn_attr)
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to add attribute: {}", e)))?;

    let rdn = RelativeDistinguishedName::from(attr_set);

    Ok(RdnSequence(vec![rdn]))
}

fn create_validity(days: u32) -> Result<Validity> {
    Validity::from_now(std::time::Duration::from_secs(days as u64 * 86400))
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to create validity: {}", e)))
}

fn create_subject_public_key_info(public_key: &VerifyingKey) -> Result<SubjectPublicKeyInfoOwned> {
    let algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc8410::ID_ED_25519,
        parameters: None,
    };

    let public_key_bytes = public_key.to_bytes();
    let subject_public_key = BitString::from_bytes(&public_key_bytes)
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to create bit string: {}", e)))?;

    Ok(SubjectPublicKeyInfoOwned {
        algorithm,
        subject_public_key,
    })
}

fn ed25519_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc8410::ID_ED_25519,
        parameters: None,
    }
}

fn sign_tbs(tbs: &TbsCertificate, signing_key: &SigningKey) -> Result<BitString> {
    let tbs_der = tbs
        .to_der()
        .map_err(|e| DeTlsError::CertificateError(format!("Failed to encode TBS: {}", e)))?;

    let signature = signing_key.sign(&tbs_der);
    let signature_bytes = signature.to_bytes();

    BitString::from_bytes(&signature_bytes).map_err(|e| {
        DeTlsError::CertificateError(format!("Failed to create signature bitstring: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519_keypair;

    #[test]
    fn test_create_self_signed_ca() {
        let keypair = generate_ed25519_keypair().unwrap();
        let pem = create_self_signed_ca(&keypair, "Test CA", 365);
        assert!(pem.is_ok());
        let pem_str = pem.unwrap();
        assert!(pem_str.contains("BEGIN CERTIFICATE"));
        assert!(pem_str.contains("END CERTIFICATE"));
    }

    #[test]
    fn test_cert_roundtrip() {
        let keypair = generate_ed25519_keypair().unwrap();
        let pem = create_self_signed_ca(&keypair, "Test CA", 365).unwrap();
        let loaded = cert_from_pem(&pem);
        assert!(loaded.is_ok());
    }

    #[test]
    fn test_sign_client_certificate() {
        // Create Root CA
        let ca_keypair = generate_ed25519_keypair().unwrap();
        let ca_cert_pem = create_self_signed_ca(&ca_keypair, "Root CA", 3650).unwrap();

        // Create client certificate signed by CA
        let client_keypair = generate_ed25519_keypair().unwrap();
        let client_cert_pem = sign_certificate(
            &client_keypair,
            "Client 1",
            &ca_keypair,
            &ca_cert_pem,
            false,
            365,
        );

        assert!(client_cert_pem.is_ok());

        let client_pem = client_cert_pem.unwrap();
        assert!(client_pem.contains("BEGIN CERTIFICATE"));

        // Load and verify issuers
        let ca_cert = cert_from_pem(&ca_cert_pem).unwrap();
        let client_cert = cert_from_pem(&client_pem).unwrap();

        // Issuer should be the CA's subject
        assert_eq!(
            client_cert.tbs_certificate.issuer,
            ca_cert.tbs_certificate.subject
        );
    }

    #[test]
    fn test_sign_intermediate_ca() {
        // Create Root CA
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert_pem = create_self_signed_ca(&root_keypair, "Root CA", 3650).unwrap();

        // Create Intermediate CA signed by Root
        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert_pem = sign_certificate(
            &inter_keypair,
            "Intermediate CA",
            &root_keypair,
            &root_cert_pem,
            true, // Is a CA
            1825,
        );

        assert!(inter_cert_pem.is_ok());

        let inter_pem = inter_cert_pem.unwrap();
        let root_cert = cert_from_pem(&root_cert_pem).unwrap();
        let inter_cert = cert_from_pem(&inter_pem).unwrap();

        // Issuer should be the Root CA
        assert_eq!(
            inter_cert.tbs_certificate.issuer,
            root_cert.tbs_certificate.subject
        );
    }

    #[test]
    fn test_complete_signing_chain() {
        // Create Root CA (self-signed)
        let root_keypair = generate_ed25519_keypair().unwrap();
        let root_cert_pem = create_self_signed_ca(&root_keypair, "Root CA", 3650).unwrap();

        // Root CA signs Intermediate CA
        let inter_keypair = generate_ed25519_keypair().unwrap();
        let inter_cert_pem = sign_certificate(
            &inter_keypair,
            "Intermediate CA",
            &root_keypair,
            &root_cert_pem,
            true,
            1825,
        )
        .unwrap();

        // Intermediate CA signs End-entity
        let entity_keypair = generate_ed25519_keypair().unwrap();
        let entity_cert_pem = sign_certificate(
            &entity_keypair,
            "example.com",
            &inter_keypair,
            &inter_cert_pem,
            false,
            365,
        )
        .unwrap();

        // Load all certs
        let root_cert = cert_from_pem(&root_cert_pem).unwrap();
        let inter_cert = cert_from_pem(&inter_cert_pem).unwrap();
        let entity_cert = cert_from_pem(&entity_cert_pem).unwrap();

        // Verify issuers
        assert_eq!(
            root_cert.tbs_certificate.issuer,
            root_cert.tbs_certificate.subject
        ); // Self-signed
        assert_eq!(
            inter_cert.tbs_certificate.issuer,
            root_cert.tbs_certificate.subject
        ); // Signed by root
        assert_eq!(
            entity_cert.tbs_certificate.issuer,
            inter_cert.tbs_certificate.subject
        ); // Signed by intermediate
    }
}
