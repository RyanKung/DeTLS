//! Ed25519 key operations.
//!
//! This module provides functions for generating and managing Ed25519 keypairs
//! compatible with the Solana ecosystem.

use crate::error::{DeTlsError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// An Ed25519 keypair consisting of a secret key and public key.
#[derive(Debug, Clone)]
pub struct Keypair {
    pub secret: SigningKey,
    pub public: VerifyingKey,
}

impl Keypair {
    /// Create a new keypair from a signing key.
    pub fn from_secret(secret: SigningKey) -> Self {
        let public = secret.verifying_key();
        Self { secret, public }
    }

    /// Get the public key as bytes.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get the secret key as bytes.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.secret.sign(message)
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.public
            .verify(message, signature)
            .map_err(|e| DeTlsError::CryptoError(format!("Signature verification failed: {}", e)))
    }
}

/// Generate a new Ed25519 keypair using a cryptographically secure random number generator.
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::generate_ed25519_keypair;
///
/// let keypair = generate_ed25519_keypair().unwrap();
/// assert_eq!(keypair.public_bytes().len(), 32);
/// ```
pub fn generate_ed25519_keypair() -> Result<Keypair> {
    let secret = SigningKey::generate(&mut OsRng);
    Ok(Keypair::from_secret(secret))
}

/// Import an Ed25519 keypair from a 32-byte secret key.
///
/// # Arguments
///
/// * `bytes` - A 32-byte slice representing the secret key
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::{generate_ed25519_keypair, import_ed25519_from_bytes};
///
/// let keypair = generate_ed25519_keypair().unwrap();
/// let secret_bytes = keypair.secret_bytes();
/// let imported = import_ed25519_from_bytes(&secret_bytes).unwrap();
/// assert_eq!(keypair.public_bytes(), imported.public_bytes());
/// ```
pub fn import_ed25519_from_bytes(bytes: &[u8]) -> Result<Keypair> {
    if bytes.len() != 32 {
        return Err(DeTlsError::InvalidKeyError(format!(
            "Expected 32 bytes for Ed25519 secret key, got {}",
            bytes.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(bytes);

    let secret = SigningKey::from_bytes(&key_bytes);
    Ok(Keypair::from_secret(secret))
}

/// Import an Ed25519 keypair from a hex-encoded string.
///
/// # Example
///
/// ```
/// use detls::crypto::ed25519::{generate_ed25519_keypair, import_ed25519_from_hex};
///
/// let keypair = generate_ed25519_keypair().unwrap();
/// let hex_string = hex::encode(keypair.secret_bytes());
/// let imported = import_ed25519_from_hex(&hex_string).unwrap();
/// assert_eq!(keypair.public_bytes(), imported.public_bytes());
/// ```
pub fn import_ed25519_from_hex(hex_string: &str) -> Result<Keypair> {
    let bytes = hex::decode(hex_string)
        .map_err(|e| DeTlsError::ParseError(format!("Invalid hex string: {}", e)))?;
    import_ed25519_from_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair_produces_valid_keys() {
        let keypair = generate_ed25519_keypair().unwrap();

        // Check that keys are 32 bytes
        assert_eq!(keypair.public_bytes().len(), 32);
        assert_eq!(keypair.secret_bytes().len(), 32);

        // Check that we can derive the same public key
        let derived = keypair.secret.verifying_key();
        assert_eq!(derived.to_bytes(), keypair.public_bytes());
    }

    #[test]
    fn test_generate_keypair_produces_different_keys() {
        let keypair1 = generate_ed25519_keypair().unwrap();
        let keypair2 = generate_ed25519_keypair().unwrap();

        // Different keypairs should have different keys
        assert_ne!(keypair1.public_bytes(), keypair2.public_bytes());
        assert_ne!(keypair1.secret_bytes(), keypair2.secret_bytes());
    }

    #[test]
    fn test_import_from_bytes_valid() {
        let original = generate_ed25519_keypair().unwrap();
        let secret_bytes = original.secret_bytes();

        let imported = import_ed25519_from_bytes(&secret_bytes).unwrap();

        assert_eq!(original.public_bytes(), imported.public_bytes());
        assert_eq!(original.secret_bytes(), imported.secret_bytes());
    }

    #[test]
    fn test_import_from_bytes_invalid_length() {
        let result = import_ed25519_from_bytes(&[0u8; 16]);
        assert!(result.is_err());

        match result {
            Err(DeTlsError::InvalidKeyError(msg)) => {
                assert!(msg.contains("Expected 32 bytes"));
            }
            _ => panic!("Expected InvalidKeyError"),
        }
    }

    #[test]
    fn test_import_from_hex_valid() {
        let original = generate_ed25519_keypair().unwrap();
        let hex_string = hex::encode(original.secret_bytes());

        let imported = import_ed25519_from_hex(&hex_string).unwrap();

        assert_eq!(original.public_bytes(), imported.public_bytes());
    }

    #[test]
    fn test_import_from_hex_invalid() {
        let result = import_ed25519_from_hex("not-valid-hex");
        assert!(result.is_err());

        match result {
            Err(DeTlsError::ParseError(_)) => {}
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_public_key_derivation() {
        let keypair = generate_ed25519_keypair().unwrap();

        // Public key should be derivable from secret key
        let derived_public = keypair.secret.verifying_key();
        assert_eq!(derived_public.to_bytes(), keypair.public_bytes());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = generate_ed25519_keypair().unwrap();
        let message = b"Hello, world!";

        // Sign the message
        let signature = keypair.sign(message);

        // Verify the signature
        let result = keypair.verify(message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let keypair = generate_ed25519_keypair().unwrap();
        let message = b"Hello, world!";
        let wrong_message = b"Goodbye, world!";

        // Sign one message
        let signature = keypair.sign(message);

        // Try to verify with different message
        let result = keypair.verify(wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_keypair_clone() {
        let keypair = generate_ed25519_keypair().unwrap();
        let cloned = keypair.clone();

        assert_eq!(keypair.public_bytes(), cloned.public_bytes());
        assert_eq!(keypair.secret_bytes(), cloned.secret_bytes());
    }
}
