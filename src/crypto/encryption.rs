//! Key encryption and decryption using AES-GCM.
//!
//! This module provides password-based encryption for private keys using
//! Argon2 for key derivation and AES-256-GCM for encryption.

use crate::crypto::password::{derive_key, generate_salt, SALT_LENGTH};
use crate::error::{DeTlsError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};

/// The length of the nonce used for AES-GCM encryption.
const NONCE_LENGTH: usize = 12;

/// Encrypt a private key using a password.
///
/// The encrypted output format is:
/// [salt (32 bytes)][nonce (12 bytes)][ciphertext (variable)]
///
/// # Arguments
///
/// * `key` - The private key bytes to encrypt
/// * `password` - The password to use for encryption
///
/// # Example
///
/// ```
/// use detls::crypto::encryption::{encrypt_private_key, decrypt_private_key};
///
/// let key = b"this is a secret key";
/// let password = "secure-password";
///
/// let encrypted = encrypt_private_key(key, password).unwrap();
/// let decrypted = decrypt_private_key(&encrypted, password).unwrap();
///
/// assert_eq!(key.as_slice(), decrypted.as_slice());
/// ```
pub fn encrypt_private_key(key: &[u8], password: &str) -> Result<Vec<u8>> {
    // Generate salt and derive encryption key
    let salt = generate_salt();
    let derived_key = derive_key(password, &salt)?;

    // Generate nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| DeTlsError::EncryptionError(format!("Invalid key length: {}", e)))?;
    let ciphertext = cipher
        .encrypt(&nonce_bytes.into(), key)
        .map_err(|e| DeTlsError::EncryptionError(format!("Encryption failed: {}", e)))?;

    // Combine salt + nonce + ciphertext
    let mut output = Vec::with_capacity(SALT_LENGTH + NONCE_LENGTH + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt a private key using a password.
///
/// # Arguments
///
/// * `encrypted` - The encrypted key (format: \[salt\]\[nonce\]\[ciphertext\])
/// * `password` - The password used for encryption
///
/// # Example
///
/// ```
/// use detls::crypto::encryption::{encrypt_private_key, decrypt_private_key};
///
/// let key = b"this is a secret key";
/// let password = "secure-password";
///
/// let encrypted = encrypt_private_key(key, password).unwrap();
/// let decrypted = decrypt_private_key(&encrypted, password).unwrap();
///
/// assert_eq!(key.as_slice(), decrypted.as_slice());
/// ```
pub fn decrypt_private_key(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
    // Validate minimum length
    let min_length = SALT_LENGTH + NONCE_LENGTH;
    if encrypted.len() < min_length {
        return Err(DeTlsError::EncryptionError(format!(
            "Encrypted data too short: expected at least {} bytes, got {}",
            min_length,
            encrypted.len()
        )));
    }

    // Extract salt, nonce, and ciphertext
    let salt = &encrypted[0..SALT_LENGTH];
    let nonce_bytes = &encrypted[SALT_LENGTH..SALT_LENGTH + NONCE_LENGTH];
    let ciphertext = &encrypted[SALT_LENGTH + NONCE_LENGTH..];

    // Derive key from password and salt
    let derived_key = derive_key(password, salt)?;

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| DeTlsError::EncryptionError(format!("Invalid key length: {}", e)))?;

    let plaintext = cipher
        .decrypt(nonce_bytes.into(), ciphertext)
        .map_err(|_| DeTlsError::InvalidPasswordError)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = b"this is a test private key";
        let password = "secure-password";

        let encrypted = encrypt_private_key(key, password).unwrap();
        let decrypted = decrypt_private_key(&encrypted, password).unwrap();

        assert_eq!(key.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_produces_different_output() {
        let key = b"test key";
        let password = "password";

        let encrypted1 = encrypt_private_key(key, password).unwrap();
        let encrypted2 = encrypt_private_key(key, password).unwrap();

        // Each encryption should use different salt/nonce
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_encrypt_output_format() {
        let key = b"test key";
        let password = "password";

        let encrypted = encrypt_private_key(key, password).unwrap();

        // Should contain salt + nonce + ciphertext (with auth tag)
        assert!(encrypted.len() >= SALT_LENGTH + NONCE_LENGTH + key.len());
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let key = b"test key";
        let password = "correct-password";
        let wrong_password = "wrong-password";

        let encrypted = encrypt_private_key(key, password).unwrap();
        let result = decrypt_private_key(&encrypted, wrong_password);

        assert!(result.is_err());
        match result {
            Err(DeTlsError::InvalidPasswordError) => {}
            _ => panic!("Expected InvalidPasswordError"),
        }
    }

    #[test]
    fn test_decrypt_corrupted_data() {
        let key = b"test key";
        let password = "password";

        let mut encrypted = encrypt_private_key(key, password).unwrap();

        // Corrupt the ciphertext
        let len = encrypted.len();
        encrypted[len - 1] ^= 0xFF;

        let result = decrypt_private_key(&encrypted, password);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let short_data = vec![0u8; 20];
        let result = decrypt_private_key(&short_data, "password");

        assert!(result.is_err());
        match result {
            Err(DeTlsError::EncryptionError(msg)) => {
                assert!(msg.contains("too short"));
            }
            _ => panic!("Expected EncryptionError"),
        }
    }

    #[test]
    fn test_encrypt_empty_key() {
        let key = b"";
        let password = "password";

        let encrypted = encrypt_private_key(key, password).unwrap();
        let decrypted = decrypt_private_key(&encrypted, password).unwrap();

        assert_eq!(key.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_large_key() {
        let key = vec![42u8; 10000];
        let password = "password";

        let encrypted = encrypt_private_key(&key, password).unwrap();
        let decrypted = decrypt_private_key(&encrypted, password).unwrap();

        assert_eq!(key, decrypted);
    }

    #[test]
    fn test_different_passwords_produce_different_ciphertexts() {
        let key = b"test key";
        let password1 = "password1";
        let password2 = "password2";

        let encrypted1 = encrypt_private_key(key, password1).unwrap();
        let encrypted2 = encrypt_private_key(key, password2).unwrap();

        // Different passwords should produce different ciphertexts
        // (even though salt is different too)
        let result1 = decrypt_private_key(&encrypted1, password2);
        let result2 = decrypt_private_key(&encrypted2, password1);

        assert!(result1.is_err());
        assert!(result2.is_err());
    }
}
