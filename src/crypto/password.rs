//! Password derivation and handling.
//!
//! This module provides secure password-based key derivation using Argon2.

use crate::error::{DeTlsError, Result};
use argon2::Argon2;
use rand::RngCore;

/// The length of the salt used for key derivation.
pub const SALT_LENGTH: usize = 32;

/// The length of the derived key.
pub const KEY_LENGTH: usize = 32;

/// Generate a random salt for key derivation.
///
/// # Example
///
/// ```
/// use detls::crypto::password::{generate_salt, SALT_LENGTH};
///
/// let salt = generate_salt();
/// assert_eq!(salt.len(), SALT_LENGTH);
/// ```
pub fn generate_salt() -> [u8; SALT_LENGTH] {
    let mut salt = [0u8; SALT_LENGTH];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Derive an encryption key from a password and salt using Argon2.
///
/// This function uses Argon2id with default parameters for secure key derivation.
///
/// # Arguments
///
/// * `password` - The password to derive from
/// * `salt` - A random salt (should be SALT_LENGTH bytes)
///
/// # Example
///
/// ```
/// use detls::crypto::password::{derive_key, generate_salt, KEY_LENGTH};
///
/// let password = "secure-password";
/// let salt = generate_salt();
/// let key = derive_key(password, &salt).unwrap();
/// assert_eq!(key.len(), KEY_LENGTH);
/// ```
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LENGTH]> {
    if salt.len() != SALT_LENGTH {
        return Err(DeTlsError::KeyDerivationError(format!(
            "Salt must be {} bytes, got {}",
            SALT_LENGTH,
            salt.len()
        )));
    }

    let mut output = [0u8; KEY_LENGTH];
    let argon2 = Argon2::default();

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| DeTlsError::KeyDerivationError(format!("Argon2 error: {}", e)))?;

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_salt_produces_correct_length() {
        let salt = generate_salt();
        assert_eq!(salt.len(), SALT_LENGTH);
    }

    #[test]
    fn test_generate_salt_produces_different_values() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_derive_key_produces_correct_length() {
        let password = "test-password";
        let salt = generate_salt();
        let key = derive_key(password, &salt).unwrap();
        assert_eq!(key.len(), KEY_LENGTH);
    }

    #[test]
    fn test_derive_key_same_password_same_salt() {
        let password = "test-password";
        let salt = generate_salt();

        let key1 = derive_key(password, &salt).unwrap();
        let key2 = derive_key(password, &salt).unwrap();

        // Same password and salt should produce same key
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_passwords() {
        let salt = generate_salt();

        let key1 = derive_key("password1", &salt).unwrap();
        let key2 = derive_key("password2", &salt).unwrap();

        // Different passwords should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_different_salts() {
        let password = "test-password";
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let key1 = derive_key(password, &salt1).unwrap();
        let key2 = derive_key(password, &salt2).unwrap();

        // Same password but different salts should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_key_invalid_salt_length() {
        let password = "test-password";
        let short_salt = [0u8; 16];

        let result = derive_key(password, &short_salt);
        assert!(result.is_err());

        match result {
            Err(DeTlsError::KeyDerivationError(msg)) => {
                assert!(msg.contains("Salt must be"));
            }
            _ => panic!("Expected KeyDerivationError"),
        }
    }

    #[test]
    fn test_derive_key_empty_password() {
        let password = "";
        let salt = generate_salt();

        // Empty password should still work (though not recommended)
        let result = derive_key(password, &salt);
        assert!(result.is_ok());
    }
}
