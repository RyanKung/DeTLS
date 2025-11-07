//! Error types for the DeTLS library.
//!
//! This module defines all error types used throughout the library.
//! All errors implement `std::error::Error` and are designed to provide
//! clear, actionable error messages.

use thiserror::Error;

/// The main error type for DeTLS operations.
///
/// This enum covers all possible errors that can occur during
/// cryptographic operations, certificate generation, storage, and network operations.
#[derive(Error, Debug)]
pub enum DeTlsError {
    /// Cryptographic operation failed
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Key derivation failed
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),

    /// Encryption or decryption failed
    #[error("Encryption/decryption error: {0}")]
    EncryptionError(String),

    /// Invalid key format or content
    #[error("Invalid key: {0}")]
    InvalidKeyError(String),

    /// Keystore operation failed
    #[error("Keystore error: {0}")]
    KeystoreError(String),

    /// Storage I/O error
    #[error("Storage I/O error: {0}")]
    StorageError(#[from] std::io::Error),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Certificate generation or validation error
    #[error("Certificate error: {0}")]
    CertificateError(String),

    /// TLS handshake or connection error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Invalid input data
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Resource not found
    #[error("Not found: {0}")]
    NotFoundError(String),

    /// Resource already exists
    #[error("Already exists: {0}")]
    AlreadyExistsError(String),

    /// Invalid password
    #[error("Invalid password")]
    InvalidPasswordError,

    /// PEM encoding/decoding error
    #[error("PEM error: {0}")]
    PemError(String),
}

/// A specialized Result type for DeTLS operations.
pub type Result<T> = std::result::Result<T, DeTlsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DeTlsError::CryptoError("test error".to_string());
        assert_eq!(err.to_string(), "Cryptographic error: test error");
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<DeTlsError>();
    }

    #[test]
    fn test_result_type() {
        let ok_result: Result<i32> = Ok(42);
        assert!(ok_result.is_ok());

        let err_result: Result<i32> = Err(DeTlsError::NotFoundError("test".to_string()));
        assert!(err_result.is_err());
    }
}
