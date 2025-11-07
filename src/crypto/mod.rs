//! Cryptographic operations module.
//!
//! This module provides cryptographic primitives for DeTLS, including:
//!
//! - Ed25519 key generation and management
//! - Password-based key encryption using Argon2 and AES-GCM
//! - Secure password handling
//!
//! All cryptographic operations are designed to be constant-time where possible
//! and follow security best practices.
//!
//! # Example
//!
//! ```rust
//! use detls::crypto::ed25519::generate_ed25519_keypair;
//! use detls::crypto::encryption::{encrypt_private_key, decrypt_private_key};
//!
//! # fn example() -> detls::error::Result<()> {
//! // Generate a keypair
//! let keypair = generate_ed25519_keypair()?;
//!
//! // Encrypt the private key with a password
//! let password = "secure-password";
//! let encrypted = encrypt_private_key(keypair.secret.as_bytes(), password)?;
//!
//! // Decrypt it back
//! let decrypted = decrypt_private_key(&encrypted, password)?;
//! assert_eq!(keypair.secret.as_bytes(), decrypted.as_slice());
//! # Ok(())
//! # }
//! ```

pub mod ed25519;
pub mod encryption;
pub mod password;
