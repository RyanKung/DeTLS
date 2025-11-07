//! DeTLS: Decentralized TLS with Solana Ed25519 Keys
//!
//! This library provides tools for managing Ed25519-based X.509 certificates
//! for mutual TLS (mTLS) authentication. It enables users to:
//!
//! - Generate and manage Ed25519 keypairs compatible with the Solana ecosystem
//! - Store private keys with password-based encryption
//! - Generate X.509 certificates using a two-level CA hierarchy
//! - Perform mTLS connections using pure Rust (WASM-compatible)
//!
//! # Architecture
//!
//! The library follows a functional programming style where complex operations
//! are composed from smaller, testable functions. All operations return
//! `Result` types with comprehensive error handling - no `unwrap()` or panic.
//!
//! # Example
//!
//! ```rust,no_run
//! use detls::crypto::ed25519::generate_ed25519_keypair;
//! use detls::error::Result;
//!
//! fn example() -> Result<()> {
//!     // Generate a new keypair
//!     let keypair = generate_ed25519_keypair()?;
//!     println!("Generated keypair with public key: {:?}", keypair.public);
//!     Ok(())
//! }
//! ```

pub mod cert;
pub mod crypto;
pub mod error;
pub mod net;
pub mod storage;

// Re-export commonly used types
pub use error::{DeTlsError, Result};
