//! Key metadata management.
//!
//! This module provides structures for storing key metadata including aliases and public keys.

use serde::{Deserialize, Serialize};

/// Metadata for a stored key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyMetadata {
    /// The alias name for this key.
    pub alias: String,

    /// The public key in hex format.
    pub public_key_hex: String,

    /// The encrypted private key data.
    pub encrypted_key: Vec<u8>,

    /// Timestamp when the key was created (Unix timestamp).
    pub created_at: u64,
}

impl KeyMetadata {
    /// Create new key metadata.
    pub fn new(alias: String, public_key_hex: String, encrypted_key: Vec<u8>) -> Self {
        Self {
            alias,
            public_key_hex,
            encrypted_key,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Information about a key for display purposes.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyInfo {
    /// The alias name for this key.
    pub alias: String,

    /// The public key in hex format.
    pub public_key_hex: String,

    /// Timestamp when the key was created.
    pub created_at: u64,
}

impl From<&KeyMetadata> for KeyInfo {
    fn from(metadata: &KeyMetadata) -> Self {
        Self {
            alias: metadata.alias.clone(),
            public_key_hex: metadata.public_key_hex.clone(),
            created_at: metadata.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_metadata_creation() {
        let alias = "test-key".to_string();
        let public_key = "abcd1234".to_string();
        let encrypted = vec![1, 2, 3, 4];

        let metadata = KeyMetadata::new(alias.clone(), public_key.clone(), encrypted.clone());

        assert_eq!(metadata.alias, alias);
        assert_eq!(metadata.public_key_hex, public_key);
        assert_eq!(metadata.encrypted_key, encrypted);
        assert!(metadata.created_at > 0);
    }

    #[test]
    fn test_key_info_from_metadata() {
        let metadata = KeyMetadata::new("test".to_string(), "pubkey".to_string(), vec![1, 2, 3]);

        let info = KeyInfo::from(&metadata);

        assert_eq!(info.alias, metadata.alias);
        assert_eq!(info.public_key_hex, metadata.public_key_hex);
        assert_eq!(info.created_at, metadata.created_at);
    }

    #[test]
    fn test_key_metadata_serialization() {
        let metadata = KeyMetadata::new("test".to_string(), "pubkey".to_string(), vec![1, 2, 3]);

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: KeyMetadata = serde_json::from_str(&json).unwrap();

        assert_eq!(metadata, deserialized);
    }
}
