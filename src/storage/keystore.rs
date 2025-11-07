//! Keystore implementation for managing encrypted keys.
//!
//! This module provides a keystore that stores encrypted Ed25519 keys with aliases.

use crate::crypto::ed25519::{import_ed25519_from_bytes, Keypair};
use crate::crypto::encryption::{decrypt_private_key, encrypt_private_key};
use crate::error::{DeTlsError, Result};
use crate::storage::metadata::{KeyInfo, KeyMetadata};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Default keystore filename.
const KEYSTORE_FILENAME: &str = "detls_keystore.json";

/// A keystore for managing encrypted Ed25519 keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    /// Path to the keystore file.
    #[serde(skip)]
    path: PathBuf,

    /// Map of alias to key metadata.
    keys: HashMap<String, KeyMetadata>,
}

impl KeyStore {
    /// Create a new empty keystore.
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            keys: HashMap::new(),
        }
    }

    /// Get the full path to the keystore file.
    fn get_keystore_path(directory: &Path) -> PathBuf {
        directory.join(KEYSTORE_FILENAME)
    }

    /// Save the keystore to disk.
    fn save(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self).map_err(DeTlsError::JsonError)?;

        fs::write(&self.path, json).map_err(DeTlsError::StorageError)?;

        Ok(())
    }
}

/// Create or load a keystore from the specified directory.
///
/// If a keystore already exists at the path, it will be loaded.
/// Otherwise, a new empty keystore will be created.
///
/// # Arguments
///
/// * `directory` - The directory where the keystore file should be located
///
/// # Example
///
/// ```rust,no_run
/// use detls::storage::keystore::create_keystore;
/// use std::path::Path;
///
/// let keystore = create_keystore(Path::new(".")).unwrap();
/// ```
pub fn create_keystore(directory: &Path) -> Result<KeyStore> {
    let keystore_path = KeyStore::get_keystore_path(directory);

    if keystore_path.exists() {
        // Load existing keystore
        let contents = fs::read_to_string(&keystore_path).map_err(DeTlsError::StorageError)?;

        let mut keystore: KeyStore =
            serde_json::from_str(&contents).map_err(DeTlsError::JsonError)?;

        keystore.path = keystore_path;
        Ok(keystore)
    } else {
        // Create new keystore
        let keystore = KeyStore::new(keystore_path);
        keystore.save()?;
        Ok(keystore)
    }
}

/// Import a key into the keystore with an alias.
///
/// # Arguments
///
/// * `keystore` - The keystore to import into
/// * `alias` - The alias name for the key
/// * `key_bytes` - The 32-byte Ed25519 secret key
/// * `password` - The password to encrypt the key with
///
/// # Example
///
/// ```rust,no_run
/// use detls::storage::keystore::{create_keystore, import_key};
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use std::path::Path;
///
/// # fn example() -> detls::error::Result<()> {
/// let mut keystore = create_keystore(Path::new("."))?;
/// let keypair = generate_ed25519_keypair()?;
///
/// import_key(&mut keystore, "my-key".to_string(), &keypair.secret_bytes(), "password")?;
/// # Ok(())
/// # }
/// ```
pub fn import_key(
    keystore: &mut KeyStore,
    alias: String,
    key_bytes: &[u8],
    password: &str,
) -> Result<()> {
    // Check if alias already exists
    if keystore.keys.contains_key(&alias) {
        return Err(DeTlsError::AlreadyExistsError(format!(
            "Key with alias '{}' already exists",
            alias
        )));
    }

    // Validate the key by importing it
    let keypair = import_ed25519_from_bytes(key_bytes)?;

    // Encrypt the key
    let encrypted = encrypt_private_key(key_bytes, password)?;

    // Get public key hex
    let public_key_hex = hex::encode(keypair.public_bytes());

    // Create metadata
    let metadata = KeyMetadata::new(alias.clone(), public_key_hex, encrypted);

    // Store in keystore
    keystore.keys.insert(alias, metadata);

    // Save to disk
    keystore.save()?;

    Ok(())
}

/// Export a key from the keystore.
///
/// # Arguments
///
/// * `keystore` - The keystore to export from
/// * `alias` - The alias of the key to export
/// * `password` - The password to decrypt the key
///
/// # Example
///
/// ```rust,no_run
/// use detls::storage::keystore::{create_keystore, import_key, export_key};
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use std::path::Path;
///
/// # fn example() -> detls::error::Result<()> {
/// let mut keystore = create_keystore(Path::new("."))?;
/// let keypair = generate_ed25519_keypair()?;
/// let secret = keypair.secret_bytes();
///
/// import_key(&mut keystore, "my-key".to_string(), &secret, "password")?;
/// let exported = export_key(&keystore, "my-key", "password")?;
/// assert_eq!(secret.to_vec(), exported);
/// # Ok(())
/// # }
/// ```
pub fn export_key(keystore: &KeyStore, alias: &str, password: &str) -> Result<Vec<u8>> {
    // Find the key
    let metadata = keystore
        .keys
        .get(alias)
        .ok_or_else(|| DeTlsError::NotFoundError(format!("Key '{}' not found", alias)))?;

    // Decrypt the key
    let decrypted = decrypt_private_key(&metadata.encrypted_key, password)?;

    Ok(decrypted)
}

/// Get a keypair from the keystore.
///
/// # Arguments
///
/// * `keystore` - The keystore to get from
/// * `alias` - The alias of the key
/// * `password` - The password to decrypt the key
///
/// # Example
///
/// ```rust,no_run
/// use detls::storage::keystore::{create_keystore, import_key, get_key};
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use std::path::Path;
///
/// # fn example() -> detls::error::Result<()> {
/// let mut keystore = create_keystore(Path::new("."))?;
/// let keypair = generate_ed25519_keypair()?;
///
/// import_key(&mut keystore, "my-key".to_string(), &keypair.secret_bytes(), "password")?;
/// let retrieved = get_key(&keystore, "my-key", "password")?;
/// assert_eq!(keypair.public_bytes(), retrieved.public_bytes());
/// # Ok(())
/// # }
/// ```
pub fn get_key(keystore: &KeyStore, alias: &str, password: &str) -> Result<Keypair> {
    let key_bytes = export_key(keystore, alias, password)?;
    import_ed25519_from_bytes(&key_bytes)
}

/// List all keys in the keystore.
///
/// # Arguments
///
/// * `keystore` - The keystore to list
///
/// # Example
///
/// ```rust,no_run
/// use detls::storage::keystore::{create_keystore, import_key, list_keys};
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use std::path::Path;
///
/// # fn example() -> detls::error::Result<()> {
/// let mut keystore = create_keystore(Path::new("."))?;
/// let keypair = generate_ed25519_keypair()?;
///
/// import_key(&mut keystore, "my-key".to_string(), &keypair.secret_bytes(), "password")?;
/// let keys = list_keys(&keystore)?;
/// assert_eq!(keys.len(), 1);
/// assert_eq!(keys[0].alias, "my-key");
/// # Ok(())
/// # }
/// ```
pub fn list_keys(keystore: &KeyStore) -> Result<Vec<KeyInfo>> {
    let mut keys: Vec<KeyInfo> = keystore.keys.values().map(KeyInfo::from).collect();

    // Sort by alias for consistent output
    keys.sort_by(|a, b| a.alias.cmp(&b.alias));

    Ok(keys)
}

/// Delete a key from the keystore.
///
/// # Arguments
///
/// * `keystore` - The keystore to delete from
/// * `alias` - The alias of the key to delete
///
/// # Example
///
/// ```rust,no_run
/// use detls::storage::keystore::{create_keystore, import_key, delete_key, list_keys};
/// use detls::crypto::ed25519::generate_ed25519_keypair;
/// use std::path::Path;
///
/// # fn example() -> detls::error::Result<()> {
/// let mut keystore = create_keystore(Path::new("."))?;
/// let keypair = generate_ed25519_keypair()?;
///
/// import_key(&mut keystore, "my-key".to_string(), &keypair.secret_bytes(), "password")?;
/// delete_key(&mut keystore, "my-key")?;
/// assert_eq!(list_keys(&keystore)?.len(), 0);
/// # Ok(())
/// # }
/// ```
pub fn delete_key(keystore: &mut KeyStore, alias: &str) -> Result<()> {
    if keystore.keys.remove(alias).is_none() {
        return Err(DeTlsError::NotFoundError(format!(
            "Key '{}' not found",
            alias
        )));
    }

    keystore.save()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::generate_ed25519_keypair;
    use tempfile::TempDir;

    #[test]
    fn test_create_keystore_new() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = create_keystore(temp_dir.path()).unwrap();

        assert_eq!(keystore.keys.len(), 0);
        assert!(temp_dir.path().join(KEYSTORE_FILENAME).exists());
    }

    #[test]
    fn test_create_keystore_load_existing() {
        let temp_dir = TempDir::new().unwrap();

        // Create initial keystore
        let mut keystore1 = create_keystore(temp_dir.path()).unwrap();
        let keypair = generate_ed25519_keypair().unwrap();
        import_key(
            &mut keystore1,
            "test".to_string(),
            &keypair.secret_bytes(),
            "password",
        )
        .unwrap();

        // Load existing keystore
        let keystore2 = create_keystore(temp_dir.path()).unwrap();
        assert_eq!(keystore2.keys.len(), 1);
        assert!(keystore2.keys.contains_key("test"));
    }

    #[test]
    fn test_import_key_success() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let keypair = generate_ed25519_keypair().unwrap();
        let result = import_key(
            &mut keystore,
            "my-key".to_string(),
            &keypair.secret_bytes(),
            "password",
        );

        assert!(result.is_ok());
        assert_eq!(keystore.keys.len(), 1);
        assert!(keystore.keys.contains_key("my-key"));
    }

    #[test]
    fn test_import_key_duplicate_alias() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let keypair1 = generate_ed25519_keypair().unwrap();
        let keypair2 = generate_ed25519_keypair().unwrap();

        import_key(
            &mut keystore,
            "test".to_string(),
            &keypair1.secret_bytes(),
            "password",
        )
        .unwrap();
        let result = import_key(
            &mut keystore,
            "test".to_string(),
            &keypair2.secret_bytes(),
            "password",
        );

        assert!(result.is_err());
        match result {
            Err(DeTlsError::AlreadyExistsError(_)) => {}
            _ => panic!("Expected AlreadyExistsError"),
        }
    }

    #[test]
    fn test_export_key_success() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let keypair = generate_ed25519_keypair().unwrap();
        let secret = keypair.secret_bytes();

        import_key(&mut keystore, "test".to_string(), &secret, "password").unwrap();
        let exported = export_key(&keystore, "test", "password").unwrap();

        assert_eq!(secret.to_vec(), exported);
    }

    #[test]
    fn test_export_key_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = create_keystore(temp_dir.path()).unwrap();

        let result = export_key(&keystore, "nonexistent", "password");

        assert!(result.is_err());
        match result {
            Err(DeTlsError::NotFoundError(_)) => {}
            _ => panic!("Expected NotFoundError"),
        }
    }

    #[test]
    fn test_export_key_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let keypair = generate_ed25519_keypair().unwrap();
        import_key(
            &mut keystore,
            "test".to_string(),
            &keypair.secret_bytes(),
            "correct",
        )
        .unwrap();

        let result = export_key(&keystore, "test", "wrong");

        assert!(result.is_err());
        match result {
            Err(DeTlsError::InvalidPasswordError) => {}
            _ => panic!("Expected InvalidPasswordError"),
        }
    }

    #[test]
    fn test_get_key_success() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let keypair = generate_ed25519_keypair().unwrap();
        import_key(
            &mut keystore,
            "test".to_string(),
            &keypair.secret_bytes(),
            "password",
        )
        .unwrap();

        let retrieved = get_key(&keystore, "test", "password").unwrap();
        assert_eq!(keypair.public_bytes(), retrieved.public_bytes());
    }

    #[test]
    fn test_list_keys_empty() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = create_keystore(temp_dir.path()).unwrap();

        let keys = list_keys(&keystore).unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[test]
    fn test_list_keys_multiple() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let keypair1 = generate_ed25519_keypair().unwrap();
        let keypair2 = generate_ed25519_keypair().unwrap();

        import_key(
            &mut keystore,
            "key1".to_string(),
            &keypair1.secret_bytes(),
            "password",
        )
        .unwrap();
        import_key(
            &mut keystore,
            "key2".to_string(),
            &keypair2.secret_bytes(),
            "password",
        )
        .unwrap();

        let keys = list_keys(&keystore).unwrap();
        assert_eq!(keys.len(), 2);

        // Check sorting
        assert_eq!(keys[0].alias, "key1");
        assert_eq!(keys[1].alias, "key2");

        // Check public keys match
        assert_eq!(keys[0].public_key_hex, hex::encode(keypair1.public_bytes()));
        assert_eq!(keys[1].public_key_hex, hex::encode(keypair2.public_bytes()));
    }

    #[test]
    fn test_delete_key_success() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let keypair = generate_ed25519_keypair().unwrap();
        import_key(
            &mut keystore,
            "test".to_string(),
            &keypair.secret_bytes(),
            "password",
        )
        .unwrap();

        assert_eq!(list_keys(&keystore).unwrap().len(), 1);

        delete_key(&mut keystore, "test").unwrap();
        assert_eq!(list_keys(&keystore).unwrap().len(), 0);
    }

    #[test]
    fn test_delete_key_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let mut keystore = create_keystore(temp_dir.path()).unwrap();

        let result = delete_key(&mut keystore, "nonexistent");

        assert!(result.is_err());
        match result {
            Err(DeTlsError::NotFoundError(_)) => {}
            _ => panic!("Expected NotFoundError"),
        }
    }

    #[test]
    fn test_keystore_persistence() {
        let temp_dir = TempDir::new().unwrap();

        let keypair = generate_ed25519_keypair().unwrap();
        let secret = keypair.secret_bytes();

        // Create and populate keystore
        {
            let mut keystore = create_keystore(temp_dir.path()).unwrap();
            import_key(&mut keystore, "persistent".to_string(), &secret, "password").unwrap();
        }

        // Load keystore and verify
        {
            let keystore = create_keystore(temp_dir.path()).unwrap();
            let exported = export_key(&keystore, "persistent", "password").unwrap();
            assert_eq!(secret.to_vec(), exported);
        }
    }
}
