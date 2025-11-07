//! Integration tests for DeTLS.
//!
//! These tests verify the complete workflows of the system.

use detls::cert::ca::create_root_ca;
use detls::cert::entity::{build_cert_chain_pem, create_end_entity_cert};
use detls::cert::intermediate::create_intermediate_ca;
use detls::crypto::ed25519::generate_ed25519_keypair;
use detls::crypto::encryption::{decrypt_private_key, encrypt_private_key};
use detls::error::Result;
use detls::storage::keystore::{create_keystore, export_key, get_key, import_key, list_keys};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_complete_key_management_workflow() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();

    // 1. Generate a keypair
    let keypair = generate_ed25519_keypair()?;
    let password = "test-password";

    // 2. Create keystore and import key
    let mut keystore = create_keystore(temp_dir.path())?;
    import_key(
        &mut keystore,
        "test-key".to_string(),
        &keypair.secret_bytes(),
        password,
    )?;

    // 3. List keys
    let keys = list_keys(&keystore)?;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].alias, "test-key");
    assert_eq!(keys[0].public_key_hex, hex::encode(keypair.public_bytes()));

    // 4. Retrieve key
    let retrieved = get_key(&keystore, "test-key", password)?;
    assert_eq!(keypair.public_bytes(), retrieved.public_bytes());

    // 5. Export key
    let exported = export_key(&keystore, "test-key", password)?;
    assert_eq!(keypair.secret_bytes().to_vec(), exported);

    Ok(())
}

#[test]
fn test_encryption_decryption_workflow() -> Result<()> {
    let keypair = generate_ed25519_keypair()?;
    let password = "secure-password";

    // Encrypt
    let encrypted = encrypt_private_key(&keypair.secret_bytes(), password)?;

    // Decrypt
    let decrypted = decrypt_private_key(&encrypted, password)?;

    // Verify
    assert_eq!(keypair.secret_bytes().to_vec(), decrypted);

    // Wrong password should fail
    let wrong_result = decrypt_private_key(&encrypted, "wrong-password");
    assert!(wrong_result.is_err());

    Ok(())
}

#[test]
fn test_complete_certificate_chain_workflow() -> Result<()> {
    // 1. Generate keys
    let root_keypair = generate_ed25519_keypair()?;
    let inter_keypair = generate_ed25519_keypair()?;
    let entity_keypair = generate_ed25519_keypair()?;

    // 2. Create Root CA
    let root_cert = create_root_ca(&root_keypair, "CN=Test Root CA,O=Test Org", 3650)?;
    let root_pem = root_cert.serialize_pem().unwrap();
    assert!(root_pem.contains("BEGIN CERTIFICATE"));

    // 3. Create Intermediate CA (note: self-signed due to rcgen 0.12)
    let inter_cert =
        create_intermediate_ca(&root_cert, &inter_keypair, "CN=Test Intermediate CA", 1825)?;
    let inter_pem = inter_cert.serialize_pem().unwrap();
    assert!(inter_pem.contains("BEGIN CERTIFICATE"));

    // 4. Create End-Entity Certificate (note: self-signed due to rcgen 0.12)
    let entity_cert = create_end_entity_cert(&inter_cert, &entity_keypair, "CN=example.com", 365)?;
    let entity_pem = entity_cert.serialize_pem().unwrap();
    assert!(entity_pem.contains("BEGIN CERTIFICATE"));

    // 5. Build complete chain
    let chain = build_cert_chain_pem(&entity_cert, &inter_cert, &root_cert)?;
    assert_eq!(chain.matches("BEGIN CERTIFICATE").count(), 3);

    Ok(())
}

#[test]
fn test_keystore_persistence_workflow() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let password = "test-password";
    let keypair = generate_ed25519_keypair()?;
    let public_key = keypair.public_bytes();

    // Create keystore and add key
    {
        let mut keystore = create_keystore(temp_dir.path())?;
        import_key(
            &mut keystore,
            "persistent-key".to_string(),
            &keypair.secret_bytes(),
            password,
        )?;
    }

    // Load keystore in new scope
    {
        let keystore = create_keystore(temp_dir.path())?;
        let keys = list_keys(&keystore)?;
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].alias, "persistent-key");

        let retrieved = get_key(&keystore, "persistent-key", password)?;
        assert_eq!(public_key, retrieved.public_bytes());
    }

    Ok(())
}

#[test]
fn test_multiple_keys_workflow() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let mut keystore = create_keystore(temp_dir.path())?;

    // Add multiple keys
    for i in 0..5 {
        let keypair = generate_ed25519_keypair()?;
        let alias = format!("key-{}", i);
        import_key(&mut keystore, alias, &keypair.secret_bytes(), "password")?;
    }

    // List should show all keys
    let keys = list_keys(&keystore)?;
    assert_eq!(keys.len(), 5);

    // Keys should be sorted by alias
    for i in 0..5 {
        assert_eq!(keys[i].alias, format!("key-{}", i));
    }

    Ok(())
}

#[test]
fn test_certificate_generation_with_keystore() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let mut keystore = create_keystore(temp_dir.path())?;
    let password = "test-password";

    // Generate and store a key
    let keypair = generate_ed25519_keypair()?;
    import_key(
        &mut keystore,
        "ca-key".to_string(),
        &keypair.secret_bytes(),
        password,
    )?;

    // Retrieve key and create certificate
    let retrieved_keypair = get_key(&keystore, "ca-key", password)?;
    let cert = create_root_ca(&retrieved_keypair, "CN=My CA", 365)?;

    // Verify certificate
    let pem = cert.serialize_pem().unwrap();
    assert!(pem.contains("BEGIN CERTIFICATE"));
    assert!(pem.contains("END CERTIFICATE"));

    Ok(())
}

#[test]
fn test_error_handling_workflow() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let keystore = create_keystore(temp_dir.path())?;

    // Test 1: Key not found
    let result = get_key(&keystore, "nonexistent", "password");
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(detls::error::DeTlsError::NotFoundError(_))
    ));

    // Test 2: Wrong password
    let mut keystore = create_keystore(temp_dir.path())?;
    let keypair = generate_ed25519_keypair()?;
    import_key(
        &mut keystore,
        "test".to_string(),
        &keypair.secret_bytes(),
        "correct",
    )?;

    let result = get_key(&keystore, "test", "wrong");
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(detls::error::DeTlsError::InvalidPasswordError)
    ));

    // Test 3: Duplicate alias
    let result = import_key(
        &mut keystore,
        "test".to_string(),
        &keypair.secret_bytes(),
        "password",
    );
    assert!(result.is_err());
    assert!(matches!(
        result,
        Err(detls::error::DeTlsError::AlreadyExistsError(_))
    ));

    Ok(())
}

#[test]
fn test_file_based_workflow() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let mut keystore = create_keystore(temp_dir.path())?;
    let password = "password";

    // Generate key and create certificate
    let keypair = generate_ed25519_keypair()?;
    import_key(
        &mut keystore,
        "root-ca".to_string(),
        &keypair.secret_bytes(),
        password,
    )?;

    let retrieved = get_key(&keystore, "root-ca", password)?;
    let cert = create_root_ca(&retrieved, "CN=Test Root CA", 365)?;

    // Write certificate to file
    let cert_path = temp_dir.path().join("root-ca.pem");
    fs::write(&cert_path, cert.serialize_pem().unwrap())?;

    // Verify file exists and contains certificate
    let cert_content = fs::read_to_string(&cert_path)?;
    assert!(cert_content.contains("BEGIN CERTIFICATE"));
    assert!(cert_content.contains("END CERTIFICATE"));

    Ok(())
}
