use tempfile::TempDir;

use sss::crypto::KeyPair;
use sss::keystore::Keystore;
use sss::project::ProjectConfig;

/// Test that demonstrates multi-key matching concept
/// This verifies the building blocks work correctly
#[test]
fn test_find_user_by_public_key_matching() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Create Alice and Bob keypairs
    let alice_keypair = KeyPair::generate()?;
    let bob_keypair = KeyPair::generate()?;

    // Create project with both users
    let mut config = ProjectConfig::new("alice", &alice_keypair.public_key())?;
    let alice_sealed = config.get_sealed_key_for_user("alice")?;
    let repository_key = sss::crypto::open_repository_key(&alice_sealed, &alice_keypair)?;

    config.add_user("bob", &bob_keypair.public_key(), &repository_key)?;
    config.save_to_file(&config_path)?;

    // Reload config
    let loaded_config = ProjectConfig::load_from_file(&config_path)?;

    // Test that we can find users by their public keys
    let alice_found = loaded_config.find_user_by_public_key(&alice_keypair.public_key());
    let bob_found = loaded_config.find_user_by_public_key(&bob_keypair.public_key());

    assert_eq!(alice_found, Some("alice".to_string()));
    assert_eq!(bob_found, Some("bob".to_string()));

    // Test with a keypair that's not in the project
    let unknown_keypair = KeyPair::generate()?;
    let unknown_found = loaded_config.find_user_by_public_key(&unknown_keypair.public_key());
    assert_eq!(unknown_found, None);

    Ok(())
}

/// Test that multiple keypairs can be stored and retrieved
#[test]
fn test_keystore_multiple_keypairs() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let keystore_dir = temp_dir.path().join("test_keystore");
    let keystore = Keystore::new_with_config_dir(keystore_dir)?;

    // Generate and store multiple keypairs
    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;
    let keypair3 = KeyPair::generate()?;

    let key_id1 = keystore.store_keypair(&keypair1, None)?;
    let key_id2 = keystore.store_keypair(&keypair2, None)?;
    let key_id3 = keystore.store_keypair(&keypair3, None)?;

    // Verify we can list all keys
    let keys = keystore.list_key_ids()?;
    assert_eq!(keys.len(), 3);

    // Verify we can load each keypair
    let loaded1 = keystore.load_keypair(&key_id1, None)?;
    let loaded2 = keystore.load_keypair(&key_id2, None)?;
    let loaded3 = keystore.load_keypair(&key_id3, None)?;

    assert_eq!(loaded1.public_key().to_base64(), keypair1.public_key().to_base64());
    assert_eq!(loaded2.public_key().to_base64(), keypair2.public_key().to_base64());
    assert_eq!(loaded3.public_key().to_base64(), keypair3.public_key().to_base64());

    Ok(())
}

/// Test that we can retrieve all keypairs (simulating the fallback search)
#[test]
fn test_keystore_get_all_keypairs() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let keystore_dir = temp_dir.path().join("test_keystore");
    let keystore = Keystore::new_with_config_dir(keystore_dir)?;

    // Store multiple unprotected keypairs
    let keypair1 = KeyPair::generate()?;
    let keypair2 = KeyPair::generate()?;
    let keypair3 = KeyPair::generate()?;

    keystore.store_keypair(&keypair1, None)?;
    keystore.store_keypair(&keypair2, None)?;
    keystore.store_keypair(&keypair3, None)?;

    // Get all keypairs (no password needed for unprotected keys)
    let all_keypairs = keystore.get_all_keypairs(None)?;

    assert_eq!(all_keypairs.len(), 3);

    // Verify all public keys match
    let public_keys: Vec<String> = all_keypairs
        .iter()
        .map(|kp| kp.public_key().to_base64())
        .collect();

    assert!(public_keys.contains(&keypair1.public_key().to_base64()));
    assert!(public_keys.contains(&keypair2.public_key().to_base64()));
    assert!(public_keys.contains(&keypair3.public_key().to_base64()));

    Ok(())
}

/// Test that unsealing works with any authorized keypair
#[test]
fn test_unseal_with_different_authorized_keys() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Create three users
    let alice_keypair = KeyPair::generate()?;
    let bob_keypair = KeyPair::generate()?;
    let charlie_keypair = KeyPair::generate()?;

    // Create project with all three users
    let mut config = ProjectConfig::new("alice", &alice_keypair.public_key())?;
    let alice_sealed = config.get_sealed_key_for_user("alice")?;
    let repository_key = sss::crypto::open_repository_key(&alice_sealed, &alice_keypair)?;

    config.add_user("bob", &bob_keypair.public_key(), &repository_key)?;
    config.add_user("charlie", &charlie_keypair.public_key(), &repository_key)?;
    config.save_to_file(&config_path)?;

    // Each user should be able to unseal their sealed key and get the same repository key
    let bob_sealed = config.get_sealed_key_for_user("bob")?;
    let charlie_sealed = config.get_sealed_key_for_user("charlie")?;

    let alice_repo_key = sss::crypto::open_repository_key(&alice_sealed, &alice_keypair)?;
    let bob_repo_key = sss::crypto::open_repository_key(&bob_sealed, &bob_keypair)?;
    let charlie_repo_key = sss::crypto::open_repository_key(&charlie_sealed, &charlie_keypair)?;

    // All three should have the same repository key (for encryption/decryption)
    // We can verify this by using them to encrypt/decrypt
    let processor_alice = sss::processor::Processor::new(alice_repo_key)?;
    let processor_bob = sss::processor::Processor::new(bob_repo_key)?;
    let processor_charlie = sss::processor::Processor::new(charlie_repo_key)?;

    let content = "Secret: ⊕{test123}";
    let encrypted_by_alice = processor_alice.process_content(content)?;

    // Bob and Charlie should be able to decrypt Alice's encryption
    let decrypted_by_bob = processor_bob.process_content(&encrypted_by_alice)?;
    let decrypted_by_charlie = processor_charlie.process_content(&encrypted_by_alice)?;

    assert_eq!(decrypted_by_bob, content);
    assert_eq!(decrypted_by_charlie, content);

    Ok(())
}

/// Test simulating the scenario where we have multiple keys and need to find the right one
#[test]
fn test_multi_key_scenario_simulation() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Scenario: User has worked on multiple projects
    // They have Alice's key from project A, and Bob's key from project B
    let alice_keypair = KeyPair::generate()?;
    let bob_keypair = KeyPair::generate()?;

    // Current project has Bob as a user
    let config = ProjectConfig::new("bob", &bob_keypair.public_key())?;
    config.save_to_file(&config_path)?;

    // Simulate having multiple keys available
    let available_keys = vec![alice_keypair.clone(), bob_keypair.clone()];

    // Find which key matches the project
    let loaded_config = ProjectConfig::load_from_file(&config_path)?;
    let mut matched_user = None;
    let mut matched_keypair = None;

    for keypair in &available_keys {
        if let Some(username) = loaded_config.find_user_by_public_key(&keypair.public_key()) {
            matched_user = Some(username);
            matched_keypair = Some(keypair.clone());
            break;
        }
    }

    // Bob's key should match
    assert_eq!(matched_user, Some("bob".to_string()));
    assert!(matched_keypair.is_some());

    let matched = matched_keypair.unwrap();
    assert_eq!(matched.public_key().to_base64(), bob_keypair.public_key().to_base64());

    Ok(())
}
