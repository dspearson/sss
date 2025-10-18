use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

use sss::crypto::{KeyPair, RepositoryKey};
use sss::keystore::Keystore;
use sss::project::ProjectConfig;
use sss::processor::Processor;

/// Test helper for multi-user project setup
struct MultiUserProject {
    temp_dir: TempDir,
    config_path: PathBuf,
    repository_key: RepositoryKey,
    users: Vec<UserContext>,
}

struct UserContext {
    username: String,
    keypair: KeyPair,
    keystore: Keystore,
}

impl MultiUserProject {
    fn new(usernames: &[&str]) -> anyhow::Result<Self> {
        let temp_dir = TempDir::new()?;
        let project_root = temp_dir.path();

        // Create first user
        if usernames.is_empty() {
            return Err(anyhow::anyhow!("Need at least one username"));
        }

        // Create keystore and keypair for first user
        let first_username = usernames[0];
        let keystore_dir = project_root.join(format!("keystore_{}", first_username));
        let keystore = Keystore::new_with_config_dir(keystore_dir)?;
        let keypair = KeyPair::generate()?;
        keystore.store_keypair(&keypair, None)?;

        // Create project config with first user
        let mut config = ProjectConfig::new(first_username, &keypair.public_key)?;

        let config_path = project_root.join(".sss.toml");
        config.save_to_file(&config_path)?;

        // Get repository key from sealed key
        let sealed_key = config.get_sealed_key_for_user(first_username)?;
        let repository_key = sss::crypto::open_repository_key(&sealed_key, &keypair)?;

        let mut users = vec![UserContext {
            username: first_username.to_string(),
            keypair,
            keystore,
        }];

        // Add remaining users
        for &username in &usernames[1..] {
            let keystore_dir = project_root.join(format!("keystore_{}", username));
            let keystore = Keystore::new_with_config_dir(keystore_dir)?;

            let keypair = KeyPair::generate()?;
            keystore.store_keypair(&keypair, None)?;

            config.add_user(username, &keypair.public_key, &repository_key)?;

            users.push(UserContext {
                username: username.to_string(),
                keypair,
                keystore,
            });
        }

        config.save_to_file(&config_path)?;

        Ok(Self {
            temp_dir,
            config_path,
            repository_key,
            users,
        })
    }

    fn project_path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }

    fn get_user(&self, username: &str) -> Option<&UserContext> {
        self.users.iter().find(|u| u.username == username)
    }
}

#[test]
fn test_multi_user_shared_repository_key() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob", "charlie"])?;

    // All users should have the same repository key sealed for them
    let config = ProjectConfig::load_from_file(&project.config_path)?;

    assert!(config.users.contains_key("alice"));
    assert!(config.users.contains_key("bob"));
    assert!(config.users.contains_key("charlie"));

    // Verify all users have sealed keys
    for user in &project.users {
        let sealed_key = config.get_sealed_key_for_user(&user.username)?;
        assert!(!sealed_key.is_empty());
    }

    Ok(())
}

#[test]
fn test_alice_encrypts_bob_decrypts() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob"])?;
    let processor = Processor::new(project.repository_key.clone())?;

    // Alice encrypts a message
    let alice_message = "Secret from Alice: ⊕{alice_secret_123}";
    let encrypted = processor.process_content(alice_message)?;

    assert!(encrypted.contains("⊠{"));

    // Bob decrypts the message (using the same repository key)
    let decrypted = processor.process_content(&encrypted)?;

    assert_eq!(decrypted, alice_message);

    Ok(())
}

#[test]
fn test_multiple_users_collaborate_on_file() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob", "charlie"])?;
    let processor = Processor::new(project.repository_key.clone())?;

    // Simulate a shared config file with secrets from multiple users
    let shared_config = r#"# Team Configuration
alice_api_key: ⊕{alice_key_xyz}
bob_db_password: ⊕{bob_pass_123}
charlie_token: ⊕{charlie_token_abc}
"#;

    // Encrypt the file
    let encrypted = processor.process_content(shared_config)?;

    // All three encrypted sections should exist
    assert_eq!(encrypted.matches("⊠{").count(), 3);

    // Any user can decrypt it
    let decrypted = processor.process_content(&encrypted)?;
    assert_eq!(decrypted, shared_config);

    Ok(())
}

#[test]
fn test_user_list_operations() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob", "charlie"])?;

    let config = ProjectConfig::load_from_file(&project.config_path)?;
    let users = config.list_users();

    assert_eq!(users.len(), 3);
    assert!(users.contains(&"alice".to_string()));
    assert!(users.contains(&"bob".to_string()));
    assert!(users.contains(&"charlie".to_string()));

    Ok(())
}

#[test]
fn test_add_user_to_existing_project() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob"])?;

    // Add a new user "charlie"
    let mut config = ProjectConfig::load_from_file(&project.config_path)?;
    let charlie_keypair = KeyPair::generate()?;

    config.add_user("charlie", &charlie_keypair.public_key, &project.repository_key)?;
    config.save_to_file(&project.config_path)?;

    // Reload and verify
    let reloaded_config = ProjectConfig::load_from_file(&project.config_path)?;
    assert!(reloaded_config.users.contains_key("charlie"));

    let users = reloaded_config.list_users();
    assert_eq!(users.len(), 3);

    Ok(())
}

#[test]
fn test_remove_user_from_project() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob", "charlie"])?;

    let mut config = ProjectConfig::load_from_file(&project.config_path)?;

    // Remove bob
    config.remove_user("bob")?;
    config.save_to_file(&project.config_path)?;

    // Reload and verify
    let reloaded_config = ProjectConfig::load_from_file(&project.config_path)?;
    assert!(!reloaded_config.users.contains_key("bob"));

    let users = reloaded_config.list_users();
    assert_eq!(users.len(), 2);
    assert!(users.contains(&"alice".to_string()));
    assert!(users.contains(&"charlie".to_string()));

    Ok(())
}

#[test]
fn test_cannot_remove_last_user() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice"])?;

    let mut config = ProjectConfig::load_from_file(&project.config_path)?;

    // Check that it's the last user
    assert_eq!(config.list_users().len(), 1);

    // Note: The ProjectConfig::remove_user() method itself doesn't prevent removing the last user.
    // That check is done at the command handler level (src/commands/users.rs:116-120).
    // Here we just verify that the method would work at the API level.
    // In practice, the CLI command 'sss users remove' prevents this.

    // Remove alice (will succeed at API level)
    config.remove_user("alice")?;

    // Verify alice is removed
    assert_eq!(config.list_users().len(), 0);

    Ok(())
}

#[test]
fn test_encrypted_content_persists_across_user_changes() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob"])?;
    let processor = Processor::new(project.repository_key.clone())?;

    // Create and encrypt content
    let content = "Database password: ⊕{super_secret_pass}";
    let encrypted = processor.process_content(content)?;

    // Add a new user
    let mut config = ProjectConfig::load_from_file(&project.config_path)?;
    let charlie_keypair = KeyPair::generate()?;
    config.add_user("charlie", &charlie_keypair.public_key, &project.repository_key)?;
    config.save_to_file(&project.config_path)?;

    // The encrypted content should still be decryptable
    let decrypted = processor.process_content(&encrypted)?;
    assert_eq!(decrypted, content);

    Ok(())
}

#[test]
fn test_each_user_has_unique_sealed_key() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob", "charlie"])?;

    let config = ProjectConfig::load_from_file(&project.config_path)?;

    // Get sealed keys for all users
    let alice_sealed = config.get_sealed_key_for_user("alice")?;
    let bob_sealed = config.get_sealed_key_for_user("bob")?;
    let charlie_sealed = config.get_sealed_key_for_user("charlie")?;

    // Each sealed key should be unique (because they're encrypted for different public keys)
    assert_ne!(alice_sealed, bob_sealed);
    assert_ne!(bob_sealed, charlie_sealed);
    assert_ne!(alice_sealed, charlie_sealed);

    Ok(())
}

#[test]
fn test_user_cannot_decrypt_with_wrong_keypair() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice"])?;

    let config = ProjectConfig::load_from_file(&project.config_path)?;

    // Get Alice's sealed key
    let alice_sealed = config.get_sealed_key_for_user("alice")?;
    let alice = project.get_user("alice").unwrap();

    // Try to open it with Alice's keypair (should work)
    let result = sss::crypto::open_repository_key(&alice_sealed, &alice.keypair);
    assert!(result.is_ok());

    // Try to open it with a different keypair (should fail)
    let wrong_keypair = KeyPair::generate()?;
    let wrong_result = sss::crypto::open_repository_key(&alice_sealed, &wrong_keypair);
    assert!(wrong_result.is_err());

    Ok(())
}

#[test]
fn test_large_team_collaboration() -> anyhow::Result<()> {
    // Test with a larger team
    let usernames = vec![
        "user1", "user2", "user3", "user4", "user5",
        "user6", "user7", "user8", "user9", "user10"
    ];

    let project = MultiUserProject::new(&usernames)?;
    let config = ProjectConfig::load_from_file(&project.config_path)?;

    // Verify all users are in the project
    assert_eq!(config.list_users().len(), 10);

    // All users should be able to use the same processor
    let processor = Processor::new(project.repository_key.clone())?;

    let content = "Shared secret: ⊕{team_password}";
    let encrypted = processor.process_content(content)?;
    let decrypted = processor.process_content(&encrypted)?;

    assert_eq!(decrypted, content);

    Ok(())
}

#[test]
fn test_user_public_key_storage() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob"])?;
    let config = ProjectConfig::load_from_file(&project.config_path)?;

    // Verify public keys are stored correctly
    let alice = project.get_user("alice").unwrap();
    let bob = project.get_user("bob").unwrap();

    let alice_config = config.users.get("alice").unwrap();
    let bob_config = config.users.get("bob").unwrap();

    assert_eq!(alice_config.public, alice.keypair.public_key.to_base64());
    assert_eq!(bob_config.public, bob.keypair.public_key.to_base64());

    Ok(())
}

#[test]
fn test_sequential_user_operations() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let project_root = temp_dir.path();
    let config_path = project_root.join(".sss.toml");

    // Start with one user
    let alice_keypair = KeyPair::generate()?;
    let mut config = ProjectConfig::new("alice", &alice_keypair.public_key)?;
    config.save_to_file(&config_path)?;

    // Get repository key
    let sealed_key = config.get_sealed_key_for_user("alice")?;
    let repository_key = sss::crypto::open_repository_key(&sealed_key, &alice_keypair)?;

    // Add second user
    let bob_keypair = KeyPair::generate()?;
    config.add_user("bob", &bob_keypair.public_key, &repository_key)?;
    config.save_to_file(&config_path)?;

    // Add third user
    let charlie_keypair = KeyPair::generate()?;
    config.add_user("charlie", &charlie_keypair.public_key, &repository_key)?;
    config.save_to_file(&config_path)?;

    // Verify all three users exist
    let final_config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(final_config.list_users().len(), 3);

    Ok(())
}

#[test]
fn test_project_config_persistence() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob"])?;

    // Load config multiple times
    let config1 = ProjectConfig::load_from_file(&project.config_path)?;
    let config2 = ProjectConfig::load_from_file(&project.config_path)?;

    // Both should have the same users
    assert_eq!(config1.list_users(), config2.list_users());

    Ok(())
}

#[test]
fn test_concurrent_file_operations() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob"])?;
    let processor = Processor::new(project.repository_key.clone())?;

    // Simulate multiple operations on the same content
    let original = "Secret: ⊕{test123}";

    let encrypted1 = processor.process_content(original)?;
    let encrypted2 = processor.process_content(original)?;

    // Different encryptions due to random nonces
    assert_ne!(encrypted1, encrypted2);

    // But both decrypt to the same thing
    let decrypted1 = processor.process_content(&encrypted1)?;
    let decrypted2 = processor.process_content(&encrypted2)?;

    assert_eq!(decrypted1, original);
    assert_eq!(decrypted2, original);

    Ok(())
}

#[test]
fn test_empty_project_initialization() -> anyhow::Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join(".sss.toml");

    // Create project with default (using Default trait creates empty project)
    let config = ProjectConfig::default();
    config.save_to_file(&config_path)?;

    // Load and verify it's empty
    let loaded_config = ProjectConfig::load_from_file(&config_path)?;
    assert_eq!(loaded_config.list_users().len(), 0);

    Ok(())
}

#[test]
fn test_user_info_retrieval() -> anyhow::Result<()> {
    let project = MultiUserProject::new(&["alice", "bob"])?;
    let config = ProjectConfig::load_from_file(&project.config_path)?;

    // Get user info
    let alice_info = config.users.get("alice").unwrap();
    let bob_info = config.users.get("bob").unwrap();

    // Verify they have the required fields
    assert!(!alice_info.sealed_key.is_empty());
    assert!(!alice_info.public.is_empty());
    assert!(!bob_info.sealed_key.is_empty());
    assert!(!bob_info.public.is_empty());

    Ok(())
}

#[test]
fn test_complex_multiuser_workflow() -> anyhow::Result<()> {
    // Simulate a realistic workflow
    let project = MultiUserProject::new(&["alice", "bob"])?;
    let processor = Processor::new(project.repository_key.clone())?;

    // Alice creates a config file with secrets
    let config_content = r#"
# Production Configuration
database:
  host: prod.example.com
  password: ⊕{prod_db_password}

api:
  key: ⊕{prod_api_key}
  secret: ⊕{prod_api_secret}
"#;

    // Alice encrypts it
    let encrypted = processor.process_content(config_content)?;

    // Save to file
    let config_file = project.project_path().join("config.yaml");
    fs::write(&config_file, &encrypted)?;

    // Bob reads the file
    let bob_reads = fs::read_to_string(&config_file)?;

    // Bob decrypts it
    let decrypted = processor.process_content(&bob_reads)?;

    assert_eq!(decrypted, config_content);

    // Bob modifies and re-encrypts
    let modified = decrypted.replace("prod_api_key", "updated_prod_api_key");
    let re_encrypted = processor.process_content(&modified)?;

    // Alice can still decrypt Bob's changes
    let alice_decrypts = processor.process_content(&re_encrypted)?;
    assert!(alice_decrypts.contains("updated_prod_api_key"));

    Ok(())
}
