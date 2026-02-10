//! Software-level database encryption using AES-256-GCM
//!
//! Provides encryption/decryption for database exports without requiring SQLCipher.
//! This works on all platforms and avoids Windows build issues.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

const APP_KDF_CONTEXT: &str = "netmapper-2026-secure-aes256-gcm";
const ARGON2_SALT: &[u8] = b"netmapper-2026-kdf-salt";
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;

/// Generate encryption key from machine ID
///
/// Same as before but now used for AES encryption
pub fn get_encryption_key() -> Result<[u8; 32], Box<dyn Error>> {
    let machine_material = get_machine_binding_material();
    tracing::debug!("Deriving encryption key with Argon2id");
    derive_key_from_machine_material(&machine_material)
}

/// Legacy key derivation retained for decrypt compatibility with old exports.
fn get_legacy_encryption_key() -> Result<[u8; 32], Box<dyn Error>> {
    let machine_material = get_machine_binding_material();
    derive_legacy_key_from_machine_material(&machine_material)
}

fn get_machine_binding_material() -> String {
    match machine_uid::get() {
        Ok(machine_id) => {
            tracing::debug!("Machine ID obtained for encryption");
            machine_id
        }
        Err(e) => {
            tracing::warn!("Could not get machine ID: {}, using fallback", e);
            format!(
                "{}-{}",
                whoami::username(),
                whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string())
            )
        }
    }
}

/// Derive 256-bit encryption key from machine-specific material using Argon2id.
fn derive_key_from_machine_material(machine_material: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let combined = format!("{}-{}", machine_material, APP_KDF_CONTEXT);
    derive_key_from_string_argon2(&combined)
}

/// Derive legacy SHA-256 key from machine-specific material (backward compatibility only).
fn derive_legacy_key_from_machine_material(
    machine_material: &str,
) -> Result<[u8; 32], Box<dyn Error>> {
    let combined = format!("{}-{}", machine_material, APP_KDF_CONTEXT);
    derive_key_from_string_legacy_sha256(&combined)
}

/// Derive 256-bit key from any string using Argon2id.
fn derive_key_from_string_argon2(input: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| format!("Argon2 parameter error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(input.as_bytes(), ARGON2_SALT, &mut key)
        .map_err(|e| format!("Argon2 key derivation failed: {}", e))?;
    Ok(key)
}

/// Legacy SHA-256 derivation kept for decrypting older encrypted exports.
fn derive_key_from_string_legacy_sha256(input: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);

    Ok(key)
}

/// Encrypt database file using AES-256-GCM
///
/// Creates an encrypted copy of the database with .encrypted extension
pub fn encrypt_database_file<P: AsRef<Path>>(db_path: P) -> Result<String, Box<dyn Error>> {
    let db_path = db_path.as_ref();
    let encrypted_path = encrypted_output_path(db_path);

    tracing::info!("Encrypting database: {:?} -> {:?}", db_path, encrypted_path);

    // Read database file
    let plaintext = fs::read(db_path)?;

    // Generate encryption key
    let key_bytes = get_encryption_key()?;
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Generate random nonce (96 bits for GCM)
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Prepend nonce to ciphertext (needed for decryption)
    let mut output = Vec::new();
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    // Write encrypted file
    fs::write(&encrypted_path, output)?;

    tracing::info!(
        "Database encrypted successfully: {} bytes",
        ciphertext.len()
    );

    Ok(encrypted_path.to_string_lossy().to_string())
}

/// Decrypt database file using AES-256-GCM
///
/// Decrypts a .encrypted file back to .db
pub fn decrypt_database_file<P: AsRef<Path>>(encrypted_path: P) -> Result<String, Box<dyn Error>> {
    let encrypted_path = encrypted_path.as_ref();
    let db_path = decrypted_output_path(encrypted_path);

    tracing::info!("Decrypting database: {:?} -> {:?}", encrypted_path, db_path);

    // Read encrypted file
    let data = fs::read(encrypted_path)?;

    if data.len() < 12 {
        return Err("Invalid encrypted file: too short".into());
    }

    // Extract nonce (first 12 bytes)
    let nonce_bytes = &data[..12];
    let nonce = Nonce::from_slice(nonce_bytes);

    // Extract ciphertext (rest of file)
    let ciphertext = &data[12..];

    // Try decrypting with the current Argon2 key first, then legacy SHA-256 key.
    let mut candidates = vec![get_encryption_key()?];
    let legacy = get_legacy_encryption_key()?;
    if !candidates.iter().any(|k| k == &legacy) {
        candidates.push(legacy);
    }

    let mut plaintext: Option<Vec<u8>> = None;
    let mut last_error = String::new();
    for key_bytes in candidates {
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        match cipher.decrypt(nonce, ciphertext) {
            Ok(bytes) => {
                plaintext = Some(bytes);
                break;
            }
            Err(e) => {
                last_error = e.to_string();
            }
        }
    }

    let plaintext = plaintext.ok_or_else(|| {
        format!(
            "Decryption failed with all supported key derivation strategies. Last error: {}",
            if last_error.is_empty() {
                "unknown"
            } else {
                &last_error
            }
        )
    })?;

    // Write decrypted database
    fs::write(&db_path, plaintext)?;

    tracing::info!("Database decrypted successfully");

    Ok(db_path.to_string_lossy().to_string())
}

/// Generate a random 96-bit nonce for AES-GCM
fn generate_nonce() -> [u8; 12] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn encrypted_output_path(db_path: &Path) -> PathBuf {
    let mut output = db_path.as_os_str().to_os_string();
    output.push(".encrypted");
    PathBuf::from(output)
}

fn decrypted_output_path(encrypted_path: &Path) -> PathBuf {
    match encrypted_path.extension().and_then(|ext| ext.to_str()) {
        Some("encrypted") => encrypted_path.with_extension(""),
        _ => {
            let mut output = encrypted_path.as_os_str().to_os_string();
            output.push(".decrypted.db");
            PathBuf::from(output)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_get_encryption_key() {
        let key = get_encryption_key().expect("Should generate key");
        assert_eq!(key.len(), 32); // 256 bits

        // Same call should return same key
        let key2 = get_encryption_key().expect("Should generate key");
        assert_eq!(key, key2);
    }

    #[test]
    fn test_legacy_key_derivation_still_available() {
        let machine_material = get_machine_binding_material();
        let key = derive_legacy_key_from_machine_material(&machine_material)
            .expect("Should generate legacy key");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create a test database file
        let test_db = "test_encryption.db";
        let test_data = b"This is a test database with some data";
        fs::write(test_db, test_data).unwrap();

        // Encrypt
        let encrypted_path = encrypt_database_file(test_db).unwrap();
        assert!(Path::new(&encrypted_path).exists());

        // Decrypt
        let decrypted_path = decrypt_database_file(&encrypted_path).unwrap();
        let decrypted_data = fs::read(&decrypted_path).unwrap();

        assert_eq!(test_data.as_ref(), decrypted_data.as_slice());

        // Cleanup
        let _ = fs::remove_file(test_db);
        let _ = fs::remove_file(&encrypted_path);
        let _ = fs::remove_file(&decrypted_path);
    }

    #[test]
    fn test_decrypt_legacy_sha256_encrypted_file() {
        let test_db = "test_legacy_encryption.db";
        let plaintext = b"legacy encrypted content";
        fs::write(test_db, plaintext).unwrap();

        let machine_material = get_machine_binding_material();
        let key_bytes = derive_legacy_key_from_machine_material(&machine_material).unwrap();
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce_bytes = generate_nonce();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();

        let encrypted_path = Path::new(test_db).with_extension("db.encrypted");
        let mut output = Vec::new();
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);
        fs::write(&encrypted_path, output).unwrap();

        let decrypted_path = decrypt_database_file(&encrypted_path).unwrap();
        let decrypted = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);

        let _ = fs::remove_file(test_db);
        let _ = fs::remove_file(&encrypted_path);
        let _ = fs::remove_file(&decrypted_path);
    }
}
