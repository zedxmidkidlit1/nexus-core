//! Test database encryption
//!
//! Run with: cargo test --lib test_encryption -- --nocapture

#[cfg(test)]
mod tests {
    use crate::Database;
    use std::path::PathBuf;

    #[test]
    fn test_encrypted_database_creation() {
        // Create encrypted database
        let test_path = PathBuf::from("test_encrypted.db");

        // Delete if exists
        let _ = std::fs::remove_file(&test_path);

        let db = Database::new(test_path.clone()).expect("Should create encrypted database");

        println!("✅ Encrypted database created successfully!");
        println!("📁 Location: {:?}", test_path);

        // Clean up
        drop(db);
        let _ = std::fs::remove_file(&test_path);
    }

    #[test]
    fn test_encryption_key_consistency() {
        use crate::database::encryption::get_encryption_key;

        let key1 = get_encryption_key().expect("Should get key");
        let key2 = get_encryption_key().expect("Should get key");

        assert_eq!(key1, key2, "Same machine should generate same key");
        assert_eq!(key1.len(), 32, "Key should be 32 bytes (256 bits)");

        println!("✅ Encryption key is consistent!");
        println!("🔑 Key (hex, first 16 bytes): {}", hex::encode(&key1[..16]));
    }
}
