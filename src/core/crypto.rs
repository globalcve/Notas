use aes_gcm::{
    aead::{AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key, Tag,
};
use argon2::{
    password_hash::rand_core::RngCore,
    Argon2, Params, Algorithm, Version,
};
use anyhow::{Result, anyhow};
use zeroize::Zeroize;

use super::data::Argon2Params;

// Constants
pub const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32; // AES-256 key size

// Header structure for the encrypted file
#[derive(Debug)]
pub struct EncryptedHeader {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub tag: [u8; TAG_LEN],
}

// Full encrypted data structure
pub struct EncryptedData {
    pub header: EncryptedHeader,
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.salt);
        bytes.extend_from_slice(&self.header.nonce);
        bytes.extend_from_slice(&self.header.tag);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
            return Err(anyhow!("Encrypted data is too short"));
        }

        let (salt_slice, rest) = bytes.split_at(SALT_LEN);
        let (nonce_slice, rest) = rest.split_at(NONCE_LEN);
        let (tag_slice, ciphertext) = rest.split_at(TAG_LEN);

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(salt_slice);

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(tag_slice);

        Ok(EncryptedData {
            header: EncryptedHeader { salt, nonce, tag },
            ciphertext: ciphertext.to_vec(),
        })
    }
}

// Key Derivation Function (KDF) with default params
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Key<Aes256Gcm>> {
    derive_key_with_params(password, salt, &Argon2Params::default())
}

// Key Derivation Function (KDF) with custom params
pub fn derive_key_with_params(password: &[u8], salt: &[u8; SALT_LEN], argon2_params: &Argon2Params) -> Result<Key<Aes256Gcm>> {
    let params = Params::new(
        argon2_params.memory_cost,
        argon2_params.time_cost,
        argon2_params.parallelism,
        Some(KEY_LEN),
    ).map_err(|e| anyhow!("Invalid Argon2 parameters: {}", e))?;
    
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key_bytes = [0u8; KEY_LEN];
    
    argon2.hash_password_into(
        password,
        salt,
        &mut key_bytes,
    ).map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let key = Key::<Aes256Gcm>::from(key_bytes);
    key_bytes.zeroize();

    Ok(key)
}

// Encryption function (salt is passed in, not regenerated)
pub fn encrypt(key: &Key<Aes256Gcm>, salt: &[u8; SALT_LEN], plaintext: &[u8]) -> Result<EncryptedData> {
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut buffer = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut buffer)
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    let mut tag_bytes = [0u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());

    Ok(EncryptedData {
        header: EncryptedHeader { salt: *salt, nonce: nonce_bytes, tag: tag_bytes },
        ciphertext: buffer,
    })
}

// Decryption function
pub fn decrypt(key: &Key<Aes256Gcm>, encrypted_data: &EncryptedData) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&encrypted_data.header.nonce);
    let tag = Tag::from_slice(&encrypted_data.header.tag);

    let mut buffer = encrypted_data.ciphertext.clone();
    
    cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
        .map_err(|e| anyhow!("Decryption failed: {}", e))?;

    Ok(buffer)
}

// Helper to generate a new random salt
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

// Helper to generate a key for initial file creation with default params
#[allow(dead_code)]
pub fn generate_test_key(password: &[u8]) -> Result<(Key<Aes256Gcm>, [u8; SALT_LEN])> {
    generate_test_key_with_params(password, &Argon2Params::default())
}

// Helper to generate a key for initial file creation with custom params
pub fn generate_test_key_with_params(password: &[u8], argon2_params: &Argon2Params) -> Result<(Key<Aes256Gcm>, [u8; SALT_LEN])> {
    let salt = generate_salt();
    let key = derive_key_with_params(password, &salt, argon2_params)?;
    Ok((key, salt))
}

