use std::{fs, path::PathBuf};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::RwLock;
use anyhow::{Result, anyhow};
use aes_gcm::Key;
use dirs::data_dir;
use once_cell::sync::OnceCell;
use zeroize::Zeroize;

use super::{
    data::{NoteList, MasterPassword, AppSettings, SecureBuffer, Argon2Params, EncryptionMode},
    crypto::{self, EncryptedData, SALT_LEN},
    cascade,
};

// Use RwLock for the crypto state to allow proper clearing
static CRYPTO_STATE: OnceCell<RwLock<Option<CryptoState>>> = OnceCell::new();

// Redirect file name - placed in default location to point to custom location
const REDIRECT_FILE: &str = "notes.redirect";

struct CryptoState {
    /// Cached AES-256-GCM key + salt for the single-layer mode fast path.
    key: Key<aes_gcm::Aes256Gcm>,
    salt: [u8; SALT_LEN],
    /// Master password, retained for the session so cascade saves can re-seal
    /// the content key (tesseract derives the KEK from the passphrase per save).
    password: SecureBuffer,
}

impl Zeroize for CryptoState {
    fn zeroize(&mut self) {
        // Key is 32 bytes, we need to zeroize the underlying data
        let key_bytes: &mut [u8; 32] = unsafe {
            &mut *(self.key.as_mut_ptr() as *mut [u8; 32])
        };
        key_bytes.zeroize();
        self.salt.zeroize();
        self.password.zeroize();
    }
}

impl Drop for CryptoState {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub struct CoreManager {
    data_path: PathBuf,
    note_list: NoteList,
    settings: AppSettings,
}

impl CoreManager {
    pub fn new() -> Result<Self> {
        let mut settings = AppSettings::load();

        // Check for redirect file if no custom path is set in settings
        // This handles the case where settings.json was lost but redirect exists
        if settings.custom_db_path.is_none() {
            if let Some(redirect_path) = Self::check_redirect_file()? {
                settings.custom_db_path = Some(redirect_path);
                // Restore the settings file
                let _ = settings.save();
            }
        }

        let data_path = Self::resolve_data_path(&settings)?;

        Ok(Self {
            data_path,
            note_list: NoteList::new(),
            settings,
        })
    }

    /// Get the default app data directory
    fn get_default_app_dir() -> Result<PathBuf> {
        let data_dir = data_dir().ok_or_else(|| anyhow!("Could not find data directory"))?;
        let app_dir = data_dir.join("notas");
        fs::create_dir_all(&app_dir)?;
        // Owner-only (0700): the vault and its temp files live here, so no other
        // local user should be able to list or read them. Best-effort tighten of
        // an existing dir that may have been created world-readable by an older
        // build (or by create_dir_all under a permissive umask).
        let _ = fs::set_permissions(&app_dir, fs::Permissions::from_mode(0o700));
        Ok(app_dir)
    }

    /// Get the default database path
    fn get_default_db_path() -> Result<PathBuf> {
        Ok(Self::get_default_app_dir()?.join("notes.dat"))
    }

    /// Get the redirect file path
    fn get_redirect_path() -> Result<PathBuf> {
        Ok(Self::get_default_app_dir()?.join(REDIRECT_FILE))
    }

    /// Check if a redirect file exists and return the path it points to
    fn check_redirect_file() -> Result<Option<PathBuf>> {
        let redirect_path = Self::get_redirect_path()?;
        if redirect_path.exists() {
            let contents = fs::read_to_string(&redirect_path)?;
            let custom_path = PathBuf::from(contents.trim());
            // Only return if the custom path actually exists
            if custom_path.exists() {
                return Ok(Some(custom_path));
            }
        }
        Ok(None)
    }

    /// Write a redirect file pointing to the custom database location
    fn write_redirect_file(custom_path: &PathBuf) -> Result<()> {
        let redirect_path = Self::get_redirect_path()?;
        fs::write(&redirect_path, custom_path.display().to_string())?;
        Ok(())
    }

    /// Remove the redirect file (when moving back to default location)
    fn remove_redirect_file() -> Result<()> {
        let redirect_path = Self::get_redirect_path()?;
        if redirect_path.exists() {
            fs::remove_file(&redirect_path)?;
        }
        Ok(())
    }

    fn resolve_data_path(settings: &AppSettings) -> Result<PathBuf> {
        if let Some(ref custom_path) = settings.custom_db_path {
            if let Some(parent) = custom_path.parent() {
                fs::create_dir_all(parent)?;
            }
            Ok(custom_path.clone())
        } else {
            Self::get_default_db_path()
        }
    }

    pub fn get_data_path(&self) -> &PathBuf {
        &self.data_path
    }

    pub fn get_settings(&self) -> &AppSettings {
        &self.settings
    }

    pub fn update_settings(&mut self, settings: AppSettings) -> Result<()> {
        let new_path = Self::resolve_data_path(&settings)?;
        let path_changed = new_path != self.data_path;
        let old_path = self.data_path.clone();
        let was_custom = self.settings.custom_db_path.is_some();
        let is_custom = settings.custom_db_path.is_some();

        // Check if Argon2 params changed - need to re-encrypt
        let params_changed = self.settings.argon2_params.memory_cost != settings.argon2_params.memory_cost
            || self.settings.argon2_params.time_cost != settings.argon2_params.time_cost
            || self.settings.argon2_params.parallelism != settings.argon2_params.parallelism;

        // Whether the encryption mode changed - if so we must rewrite the vault.
        let mode_changed = self.settings.encryption_mode != settings.encryption_mode;

        if path_changed && Self::is_unlocked() {
            // Move data file to new location
            if old_path.exists() {
                if let Some(parent) = new_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&old_path, &new_path)?;
                fs::remove_file(&old_path)?;
            }
            self.data_path = new_path.clone();

            // Handle redirect file
            if is_custom {
                // Moving to custom location - create redirect file
                Self::write_redirect_file(&new_path)?;
            } else if was_custom {
                // Moving back to default - remove redirect file
                Self::remove_redirect_file()?;
            }
        } else if is_custom && !was_custom {
            // First time setting custom path (even if path didn't change)
            Self::write_redirect_file(&new_path)?;
        } else if !is_custom && was_custom {
            // Clearing custom path
            Self::remove_redirect_file()?;
        }

        self.settings = settings;
        self.settings.save()?;

        // If the encryption mode OR the Argon2 params changed while unlocked,
        // rewrite the vault now so the on-disk format/KDF matches the new
        // settings immediately. The cascade re-derives the KEK from the cached
        // session password (no re-prompt) using the new `argon2_params`.
        if (mode_changed || params_changed) && Self::is_unlocked() {
            self.save_notes()?;
        }

        Ok(())
    }

    /// Re-encrypt the vault with new Argon2 parameters (in the current mode).
    #[allow(dead_code)]
    pub fn re_encrypt_with_params(&mut self, password: MasterPassword, new_params: &Argon2Params) -> Result<()> {
        if !Self::is_unlocked() {
            return Err(anyhow!("Application must be unlocked to change encryption parameters"));
        }

        let password_buffer = SecureBuffer::new(password.0.clone());
        let (new_key, new_salt) = crypto::generate_test_key_with_params(password_buffer.as_slice(), new_params)?;

        // Install the new key, then rewrite the vault in the current mode.
        // (Cascade reads argon2_params from settings; single uses new_key/new_salt.)
        self.set_crypto_state(password.0.clone(), new_key, new_salt);
        self.save_notes()?;

        Ok(())
    }

    fn init_crypto_state() {
        let _ = CRYPTO_STATE.set(RwLock::new(None));
    }

    /// Install a fresh crypto state, zeroizing any previous one.
    fn set_crypto_state(&self, password: Vec<u8>, key: Key<aes_gcm::Aes256Gcm>, salt: [u8; SALT_LEN]) {
        if let Some(state) = CRYPTO_STATE.get() {
            if let Ok(mut guard) = state.write() {
                if let Some(ref mut existing) = *guard {
                    existing.zeroize();
                }
                *guard = Some(CryptoState {
                    key,
                    salt,
                    password: SecureBuffer::new(password),
                });
            }
        }
    }

    /// Encrypt the current note list using the configured encryption mode.
    fn encrypt_current(&self) -> Result<Vec<u8>> {
        let serialized = bincode::serialize(&self.note_list)?;
        self.encrypt_blob(&serialized)
    }

    /// Encrypt an already-serialized vault blob per `settings.encryption_mode`.
    fn encrypt_blob(&self, blob: &[u8]) -> Result<Vec<u8>> {
        let state = CRYPTO_STATE.get().ok_or_else(|| anyhow!("Application is locked"))?;
        let guard = state.read().map_err(|_| anyhow!("Lock poisoned"))?;
        let crypto = guard.as_ref().ok_or_else(|| anyhow!("Application is locked"))?;
        match self.settings.encryption_mode {
            EncryptionMode::Cascade => cascade::encrypt_vault(
                crypto.password.as_slice(),
                blob,
                &self.settings.argon2_params,
            ),
            EncryptionMode::Single => {
                Ok(crypto::encrypt(&crypto.key, &crypto.salt, blob)?.to_bytes())
            }
        }
    }

    pub fn is_unlocked() -> bool {
        if let Some(state) = CRYPTO_STATE.get() {
            state.read().map(|s| s.is_some()).unwrap_or(false)
        } else {
            false
        }
    }

    pub fn lock(&mut self) {
        // Zeroize the note list in memory
        self.note_list.zeroize();
        self.note_list = NoteList::new();

        // Clear the crypto state
        if let Some(state) = CRYPTO_STATE.get() {
            if let Ok(mut guard) = state.write() {
                if let Some(ref mut crypto) = *guard {
                    crypto.zeroize();
                }
                *guard = None;
            }
        }
    }

    pub fn unlock(&mut self, master_password: MasterPassword) -> Result<()> {
        // Initialize crypto state container if needed
        Self::init_crypto_state();

        if Self::is_unlocked() {
            return Ok(());
        }

        // Use SecureBuffer to protect password in memory
        let password_buffer = SecureBuffer::new(master_password.0.clone());
        let password_bytes = password_buffer.as_slice();

        // ALWAYS use default params for the legacy key path - this ensures
        // backward compatibility and prevents issues from settings corruption.
        // (Cascade vaults carry their own KDF params in the file header.)
        let default_params = Argon2Params::default();

        let raw = match fs::read(&self.data_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // New vault - create it in the configured encryption mode.
                let (key, salt) = crypto::generate_test_key_with_params(password_bytes, &default_params)?;
                self.note_list = NoteList::new();
                self.set_crypto_state(master_password.0.clone(), key, salt);
                self.save_notes()?;
                return Ok(());
            },
            Err(e) => return Err(e.into()),
        };

        // Decrypt according to the on-disk format (auto-detected by magic bytes).
        let decrypted_bytes: Vec<u8> = if cascade::is_cascade(&raw) {
            cascade::decrypt_vault(password_bytes, &raw)?
        } else {
            let encrypted_data = EncryptedData::from_bytes(&raw)?;
            let key = crypto::derive_key_with_params(
                password_bytes,
                &encrypted_data.header.salt,
                &default_params,
            )?;
            crypto::decrypt(&key, &encrypted_data)
                .map_err(|_| anyhow!("Invalid password or corrupted data."))?
        };

        self.note_list = bincode::deserialize(&decrypted_bytes)?;

        // Cache a legacy key+salt so the single-layer fast path is always ready,
        // regardless of which format the vault is currently stored in.
        let (key, salt) = crypto::generate_test_key_with_params(password_bytes, &default_params)?;
        self.set_crypto_state(master_password.0.clone(), key, salt);

        Ok(())
    }

    pub fn change_password(&mut self, old_password: MasterPassword, new_password: MasterPassword) -> Result<()> {
        if !Self::is_unlocked() {
            return Err(anyhow!("Application must be unlocked to change password"));
        }

        // Always use default params for the legacy key path.
        let default_params = Argon2Params::default();

        // Verify the old password against the on-disk vault (either format).
        let raw = fs::read(&self.data_path)?;
        let old_buffer = SecureBuffer::new(old_password.0.clone());
        if cascade::is_cascade(&raw) {
            cascade::decrypt_vault(old_buffer.as_slice(), &raw)
                .map_err(|_| anyhow!("Current password is incorrect"))?;
        } else {
            let encrypted_data = EncryptedData::from_bytes(&raw)?;
            let old_key = crypto::derive_key_with_params(
                old_buffer.as_slice(),
                &encrypted_data.header.salt,
                &default_params,
            )?;
            crypto::decrypt(&old_key, &encrypted_data)
                .map_err(|_| anyhow!("Current password is incorrect"))?;
        }

        // Install the new password, then rewrite the vault in the current mode.
        let new_buffer = SecureBuffer::new(new_password.0.clone());
        let (new_key, new_salt) =
            crypto::generate_test_key_with_params(new_buffer.as_slice(), &default_params)?;
        self.set_crypto_state(new_password.0.clone(), new_key, new_salt);
        self.save_notes()?;

        Ok(())
    }

    fn save_notes(&self) -> Result<()> {
        let bytes = self.encrypt_current()?;
        Self::write_vault_atomic(&self.data_path, &bytes)?;
        Ok(())
    }

    /// Write the encrypted vault atomically and owner-only.
    ///
    /// M1 (no world-readable vault): the file is created mode 0600 so no other
    /// local user can copy the ciphertext for an offline attack.
    /// M2 (no half-written vault): we write a sibling temp file, fsync it, then
    /// `rename` it over the destination. rename is atomic on the same filesystem,
    /// so a crash / power loss / full disk can never leave a truncated vault —
    /// either the old file or the complete new file survives, never a partial.
    fn write_vault_atomic(dest: &PathBuf, bytes: &[u8]) -> Result<()> {
        let dir = dest
            .parent()
            .ok_or_else(|| anyhow!("vault path has no parent directory"))?;
        fs::create_dir_all(dir)?;

        // Temp file MUST be a sibling (same filesystem) for rename to be atomic.
        // Include the pid to avoid clobbering a concurrent writer's temp file.
        let tmp = dest.with_extension(format!("dat.tmp.{}", std::process::id()));

        // Create 0600 from the start (don't widen-then-narrow), then write+fsync.
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        let write_result = (|| -> std::io::Result<()> {
            f.write_all(bytes)?;
            f.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            drop(f);
            let _ = fs::remove_file(&tmp); // don't leave a partial temp behind
            return Err(e.into());
        }
        // Belt-and-suspenders: enforce 0600 even if a prior temp existed.
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        drop(f);

        // Atomic swap into place.
        if let Err(e) = fs::rename(&tmp, dest) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(())
    }

    pub fn get_notes(&self) -> Vec<super::data::Note> {
        self.note_list.notes.clone()
    }

    pub fn get_folders(&self) -> Vec<String> {
        self.note_list.folders.clone()
    }

    pub fn create_note(&mut self, title: String, content: String) -> Result<u64> {
        let note = super::data::Note::new(title, content);
        let id = note.id;
        self.note_list.add_note(note);
        self.save_notes()?;
        Ok(id)
    }

    #[allow(dead_code)]
    pub fn create_note_in_folder(&mut self, title: String, content: String, folder: Option<String>) -> Result<()> {
        let mut note = super::data::Note::new(title, content);
        note.folder = folder;
        self.note_list.add_note(note);
        self.save_notes()
    }

    pub fn update_note(&mut self, id: u64, title: String, content: String, folder: Option<String>) -> Result<()> {
        if self.note_list.update_note(id, title, content, folder) {
            self.save_notes()
        } else {
            Err(anyhow!("Note with ID {} not found", id))
        }
    }

    pub fn delete_note(&mut self, id: u64) -> Result<()> {
        if self.note_list.delete_note(id) {
            // Secure delete: the note's plaintext is already zeroized in RAM
            // (NoteList::delete_note). Now overwrite the on-disk vault's old bytes
            // before rewriting it, so the deleted note's old ciphertext (which is
            // decryptable with the password) can't be carved back off the disk.
            Self::scrub_file(&self.data_path);
            self.save_notes()
        } else {
            Err(anyhow!("Note with ID {} not found", id))
        }
    }

    /// Best-effort secure-erase of the vault file's current bytes: overwrite with
    /// random data and fsync. CAVEAT: on copy-on-write filesystems (btrfs/ZFS) and
    /// SSDs (wear-levelling/TRIM) the physical blocks may not be overwritten in
    /// place — true block erasure isn't guaranteed from user space. The data is
    /// AEAD-encrypted regardless, so this is defence-in-depth, not a guarantee.
    fn scrub_file(path: &PathBuf) {
        use std::io::Write;
        use aes_gcm::aead::{rand_core::RngCore, OsRng};
        let Ok(meta) = fs::metadata(path) else { return };
        let len = meta.len();
        if len == 0 {
            return;
        }
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            let mut buf = [0u8; 8192];
            let mut remaining = len;
            while remaining > 0 {
                let n = remaining.min(buf.len() as u64) as usize;
                OsRng.fill_bytes(&mut buf[..n]);
                if f.write_all(&buf[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = f.sync_all();
        }
    }

    pub fn toggle_pin(&mut self, id: u64) -> Result<bool> {
        if self.note_list.toggle_pin(id) {
            self.save_notes()?;
            // Return the new pin state
            let is_pinned = self.note_list.notes.iter()
                .find(|n| n.id == id)
                .map(|n| n.pinned)
                .unwrap_or(false);
            Ok(is_pinned)
        } else {
            Err(anyhow!("Note with ID {} not found", id))
        }
    }

    pub fn add_folder(&mut self, name: String) -> Result<()> {
        self.note_list.add_folder(name);
        self.save_notes()
    }

    pub fn delete_folder(&mut self, name: &str) -> Result<()> {
        self.note_list.delete_folder(name);
        self.save_notes()
    }

    pub fn export_all_encrypted(&self, export_path: &PathBuf) -> Result<()> {
        let bytes = self.encrypt_current()?;
        fs::write(export_path, bytes)?;
        Ok(())
    }

    pub fn import_encrypted(&mut self, import_path: &PathBuf, master_password: MasterPassword) -> Result<()> {
        let password_buffer = SecureBuffer::new(master_password.0.clone());

        let raw = fs::read(import_path).map_err(|e| anyhow!("Failed to read import file: {}", e))?;

        // Imported files may be either format; auto-detect by magic bytes.
        let decrypted_bytes = if cascade::is_cascade(&raw) {
            cascade::decrypt_vault(password_buffer.as_slice(), &raw)?
        } else {
            let encrypted_data = EncryptedData::from_bytes(&raw)?;
            let key = crypto::derive_key(password_buffer.as_slice(), &encrypted_data.header.salt)?;
            crypto::decrypt(&key, &encrypted_data)?
        };
        let imported_note_list: NoteList = bincode::deserialize(&decrypted_bytes)?;

        // Import folders
        for folder in &imported_note_list.folders {
            self.note_list.add_folder(folder.clone());
        }

        for mut note in imported_note_list.notes.clone() {
            // If the imported note's ID already exists in the vault, assign a new
            // unique ID so the existing note is not silently shadowed or clobbered.
            if self.note_list.notes.iter().any(|n| n.id == note.id) {
                let seq = super::data::ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) & 0xF_FFFF;
                note.id = (chrono::Utc::now().timestamp_millis() as u64) << 20 | seq;
            }
            self.note_list.add_note(note);
        }

        self.save_notes()?;
        Ok(())
    }
}

impl Drop for CoreManager {
    fn drop(&mut self) {
        // Zeroize all sensitive data
        self.note_list.zeroize();
    }
}
