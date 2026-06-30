use serde::{Serialize, Deserialize};
use chrono::{Utc, DateTime};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

// Monotonic counter used as low bits to prevent ID collisions when notes are
// created within the same millisecond (e.g. during import).
pub static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Note {
    pub id: u64,
    pub title: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub folder: Option<String>,
}

impl Note {
    pub fn new(title: String, content: String) -> Self {
        let now = Utc::now();
        // Combine millisecond timestamp (upper bits) with a monotonic counter
        // (lower 20 bits) so rapid creation never produces duplicate IDs.
        let millis = now.timestamp_millis() as u64;
        let seq = ID_COUNTER.fetch_add(1, Ordering::Relaxed) & 0xF_FFFF;
        let id = (millis << 20) | seq;
        Self {
            id,
            title,
            content,
            created_at: now,
            updated_at: now,
            pinned: false,
            folder: None,
        }
    }
}

// Implement Zeroize for Note to securely wipe content
impl Zeroize for Note {
    fn zeroize(&mut self) {
        self.id = 0;
        self.title.zeroize();
        self.content.zeroize();
        if let Some(ref mut f) = self.folder {
            f.zeroize();
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NoteList {
    pub notes: Vec<Note>,
    #[serde(default)]
    pub folders: Vec<String>,
}

impl NoteList {
    pub fn new() -> Self {
        Self { 
            notes: Vec::new(),
            folders: Vec::new(),
        }
    }
    
    fn sort_notes(&mut self) {
        // Sort: pinned first, then by updated_at descending
        self.notes.sort_by(|a, b| {
            match (a.pinned, b.pinned) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b.updated_at.cmp(&a.updated_at),
            }
        });
    }

    pub fn add_note(&mut self, note: Note) {
        self.notes.push(note);
        self.sort_notes();
    }

    pub fn delete_note(&mut self, id: u64) -> bool {
        let initial_len = self.notes.len();
        // Zeroize sensitive fields first, then remove by the original ID.
        // We must NOT use id==0 as a tombstone because zeroize() sets id to 0,
        // which would incorrectly delete any other note whose id happened to be 0.
        if let Some(note) = self.notes.iter_mut().find(|n| n.id == id) {
            note.title.zeroize();
            note.content.zeroize();
            if let Some(ref mut f) = note.folder {
                f.zeroize();
            }
        }
        self.notes.retain(|note| note.id != id);
        self.notes.len() < initial_len
    }

    pub fn update_note(&mut self, id: u64, title: String, content: String, folder: Option<String>) -> bool {
        if let Some(note) = self.notes.iter_mut().find(|n| n.id == id) {
            // Zeroize old content before updating
            note.title.zeroize();
            note.content.zeroize();
            note.title = title;
            note.content = content;
            note.folder = folder;
            note.updated_at = Utc::now();
            self.sort_notes();
            true
        } else {
            false
        }
    }
    
    pub fn toggle_pin(&mut self, id: u64) -> bool {
        if let Some(note) = self.notes.iter_mut().find(|n| n.id == id) {
            note.pinned = !note.pinned;
            self.sort_notes();
            true
        } else {
            false
        }
    }
    
    pub fn add_folder(&mut self, name: String) {
        if !self.folders.contains(&name) && !name.is_empty() {
            self.folders.push(name);
            self.folders.sort();
        }
    }
    
    pub fn delete_folder(&mut self, name: &str) {
        self.folders.retain(|f| f != name);
        // Remove folder assignment from notes
        for note in &mut self.notes {
            if note.folder.as_deref() == Some(name) {
                note.folder = None;
            }
        }
    }
    
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        for note in &mut self.notes {
            note.zeroize();
        }
        self.notes.clear();
        self.folders.clear();
    }
}

impl Zeroize for NoteList {
    fn zeroize(&mut self) {
        for note in &mut self.notes {
            note.zeroize();
        }
        self.notes.clear();
        self.folders.clear();
    }
}

impl Drop for NoteList {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Struct to hold the master password securely in memory
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterPassword(pub Vec<u8>);

impl From<String> for MasterPassword {
    fn from(s: String) -> Self {
        MasterPassword(s.into_bytes())
    }
}

impl From<&str> for MasterPassword {
    fn from(s: &str) -> Self {
        MasterPassword(s.as_bytes().to_vec())
    }
}

// Argon2 parameters for key derivation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 19456 = 19 MiB)
    pub memory_cost: u32,
    /// Time cost / iterations (default: 2)
    pub time_cost: u32,
    /// Parallelism (default: 1)
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: 19456,  // 19 MiB - Argon2 default
            time_cost: 2,        // Argon2 default
            parallelism: 1,      // Argon2 default
        }
    }
}

// Key-derivation strength. This is FIXED at Strong for every vault and is not
// user-selectable: Paranoid (256 MiB) caused multi-second UI freezes during the
// synchronous re-encrypt, and exposing the choice invited that footgun. Balanced
// (OWASP min) and Paranoid remain defined for reference / possible future use,
// but `AppSettings` always derives keys at Strong.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Balanced/Paranoid kept for reference; only Strong is used.
pub enum KdfStrength {
    /// 19 MiB, t=2 — OWASP minimum.
    Balanced,
    /// 64 MiB, t=3 — the fixed default. Strong margin, ~0.3s derive.
    Strong,
    /// 256 MiB, t=4 — strongest, but ~1.4s/derive (caused UI freezes).
    Paranoid,
}

impl KdfStrength {
    /// The Argon2id parameters this strength maps to.
    pub fn params(&self) -> Argon2Params {
        match self {
            KdfStrength::Balanced => Argon2Params { memory_cost: 19456,  time_cost: 2, parallelism: 1 },
            KdfStrength::Strong   => Argon2Params { memory_cost: 65536,  time_cost: 3, parallelism: 1 },
            KdfStrength::Paranoid => Argon2Params { memory_cost: 262144, time_cost: 4, parallelism: 1 },
        }
    }
}

// Vault encryption mode. Selected by the user; the on-disk format is
// self-describing, so unlocking auto-detects which mode a vault uses
// regardless of this setting.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum EncryptionMode {
    /// Single-layer AES-256-GCM (original Notas format).
    Single,
    /// Password-gated 3-layer AEAD cascade (tesseract-core file mode):
    /// AES-256-GCM -> ChaCha20-Poly1305 -> AES-256-GCM-SIV, each layer keyed
    /// independently. Quantum-resistant.
    Cascade,
}

impl Default for EncryptionMode {
    fn default() -> Self {
        // Cascade is the default: strongest protection out of the box.
        EncryptionMode::Cascade
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum AppTheme {
    Dark,
    Light,
    /// A palette ported from the tesseract UI, identified by its palette id.
    Palette(String),
}

impl Default for AppTheme {
    fn default() -> Self {
        AppTheme::Dark
    }
}

// Editor font family options
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum EditorFont {
    Monospace,
    SansSerif,
    Serif,
    JetBrainsMono,
    FiraCode,
    SourceCodePro,
    IBMPlexMono,
    Inter,
    Roboto,
    NotoSans,
    OpenSans,
    Merriweather,
    CrimsonText,
    LibreBaskerville,
}

impl Default for EditorFont {
    fn default() -> Self {
        EditorFont::Monospace
    }
}

impl EditorFont {
    pub fn to_css_family(&self) -> &'static str {
        match self {
            EditorFont::Monospace => "monospace",
            EditorFont::SansSerif => "sans-serif",
            EditorFont::Serif => "serif",
            EditorFont::JetBrainsMono => "'JetBrains Mono', 'Fira Code', monospace",
            EditorFont::FiraCode => "'Fira Code', 'JetBrains Mono', monospace",
            EditorFont::SourceCodePro => "'Source Code Pro', monospace",
            EditorFont::IBMPlexMono => "'IBM Plex Mono', monospace",
            EditorFont::Inter => "'Inter', 'Roboto', sans-serif",
            EditorFont::Roboto => "'Roboto', 'Inter', sans-serif",
            EditorFont::NotoSans => "'Noto Sans', sans-serif",
            EditorFont::OpenSans => "'Open Sans', sans-serif",
            EditorFont::Merriweather => "'Merriweather', serif",
            EditorFont::CrimsonText => "'Crimson Text', serif",
            EditorFont::LibreBaskerville => "'Libre Baskerville', serif",
        }
    }
    
    pub fn display_name(&self) -> &'static str {
        match self {
            EditorFont::Monospace => "Monospace (System)",
            EditorFont::SansSerif => "Sans Serif (System)",
            EditorFont::Serif => "Serif (System)",
            EditorFont::JetBrainsMono => "JetBrains Mono",
            EditorFont::FiraCode => "Fira Code",
            EditorFont::SourceCodePro => "Source Code Pro",
            EditorFont::IBMPlexMono => "IBM Plex Mono",
            EditorFont::Inter => "Inter",
            EditorFont::Roboto => "Roboto",
            EditorFont::NotoSans => "Noto Sans",
            EditorFont::OpenSans => "Open Sans",
            EditorFont::Merriweather => "Merriweather",
            EditorFont::CrimsonText => "Crimson Text",
            EditorFont::LibreBaskerville => "Libre Baskerville",
        }
    }
    
    pub fn all_fonts() -> Vec<EditorFont> {
        vec![
            EditorFont::Monospace,
            EditorFont::SansSerif,
            EditorFont::Serif,
            EditorFont::JetBrainsMono,
            EditorFont::FiraCode,
            EditorFont::SourceCodePro,
            EditorFont::IBMPlexMono,
            EditorFont::Inter,
            EditorFont::Roboto,
            EditorFont::NotoSans,
            EditorFont::OpenSans,
            EditorFont::Merriweather,
            EditorFont::CrimsonText,
            EditorFont::LibreBaskerville,
        ]
    }
    
    pub fn from_index(idx: u32) -> Self {
        Self::all_fonts().get(idx as usize).cloned().unwrap_or_default()
    }
    
    pub fn to_index(&self) -> u32 {
        Self::all_fonts().iter().position(|f| f == self).unwrap_or(0) as u32
    }
}

// Application settings/preferences
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppSettings {
    /// Auto-lock timeout in seconds (0 = disabled)
    pub auto_lock_timeout: u64,
    /// Clipboard clear timeout in seconds (0 = disabled)
    pub clipboard_timeout: u64,
    /// Custom database path (None = default)
    pub custom_db_path: Option<PathBuf>,
    /// Argon2 parameters
    #[serde(default)]
    pub argon2_params: Argon2Params,
    /// Vault encryption mode (single AES-GCM vs. cascade)
    #[serde(default)]
    pub encryption_mode: EncryptionMode,
    /// UI Theme
    #[serde(default)]
    pub theme: AppTheme,
    /// Editor font family
    #[serde(default)]
    pub editor_font: EditorFont,
    /// Editor font size in points
    #[serde(default = "default_font_size")]
    pub editor_font_size: u32,
    /// Show note title field
    #[serde(default = "default_true")]
    pub show_note_title: bool,
    /// Show the "Notas" logo/wordmark in the sidebar header
    #[serde(default = "default_true")]
    pub show_app_logo: bool,
    /// Show the first-line preview under each note in the sidebar
    #[serde(default = "default_true")]
    pub show_note_previews: bool,
    /// Show the word & character count in the editor status bar
    #[serde(default = "default_true")]
    pub show_word_count: bool,
    /// Optional custom editor text colour as a "#rrggbb" hex string (None =
    /// follow the theme). Ignored while rainbow mode is on.
    #[serde(default)]
    pub editor_text_color: Option<String>,
    /// Rainbow ("lolcat") editor text — per-character hue cycling.
    #[serde(default)]
    pub rainbow_text: bool,
    /// Minimal mode: start with the sidebar note-list collapsed (switch notes via
    /// the top-bar dropdown). The sidebar can still be toggled back with ☰.
    #[serde(default)]
    pub minimal_mode: bool,
}

fn default_true() -> bool {
    true
}

fn default_font_size() -> u32 {
    12
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            auto_lock_timeout: 300, // 5 minutes default
            clipboard_timeout: 30,  // 30 seconds default
            custom_db_path: None,
            // Every vault derives keys at Strong (64 MiB). FIXED, not
            // user-selectable. We do NOT touch Argon2Params::default() (kept at
            // 19456) because the legacy key cache uses it on every unlock.
            argon2_params: KdfStrength::Strong.params(),
            encryption_mode: EncryptionMode::Cascade,
            theme: AppTheme::Dark,
            editor_font: EditorFont::default(),
            editor_font_size: 12,
            show_note_title: true,
            show_app_logo: true,
            show_note_previews: true,
            show_word_count: true,
            editor_text_color: None,
            rainbow_text: false,
            minimal_mode: false,
        }
    }
}

impl AppSettings {
    pub fn load() -> Self {
        let config_path = Self::config_path();
        if let Ok(contents) = std::fs::read_to_string(&config_path) {
            serde_json::from_str(&contents).unwrap_or_default()
        } else {
            Self::default()
        }
    }
    
    pub fn save(&self) -> anyhow::Result<()> {
        let config_path = Self::config_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path, contents)?;
        Ok(())
    }
    
    fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("notas")
            .join("settings.json")
    }
}

// Secure buffer that is mlocked and zeroized on drop
pub struct SecureBuffer {
    data: Vec<u8>,
    locked: bool,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        let mut buf = Self { data, locked: false };
        buf.mlock();
        buf
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    fn mlock(&mut self) {
        if !self.data.is_empty() {
            let ptr = self.data.as_ptr() as *const libc::c_void;
            let len = self.data.len();
            unsafe {
                if libc::mlock(ptr, len) == 0 {
                    self.locked = true;
                }
            }
        }
    }
    
    fn munlock(&mut self) {
        if self.locked && !self.data.is_empty() {
            let ptr = self.data.as_ptr() as *const libc::c_void;
            let len = self.data.len();
            unsafe {
                libc::munlock(ptr, len);
            }
            self.locked = false;
        }
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
        self.munlock();
    }
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_preset_param_values() {
        assert_eq!(KdfStrength::Balanced.params().memory_cost, 19456);
        assert_eq!(KdfStrength::Strong.params().memory_cost, 65536);
        assert_eq!(KdfStrength::Strong.params().time_cost, 3);
        assert_eq!(KdfStrength::Paranoid.params().memory_cost, 262144);
    }

    #[test]
    fn settings_default_is_strong_but_argon_fn_default_is_not() {
        // The fixed settings default derives keys at Strong (64 MiB) ...
        assert_eq!(AppSettings::default().argon2_params.memory_cost, 65536);
        // ... but Argon2Params::default() stays at 19456 (used by the legacy key
        // cache on every unlock; raising it would slow every unlock).
        assert_eq!(Argon2Params::default().memory_cost, 19456);
    }
}
