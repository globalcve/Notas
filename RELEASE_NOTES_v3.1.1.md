# Notas v3.1.1

A major update to Notas — the secure, encrypted notes app for the Linux desktop
(Rust + GTK4 / libadwaita). Since v3.0.0 this brings a new cascade-encryption core,
a full theme system, a redesigned interface, powerful editor tools, and a round of
security hardening.

## Encryption — new Tesseract cascade core
- **3-layer cascade encryption** (default, no opt-out): every vault is sealed through
  **AES-256-GCM → ChaCha20-Poly1305 → AES-256-GCM-SIV**, powered by the Tesseract crypto core.
- **Argon2id key derivation** with selectable strength presets — **Strong** (64 MiB) by default,
  **Paranoid** (256 MiB) for maximum resistance. Changing strength re-encrypts off the UI thread.
- **Portable vaults.** A vault is unlocked by your master password alone — the salt and parameters
  live inside the file, with no machine binding. Copy the `.dat` to any machine and the same
  password opens it.
- **Secure delete** scrubs vault data on removal.

## Themes & appearance
- **19+ Tesseract color palettes**, light and dark.
- **Custom text color**, plus rainbow / pastel (Catppuccin) text styling.
- Bundled **DotGothic16** font and multiple customizable font families.
- macOS-style window controls.

## Editor
- **Markdown live preview** — toggle a clean read-only preview with **Ctrl+P** (rendered in-process,
  no dependencies).
- **Encode / Decode / Hash** from the right-click menu on any selection: Base64, Base32, Hex, Binary,
  Morse, ROT13 (encode and decode), and MD5 / SHA-1 / SHA-256 / CRC32 / Adler-32 hashes.
- **Passphrase encryption** — encrypt or decrypt selected text with a separate passphrase
  (Argon2id + AES-256-GCM) as a single clean, portable token.
- **Generators** — passwords, passphrases, PINs, UUIDs, and hex, inserted at the cursor.
- **Find & replace** (Ctrl+H), undo/redo, clickable checklists, word & character count, and a
  copy-with-auto-clear action.
- Fixed a bug where a quick right-click could accidentally trigger "Cut".

## Interface
- Redesigned top bar (note switcher, quick actions, new note, theme / preferences / lock).
- Collapsible sidebar and a minimal distraction-free mode (**F11**).
- Autosave — no Save button; changes are written automatically.
- Per-note right-click menu in the sidebar, optional hidden previews for privacy, and a
  password-strength meter.

## Security hardening (v3.1.1)
- **Stricter permissions** — the vault file is now `0600` and its data directory `0700` (owner-only).
- **Crash-safe atomic saves** — notes are written to a temp file, fsync'd, then atomically renamed,
  so an interrupted save can never truncate or destroy your vault.
- **Hardened decryption** — allocation is bounded by the real ciphertext size, so a malformed or
  forged vault can't trigger excessive memory use.
- **Fixed duplicate lock screen** — a leaked auto-lock timer could spawn a second lock screen;
  only one is ever active now.

## Under the hood
- The Tesseract cascade-crypto core is vendored in-tree — Notas builds fully standalone.

---

**Note:** uninstalling the `.deb` removes your notes data (`~/.local/share/notas`). Back up your
vault file first if you want to keep it.
