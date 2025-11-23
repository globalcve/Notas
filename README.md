<p align="center">
<img src="https://github.com/globalcve/NocturneNotes/blob/main/NocturneNotesBanner.png" alt="Nocturne Notes Banner" width="600"/>
</p>

<p align="center">
<img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust Badge"/>
<img src="https://img.shields.io/badge/GTK4-7D7D7D?style=for-the-badge&logo=gtk&logoColor=white" alt="GTK4 Badge"/>
<img src="https://img.shields.io/badge/Linux-333333?style=for-the-badge&logo=linux&logoColor=white" alt="Linux Badge"/>
</p>

---

## 📝 About

**Nocturne Notes** is a lightweight, encrypted note-taking app for Linux. 

I built this because I couldn't find a decent note app that checked all the boxes:
- ✅ Actually runs on Linux (not just "technically supported")
- ✅ Keeps notes local (no cloud, no account, no tracking)
- ✅ Uses real encryption (not just obfuscation)
- ✅ No paywall or premium features
- ✅ Built with Rust (memory-safe, fast, maintainable)

So here it is. Simple notes, strong encryption, zero nonsense.

---

## ✨ Features

### 🔐 Security First
- **AES-256-GCM encryption** - Industry-standard authenticated encryption
- **Argon2 key derivation** - Resistant to brute-force attacks
- **Local-only storage** - Your notes never leave your computer
- **No cloud, no accounts** - Just you and your encrypted database
- **Export/Import** - Encrypted backups you can store anywhere

### 📓 Simple & Clean
- **GTK4 interface** - Native Linux feel with Dracula theme
- **Create/Edit/Delete** - Basic operations that just work
- **Quick search** - Find notes instantly (when we add it)
- **Copy/paste** - Full text selection support
- **Keyboard shortcuts** - Work efficiently

### 🛠️ Technical
- **Rust-powered** - Memory-safe, fast, no garbage collection
- **GTK4** - Modern toolkit, Wayland-ready
- **Single binary** - No runtime dependencies beyond GTK4
- **Debian packages** - Easy installation with .deb
- **Open source** - MIT license, contribute freely

---

## 🚀 Installation

### From .deb Package (Recommended)

Download the latest `.deb` from [Releases](https://github.com/globalcve/NocturneNotes/releases):

```bash
sudo dpkg -i nocturne-notes_*.deb
```

Then run from your application menu or terminal:
```bash
nocturne_notes
```

### Build from Source

**Prerequisites:**
```bash
# Ubuntu/Debian
sudo apt install libgtk-4-dev libadwaita-1-dev build-essential cargo

# Fedora
sudo dnf install gtk4-devel libadwaita-devel gcc cargo

# Arch
sudo pacman -S gtk4 libadwaita rust cargo
```

**Build:**
```bash
git clone https://github.com/globalcve/NocturneNotes.git
cd NocturneNotes
cargo build --release
```

**Run:**
```bash
./target/release/nocturne_notes
```

**Build .deb package:**
```bash
cargo install cargo-deb
cargo deb
sudo dpkg -i target/debian/nocturne-notes_*.deb
```

---

## 🎯 Usage

### First Launch
1. Set your **master password** - This encrypts all your notes
2. Create your first note
3. Start writing!

### Basic Operations
- **New Note** - Creates a blank "Untitled" note
- **Save Note** - Saves changes (automatic on every edit, button for manual save)
- **Delete Note** - Permanently removes the note
- **Export Notes** - Save encrypted backup to any location
- **Import Notes** - Restore from encrypted backup

### Keyboard Shortcuts
- `Ctrl+C` - Copy selected text
- `Ctrl+V` - Paste text
- `Ctrl+X` - Cut selected text
- `Ctrl+A` - Select all text

---

## 🔐 Security & Privacy

### Encryption Details
- **Algorithm:** AES-256-GCM (Galois/Counter Mode)
- **Key Derivation:** Argon2 (memory-hard, GPU-resistant)
- **Nonce:** 96-bit random (per encryption)
- **Tag:** 128-bit authentication tag
- **Salt:** 128-bit random (per database)

### What's Encrypted
✅ Note titles  
✅ Note content  
✅ All metadata (timestamps, etc.)  
✅ Export files  

### What's NOT Encrypted
❌ Database file location (`~/.config/nocturne_notes/notes.dat`)  
❌ Application binary  

### Privacy Guarantees
- **No telemetry** - We don't track anything
- **No analytics** - We don't know you exist
- **No network access** - App never connects to internet
- **No accounts** - No sign-up, no login, no email
- **Open source** - Audit the code yourself

For more details, see [SECURITY.md](SECURITY.md)

---

## 🔓 Password Reset

**Forgot your password?** Unfortunately, there's no recovery mechanism (by design - we can't access your notes either).

### To reset:
```bash
rm ~/.config/nocturne_notes/notes.dat
```

⚠️ **This permanently deletes all your notes!**

### Safe reset process:
1. **Export your notes first** (if you can still unlock the app)
2. Delete the database file (command above)
3. Restart Nocturne Notes with a new password
4. **Import your notes** (you'll need the old password for the export file)

**Database location:** `~/.config/nocturne_notes/notes.dat`

💡 **Pro tip:** Export your notes regularly as encrypted backups!

For detailed instructions, see [PASSWORD_RESET.md](PASSWORD_RESET.md)

---

## 🏗️ Architecture

### Stack
- **Language:** Rust 2021 edition
- **GUI:** GTK4 with libadwaita
- **Crypto:** `aes-gcm`, `argon2` crates
- **Async:** `tokio`, `async-channel`
- **Serialization:** `bincode`, `serde`

### Project Structure
```
nocturne_notes/
├── src/
│   ├── main.rs          # UI and app logic
│   └── core/
│       ├── manager.rs   # Note management
│       ├── data.rs      # Data structures
│       ├── crypto.rs    # Encryption/decryption
│       └── mod.rs
├── icons/
│   └── nocturne-notes.svg
├── Cargo.toml
├── nocturne-notes.desktop
└── README.md
```

### How Encryption Works
1. You enter your master password
2. Argon2 derives a 256-bit key from your password + random salt
3. Notes are serialized with `bincode`
4. Encrypted with AES-256-GCM + random nonce
5. Saved to `~/.config/nocturne_notes/notes.dat`

When you unlock:
1. Your password + stored salt → same 256-bit key
2. Decrypt the database
3. Deserialize notes back into memory
4. Edit freely
5. Re-encrypt on every save

---

## 🤝 Contributing

Found a bug? Want to add a feature? Contributions welcome!

### Quick Start
1. Fork the repo
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly: `cargo test && cargo build --release`
5. Submit a pull request

### Ideas for Contributions
- [ ] Search functionality
- [ ] Tags/categories
- [ ] Dark/light theme toggle
- [ ] Password change feature (without data loss)
- [ ] Rich text formatting
- [ ] Attachments/images
- [ ] Multi-language support
- [ ] Automatic backups


### Reporting Bugs
Open an [issue](https://github.com/globalcve/NocturneNotes/issues) with:
- Your OS and GTK version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs (no sensitive data!)

### Security Issues
**Don't open public issues for security vulnerabilities!**

Email: [globalcve@gmail.com] or use [GitHub Security Advisories](https://github.com/globalcve/NocturneNotes/security/advisories)

---

## 📦 Dependencies

### Runtime
- GTK4 (4.8+)
- libadwaita (1.1+)

### Build-time
- Rust (1.70+)
- Cargo
- GTK4 development headers
- libadwaita development headers

---

## 🎨 Theming

Nocturne Notes uses the **Dracula color scheme**:
- Background: `#282a36`
- Foreground: `#f8f8f2`
- Accent (Green): `#50fa7b`
- Selection: `#44475a`

The GTK4 interface respects your system theme but adds Dracula-inspired highlights for a cohesive look.

---

## 🐛 Known Issues

- ~~Deleting notes caused UI freeze~~ ✅ Fixed in v0.1.1
- ~~Save button caused "not responding" dialog~~ ✅ Fixed in v0.1.1
- ~~Copy/paste selection not visible~~ ✅ Fixed in v0.1.1
- No search functionality yet (coming soon)
- No rich text formatting (plain text only)
- No password change without data loss
- Find something ? tell me ! 
---

## 🗺️ Roadmap

### v2.0.0 (Next Release)
- [ ] Search notes
- [ ] Sort by date/title
- [ ] Note categories/tags
- [ ] Keyboard shortcuts menu

### v3.0.0
- [ ] Password change feature
- [ ] Automatic encrypted backups
- [ ] Settings panel
- [ ] Light theme option

### v4.0.0
- [ ] Stable API
- [ ] Full documentation
- [ ] Professional security audit
- [ ] Multi-platform (macOS, Windows)

---

## ❓ FAQ

**Q: Is this secure enough for sensitive data?**  
A: It uses industry-standard encryption (AES-256-GCM, Argon2), the same algorithms used by password managers and encrypted messengers. However, no software is 100% secure. Use strong passwords and keep your system updated.

**Q: Why not use cloud sync?**  
A: Cloud sync means trusting a third party with your encrypted data and adding attack surface. Nocturne Notes keeps everything local. Use the Export feature to manually sync across devices.

**Q: Can you recover my password?**  
A: No. That's a feature, not a bug. We designed it so nobody (not even us) can access your notes without your password.

**Q: Why Rust?**  
A: Memory safety without garbage collection, strong type system, great crypto libraries, and no runtime dependencies. Perfect for security-focused applications.

**Q: Why GTK4 and not Qt/Electron?**  
A: GTK4 is native to Linux, lightweight, and doesn't require bundling a web browser (looking at you, Electron). Plus it's the GNOME standard.

**Q: Can I use this on Windows/Mac?**  
A: Not officially, but GTK4 is cross-platform. If you want to package it for other OS's, PRs welcome!

**Q: Is this a 1-person project?**  
A: Yes. I built this for myself, but I'm sharing it because maybe you need it too. Contributions are welcome if you want to help improve it!

---

## 📄 License

MIT License - See [LICENSE](LICENSE)

**TL;DR:** Do whatever you want with this code. Just don't blame me if something breaks.

---

## 🙏 Acknowledgments

Built with:
- [Rust](https://www.rust-lang.org/) - The language
- [GTK4](https://www.gtk.org/) - The toolkit
- [aes-gcm](https://github.com/RustCrypto/AEADs) - Encryption
- [argon2](https://github.com/RustCrypto/password-hashes) - Key derivation
- [tokio](https://tokio.rs/) - Async runtime

Inspired by:
- Standard Notes (but simpler)
- Joplin (but lighter)
- Every note app that wanted my email address

---

## 💬 Support

- 🐛 **Bug reports:** [GitHub Issues](https://github.com/globalcve/NocturneNotes/issues)
- 💡 **Feature requests:** [GitHub Discussions](https://github.com/globalcve/NocturneNotes/discussions)
- 📖 **Documentation:** [Wiki](https://github.com/globalcve/NocturneNotes/wiki)
- 🔒 **Security:** [SECURITY.md](SECURITY.md)

---

<p align="center">
Made with ☕ and 🦀 because I needed a damn note app that just works.
</p>

<p align="center">
⭐ Star this repo if it helped you avoid yet another subscription!
</p>
