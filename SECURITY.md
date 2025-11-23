# Security Policy

## Encryption

Nocturne Notes uses **AES-256-GCM** encryption with **Argon2** key derivation to protect your notes.

### What's Encrypted
- ✅ Note titles
- ✅ Note content
- ✅ All metadata (timestamps, etc.)
- ✅ Export files

### What's NOT Encrypted
- ❌ Database file location (`~/.config/nocturne_notes/notes.dat`)
- ❌ Application binary

---

## Password Security

### Your Password
- **Never stored** - Only the derived encryption key is used
- **No recovery** - If you forget it, your notes are unrecoverable (by design)
- **No backdoor** - Not even we can access your notes without your password

### Best Practices
- ✅ Use a strong, unique password (12+ characters)
- ✅ Include uppercase, lowercase, numbers, and symbols
- ✅ Don't reuse passwords from other services
- ✅ Consider using a password manager
- ✅ Export your notes regularly as encrypted backups

---

## Data Storage

### Where Your Data Lives
```
~/.config/nocturne_notes/notes.dat
```

This file contains:
- All your notes (encrypted)
- Encryption salt
- File format version

### File Permissions
The app creates the config directory with standard user permissions:
```bash
~/.config/nocturne_notes/   (700 - owner only)
notes.dat                    (600 - owner read/write)
```

---

## Password Reset

### If You Forget Your Password

⚠️ **There is no password recovery!** This is by design for security.

If you've forgotten your password, you must delete the database:

```bash
rm ~/.config/nocturne_notes/notes.dat
```

**This permanently deletes all notes.**

### Safe Reset Process
1. **Export your notes first** (if you can still unlock the app)
2. Delete the database file
3. Restart Nocturne Notes with a new password
4. Import your notes (requires the old export password)

See [PASSWORD_RESET.md](docs/PASSWORD_RESET.md) for detailed instructions.

---

## Threat Model

### What Nocturne Notes Protects Against
- ✅ **At-rest attacks** - Database file is encrypted
- ✅ **File theft** - Stolen `notes.dat` is unreadable without password
- ✅ **Backup exposure** - Exports are also encrypted

### What Nocturne Notes Does NOT Protect Against
- ❌ **Keyloggers** - If your system is compromised, passwords can be stolen
- ❌ **Screen capture** - Notes are visible when app is open
- ❌ **Memory dumps** - Decrypted notes exist in RAM while editing
- ❌ **Rubber-hose cryptanalysis** - Physical coercion
- ❌ **Brute force** - Weak passwords can be guessed (use strong passwords!)

---

## Security Best Practices

### For Regular Users
1. **Use a strong master password**
2. **Export notes regularly** (encrypted backups)
3. **Keep your system secure** (updated OS, antivirus)
4. **Lock your screen** when away
5. **Don't share your password**

### For Paranoid Users
1. Use a **20+ character passphrase**
2. Store exports on **encrypted USB drives**
3. Use **full disk encryption** (LUKS/dm-crypt)
4. **Disconnect from internet** while using the app
5. Run on a **dedicated secure machine**

### For Developers Contributing
1. Never log sensitive data
2. Zeroize passwords in memory when possible
3. Use constant-time comparisons for crypto
4. Follow Rust security best practices
5. Report security issues privately (see below)

---

## Reporting a Vulnerability

### 🔒 Private Disclosure

**Please DO NOT open a public issue for security vulnerabilities.**

Instead, email: [your-email@example.com]

Or open a private security advisory:
https://github.com/globalcve/NocturneNotes/security/advisories/new

### What to Include
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Time
- We aim to respond within **48 hours**
- Fixes will be released as soon as possible
- You'll be credited in release notes (if desired)

---

## Cryptographic Details

### Algorithm Choices

**Encryption:** AES-256-GCM
- Industry standard AEAD cipher
- 256-bit keys for maximum security
- Authenticated encryption prevents tampering

**Key Derivation:** Argon2
- Winner of Password Hashing Competition
- Resistant to GPU/ASIC attacks
- Memory-hard to prevent rainbow tables

**Random Number Generation:** OS-provided (`OsRng`)
- Uses `/dev/urandom` on Linux
- Cryptographically secure

### Implementation
We use the `aes-gcm` and `argon2` Rust crates, which are:
- Widely audited
- Actively maintained
- Follow security best practices

---

## Known Limitations

### Current Version
- ❌ No multi-user support
- ❌ No password change without data loss
- ❌ No automatic backups
- ❌ No cloud sync
- ❌ No key stretching beyond Argon2

### Future Improvements
- [ ] Password change feature
- [ ] Automatic encrypted backups
- [ ] Audit logging
- [ ] Yubikey/hardware key support
- [ ] Secure clipboard (auto-clear)

---

## Compliance & Audits

### Status
- ⚠️ **Not audited** by professional cryptographers (yet)
- ✅ Uses well-audited crypto libraries
- ✅ Open source for community review

### For Enterprise Use
If you need:
- Professional security audit
- Compliance certifications (SOC2, HIPAA, etc.)
- Commercial support
- Custom security features

Please contact: [your-business-email@example.com]

---

## Updates & Maintenance

### Security Updates
- Subscribe to releases: https://github.com/globalcve/NocturneNotes/releases
- Star the repo for notifications
- Check for updates regularly

### Dependencies
We monitor and update dependencies for security:
```bash
cargo audit
```

---

## License & Liability

See [LICENSE](LICENSE) for full terms.

**TL;DR:** 
- Provided "as is" without warranty
- Use at your own risk
- Not liable for data loss
- Not liable for security breaches

**Remember:** While we use strong encryption, **you** are responsible for:
- Choosing a strong password
- Keeping your system secure
- Making backups
- Physical security

---

## Questions?

- 💬 Open a [Discussion](https://github.com/globalcve/NocturneNotes/discussions)
- 📖 Read the [Documentation](docs/)
- 🐛 Report bugs: [Issues](https://github.com/globalcve/NocturneNotes/issues)
- 🔒 Security: Email privately (see above)

**Stay secure!** 🔐
