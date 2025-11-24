# Password Reset Instructions

## How to Reset Your Master Password

Since Nocturne Notes uses encryption, the master password cannot be changed without the old password. If you've forgotten your password, you'll need to delete the encrypted database and start fresh.

### ⚠️ Warning
**Deleting the database will erase ALL your notes permanently!** 

If you still know your password, **export your notes first** before resetting.

---

## Steps to Reset Password

### 1. Export Notes (if you still have access)
If you can still unlock the app:
1. Open Nocturne Notes
2. Click **"Export Notes"**
3. Save the export file somewhere safe
4. You can import this later with the new password

### 2. Delete the Database File

The encrypted notes are stored at:
```bash
~/.local/share/nocturne_notes/notes.dat
```

To reset your password, delete this file:

```bash
rm ~/.local/share/nocturne_notes/notes.dat
```

Or delete the entire config directory:
```bash
rm ~/.local/share/nocturne_notes/notes.dat
```

### 3. Restart the Application

When you next open Nocturne Notes, it will ask for a password. This will be your **new master password** and will create a fresh encrypted database.

### 4. Import Your Notes (optional)

If you exported your notes in step 1:
1. Click **"Import Notes"**
2. Select your export file
3. Enter the **old password** (the one used when you exported)
4. Your notes will be imported with the new password

---

## File Locations

### Linux
- **Database:** `~/.local/share/nocturne_notes/notes.dat`
- **Exports:** Wherever you save them (default: `~/notes_export.dat`)

### What's Stored
The `notes.dat` file contains:
- All your notes (encrypted)
- Note titles (encrypted)
- Note content (encrypted)
- Timestamps (encrypted)
- The encryption salt (not sensitive on its own)

Everything is encrypted with AES-256-GCM using your master password.

---

## Security Notes

✅ **Good:**
- Your notes are encrypted at rest
- No password is stored - only a derived key
- Even if someone steals `notes.dat`, they can't read it without your password

⚠️ **Important:**
- If you forget your password, your notes are **unrecoverable**
- There is no password recovery mechanism (by design)
- Export your notes regularly as a backup

💡 **Best Practices:**
- Use a strong, memorable password
- Export your notes regularly
- Store exports in a secure location
- Consider using a password manager

---

## FAQ

**Q: Can I change my password without losing notes?**  
A: Not currently. Future versions may support password change, but for now you must export, delete database, and re-import.

**Q: I forgot my password. Can you help?**  
A: No. The encryption is designed so that nobody (not even us) can recover your notes without the password. This is a security feature, not a bug.

**Q: Where should I store my export files?**  
A: Somewhere secure! Export files are also encrypted with the same password. Keep them on an encrypted USB drive, cloud storage, or another secure location.

**Q: Can I have multiple password-protected databases?**  
A: Not directly, but you can:
1. Export your notes
2. Delete `notes.dat`
3. Create new database with different password
4. Keep the export file as your "second database"
5. Import it when you want to switch

**Q: How do I back up my notes?**  
A: Click "Export Notes" regularly. The export file is encrypted and portable.

---

Pull requests welcome! 🎉
