//! Native, in-process re-implementation of the text-oriented operations from
//! `toolkit.py` (https://github.com/jegly/toolkit.py), exposed in the note
//! editor's right-click menu (Encode / Decode / Hash submenus).
//!
//! Every operation takes the selected text and returns the transformed text, or
//! `Err(message)` for invalid input on the decode side (shown in the status bar
//! instead of replacing the selection). Pure Rust, offline — no Python, no
//! runtime dependencies, consistent with the existing "Transform selection" menu.

use aes_gcm::aead::{rand_core::RngCore, Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use sha2::Digest as _;
use zeroize::Zeroize as _;

// ── Base64 (RFC 4648, standard alphabet + padding) ──────────────────────────
pub fn base64_encode(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}
pub fn base64_decode(s: &str) -> Result<String, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| format!("Base64 decode failed: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "Base64 decoded to non-UTF-8 bytes".to_string())
}

// ── Base32 (RFC 4648, hand-rolled to avoid an extra dep / API churn) ─────────
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn base32_encode(s: &str) -> String {
    let data = s.as_bytes();
    let mut out = String::new();
    for chunk in data.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let groups = [
            buf[0] >> 3,
            ((buf[0] & 0x07) << 2) | (buf[1] >> 6),
            (buf[1] >> 1) & 0x1f,
            ((buf[1] & 0x01) << 4) | (buf[2] >> 4),
            ((buf[2] & 0x0f) << 1) | (buf[3] >> 7),
            (buf[3] >> 2) & 0x1f,
            ((buf[3] & 0x03) << 3) | (buf[4] >> 5),
            buf[4] & 0x1f,
        ];
        let n = match chunk.len() {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 8,
        };
        for g in groups.iter().take(n) {
            out.push(B32[*g as usize] as char);
        }
        for _ in n..8 {
            out.push('=');
        }
    }
    out
}
pub fn base32_decode(s: &str) -> Result<String, String> {
    let mut out: Vec<u8> = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for ch in s.trim().chars() {
        if ch == '=' || ch.is_whitespace() {
            continue;
        }
        let up = ch.to_ascii_uppercase();
        let val = B32
            .iter()
            .position(|&c| c as char == up)
            .ok_or_else(|| format!("Base32 decode failed: invalid character '{ch}'"))?
            as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    String::from_utf8(out).map_err(|_| "Base32 decoded to non-UTF-8 bytes".to_string())
}

// ── Hex ──────────────────────────────────────────────────────────────────────
pub fn hex_encode(s: &str) -> String {
    hex::encode(s.as_bytes())
}
pub fn hex_decode(s: &str) -> Result<String, String> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = hex::decode(&cleaned).map_err(|e| format!("Hex decode failed: {e}"))?;
    String::from_utf8(bytes).map_err(|_| "Hex decoded to non-UTF-8 bytes".to_string())
}

// ── Binary (space-separated 8-bit groups) ────────────────────────────────────
pub fn binary_encode(s: &str) -> String {
    s.as_bytes()
        .iter()
        .map(|b| format!("{b:08b}"))
        .collect::<Vec<_>>()
        .join(" ")
}
pub fn binary_decode(s: &str) -> Result<String, String> {
    let mut bytes = Vec::new();
    for tok in s.split_whitespace() {
        let b = u8::from_str_radix(tok, 2)
            .map_err(|_| format!("Binary decode failed: '{tok}' is not an 8-bit byte"))?;
        bytes.push(b);
    }
    String::from_utf8(bytes).map_err(|_| "Binary decoded to non-UTF-8 bytes".to_string())
}

// ── ROT13 (its own inverse) ──────────────────────────────────────────────────
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

// ── Morse (international; "/" separates words) ────────────────────────────────
const MORSE: &[(char, &str)] = &[
    ('A', ".-"), ('B', "-..."), ('C', "-.-."), ('D', "-.."), ('E', "."),
    ('F', "..-."), ('G', "--."), ('H', "...."), ('I', ".."), ('J', ".---"),
    ('K', "-.-"), ('L', ".-.."), ('M', "--"), ('N', "-."), ('O', "---"),
    ('P', ".--."), ('Q', "--.-"), ('R', ".-."), ('S', "..."), ('T', "-"),
    ('U', "..-"), ('V', "...-"), ('W', ".--"), ('X', "-..-"), ('Y', "-.--"),
    ('Z', "--.."), ('0', "-----"), ('1', ".----"), ('2', "..---"), ('3', "...--"),
    ('4', "....-"), ('5', "....."), ('6', "-...."), ('7', "--..."), ('8', "---.."),
    ('9', "----."), ('.', ".-.-.-"), (',', "--..--"), ('?', "..--.."),
    ('\'', ".----."), ('!', "-.-.--"), ('/', "-..-."), ('(', "-.--."),
    (')', "-.--.-"), ('&', ".-..."), (':', "---..."), (';', "-.-.-."),
    ('=', "-...-"), ('+', ".-.-."), ('-', "-....-"), ('_', "..--.-"),
    ('"', ".-..-."), ('$', "...-..-"), ('@', ".--.-."),
];
pub fn morse_encode(s: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for ch in s.chars() {
        if ch == ' ' {
            out.push("/".to_string());
            continue;
        }
        let up = ch.to_ascii_uppercase();
        match MORSE.iter().find(|(c, _)| *c == up) {
            Some((_, code)) => out.push((*code).to_string()),
            None => out.push("?".to_string()),
        }
    }
    out.join(" ")
}
pub fn morse_decode(s: &str) -> Result<String, String> {
    let mut out = String::new();
    for tok in s.split_whitespace() {
        if tok == "/" {
            out.push(' ');
            continue;
        }
        match MORSE.iter().find(|(_, code)| *code == tok) {
            Some((c, _)) => out.push(*c),
            None => return Err(format!("Morse decode failed: unknown symbol '{tok}'")),
        }
    }
    Ok(out)
}

// ── Hashes (hex digest) ──────────────────────────────────────────────────────
pub fn md5(s: &str) -> String {
    let mut h = md5::Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}
pub fn sha1(s: &str) -> String {
    let mut h = sha1::Sha1::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}
pub fn sha256(s: &str) -> String {
    let mut h = sha2::Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

// ── Checksums (8-hex-digit) ──────────────────────────────────────────────────
pub fn crc32(s: &str) -> String {
    format!("{:08x}", crc32fast::hash(s.as_bytes()))
}
pub fn adler32(s: &str) -> String {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in s.as_bytes() {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    format!("{:08x}", (b << 16) | a)
}

// ── Passphrase encryption (Argon2id KDF + AES-256-GCM AEAD) ──────────────────
// "Encrypt" turns the selection into a single Base64 token; "Decrypt" reverses it
// given the same passphrase. The decoded blob carries its own magic (NENC) +
// random salt (16) + nonce (12), so the passphrase is never stored, identical
// plaintext encrypts differently every time, and decrypt can recognise it without
// any wrapper markers. GCM authenticates, so a wrong passphrase or any tampering
// fails cleanly rather than returning garbage.
const ENC_MAGIC: &[u8; 4] = b"NENC";
const ENC_VERSION: u8 = 1;

fn derive_key(pass: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    // 64 MiB, t=3, p=1 — matches the vault's "Strong" preset; ~0.25s, strong
    // against offline brute-force while staying snappy for an explicit click.
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(pass.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {e}"))?;
    Ok(key)
}

pub fn encrypt_text(plain: &str, pass: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = derive_key(pass, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_bytes())
        .map_err(|_| "Encryption failed".to_string())?;
    key.zeroize();

    let mut blob = Vec::with_capacity(4 + 1 + 16 + 12 + ct.len());
    blob.extend_from_slice(ENC_MAGIC);
    blob.push(ENC_VERSION);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);

    Ok(base64::engine::general_purpose::STANDARD.encode(&blob))
}

pub fn decrypt_text(envelope: &str, pass: &str) -> Result<String, String> {
    // Tolerant: drop any whitespace (and legacy `-----` marker lines), leaving
    // just the Base64 token.
    let b64: String = envelope
        .lines()
        .filter(|l| !l.trim_start().starts_with("-----"))
        .flat_map(|l| l.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    if b64.is_empty() {
        return Err("No encrypted data in the selection".to_string());
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|_| "Not valid encrypted text (bad Base64)".to_string())?;
    if blob.len() < 4 + 1 + 16 + 12 || &blob[..4] != ENC_MAGIC {
        return Err("Not a Notas-encrypted block".to_string());
    }
    if blob[4] != ENC_VERSION {
        return Err(format!("Unsupported encryption version {}", blob[4]));
    }
    let salt = &blob[5..21];
    let nonce = &blob[21..33];
    let ct = &blob[33..];

    let mut key = derive_key(pass, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "Decryption failed — wrong passphrase or corrupted data".to_string());
    key.zeroize();
    let pt = pt?;
    String::from_utf8(pt).map_err(|_| "Decrypted data is not valid text".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip_and_vector() {
        assert_eq!(base64_encode("hello"), "aGVsbG8=");
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), "hello");
        assert!(base64_decode("@@not base64@@").is_err());
    }

    #[test]
    fn base32_roundtrip_and_vector() {
        assert_eq!(base32_encode("foobar"), "MZXW6YTBOI======");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), "foobar");
        assert_eq!(base32_decode(&base32_encode("Notas")).unwrap(), "Notas");
    }

    #[test]
    fn hex_roundtrip_and_vector() {
        assert_eq!(hex_encode("hi"), "6869");
        assert_eq!(hex_decode("68 69").unwrap(), "hi");
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn binary_roundtrip() {
        assert_eq!(binary_encode("A"), "01000001");
        assert_eq!(binary_decode("01000001 01000010").unwrap(), "AB");
        assert!(binary_decode("2222").is_err());
    }

    #[test]
    fn rot13_is_involution() {
        assert_eq!(rot13("hello"), "uryyb");
        assert_eq!(rot13(&rot13("Hello, World!")), "Hello, World!");
    }

    #[test]
    fn morse_roundtrip_and_vector() {
        assert_eq!(morse_encode("SOS"), "... --- ...");
        assert_eq!(morse_decode("... --- ...").unwrap(), "SOS");
        assert_eq!(morse_decode(&morse_encode("HI THERE")).unwrap(), "HI THERE");
    }

    #[test]
    fn hash_vectors() {
        assert_eq!(md5(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            sha256(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn checksum_vectors() {
        assert_eq!(crc32("123456789"), "cbf43926");
        assert_eq!(adler32("Wikipedia"), "11e60398");
    }

    #[test]
    fn encrypt_roundtrip_and_failures() {
        let blob = encrypt_text("Top secret note", "correct horse").unwrap();
        // Output is a single clean Base64 token (no markers, no newlines).
        assert!(!blob.contains('\n') && !blob.contains("BEGIN"));
        assert_ne!(blob, "Top secret note");
        // Right passphrase round-trips.
        assert_eq!(decrypt_text(&blob, "correct horse").unwrap(), "Top secret note");
        // Wrong passphrase fails (does not return garbage).
        assert!(decrypt_text(&blob, "wrong").is_err());
        // Same plaintext + passphrase encrypts differently (random salt/nonce).
        let blob2 = encrypt_text("Top secret note", "correct horse").unwrap();
        assert_ne!(blob, blob2);
        // Non-encrypted selection is rejected cleanly.
        assert!(decrypt_text("just some text", "x").is_err());
    }
}
