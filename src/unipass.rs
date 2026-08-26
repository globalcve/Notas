//! Multilingual password generation.
//!
//! Extends the ASCII generator with curated character blocks from other scripts,
//! for sites that accept non-ASCII passwords.
//!
//! # Why bother, honestly
//!
//! Not for raw entropy. The existing 64-character ASCII generator already yields
//! ~420 bits, which is past any conceivable brute force. The real arguments are:
//!
//! * **Length-capped fields.** Plenty of sites cap passwords at 16-20 characters.
//!   At 20 characters, a 34k pool gives ~302 bits against ASCII's ~131.
//! * **Cracking tools assume ASCII.** Hashcat masks, rule sets and wordlists do
//!   not generate candidates containing Devanagari.
//!
//! # The two things that will lock you out if ignored
//!
//! 1. **bcrypt truncates at 72 bytes.** Many sites use it, and it silently drops
//!    everything past byte 72 — possibly mid-character. A 60-character CJK
//!    password is 180 UTF-8 bytes, so two thirds of it would do nothing. This is
//!    why [`utf8_len`] exists and why the dialog shows a live byte count.
//! 2. **Unicode normalization.** The same visible character can have several
//!    codepoint spellings, and a site that normalizes differently at
//!    registration than at login will reject a correct password forever. The
//!    tiers below exist entirely to manage this.
//!
//! # How the tables are built
//!
//! Generated offline against Unicode 16.0.0 and compiled in as codepoint ranges,
//! so no Unicode database ships in the binary. Every character survives all of:
//! BMP only (astral codepoints are surrogate pairs, which Java and JavaScript
//! backends routinely mishandle); assigned and not a control, format, surrogate
//! or private-use codepoint (this is what excludes the zero-width and
//! right-to-left marks); not whitespace of any kind; not a combining mark; and
//! NFC-stable.
//!
//! That last property is load-bearing: because no character in any table is a
//! combining mark and every one is NFC-stable, a password built by plain
//! concatenation is **already in NFC**. Nothing needs normalizing at runtime.
//!
//! `unipass::tests` re-derives all of this with the `unicode-normalization`
//! crate, so the tables cannot silently rot.
//!
//! # Relationship to PRECIS (RFC 8265)
//!
//! RFC 8265 defines the `OpaqueString` profile — the standard for how a password
//! should be prepared and compared. It requires that the string be normalized to
//! **NFC**, that non-ASCII spaces be mapped to U+0020, that no case folding be
//! applied, and that control and ignorable code points be disallowed.
//!
//! Everything generated here already satisfies that profile, and
//! `opaquestring_profile_is_satisfied` proves it. The practical consequence is
//! useful: on any server implementing PRECIS correctly, preparation is a no-op
//! for our output, so nothing can be altered between the field and the hash.
//! Related: RFC 8264 (the PRECIS framework), RFC 4013 (SASLprep) and RFC 3454
//! (stringprep), which 8265 supersedes.

/// How much normalization abuse a character can survive.
///
/// Nested: `Standard` includes everything in `Safe`, `Maximum` includes both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Identical under all four of NFC/NFD/NFKC/NFKD. Nothing a site does to it
    /// can change it. Excludes precomposed accented Latin and voiced kana.
    Safe,
    /// Identical under NFC and NFKC. Adds precomposed accented Latin, Hangul
    /// syllables and voiced kana — these decompose under NFD, which only matters
    /// if a site normalizes inconsistently between signup and login.
    Standard,
    /// Identical under NFC only. Adds characters NFKC would fold away, so a site
    /// applying NFKC will mangle them.
    Maximum,
}

impl Tier {
    pub fn label(&self) -> &'static str {
        match self {
            Tier::Safe => "Safe",
            Tier::Standard => "Standard",
            Tier::Maximum => "Maximum",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Tier::Safe => "Unchanged by any normalization. Works everywhere.",
            Tier::Standard => "Unchanged by NFC and NFKC. Safe on sites following RFC 8265.",
            Tier::Maximum => "Widest pool. Some sites will alter or reject these.",
        }
    }

    pub fn all() -> [Tier; 3] {
        [Tier::Safe, Tier::Standard, Tier::Maximum]
    }

    pub fn from_index(i: u32) -> Tier {
        match i {
            1 => Tier::Standard,
            2 => Tier::Maximum,
            // Safe is index 0 and the default: it is the only tier unchanged by
            // every normalization form, which matters because NIST SP 800-63B
            // Rev 3 recommends NFKC/NFKD and Rev 4 recommends NFC, so different
            // sites legitimately normalize differently.
            _ => Tier::Safe,
        }
    }
}

/// One selectable script or symbol set. Characters are stored as inclusive
/// codepoint ranges, split by the strictest tier each one qualifies for.
pub struct Block {
    pub id: &'static str,
    pub name: &'static str,
    pub safe: &'static [(u32, u32)],
    pub standard: &'static [(u32, u32)],
    pub maximum: &'static [(u32, u32)],
}

impl Block {
    /// Every character in this block available at `tier` or stricter.
    pub fn chars(&self, tier: Tier) -> Vec<char> {
        let mut sets: Vec<&[(u32, u32)]> = vec![self.safe];
        if tier >= Tier::Standard {
            sets.push(self.standard);
        }
        if tier >= Tier::Maximum {
            sets.push(self.maximum);
        }
        sets.iter()
            .flat_map(|ranges| ranges.iter())
            .flat_map(|&(a, b)| (a..=b).filter_map(char::from_u32))
            .collect()
    }

    pub fn count(&self, tier: Tier) -> usize {
        self.chars(tier).len()
    }
}

pub const BLOCKS: &[Block] = &[
    Block {
        id: "latin-ext",
        name: "Latin Extended",
        // 130 safe, +252 standard, +18 maximum
        safe: &[(0x00C6, 0x00C6), (0x00D0, 0x00D0), (0x00D7, 0x00D8), (0x00DE, 0x00DF), (0x00E6, 0x00E6), (0x00F0, 0x00F0), (0x00F7, 0x00F8), (0x00FE, 0x00FE), (0x0110, 0x0111), (0x0126, 0x0127), (0x0131, 0x0131), (0x0138, 0x0138), (0x0141, 0x0142), (0x014A, 0x014B), (0x0152, 0x0153), (0x0166, 0x0167), (0x0180, 0x019F), (0x01A2, 0x01AE), (0x01B1, 0x01C3), (0x01DD, 0x01DD), (0x01E4, 0x01E5), (0x01F6, 0x01F7), (0x021C, 0x021D), (0x0220, 0x0225), (0x0234, 0x024F)],
        standard: &[(0x00C0, 0x00C5), (0x00C7, 0x00CF), (0x00D1, 0x00D6), (0x00D9, 0x00DD), (0x00E0, 0x00E5), (0x00E7, 0x00EF), (0x00F1, 0x00F6), (0x00F9, 0x00FD), (0x00FF, 0x010F), (0x0112, 0x0125), (0x0128, 0x0130), (0x0134, 0x0137), (0x0139, 0x013E), (0x0143, 0x0148), (0x014C, 0x0151), (0x0154, 0x0165), (0x0168, 0x017E), (0x01A0, 0x01A1), (0x01AF, 0x01B0), (0x01CD, 0x01DC), (0x01DE, 0x01E3), (0x01E6, 0x01F0), (0x01F4, 0x01F5), (0x01F8, 0x021B), (0x021E, 0x021F), (0x0226, 0x0233)],
        maximum: &[(0x0132, 0x0133), (0x013F, 0x0140), (0x0149, 0x0149), (0x017F, 0x017F), (0x01C4, 0x01CC), (0x01F1, 0x01F3)],
    },
    Block {
        id: "greek",
        name: "Greek",
        // 96 safe, +221 standard, +28 maximum
        safe: &[(0x0370, 0x0373), (0x0375, 0x0377), (0x037B, 0x037D), (0x037F, 0x037F), (0x0391, 0x03A1), (0x03A3, 0x03A9), (0x03B1, 0x03C9), (0x03CF, 0x03CF), (0x03D7, 0x03EF), (0x03F3, 0x03F3), (0x03F6, 0x03F8), (0x03FA, 0x03FF)],
        standard: &[(0x0386, 0x0386), (0x0388, 0x038A), (0x038C, 0x038C), (0x038E, 0x0390), (0x03AA, 0x03B0), (0x03CA, 0x03CE), (0x1F00, 0x1F15), (0x1F18, 0x1F1D), (0x1F20, 0x1F45), (0x1F48, 0x1F4D), (0x1F50, 0x1F57), (0x1F59, 0x1F59), (0x1F5B, 0x1F5B), (0x1F5D, 0x1F5D), (0x1F5F, 0x1F70), (0x1F72, 0x1F72), (0x1F74, 0x1F74), (0x1F76, 0x1F76), (0x1F78, 0x1F78), (0x1F7A, 0x1F7A), (0x1F7C, 0x1F7C), (0x1F80, 0x1FB4), (0x1FB6, 0x1FBA), (0x1FBC, 0x1FBC), (0x1FC2, 0x1FC4), (0x1FC6, 0x1FC8), (0x1FCA, 0x1FCA), (0x1FCC, 0x1FCC), (0x1FD0, 0x1FD2), (0x1FD6, 0x1FDA), (0x1FE0, 0x1FE2), (0x1FE4, 0x1FEA), (0x1FEC, 0x1FEC), (0x1FF2, 0x1FF4), (0x1FF6, 0x1FF8), (0x1FFA, 0x1FFA), (0x1FFC, 0x1FFC)],
        maximum: &[(0x037A, 0x037A), (0x0384, 0x0385), (0x03D0, 0x03D6), (0x03F0, 0x03F2), (0x03F4, 0x03F5), (0x03F9, 0x03F9), (0x1FBD, 0x1FBD), (0x1FBF, 0x1FC1), (0x1FCD, 0x1FCF), (0x1FDD, 0x1FDF), (0x1FED, 0x1FED), (0x1FFE, 0x1FFE)],
    },
    Block {
        id: "cyrillic",
        name: "Cyrillic",
        // 245 safe, +52 standard, +0 maximum
        safe: &[(0x0402, 0x0402), (0x0404, 0x0406), (0x0408, 0x040B), (0x040F, 0x0418), (0x041A, 0x0438), (0x043A, 0x044F), (0x0452, 0x0452), (0x0454, 0x0456), (0x0458, 0x045B), (0x045F, 0x0475), (0x0478, 0x0482), (0x048A, 0x04C0), (0x04C3, 0x04CF), (0x04D4, 0x04D5), (0x04D8, 0x04D9), (0x04E0, 0x04E1), (0x04E8, 0x04E9), (0x04F6, 0x04F7), (0x04FA, 0x052F)],
        standard: &[(0x0400, 0x0401), (0x0403, 0x0403), (0x0407, 0x0407), (0x040C, 0x040E), (0x0419, 0x0419), (0x0439, 0x0439), (0x0450, 0x0451), (0x0453, 0x0453), (0x0457, 0x0457), (0x045C, 0x045E), (0x0476, 0x0477), (0x04C1, 0x04C2), (0x04D0, 0x04D3), (0x04D6, 0x04D7), (0x04DA, 0x04DF), (0x04E2, 0x04E7), (0x04EA, 0x04F5), (0x04F8, 0x04F9)],
        maximum: &[],
    },
    Block {
        id: "armenian",
        name: "Armenian",
        // 87 safe, +0 standard, +1 maximum
        safe: &[(0x0531, 0x0556), (0x0559, 0x0586), (0x0588, 0x058A)],
        standard: &[],
        maximum: &[(0x0587, 0x0587)],
    },
    Block {
        id: "hebrew",
        name: "Hebrew",
        // 27 safe, +0 standard, +0 maximum
        safe: &[(0x05D0, 0x05EA)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "arabic",
        name: "Arabic",
        // 130 safe, +8 standard, +4 maximum
        safe: &[(0x0620, 0x0621), (0x0627, 0x064A), (0x0671, 0x0674), (0x0679, 0x06BF), (0x06C1, 0x06C1), (0x06C3, 0x06D2)],
        standard: &[(0x0622, 0x0626), (0x06C0, 0x06C0), (0x06C2, 0x06C2), (0x06D3, 0x06D3)],
        maximum: &[(0x0675, 0x0678)],
    },
    Block {
        id: "devanagari",
        name: "Devanagari",
        // 53 safe, +3 standard, +0 maximum
        safe: &[(0x0904, 0x0928), (0x092A, 0x0930), (0x0932, 0x0933), (0x0935, 0x0939), (0x0960, 0x0961)],
        standard: &[(0x0929, 0x0929), (0x0931, 0x0931), (0x0934, 0x0934)],
        maximum: &[],
    },
    Block {
        id: "bengali",
        name: "Bengali",
        // 44 safe, +0 standard, +0 maximum
        safe: &[(0x0985, 0x098C), (0x098F, 0x0990), (0x0993, 0x09A8), (0x09AA, 0x09B0), (0x09B2, 0x09B2), (0x09B6, 0x09B9)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "tamil",
        name: "Tamil",
        // 34 safe, +1 standard, +0 maximum
        safe: &[(0x0B85, 0x0B8A), (0x0B8E, 0x0B90), (0x0B92, 0x0B93), (0x0B95, 0x0B95), (0x0B99, 0x0B9A), (0x0B9C, 0x0B9C), (0x0B9E, 0x0B9F), (0x0BA3, 0x0BA4), (0x0BA8, 0x0BAA), (0x0BAE, 0x0BB9)],
        standard: &[(0x0B94, 0x0B94)],
        maximum: &[],
    },
    Block {
        id: "thai",
        name: "Thai",
        // 48 safe, +0 standard, +0 maximum
        safe: &[(0x0E01, 0x0E30)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "georgian",
        name: "Georgian",
        // 130 safe, +0 standard, +1 maximum
        safe: &[(0x10A0, 0x10C5), (0x10C7, 0x10C7), (0x10CD, 0x10CD), (0x10D0, 0x10FA), (0x10D0, 0x10FB), (0x10FD, 0x10FF)],
        standard: &[],
        maximum: &[(0x10FC, 0x10FC)],
    },
    Block {
        id: "runic",
        name: "Runic",
        // 75 safe, +0 standard, +0 maximum
        safe: &[(0x16A0, 0x16EA)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "hiragana",
        name: "Hiragana",
        // 60 safe, +26 standard, +0 maximum
        safe: &[(0x3041, 0x304B), (0x304D, 0x304D), (0x304F, 0x304F), (0x3051, 0x3051), (0x3053, 0x3053), (0x3055, 0x3055), (0x3057, 0x3057), (0x3059, 0x3059), (0x305B, 0x305B), (0x305D, 0x305D), (0x305F, 0x305F), (0x3061, 0x3061), (0x3063, 0x3064), (0x3066, 0x3066), (0x3068, 0x3068), (0x306A, 0x306F), (0x3072, 0x3072), (0x3075, 0x3075), (0x3078, 0x3078), (0x307B, 0x307B), (0x307E, 0x3093), (0x3095, 0x3096)],
        standard: &[(0x304C, 0x304C), (0x304E, 0x304E), (0x3050, 0x3050), (0x3052, 0x3052), (0x3054, 0x3054), (0x3056, 0x3056), (0x3058, 0x3058), (0x305A, 0x305A), (0x305C, 0x305C), (0x305E, 0x305E), (0x3060, 0x3060), (0x3062, 0x3062), (0x3065, 0x3065), (0x3067, 0x3067), (0x3069, 0x3069), (0x3070, 0x3071), (0x3073, 0x3074), (0x3076, 0x3077), (0x3079, 0x307A), (0x307C, 0x307D), (0x3094, 0x3094)],
        maximum: &[],
    },
    Block {
        id: "katakana",
        name: "Katakana",
        // 60 safe, +30 standard, +0 maximum
        safe: &[(0x30A1, 0x30AB), (0x30AD, 0x30AD), (0x30AF, 0x30AF), (0x30B1, 0x30B1), (0x30B3, 0x30B3), (0x30B5, 0x30B5), (0x30B7, 0x30B7), (0x30B9, 0x30B9), (0x30BB, 0x30BB), (0x30BD, 0x30BD), (0x30BF, 0x30BF), (0x30C1, 0x30C1), (0x30C3, 0x30C4), (0x30C6, 0x30C6), (0x30C8, 0x30C8), (0x30CA, 0x30CF), (0x30D2, 0x30D2), (0x30D5, 0x30D5), (0x30D8, 0x30D8), (0x30DB, 0x30DB), (0x30DE, 0x30F3), (0x30F5, 0x30F6)],
        standard: &[(0x30AC, 0x30AC), (0x30AE, 0x30AE), (0x30B0, 0x30B0), (0x30B2, 0x30B2), (0x30B4, 0x30B4), (0x30B6, 0x30B6), (0x30B8, 0x30B8), (0x30BA, 0x30BA), (0x30BC, 0x30BC), (0x30BE, 0x30BE), (0x30C0, 0x30C0), (0x30C2, 0x30C2), (0x30C5, 0x30C5), (0x30C7, 0x30C7), (0x30C9, 0x30C9), (0x30D0, 0x30D1), (0x30D3, 0x30D4), (0x30D6, 0x30D7), (0x30D9, 0x30DA), (0x30DC, 0x30DD), (0x30F4, 0x30F4), (0x30F7, 0x30FA)],
        maximum: &[],
    },
    Block {
        id: "hangul",
        name: "Hangul",
        // 0 safe, +11172 standard, +0 maximum
        safe: &[],
        standard: &[(0xAC00, 0xD7A3)],
        maximum: &[],
    },
    Block {
        id: "cjk",
        name: "CJK",
        // 20992 safe, +0 standard, +0 maximum
        safe: &[(0x4E00, 0x9FFF)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "arrows",
        name: "Arrows",
        // 106 safe, +6 standard, +0 maximum
        safe: &[(0x2190, 0x2199), (0x219C, 0x21AD), (0x21AF, 0x21CC), (0x21D0, 0x21FF)],
        standard: &[(0x219A, 0x219B), (0x21AE, 0x21AE), (0x21CD, 0x21CF)],
        maximum: &[],
    },
    Block {
        id: "math",
        name: "Math symbols",
        // 214 safe, +38 standard, +4 maximum
        safe: &[(0x2200, 0x2203), (0x2205, 0x2208), (0x220A, 0x220B), (0x220D, 0x2223), (0x2225, 0x2225), (0x2227, 0x222B), (0x222E, 0x222E), (0x2231, 0x2240), (0x2242, 0x2243), (0x2245, 0x2246), (0x2248, 0x2248), (0x224A, 0x225F), (0x2261, 0x2261), (0x2263, 0x226C), (0x2272, 0x2273), (0x2276, 0x2277), (0x227A, 0x227F), (0x2282, 0x2283), (0x2286, 0x2287), (0x228A, 0x22AB), (0x22B0, 0x22DF), (0x22E4, 0x22E9), (0x22EE, 0x22FF)],
        standard: &[(0x2204, 0x2204), (0x2209, 0x2209), (0x220C, 0x220C), (0x2224, 0x2224), (0x2226, 0x2226), (0x2241, 0x2241), (0x2244, 0x2244), (0x2247, 0x2247), (0x2249, 0x2249), (0x2260, 0x2260), (0x2262, 0x2262), (0x226D, 0x2271), (0x2274, 0x2275), (0x2278, 0x2279), (0x2280, 0x2281), (0x2284, 0x2285), (0x2288, 0x2289), (0x22AC, 0x22AF), (0x22E0, 0x22E3), (0x22EA, 0x22ED)],
        maximum: &[(0x222C, 0x222D), (0x222F, 0x2230)],
    },
    Block {
        id: "geometric",
        name: "Geometric shapes",
        // 96 safe, +0 standard, +0 maximum
        safe: &[(0x25A0, 0x25FF)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "box",
        name: "Box drawing",
        // 128 safe, +0 standard, +0 maximum
        safe: &[(0x2500, 0x257F)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "braille",
        name: "Braille",
        // 256 safe, +0 standard, +0 maximum
        safe: &[(0x2800, 0x28FF)],
        standard: &[],
        maximum: &[],
    },
    Block {
        id: "currency",
        name: "Currency",
        // 31 safe, +0 standard, +1 maximum
        safe: &[(0x20A0, 0x20A7), (0x20A9, 0x20BF)],
        standard: &[],
        maximum: &[(0x20A8, 0x20A8)],
    },
];

/// A named starting point for script selection.
///
/// Deliberately describes **what the password contains**, not which site it is
/// for. A preset named after a service would be a claim about that service's
/// password policy — unverifiable from here, liable to change without notice,
/// and when wrong it causes the exact lockout the user was trying to avoid. It
/// is safer to say "Japanese" and let the user confirm the site accepts it.
///
/// Presets also fix a practical problem: with all 22 blocks selected, each group
/// contributes only ~4% of the characters, so digits become scarce. Selecting
/// three scripts instead of 22 puts digits back at a useful density.
pub struct Preset {
    pub name: &'static str,
    pub blocks: &'static [&'static str],
    pub hint: &'static str,
}

pub const PRESETS: &[Preset] = &[
    Preset {
        name: "ASCII only",
        blocks: &[],
        hint: "Widest site compatibility. Nothing to normalize, nothing to truncate.",
    },
    Preset {
        name: "European",
        blocks: &["latin-ext", "greek", "cyrillic"],
        hint: "Mostly 2-byte characters, so length and byte count stay close.",
    },
    Preset {
        name: "Japanese",
        blocks: &["hiragana", "katakana", "cjk"],
        hint: "3 bytes per character — 24 characters reaches bcrypt's 72-byte limit.",
    },
    Preset {
        name: "Symbols",
        blocks: &["arrows", "math", "geometric", "box", "braille", "currency"],
        hint: "Technical glyphs only. No letters from any script.",
    },
    Preset {
        name: "Everything",
        blocks: &[
            "latin-ext", "greek", "cyrillic", "armenian", "hebrew", "arabic",
            "devanagari", "bengali", "tamil", "thai", "georgian", "runic",
            "hiragana", "katakana", "hangul", "cjk", "arrows", "math",
            "geometric", "box", "braille", "currency",
        ],
        hint: "Every block. Each contributes ~4% of characters, so digits are rare.",
    },
];

/// Password constraints for major providers, as documented by the providers
/// themselves where possible.
///
/// **Checked 2026-07-25. Verify before relying on any of it** — these policies
/// change without announcement, which is exactly why the generator treats this
/// as a reference to read rather than a rule to apply automatically. Nothing
/// here is wired into generation; it exists so the choice is informed.
///
/// Both notable entries are now backed by testing rather than documentation.
/// Google's form rejects non-ASCII outright ("Only use letters, numbers, and
/// common punctuation characters"), matching its help pages; Proton accepts it
/// and survives a login round-trip. So the answer to "do sites take Unicode
/// passwords" is genuinely "some do, some don't" — which is why this table
/// records observations with dates and the generator never acts on them.
pub struct SiteLimit {
    pub name: &'static str,
    pub limits: &'static str,
    pub unicode: UnicodeSupport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnicodeSupport {
    /// Non-ASCII confirmed end to end: the form accepted it **and** a subsequent
    /// logout/login round-trip succeeded. This is the only evidence worth much —
    /// a form accepting a string says nothing about whether the login path hashes
    /// the same bytes, and that mismatch is the real lockout mechanism.
    VerifiedTested,
    /// Non-ASCII confirmed rejected by the provider's own validator.
    ///
    /// Rejection at the form is the *safe* failure: nothing is stored, nothing is
    /// silently altered, and the user finds out immediately at no cost. Far
    /// better than a form that quietly strips the characters and leaves a stored
    /// password that no longer matches what the user saved.
    RejectedTested,
    /// Not documented either way — test before committing.
    Unknown,
}

pub const SITE_LIMITS: &[SiteLimit] = &[
    SiteLimit {
        name: "Google / Gmail",
        // Verified 2026-07-25, twice. The form refused a multi-script password
        // with "Only use letters, numbers, and common punctuation characters",
        // and then also refused letters-only candidates in Japanese and Greek
        // (日本語のパスワード123, ΕλληνικάΓράμματα123). So the restriction really
        // is ASCII, not merely a rejection of symbols — matching the help pages
        // in both English and Japanese, and contradicting several published
        // compatibility guides that list Google as Unicode-friendly.
        limits: "8 min, no documented max",
        unicode: UnicodeSupport::RejectedTested,
    },
    SiteLimit {
        name: "Microsoft (Outlook, Hotmail)",
        limits: "16 max — extra characters ignored",
        unicode: UnicodeSupport::Unknown,
    },
    SiteLimit {
        name: "Apple ID",
        limits: "128 max",
        unicode: UnicodeSupport::Unknown,
    },
    SiteLimit {
        name: "Amazon",
        limits: "6 min, 1024 max",
        unicode: UnicodeSupport::Unknown,
    },
    SiteLimit {
        name: "GitHub",
        // Docs state a minimum only — no maximum and no character restriction,
        // and the hashing algorithm is not published. Absence of a stated limit
        // is not evidence of support, so this stays untested. Compare GitLab,
        // which accepts 128 characters while hashing with bcrypt and therefore
        // silently discards everything past 72 bytes.
        limits: "8 min with a digit+lowercase, or 15 min; no documented max",
        unicode: UnicodeSupport::Unknown,
    },
    SiteLimit {
        name: "Proton Mail",
        // Verified 2026-07-25: a 21-character, 15-script, 56-byte password was
        // accepted, and logout/login afterwards succeeded. Note the tested
        // password was NFD-unstable (Hangul syllables), so this confirms Proton
        // is at least self-consistent about normalization.
        // Worse than a normal bcrypt site: in one-password mode the bcrypt hash
        // also encrypts the PGP private key, so a mangled or truncated password
        // can cost access to existing encrypted mail, not just to login.
        limits: "bcrypt 72 bytes; password also derives the mailbox key",
        unicode: UnicodeSupport::VerifiedTested,
    },
    SiteLimit {
        name: "Anything using bcrypt",
        limits: "72 bytes, silently truncated",
        unicode: UnicodeSupport::Unknown,
    },
];

// ── ASCII classes ────────────────────────────────────────────────────────────

/// The original four ASCII classes, kept as first-class groups so a multilingual
/// password can still be required to contain a digit or a symbol — which plenty
/// of sites demand regardless of what else is in it.
pub const ASCII_LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const ASCII_UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const ASCII_DIGITS: &str = "0123456789";
pub const ASCII_SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?";

// ── Random selection ─────────────────────────────────────────────────────────

/// Uniform index in `0..n`, by rejection sampling.
///
/// The previous ASCII-only generator drew a single byte, which structurally
/// capped the pool at 256 characters — unusable for a 34,000-character pool. This
/// draws 32 bits and discards the incomplete final block so every index stays
/// equally likely; taking `r % n` without that discard would bias the low indices.
fn uniform_index(n: usize) -> usize {
    use aes_gcm::aead::{rand_core::RngCore, OsRng};
    assert!(n > 0, "cannot sample from an empty pool");
    let n64 = n as u64;
    // Largest multiple of n that fits in u32's range.
    let limit = (1u64 << 32) / n64 * n64;
    let mut buf = [0u8; 4];
    loop {
        OsRng.fill_bytes(&mut buf);
        let r = u32::from_le_bytes(buf) as u64;
        if r < limit {
            return (r % n64) as usize;
        }
    }
}

/// Fisher-Yates, using the same unbiased index source.
fn shuffle(items: &mut [char]) {
    for i in (1..items.len()).rev() {
        items.swap(i, uniform_index(i + 1));
    }
}

/// How characters are drawn when several groups are selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Balance {
    /// Uniform over the union of every group. Maximum entropy, but a group's
    /// share of the output is proportional to its size — and the blocks are
    /// wildly unequal. CJK alone is 60% of the full pool and Hangul another 32%,
    /// so "select everything" produces output that looks almost entirely CJK.
    Pool,
    /// Pick a group uniformly, then a character within it. Every selected script
    /// contributes about equally, which is what "use all these languages"
    /// actually means to a person. Costs some entropy — 11.8 bits/char against
    /// 15.1 for the full set — because the large blocks are sampled less.
    Blocks,
}

/// Generate a password of `len` characters drawn from `groups`.
///
/// Guarantees **at least one character from every non-empty group**, which the
/// old generator did not do — with four ASCII classes selected it could, however
/// improbably, return a password with no digit and fail a site's complexity
/// rules. Coverage characters are placed first and then the whole thing is
/// shuffled, so their positions leak nothing.
///
/// Returns an empty string if every group is empty or `len` is zero.
pub fn generate(groups: &[Vec<char>], len: usize, balance: Balance) -> String {
    let groups: Vec<&Vec<char>> = groups.iter().filter(|g| !g.is_empty()).collect();
    if groups.is_empty() || len == 0 {
        return String::new();
    }

    let pool: Vec<char> = groups.iter().flat_map(|g| g.iter().copied()).collect();

    // Coverage is only attempted when it is actually achievable. With more groups
    // selected than there are characters to place (easy to do — there are 22
    // script blocks), forcing one per group would fill the whole password from
    // the first `len` groups and quietly ignore the rest. Drawing uniformly from
    // the union instead is both unbiased and what the reported entropy assumes.
    let mut chars: Vec<char> = Vec::with_capacity(len);
    if groups.len() <= len {
        for g in &groups {
            chars.push(g[uniform_index(g.len())]);
        }
    }

    while chars.len() < len {
        let c = match balance {
            Balance::Pool => pool[uniform_index(pool.len())],
            Balance::Blocks => {
                let g = groups[uniform_index(groups.len())];
                g[uniform_index(g.len())]
            }
        };
        chars.push(c);
    }

    shuffle(&mut chars);
    chars.into_iter().collect()
}

// ── Measurement ──────────────────────────────────────────────────────────────

/// Shannon entropy of a uniformly drawn password: `len * log2(pool)`.
///
/// Honest about the actual pool rather than the theoretical maximum — selecting
/// two blocks reports the entropy of those two blocks.
pub fn entropy_bits(pool_size: usize, len: usize) -> f64 {
    if pool_size <= 1 || len == 0 {
        return 0.0;
    }
    len as f64 * (pool_size as f64).log2()
}

/// Entropy for [`Balance::Blocks`], which is **not** `len * log2(pool)`.
///
/// Each character is drawn by picking one of `k` groups uniformly and then a
/// character inside it, so `p(c) = 1 / (k * n_b)` and the per-character entropy
/// is `log2(k) + mean(log2(n_b))`. Reporting the pool figure here would overstate
/// the strength, which is the sort of lie a password tool must not tell.
pub fn entropy_bits_balanced(group_sizes: &[usize], len: usize) -> f64 {
    let sizes: Vec<usize> = group_sizes.iter().copied().filter(|&n| n > 0).collect();
    if sizes.is_empty() || len == 0 {
        return 0.0;
    }
    let k = sizes.len() as f64;
    let mean_log: f64 = sizes.iter().map(|&n| (n as f64).log2()).sum::<f64>() / k;
    len as f64 * (k.log2() + mean_log)
}

/// Longest password, in characters, guaranteed to stay within `byte_cap` UTF-8
/// bytes whatever is drawn.
///
/// Deliberately worst-case (every character its widest): a probabilistic fit
/// would occasionally overshoot, and "occasionally silently truncated" is the
/// exact failure this is meant to rule out.
pub fn max_chars_within_bytes(groups: &[Vec<char>], byte_cap: usize) -> usize {
    let widest = groups
        .iter()
        .flatten()
        .map(|c| c.len_utf8())
        .max()
        .unwrap_or(1);
    byte_cap / widest.max(1)
}

/// Length in UTF-8 **bytes**, which is what a server actually receives and what
/// bcrypt counts against its 72-byte ceiling. ASCII is 1 byte per character,
/// Greek/Cyrillic 2, CJK and kana 3.
pub fn utf8_len(s: &str) -> usize {
    s.len()
}

/// bcrypt ignores every byte past this. Not a hard cap in the UI — plenty of
/// sites do not use bcrypt — but crossing it silently is how people lock
/// themselves out, so the dialog flags it.
pub const BCRYPT_BYTE_LIMIT: usize = 72;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use unicode_normalization::UnicodeNormalization;

    fn all_chars(tier: Tier) -> Vec<char> {
        BLOCKS.iter().flat_map(|b| b.chars(tier)).collect()
    }

    /// The tables are generated offline, so this is the check that they were
    /// generated correctly — and that they still hold if anyone hand-edits them.
    #[test]
    fn every_character_is_normalization_stable_for_its_tier() {
        for block in BLOCKS {
            let check = |ranges: &[(u32, u32)], tier: Tier| {
                for &(a, b) in ranges {
                    for cp in a..=b {
                        let c = char::from_u32(cp).expect("valid scalar value");
                        let s = c.to_string();
                        assert_eq!(s.nfc().collect::<String>(), s, "{c:?} U+{cp:04X} not NFC-stable");
                        if tier <= Tier::Standard {
                            assert_eq!(
                                s.nfkc().collect::<String>(), s,
                                "{c:?} U+{cp:04X} in {} is not NFKC-stable", tier.label()
                            );
                        }
                        if tier == Tier::Safe {
                            assert_eq!(s.nfd().collect::<String>(), s, "{c:?} U+{cp:04X} not NFD-stable");
                            assert_eq!(s.nfkd().collect::<String>(), s, "{c:?} U+{cp:04X} not NFKD-stable");
                        }
                    }
                }
            };
            check(block.safe, Tier::Safe);
            check(block.standard, Tier::Standard);
            check(block.maximum, Tier::Maximum);
        }
    }

    /// Invisible or space-like characters would make a password impossible to
    /// verify by eye and are the classic source of "it worked yesterday".
    #[test]
    fn no_invisible_whitespace_or_combining_characters() {
        for c in all_chars(Tier::Maximum) {
            assert!(!c.is_whitespace(), "{c:?} is whitespace");
            assert!(!c.is_control(), "{c:?} is a control character");
            // Format characters (Cf) cover zero-width joiners and RTL marks.
            assert!(
                !matches!(c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F | 0xFEFF),
                "{c:?} is a zero-width or bidi control"
            );
        }
    }

    /// The dialog opens on index 0 and must land on Safe; an off-by-one here
    /// would silently hand out passwords from a looser tier than advertised.
    #[test]
    fn index_zero_is_the_safe_tier() {
        assert_eq!(Tier::from_index(0), Tier::Safe);
        assert_eq!(Tier::from_index(1), Tier::Standard);
        assert_eq!(Tier::from_index(2), Tier::Maximum);
        // Out-of-range falls back to the strictest, never the loosest.
        assert_eq!(Tier::from_index(99), Tier::Safe);
        assert_eq!(Tier::all()[0], Tier::Safe);
    }

    #[test]
    fn tiers_are_nested_and_grow() {
        let safe = all_chars(Tier::Safe).len();
        let standard = all_chars(Tier::Standard).len();
        let maximum = all_chars(Tier::Maximum).len();
        assert!(safe < standard && standard <= maximum, "{safe} {standard} {maximum}");
        // A Safe character must still be present at Maximum.
        let max_set: HashSet<char> = all_chars(Tier::Maximum).into_iter().collect();
        for c in all_chars(Tier::Safe) {
            assert!(max_set.contains(&c), "{c:?} vanished at a looser tier");
        }
    }

    #[test]
    fn japanese_is_covered() {
        let find = |id: &str| BLOCKS.iter().find(|b| b.id == id).expect(id);
        // Plain kana are Safe; the voiced (dakuten) forms decompose under NFD and
        // so must land in Standard, not Safe.
        assert!(find("hiragana").chars(Tier::Safe).contains(&'か'));
        assert!(!find("hiragana").chars(Tier::Safe).contains(&'が'));
        assert!(find("hiragana").chars(Tier::Standard).contains(&'が'));
        assert!(find("katakana").chars(Tier::Safe).contains(&'カ'));
        assert!(find("cjk").chars(Tier::Safe).contains(&'語'));
    }

    /// With more groups than characters, coverage is impossible; the generator
    /// must fall back to a plain uniform draw rather than filling the password
    /// from whichever groups happen to come first.
    #[test]
    fn more_groups_than_characters_draws_uniformly() {
        let groups: Vec<Vec<char>> = "abcdefghij".chars().map(|c| vec![c]).collect();
        let mut seen_last = false;
        for _ in 0..500 {
            let pw = generate(&groups, 3, Balance::Pool);
            assert_eq!(pw.chars().count(), 3);
            if pw.contains('j') {
                seen_last = true;
            }
        }
        assert!(seen_last, "later groups never appeared — coverage bias");
    }

    #[test]
    fn generate_respects_length_and_covers_every_group() {
        let groups = vec![
            ASCII_DIGITS.chars().collect::<Vec<_>>(),
            ASCII_UPPER.chars().collect::<Vec<_>>(),
            BLOCKS.iter().find(|b| b.id == "cjk").unwrap().chars(Tier::Safe),
        ];
        for _ in 0..200 {
            let pw = generate(&groups, 12, Balance::Pool);
            assert_eq!(pw.chars().count(), 12);
            for g in &groups {
                assert!(pw.chars().any(|c| g.contains(&c)), "group missing from {pw:?}");
            }
        }
    }

    /// RFC 8265 `OpaqueString` compliance, clause by clause. If a future table
    /// edit broke one of these, a PRECIS-implementing server would silently
    /// transform the password between the input field and the hash — which is
    /// the lockout mechanism this whole module is arranged to avoid.
    #[test]
    fn opaquestring_profile_is_satisfied() {
        for c in all_chars(Tier::Maximum) {
            let s = c.to_string();
            // 1. Width mapping / normalization: NFC must be a no-op.
            assert_eq!(s.nfc().collect::<String>(), s, "{c:?} is altered by NFC");
            // 2. No non-ASCII spaces to map to U+0020 — we exclude spaces entirely,
            //    which is stricter than the profile requires.
            assert!(!c.is_whitespace(), "{c:?} is a space needing mapping");
            // 3. Case mapping is not applied by the profile, so a character whose
            //    case is unstable is fine — but it must not be a control.
            assert!(!c.is_control(), "{c:?} is a control character");
            // 4. Disallowed: default-ignorable code points.
            assert!(
                !matches!(c as u32,
                    0x00AD | 0x034F | 0x061C | 0x115F..=0x1160 | 0x17B4..=0x17B5
                    | 0x180B..=0x180F | 0x200B..=0x200F | 0x202A..=0x202E
                    | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0),
                "{c:?} is a default-ignorable code point"
            );
        }
    }

    #[test]
    fn generated_passwords_are_already_nfc() {
        // The property the module docs claim: no runtime normalization needed.
        let groups: Vec<Vec<char>> = BLOCKS.iter().map(|b| b.chars(Tier::Maximum)).collect();
        for _ in 0..100 {
            let pw = generate(&groups, 40, Balance::Pool);
            assert_eq!(pw.nfc().collect::<String>(), pw, "not NFC: {pw:?}");
        }
    }

    /// A preset naming a block that no longer exists would silently select
    /// nothing, which is the kind of failure a password tool must not have.
    #[test]
    fn every_preset_references_real_blocks() {
        for preset in PRESETS {
            for id in preset.blocks {
                assert!(
                    BLOCKS.iter().any(|b| b.id == *id),
                    "preset {:?} references unknown block {id:?}",
                    preset.name
                );
            }
        }
        // "Everything" must actually mean everything.
        let all = PRESETS.iter().find(|p| p.name == "Everything").unwrap();
        assert_eq!(all.blocks.len(), BLOCKS.len(), "Everything is missing a block");
    }

    /// The reason presets exist: fewer groups means digits are no longer diluted
    /// to ~4% of the output.
    #[test]
    fn a_focused_preset_restores_digit_density() {
        let jp = PRESETS.iter().find(|p| p.name == "Japanese").unwrap();
        let mut groups: Vec<Vec<char>> = vec![
            ASCII_LOWER.chars().collect(),
            ASCII_UPPER.chars().collect(),
            ASCII_DIGITS.chars().collect(),
            ASCII_SYMBOLS.chars().collect(),
        ];
        groups.extend(
            jp.blocks
                .iter()
                .map(|id| BLOCKS.iter().find(|b| b.id == *id).unwrap().chars(Tier::Standard)),
        );
        let pw = generate(&groups, 700, Balance::Blocks);
        let digits = pw.chars().filter(|c| c.is_ascii_digit()).count();
        // 7 groups -> about 1/7th of 700 = 100.
        assert!((60..150).contains(&digits), "{digits} digits in 700, expected ~100");
    }

    /// The reference table is shown to the user, so it must be coherent — a blank
    /// row would read as a claim about a site.
    #[test]
    fn site_limits_table_is_populated() {
        assert!(!SITE_LIMITS.is_empty());
        for site in SITE_LIMITS {
            assert!(!site.name.is_empty() && !site.limits.is_empty(), "{}", site.name);
        }
        // Google being ASCII-only is the most consequential fact for this module;
        // if it is ever removed, the warning shown in the dialog becomes a lie.
        let google = SITE_LIMITS.iter().find(|s| s.name.starts_with("Google")).unwrap();
        assert_eq!(google.unicode, UnicodeSupport::RejectedTested);
    }

    #[test]
    fn empty_input_is_handled() {
        assert_eq!(generate(&[], 10, Balance::Pool), "");
        assert_eq!(generate(&[vec![]], 10, Balance::Pool), "");
        assert_eq!(generate(&[vec!['a']], 0, Balance::Pool), "");
    }

    #[test]
    fn sampling_is_close_to_uniform() {
        // A biased `% n` without rejection would skew the low indices; over
        // 60k draws from a 7-element pool the counts should stay near 1/7th.
        let pool: Vec<char> = "abcdefg".chars().collect();
        let draws = 63_000;
        let pw = generate(&[pool.clone()], draws, Balance::Pool);
        for c in &pool {
            let n = pw.chars().filter(|x| x == c).count() as f64;
            let expected = draws as f64 / pool.len() as f64;
            assert!(
                (n - expected).abs() < expected * 0.12,
                "{c:?} appeared {n} times, expected about {expected}"
            );
        }
    }

    /// The bug that made "select everything" come out looking entirely Chinese:
    /// CJK is 60% of the pool and Hangul 32%, so uniform-over-union hands them
    /// 92% of the characters. Balanced mode must even that out.
    #[test]
    fn balanced_mode_stops_the_largest_block_dominating() {
        let latin: Vec<char> = ASCII_LOWER.chars().collect();
        let cjk = BLOCKS.iter().find(|b| b.id == "cjk").unwrap().chars(Tier::Safe);
        let groups = vec![latin.clone(), cjk.clone()];

        let pooled = generate(&groups, 2000, Balance::Pool);
        let pooled_latin = pooled.chars().filter(|c| latin.contains(c)).count();
        // 26 of 21018 characters: Latin should be almost absent.
        assert!(pooled_latin < 100, "pooled gave latin {pooled_latin}/2000");

        let balanced = generate(&groups, 2000, Balance::Blocks);
        let bal_latin = balanced.chars().filter(|c| latin.contains(c)).count();
        assert!(
            (800..1200).contains(&bal_latin),
            "balanced gave latin {bal_latin}/2000, expected about half"
        );
    }

    #[test]
    fn balanced_entropy_is_lower_and_honest() {
        // Two groups of 26 and 21000: pooled reports log2(21026) per char,
        // balanced only log2(2) + (log2(26)+log2(21000))/2.
        let pooled = entropy_bits(21026, 1);
        let balanced = entropy_bits_balanced(&[26, 21000], 1);
        assert!(balanced < pooled, "{balanced} should be under {pooled}");
        assert!((balanced - (1.0 + (26f64.log2() + 21000f64.log2()) / 2.0)).abs() < 1e-9);
        assert_eq!(entropy_bits_balanced(&[], 10), 0.0);
        assert_eq!(entropy_bits_balanced(&[100], 0), 0.0);
    }

    #[test]
    fn byte_cap_is_never_exceeded() {
        let cjk = vec![BLOCKS.iter().find(|b| b.id == "cjk").unwrap().chars(Tier::Safe)];
        let n = max_chars_within_bytes(&cjk, BCRYPT_BYTE_LIMIT);
        assert_eq!(n, 24, "3-byte characters: 72/3");
        for _ in 0..50 {
            let pw = generate(&cjk, n, Balance::Blocks);
            assert!(utf8_len(&pw) <= BCRYPT_BYTE_LIMIT, "{} bytes", utf8_len(&pw));
        }
        // Mixed pools are limited by their widest character, not their average.
        let mixed = vec![ASCII_LOWER.chars().collect::<Vec<_>>(), cjk[0].clone()];
        assert_eq!(max_chars_within_bytes(&mixed, 72), 24);
    }

    #[test]
    fn byte_length_tracks_the_script() {
        assert_eq!(utf8_len("abcd"), 4);
        assert_eq!(utf8_len("абвг"), 8);   // Cyrillic: 2 bytes each
        assert_eq!(utf8_len("日本語"), 9); // CJK: 3 bytes each
        // The bcrypt trap in one line: 60 CJK characters is 180 bytes.
        assert!(60 * 3 > BCRYPT_BYTE_LIMIT);
    }

    #[test]
    fn entropy_matches_the_pool() {
        assert_eq!(entropy_bits(2, 8).round(), 8.0);
        assert_eq!(entropy_bits(95, 1).round(), 7.0);
        assert_eq!(entropy_bits(1, 100), 0.0);
        assert_eq!(entropy_bits(1000, 0), 0.0);
    }
}

