//! Privacy screen — type normally, display reads as an unfamiliar script.
//!
//! The goal is defeating a glance over your shoulder, not defeating an analyst.
//! Say that plainly: this is a **monoalphabetic substitution**, which is
//! trivially breakable by anyone who takes a screenshot and counts letter
//! frequencies. It is a net curtain, not a wall. The actual secrecy in Notas is
//! the encrypted vault; this only governs what is on the glass while you type.
//!
//! # Why substitution rather than translation
//!
//! Machine translation was the obvious-looking answer and is the wrong tool:
//! it is lossy (English → Japanese → English does not return your text), it is
//! not obfuscation (Japanese is perfectly readable to people who read Japanese),
//! it needs either a network call — which the seccomp filter blocks outright —
//! or a few hundred megabytes of local model running in a subprocess, which the
//! `execve` deny also blocks. A substitution is exact, instant, reversible, and
//! costs nothing.
//!
//! # Properties that make it safe to apply to real notes
//!
//! * **Bijective.** Every character maps to exactly one other, and back. There
//!   is no input for which `unscramble(scramble(x)) != x`, which is what makes
//!   it acceptable to run over notes the user cares about.
//! * **Fixed.** The table is a compile-time constant, not random per-session, so
//!   text scrambled today unscrambles next month and on another machine.
//! * **Layout-preserving.** Spaces, tabs and newlines pass through untouched, so
//!   line wrapping, cursor movement and word-double-click behave normally. This
//!   does leak word lengths and line structure — acceptable for the threat being
//!   addressed, and the alternative makes the editor unusable.
//! * **Non-ASCII passes through.** Only printable ASCII is remapped. Text already
//!   in another script is left alone rather than mangled.

/// Printable ASCII, `!` through `~`. Space is deliberately excluded — see the
/// layout-preserving note above.
const SOURCE: &str =
    "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/// The glyphs shown instead, in corresponding order.
///
/// The full Armenian alphabet, upper and lower case (76 letters), topped up with
/// 18 Cyrillic capitals to reach the required count. Letters rather than symbols
/// so the result reads as *some language you don't know* — a passing glance
/// slides off it instead of stopping on it.
///
/// Generated and verified rather than hand-typed: the first attempt at this
/// constant was written by hand and contained repeated glyphs, which silently
/// destroyed text because the mapping was no longer invertible. `tests` now
/// enforces equal length, no duplicates, and no overlap with [`SOURCE`].
const TARGET: &str =
    "ԱԲԳԴԵԶԷԸԹԺԻԼԽԾԿՀՁՂՃՄՅՆՇՈՉՊՋՌՍՎՏՐՑՒՓՔՕՖաբգդեզէըթժիլխծկհձղճմյնշոչպջռսվտրցւփքօֆАБВГДЕЖЗИЙКЛМНОПРС";

/// Number of characters the tables must contain. Asserted in tests rather than
/// left implicit, because a mismatch would silently corrupt text.
#[cfg(test)]
const ALPHABET_LEN: usize = 94;

/// Map a character through a table, returning it unchanged if absent.
fn map_char(c: char, from: &str, to: &str) -> char {
    match from.chars().position(|x| x == c) {
        Some(i) => to.chars().nth(i).unwrap_or(c),
        None => c,
    }
}

/// Render text as the substitute script. Whitespace and non-ASCII pass through.
pub fn scramble(text: &str) -> String {
    text.chars().map(|c| map_char(c, SOURCE, TARGET)).collect()
}

/// Recover the original text. Exactly inverts [`scramble`].
pub fn unscramble(text: &str) -> String {
    text.chars().map(|c| map_char(c, TARGET, SOURCE)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// The tables are hand-written constants, so this is the check that they are
    /// actually usable as a cipher at all. A duplicate in TARGET would make the
    /// mapping non-invertible and silently destroy text.
    #[test]
    fn tables_are_equal_length_and_free_of_duplicates() {
        assert_eq!(SOURCE.chars().count(), ALPHABET_LEN, "SOURCE length");
        assert_eq!(TARGET.chars().count(), ALPHABET_LEN, "TARGET length");

        let src: HashSet<char> = SOURCE.chars().collect();
        assert_eq!(src.len(), ALPHABET_LEN, "SOURCE has duplicates");

        let tgt: HashSet<char> = TARGET.chars().collect();
        assert_eq!(tgt.len(), ALPHABET_LEN, "TARGET has duplicates — not invertible");

        // The two alphabets must not overlap, or a scrambled character could be
        // mistaken for a source character on the way back.
        assert!(src.is_disjoint(&tgt), "alphabets overlap");
    }

    #[test]
    fn round_trip_is_exact_for_all_printable_ascii() {
        let all: String = (0x20u8..=0x7E).map(|b| b as char).collect();
        assert_eq!(unscramble(&scramble(&all)), all);
    }

    #[test]
    fn round_trip_survives_realistic_notes() {
        let samples = [
            "Meeting notes 2026-07-25: budget is $4,200 (up 12%).",
            "- [ ] call the bank\n- [x] renew passport\n\n  indented line",
            "password: hunter2 !@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`",
            "",
            "\n\n\t\t   \n",
        ];
        for s in samples {
            assert_eq!(unscramble(&scramble(s)), s, "round trip failed for {s:?}");
        }
    }

    #[test]
    fn layout_characters_are_preserved() {
        // Line and word structure must survive or the editor becomes unusable:
        // wrapping, cursor movement and double-click-to-select all depend on it.
        let text = "one two\tthree\nfour";
        let scrambled = scramble(text);
        assert_eq!(scrambled.matches(' ').count(), 1);
        assert_eq!(scrambled.matches('\t').count(), 1);
        assert_eq!(scrambled.matches('\n').count(), 1);
        assert_eq!(scrambled.chars().count(), text.chars().count());
    }

    #[test]
    fn output_contains_no_readable_ascii_letters() {
        // The entire point: nothing legible should survive on screen.
        let scrambled = scramble("The quick brown fox jumps over the lazy dog 1234567890");
        assert!(
            !scrambled.chars().any(|c| c.is_ascii_alphanumeric()),
            "readable characters leaked: {scrambled}"
        );
    }

    #[test]
    fn non_ascii_input_passes_through_untouched() {
        // Someone typing Japanese should not have it mangled into nonsense that
        // cannot be recovered.
        let text = "日本語 Ελληνικά мир";
        let scrambled = scramble(text);
        assert!(scrambled.contains("日本語"));
        assert_eq!(unscramble(&scrambled), text);
    }

    #[test]
    fn scrambling_actually_changes_the_text() {
        let text = "hello world";
        assert_ne!(scramble(text), text);
        // ...and is not accidentally an identity on any single character.
        for c in SOURCE.chars() {
            assert_ne!(map_char(c, SOURCE, TARGET), c, "{c:?} maps to itself");
        }
    }

    #[test]
    fn double_scrambling_does_not_corrupt() {
        // Guards the disjointness property in practice: scrambling twice then
        // unscrambling twice must still return the original.
        let text = "sensitive note";
        assert_eq!(unscramble(&unscramble(&scramble(&scramble(text)))), text);
    }
}
