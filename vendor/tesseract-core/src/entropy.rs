//! Entropy pool for volume/key creation.
//!
//! User events (mouse/keyboard timings collected by the GUI) are mixed into a
//! BLAKE3 pool. The pool NEVER replaces the OS CSPRNG: the agent's
//! [`crate::EntropySource`] implementation XORs pool output over
//! `getrandom()` bytes, so output is at least as strong as the OS CSPRNG
//! even if the collected events are fully attacker-known, and at least as
//! strong as the pool if the OS CSPRNG were somehow compromised.

/// Accumulates entropy events. Cheap to update from the IPC handler.
pub struct EntropyPool {
    hasher: blake3::Hasher,
    events: u64,
}

impl core::fmt::Debug for EntropyPool {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "EntropyPool(events={})", self.events)
    }
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyPool {
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new_derive_key("tesseract v1 entropy pool"),
            events: 0,
        }
    }

    /// Mix in one event (timestamp deltas, coordinates, raw timing bytes...).
    pub fn mix(&mut self, data: &[u8]) {
        self.events += 1;
        self.hasher.update(&self.events.to_le_bytes());
        self.hasher.update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);
    }

    pub fn events(&self) -> u64 {
        self.events
    }

    /// Produce `out.len()` bytes of pool output. Consumes a snapshot; the
    /// pool keeps accumulating afterwards (self-ratcheting: the extraction
    /// counter is mixed back in).
    pub fn extract(&mut self, out: &mut [u8]) {
        let mut x = self.hasher.clone();
        x.update(b"extract");
        x.finalize_xof().fill(out);
        // ratchet so the same output is never produced twice
        let ratchet = *x.finalize().as_bytes();
        self.hasher.update(&ratchet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extraction_ratchets() {
        let mut p = EntropyPool::new();
        p.mix(b"event one");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        p.extract(&mut a);
        p.extract(&mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn events_change_output() {
        let mut p1 = EntropyPool::new();
        let mut p2 = EntropyPool::new();
        p1.mix(b"x");
        p2.mix(b"y");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        p1.extract(&mut a);
        p2.extract(&mut b);
        assert_ne!(a, b);
    }
}
