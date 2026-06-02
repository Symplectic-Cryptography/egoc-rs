//! A deterministic `RngCore` backed by a BLAKE3 extendable-output reader.
//! Used to expand public generators and to derive `S,T` from 32-byte seeds so
//! that an opening can reveal just the seeds (never the matrices themselves).

use blake3::Hasher;
use rand_core::{Error, RngCore};

/// XOF-backed deterministic stream. Domain-separated by `context`.
pub struct XofRng {
    reader: blake3::OutputReader,
}

impl XofRng {
    pub fn new(context: &[u8], seed: &[u8; 32]) -> Self {
        let mut h = Hasher::new();
        h.update(context);
        h.update(&[0u8]); // separator
        h.update(seed);
        Self { reader: h.finalize_xof() }
    }
}

impl RngCore for XofRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.reader.fill(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.reader.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.reader.fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
