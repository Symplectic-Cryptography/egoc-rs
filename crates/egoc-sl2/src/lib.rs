//! `egoc-sl2` — the sl(2) message **encoder**. STRUCTURE ONLY.
//!
//! # ⚠ This crate contributes ZERO cryptographic hardness.
//! It is the elegant skin inherited from the two-time-physics inspiration: each
//! witness pair `(mᵢ, rᵢ)` becomes the traceless symmetric `sl(2)` block
//! `Bᵢ = [[mᵢ, rᵢ], [rᵢ, -mᵢ]]`, whose determinant `det(Bᵢ) = -(mᵢ² + rᵢ²)` is
//! the Sp(2,ℝ) Casimir / the norm of `mᵢ + rᵢ·t ∈ E`.
//!
//! In the predecessor this determinant **leaked** because the commitment applied
//! a `det = 1` action that preserves it. Here the block is only an *injective
//! `F_q`-linear coordinate map*; the determinant is **never exported as a public
//! value** (there is no public method returning it on the witness). Hiding comes
//! entirely from the matrix-code-equivalence layer downstream — not from here.
#![forbid(unsafe_code)]

use egoc_field::Fp;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret witness `w = (m, r) ∈ F_q^n × F_q^n`. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Witness<const Q: u64> {
    pub m: Vec<Fp<Q>>,
    pub r: Vec<Fp<Q>>,
}

impl<const Q: u64> Witness<Q> {
    /// Build from raw vectors (`m.len() == r.len()`, nonempty).
    pub fn new(m: Vec<Fp<Q>>, r: Vec<Fp<Q>>) -> Self {
        assert!(!m.is_empty() && m.len() == r.len(), "m,r must be equal nonempty length");
        Self { m, r }
    }

    /// `n = m.len()`.
    #[inline]
    pub fn n(&self) -> usize {
        self.m.len()
    }

    /// Uniform random witness of length `n`.
    pub fn random(n: usize, rng: &mut impl rand_core::RngCore) -> Self {
        let m = (0..n).map(|_| Fp::random(rng)).collect();
        let r = (0..n).map(|_| Fp::random(rng)).collect();
        Self { m, r }
    }
}

impl<const Q: u64> core::fmt::Debug for Witness<Q> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Witness<{}> {{ n={}, [REDACTED] }}", Q, self.n())
    }
}

/// The `sl(2)` block `[[m, r], [r, -m]]`. Structural; not a security object.
#[derive(Clone, Copy, Debug)]
pub struct Sl2Block<const Q: u64> {
    pub m: Fp<Q>,
    pub r: Fp<Q>,
}

impl<const Q: u64> Sl2Block<Q> {
    #[inline]
    pub fn from_pair(m: Fp<Q>, r: Fp<Q>) -> Self {
        Self { m, r }
    }

    /// The four entries `[[m, r], [r, -m]]` in row-major order.
    #[inline]
    pub fn entries(self) -> [Fp<Q>; 4] {
        [self.m, self.r, self.r, self.m.neg()]
    }

    /// The Casimir `det = -(m² + r²)`.
    ///
    /// **Deliberately `pub(crate)`-spirited and used only in internal tests.**
    /// No public commitment output ever exposes this — see the crate docs and
    /// the `invariant-leak` regression in `egoc-attack`.
    #[doc(hidden)]
    pub fn casimir_for_tests(self) -> Fp<Q> {
        self.m.mul(self.m).add(self.r.mul(self.r)).neg()
    }
}

/// Injective `F_q`-linear encoder: witness ↔ coordinate vector of length `2n`,
/// laid out `[m₀, r₀, m₁, r₁, …]`. This is the message-coordinate map fed to the
/// matrix-code layer; injectivity is what gives binding its message-injectivity
/// term (independently of the hardness assumption).
pub struct Encoder;

impl Encoder {
    /// `pack(w) = (m₀, r₀, …, m_{n-1}, r_{n-1})`.
    pub fn pack<const Q: u64>(w: &Witness<Q>) -> Vec<Fp<Q>> {
        let mut out = Vec::with_capacity(2 * w.n());
        for i in 0..w.n() {
            out.push(w.m[i]);
            out.push(w.r[i]);
        }
        out
    }

    /// Inverse of [`Encoder::pack`]; `coords.len()` must be even.
    pub fn unpack<const Q: u64>(coords: &[Fp<Q>]) -> Witness<Q> {
        assert!(coords.len() % 2 == 0 && !coords.is_empty(), "coords must be even, nonempty");
        let n = coords.len() / 2;
        let mut m = Vec::with_capacity(n);
        let mut r = Vec::with_capacity(n);
        for i in 0..n {
            m.push(coords[2 * i]);
            r.push(coords[2 * i + 1]);
        }
        Witness { m, r }
    }

    /// Number of message coordinates a witness of length `n` occupies.
    #[inline]
    pub fn coord_len(n: usize) -> usize {
        2 * n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::Q_MCE;
    use rand::{rngs::StdRng, SeedableRng};

    type W = Witness<Q_MCE>;

    #[test]
    fn pack_unpack_roundtrip() {
        let mut rng = StdRng::seed_from_u64(1);
        let w = W::random(10, &mut rng);
        let coords = Encoder::pack(&w);
        assert_eq!(coords.len(), Encoder::coord_len(10));
        let w2 = Encoder::unpack::<Q_MCE>(&coords);
        assert_eq!(w.m, w2.m);
        assert_eq!(w.r, w2.r);
    }

    #[test]
    fn encoder_is_injective() {
        // Distinct witnesses → distinct coordinate vectors (collision search).
        let mut rng = StdRng::seed_from_u64(2);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5000 {
            let w = W::random(4, &mut rng);
            let key: Vec<u64> = Encoder::pack(&w).iter().map(|x| x.val()).collect();
            assert!(seen.insert(key), "encoder produced a collision — not injective");
        }
    }

    #[test]
    fn block_entries_are_traceless() {
        let b = Sl2Block::<Q_MCE>::from_pair(Fp::new(7), Fp::new(11));
        let e = b.entries();
        // trace = e[0] + e[3] = m + (-m) = 0
        assert_eq!(e[0].add(e[3]), Fp::zero());
        // symmetric: e[1] == e[2]
        assert_eq!(e[1], e[2]);
    }
}
