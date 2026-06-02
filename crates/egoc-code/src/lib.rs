//! `egoc-code` — the public matrix code and message embedding for EGOC-MCE-R.
//!
//! A code is a `k`-dimensional `E`-subspace of `E^{mr×mc}`, spanned by a public
//! **nothing-up-my-sleeve** generator set `{G₀,…,G_{k-1}}` expanded from a
//! published seed via a BLAKE3 XOF. The message matrix is
//!
//! ```text
//!   M = Σ_{l=0}^{k-1} c_l · G_l ,
//! ```
//!
//! where the first `2·ℓ` coefficients carry the witness coordinates `x(w)`
//! (each `F_q` value embedded as `x + 0·t ∈ E`) and the remaining `k − 2ℓ`
//! coefficients are **fresh uniform masking randomness `ρ ∈ E`**. This `ρ` is
//! the real hiding randomness (the predecessor's scalar `r` was not enough).
//!
//! Critical regime fix (PATCH 3): `k ≪ mr·mc` — we stay far from the easy
//! near-full-rank `D ≈ mr·mc` MCE regime. The shipped sizes here are a
//! STRUCTURAL DEMO set, **not** security-calibrated (that is Milestone M3).
#![forbid(unsafe_code)]

use egoc_field::{Fp, Fp2};
use egoc_linalg::Mat;
use rand_core::RngCore;

mod xof;
pub use xof::XofRng;

/// Code/embedding parameters. `k = 2·ell + mask_len`, and we require `k ≪ mr·mc`.
#[derive(Clone, Copy, Debug)]
pub struct CodeParams {
    /// witness length ℓ (number of `(m,r)` pairs)
    pub ell: usize,
    /// masking coordinates `k − 2ℓ`
    pub mask_len: usize,
    /// matrix rows
    pub mr: usize,
    /// matrix cols
    pub mc: usize,
}

impl CodeParams {
    /// Code dimension `k = 2ℓ + mask_len`.
    #[inline]
    pub fn k(&self) -> usize {
        2 * self.ell + self.mask_len
    }
    /// Ambient dimension `mr·mc`.
    #[inline]
    pub fn ambient(&self) -> usize {
        self.mr * self.mc
    }
    /// Sanity: code is far from full rank, and fits.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.ell == 0 {
            return Err("ell must be > 0");
        }
        if self.k() >= self.ambient() {
            return Err("k must be << mr*mc (stay out of the easy MCE regime)");
        }
        // demo guard: insist k <= ambient/3 so we are visibly low-rate
        if 3 * self.k() > self.ambient() {
            return Err("demo guard: require 3k <= mr*mc");
        }
        Ok(())
    }

    /// A structural-demo parameter set. NOT security-calibrated (see M3).
    pub const DEMO: CodeParams = CodeParams { ell: 4, mask_len: 8, mr: 8, mc: 9 };

    /// The security-calibrated candidate (the "OPT1" reparameterization).
    /// `ell = 8`, `k = 2·8 + 30 = 46`, rectangular `22 × 31` (so the cheapest
    /// rank-drop codimension is `mc − mr + 1 = 10`). Use with the field
    /// `Q_MCE_L1` (`|E| ≈ 2⁴⁸`). Rank-collision floors: classical `2²⁴⁰`,
    /// optimistic free-QRAM `2¹⁶⁰`; the algebraic surface is a band `≈ 180–202`
    /// (NEEDS-REVIEW). See `docs/CRYPTANALYSIS.md`.
    pub const L1: CodeParams = CodeParams { ell: 8, mask_len: 30, mr: 22, mc: 31 };
}

/// Public NUMS generator set `{G_l}`, deterministic from a seed.
#[derive(Clone, Debug)]
pub struct GenSet<const Q: u64> {
    pub params: CodeParams,
    pub gens: Vec<Mat<Q>>,
}

impl<const Q: u64> GenSet<Q> {
    /// Expand `k` generators `E^{mr×mc}` from a published seed (attempt 0).
    pub fn expand(seed: &[u8; 32], params: CodeParams) -> Self {
        Self::expand_with_attempt(seed, params, 0)
    }

    /// Expand with an explicit attempt counter folded into domain separation —
    /// used by [`GenSet::expand_checked`] to re-derive on a rejected seed.
    pub fn expand_with_attempt(seed: &[u8; 32], params: CodeParams, attempt: u32) -> Self {
        params.validate().expect("invalid code params");
        let mut rng = XofRng::new(b"egoc-mce-r/genset/v1", seed);
        // Advance the stream by `attempt` blocks so distinct attempts give
        // independent gensets; attempt 0 is identical to the plain `expand`.
        let mut sink = [0u8; 32];
        for _ in 0..attempt {
            rng.fill_bytes(&mut sink);
        }
        let gens = (0..params.k())
            .map(|_| Mat::random(params.mr, params.mc, &mut rng))
            .collect();
        Self { params, gens }
    }

    /// Keygen genericity reject (Highway-to-Hull / CDG defense): re-derive the
    /// genset, incrementing the attempt counter, until its Frobenius hull
    /// dimension is `≤ h_max` (use `h_max = 0` or `1`; `P(reject) ≈ 1/q`).
    /// Returns the accepted genset and the attempt index that produced it.
    pub fn expand_checked(seed: &[u8; 32], params: CodeParams, h_max: usize) -> (Self, u32) {
        for attempt in 0u32..1024 {
            let gs = Self::expand_with_attempt(seed, params, attempt);
            if egoc_linalg::frobenius_hull_dim(&gs.gens) <= h_max {
                return (gs, attempt);
            }
        }
        panic!("keygen genericity reject exhausted — h_max too strict for params");
    }

    /// Frobenius hull dimension of this code (0 is the generic, desired value).
    pub fn hull_dim(&self) -> usize {
        egoc_linalg::frobenius_hull_dim(&self.gens)
    }

    /// Build the message matrix `M = Σ c_l G_l` from witness coordinates
    /// (`x_coords`, length `2ℓ`, in `F_q`) and masking `rho` (length `mask_len`, in `E`).
    pub fn embed(&self, x_coords: &[Fp<Q>], rho: &[Fp2<Q>]) -> Mat<Q> {
        let p = self.params;
        assert_eq!(x_coords.len(), 2 * p.ell, "wrong message coord count");
        assert_eq!(rho.len(), p.mask_len, "wrong masking length");

        let mut m = Mat::<Q>::zeros(p.mr, p.mc);
        // message coordinates: F_q ↪ E as x + 0·t
        for (l, x) in x_coords.iter().enumerate() {
            let c = Fp2::new(*x, Fp::zero());
            m = m.add(&self.gens[l].scale(c));
        }
        // masking coordinates
        for (j, rj) in rho.iter().enumerate() {
            m = m.add(&self.gens[2 * p.ell + j].scale(*rj));
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::Q_MCE;
    use egoc_sl2::{Encoder, Witness};
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    #[test]
    fn demo_params_valid() {
        assert!(CodeParams::DEMO.validate().is_ok());
        assert_eq!(CodeParams::DEMO.k(), 16);
        assert_eq!(CodeParams::DEMO.ambient(), 72);
    }

    #[test]
    fn genset_is_deterministic_from_seed() {
        let seed = [7u8; 32];
        let a = GenSet::<Q_MCE>::expand(&seed, CodeParams::DEMO);
        let b = GenSet::<Q_MCE>::expand(&seed, CodeParams::DEMO);
        for (g1, g2) in a.gens.iter().zip(b.gens.iter()) {
            assert_eq!(g1, g2);
        }
        let c = GenSet::<Q_MCE>::expand(&[8u8; 32], CodeParams::DEMO);
        assert_ne!(a.gens[0], c.gens[0], "different seed must give different gens");
    }

    #[test]
    fn embed_is_linear_in_witness() {
        let seed = [1u8; 32];
        let gs = GenSet::<Q_MCE>::expand(&seed, CodeParams::DEMO);
        let mut rng = StdRng::seed_from_u64(3);

        let w = Witness::<Q_MCE>::random(CodeParams::DEMO.ell, &mut rng);
        let x = Encoder::pack(&w);
        let rho: Vec<_> = (0..CodeParams::DEMO.mask_len).map(|_| Fp2::random(&mut rng)).collect();
        let zero_rho = vec![Fp2::zero(); CodeParams::DEMO.mask_len];

        // M(x, 0) is the pure-message part; embedding is additive in coords.
        let m_full = gs.embed(&x, &rho);
        let m_msg = gs.embed(&x, &zero_rho);
        let mut m_mask = Mat::<Q_MCE>::zeros(CodeParams::DEMO.mr, CodeParams::DEMO.mc);
        for (j, rj) in rho.iter().enumerate() {
            m_mask = m_mask.add(&gs.gens[2 * CodeParams::DEMO.ell + j].scale(*rj));
        }
        assert_eq!(m_full, m_msg.add(&m_mask));
    }

    #[test]
    fn keygen_reject_yields_generic_hull() {
        let (gs, attempt) = GenSet::<Q_MCE>::expand_checked(&[5u8; 32], CodeParams::DEMO, 0);
        assert_eq!(gs.hull_dim(), 0, "accepted genset must have trivial hull");
        // deterministic: same seed → same accepted attempt and gens
        let (gs2, a2) = GenSet::<Q_MCE>::expand_checked(&[5u8; 32], CodeParams::DEMO, 0);
        assert_eq!(attempt, a2);
        for (g1, g2) in gs.gens.iter().zip(gs2.gens.iter()) {
            assert_eq!(g1, g2);
        }
    }

    #[test]
    fn xof_rng_stream_is_reproducible() {
        let mut a = XofRng::new(b"ctx", &[5u8; 32]);
        let mut b = XofRng::new(b"ctx", &[5u8; 32]);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }
}
