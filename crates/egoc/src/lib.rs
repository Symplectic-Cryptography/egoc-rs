//! `egoc` — top-level facade for the egoc-rs post-quantum commitment library.
//!
//! Two independent backends behind one import. **Pick the assumption you trust.**
//!
//! ## `mce` — EGOC-MCE-R (the elegant `sl(2)`/2T construction)
//! Hiding reduces to Matrix Code Equivalence (NIST MEDS / Tensor-Isomorphism
//! family) via a two-sided secret action `C = S·M·T` over the anisotropic
//! extension `E = F_q[t]/(t²+1)`, `q ≡ 3 mod 4`. At the candidate parameters the
//! binding (algebraic) attack estimates to ≈2²⁰⁸ and the rank surface to
//! ≥2¹⁰⁶⁴, putting it in the 180–192 class — a bit estimate via the MEDS
//! methodology, validated against MEDS L1/L3/L5, pending independent confirmation
//! (see `docs/SECURITY.md` and `docs/CRYPTANALYSIS.md`). Ships with the
//! code-equivalence Σ, a message-hiding ZK opening, batch aggregation, and a
//! sealed-bid auction demo.
//!
//! ## `lattice` — SHADOW-SIS-FIX (the bit-pinned production backend)
//! Textbook BDLOP over module-LWE/MSIS. **Estimator-confirmed ≥2¹⁸⁶ classical /
//! ~2¹⁴⁶ quantum hiding, statistical binding** (`lattice-estimator`). Use this
//! when you need a number you can defend today.
//!
//! Every claim is labelled PROVEN / ASSUMED / NEEDS-REVIEW in `docs/SECURITY.md`.
//! The `sl(2)`/2T identification is structure/encoding only — zero hardness.
#![forbid(unsafe_code)]

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Core field and parameters.
pub use egoc_field::{Fp, Fp2, Q_MCE, Q_MCE_L1};

/// Dense matrix algebra over `E`, and the matrix-code utilities.
pub use egoc_linalg::{frobenius_hull_dim, in_span, Mat};

/// The MCE backend (EGOC-MCE-R): code, encoder, commitment, ZK, aggregation.
pub mod mce {
    pub use egoc_code::{CodeParams, GenSet, XofRng};
    pub use egoc_commit::{
        commit, commit_with, recompute, verify as verify_commitment, Commitment, Opening,
    };
    pub use egoc_proof::opening::{
        prove_opening, simulate_opening_round, verify_opening, OpenResp, OpeningProof,
    };
    pub use egoc_proof::{keygen, prove as prove_equiv, verify as verify_equiv, Code, EquivKey, Proof};
    pub use egoc_sl2::{Encoder, Sl2Block, Witness};
    /// Honest batch aggregation (one Fiat-Shamir over N commitments, per-opening).
    pub use egoc_aggregate::{prove_batch, verify_batch, AggProof};
}

/// The lattice backend (SHADOW-SIS-FIX): BDLOP commitment + Fiat-Shamir ZK.
pub mod lattice {
    pub use egoc_mlwe::poly::{Poly, N, Q};
    pub use egoc_mlwe::proof::{
        prove_opening, simulate_with_challenge, verify_opening, OpeningProof, ProofParams,
    };
    pub use egoc_mlwe::{
        commit, commit_with, sample_randomness, verify, CommitKey, Commitment, Opening, Params,
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::VERSION.is_empty());
    }

    #[test]
    fn both_backends_reachable() {
        // smoke: the re-exported entry points resolve and basic params validate
        let _ = super::mce::CodeParams::DEMO.validate().unwrap();
        let _ = super::lattice::Params::DEMO.validate().unwrap();
    }
}
