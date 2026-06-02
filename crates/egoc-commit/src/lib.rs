//! `egoc-commit` — EGOC-MCE-R commitment (hash-binding, two-sided secret keys).
//!
//! ```text
//!   keygen :  seed_S, seed_T ←$ {0,1}²⁵⁶ ;  S = ExpandGL(seed_S), T = ExpandGL(seed_T)
//!   commit :  M = Encode(w; ρ) ;  C = S·M·T ;  com = BLAKE3(dom ‖ q,ℓ,k,mr,mc ‖ C)
//!   open   :  reveal (w, ρ, seed_S, seed_T) ;  verifier recomputes and checks com
//! ```
//!
//! What is **public**: `com` (a hash) and the genset seed.
//! What is **secret**: `S, T` (their seeds), `w`, `ρ` — until opening.
//!
//! Closes the predecessor's fatal flaws:
//! * no `g` is public ⇒ no `C·g⁻¹` linear recovery (recovery ⇒ MCE);
//! * `S,T` are never hashed/published ⇒ no `H(·)` confirmation oracle;
//! * the **pushed basis `{S·G_l·T}` is NEVER produced** ⇒ no `C = C_* + Σ x_l C_l`
//!   linear-recovery footgun (PATCH 1);
//! * two-sided *equivalence* (not similarity) destroys det/Casimir/cross-ratio.
#![forbid(unsafe_code)]

use blake3::Hasher;
use egoc_code::{CodeParams, GenSet, XofRng};
use egoc_field::Fp2;
use egoc_linalg::Mat;
use egoc_sl2::{Encoder, Witness};
use rand_core::RngCore;
use subtle::ConstantTimeEq;

const DOMAIN: &[u8] = b"egoc-mce-r/commit/v1";

/// Deterministically expand a uniform invertible `n×n` matrix over `E` from a
/// 32-byte seed. Rejection retries advance the same XOF stream, so the result
/// is a deterministic function of the seed (the verifier reproduces it).
pub fn expand_gl<const Q: u64>(context: &[u8], seed: &[u8; 32], n: usize) -> Mat<Q> {
    let mut rng = XofRng::new(context, seed);
    loop {
        let m = Mat::<Q>::random(n, n, &mut rng);
        if m.is_invertible() {
            return m;
        }
        // else: keep drawing from the same stream — deterministic & reproducible
    }
}

/// The public commitment: a domain-separated BLAKE3 hash of `C = S·M·T`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commitment {
    pub com: [u8; 32],
}

/// The opening — everything the verifier needs to recompute the commitment.
/// `seed_S, seed_T` stand in for the secret keys; `w, rho` for the message.
#[derive(Clone)]
pub struct Opening<const Q: u64> {
    pub w: Witness<Q>,
    pub rho: Vec<Fp2<Q>>,
    pub seed_s: [u8; 32],
    pub seed_t: [u8; 32],
}

/// Hash `C` into the commitment, binding all public parameters into the transcript.
fn hash_commitment<const Q: u64>(params: &CodeParams, c: &Mat<Q>) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(&Q.to_le_bytes());
    h.update(&(params.ell as u64).to_le_bytes());
    h.update(&(params.mask_len as u64).to_le_bytes());
    h.update(&(params.mr as u64).to_le_bytes());
    h.update(&(params.mc as u64).to_le_bytes());
    h.update(&c.to_bytes());
    *h.finalize().as_bytes()
}

/// Commit to `w` with fresh randomness. Returns `(Commitment, Opening)`.
pub fn commit<const Q: u64>(
    gens: &GenSet<Q>,
    w: Witness<Q>,
    rng: &mut impl RngCore,
) -> (Commitment, Opening<Q>) {
    let p = gens.params;
    let rho: Vec<Fp2<Q>> = (0..p.mask_len).map(|_| Fp2::random(rng)).collect();
    let mut seed_s = [0u8; 32];
    let mut seed_t = [0u8; 32];
    rng.fill_bytes(&mut seed_s);
    rng.fill_bytes(&mut seed_t);
    commit_with(gens, w, rho, seed_s, seed_t)
}

/// Deterministic commit with explicit randomness/keys. Useful for KATs and for
/// the attack harness, which must hold keys/ρ fixed while varying the witness.
pub fn commit_with<const Q: u64>(
    gens: &GenSet<Q>,
    w: Witness<Q>,
    rho: Vec<Fp2<Q>>,
    seed_s: [u8; 32],
    seed_t: [u8; 32],
) -> (Commitment, Opening<Q>) {
    let p = gens.params;
    assert_eq!(w.n(), p.ell, "witness length must equal code ell");
    assert_eq!(rho.len(), p.mask_len, "rho length must equal mask_len");

    let x = Encoder::pack(&w);
    let m = gens.embed(&x, &rho);
    let s = expand_gl::<Q>(b"egoc-mce-r/key-S/v1", &seed_s, p.mr);
    let t = expand_gl::<Q>(b"egoc-mce-r/key-T/v1", &seed_t, p.mc);

    let c = Mat::two_sided(&s, &m, &t);
    let com = hash_commitment(&p, &c);

    (Commitment { com }, Opening { w, rho, seed_s, seed_t })
}

/// Recompute the commitment matrix `C` from an opening and the public generators.
pub fn recompute<const Q: u64>(gens: &GenSet<Q>, op: &Opening<Q>) -> Result<Mat<Q>, &'static str> {
    let p = gens.params;
    if op.w.n() != p.ell {
        return Err("opening witness length mismatch");
    }
    if op.rho.len() != p.mask_len {
        return Err("opening rho length mismatch");
    }
    let x = Encoder::pack(&op.w);
    let m = gens.embed(&x, &op.rho);
    let s = expand_gl::<Q>(b"egoc-mce-r/key-S/v1", &op.seed_s, p.mr);
    let t = expand_gl::<Q>(b"egoc-mce-r/key-T/v1", &op.seed_t, p.mc);
    Ok(Mat::two_sided(&s, &m, &t))
}

/// Verify an opening against a commitment. Constant-time hash comparison.
pub fn verify<const Q: u64>(
    gens: &GenSet<Q>,
    com: &Commitment,
    op: &Opening<Q>,
) -> Result<(), &'static str> {
    let c = recompute(gens, op)?;
    let expected = hash_commitment(&gens.params, &c);
    if bool::from(expected.ct_eq(&com.com)) {
        Ok(())
    } else {
        Err("commitment verification failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::Q_MCE;
    use rand::{rngs::StdRng, SeedableRng};

    fn demo_gens(seed: u8) -> GenSet<Q_MCE> {
        GenSet::expand(&[seed; 32], CodeParams::DEMO)
    }

    #[test]
    fn commit_open_roundtrip() {
        let gens = demo_gens(1);
        let mut rng = StdRng::seed_from_u64(42);
        let w = Witness::random(CodeParams::DEMO.ell, &mut rng);
        let (com, op) = commit(&gens, w, &mut rng);
        assert!(verify(&gens, &com, &op).is_ok());
    }

    #[test]
    fn wrong_witness_rejected() {
        let gens = demo_gens(1);
        let mut rng = StdRng::seed_from_u64(7);
        let w = Witness::random(CodeParams::DEMO.ell, &mut rng);
        let (com, mut op) = commit(&gens, w, &mut rng);
        // tamper the opened witness
        op.w = Witness::random(CodeParams::DEMO.ell, &mut rng);
        assert!(verify(&gens, &com, &op).is_err());
    }

    #[test]
    fn wrong_key_seed_rejected() {
        let gens = demo_gens(1);
        let mut rng = StdRng::seed_from_u64(8);
        let w = Witness::random(CodeParams::DEMO.ell, &mut rng);
        let (com, mut op) = commit(&gens, w, &mut rng);
        op.seed_s[0] ^= 1;
        assert!(verify(&gens, &com, &op).is_err());
    }

    #[test]
    fn expand_gl_is_deterministic_and_invertible() {
        let s1 = expand_gl::<Q_MCE>(b"ctx", &[3u8; 32], 8);
        let s2 = expand_gl::<Q_MCE>(b"ctx", &[3u8; 32], 8);
        assert_eq!(s1, s2);
        assert!(s1.is_invertible());
    }

    #[test]
    fn distinct_witnesses_distinct_commitments() {
        // Same keys (same rng seed path) but different witness ⇒ different com.
        let gens = demo_gens(2);
        let mut rng = StdRng::seed_from_u64(100);
        let w1 = Witness::random(CodeParams::DEMO.ell, &mut rng);
        let (c1, _) = commit(&gens, w1, &mut StdRng::seed_from_u64(5));
        let w2 = Witness::random(CodeParams::DEMO.ell, &mut rng);
        let (c2, _) = commit(&gens, w2, &mut StdRng::seed_from_u64(5));
        assert_ne!(c1.com, c2.com);
    }
}
