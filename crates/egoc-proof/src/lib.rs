//! `egoc-proof` — MEDS-style code-equivalence Σ protocol (M4 core).
//!
//! A **sound, non-vacuous** zero-knowledge proof of knowledge of a secret
//! two-sided equivalence `(S,T) ∈ GL_mr(E)×GL_mc(E)` between two *public* matrix
//! codes `C0 = {G_l}` and `C1 = {S·G_l·T}`. This is the identification scheme of
//! the MEDS / Tensor-Isomorphism family — the genuine "native" algebraic ZK the
//! project was reaching for, with hardness = the MCE problem calibrated in M3.
//!
//! Per round:
//! * commit  `cmt = H(Ĉ)`, `Ĉ_l = S̃·G_l·T̃` for fresh `(S̃,T̃) ←$ GL`;
//! * challenge bit `b` (Fiat–Shamir over the whole transcript);
//! * response `b=0 → (S̃, T̃)`; `b=1 → (S̃·S⁻¹, T⁻¹·T̃)`;
//! * verify `H( resp_S · (b? C1 : C0)_l · resp_T ) == cmt`.
//!
//! Soundness `2⁻λ` (binary challenge, λ rounds): two accepting transcripts that
//! differ on one round's bit yield an extractor `S = respB_S⁻¹·respA_S`,
//! `T = respA_T·respB_T⁻¹`. HVZK: responses are uniform `GL` and simulatable.
//!
//! **Scope (honest):** this proves knowledge of the code equivalence. Binding
//! the *planted message coordinates* of an EGOC-MCE-R commitment to this proof
//! (the hash-commitment opening, via a CCS commit-and-prove) is **M4b** and is
//! not yet implemented. The λ-round proof is large; fixed-weight challenges and
//! seed-tree compression (as in MEDS) are deferred optimisations.
#![forbid(unsafe_code)]

pub mod opening;

use blake3::Hasher;
use egoc_linalg::Mat;
use rand_core::RngCore;
use zeroize::Zeroize;

const DOMAIN: &[u8] = b"egoc-proof/code-equiv/v1";

/// A public matrix code: its ordered generator list.
pub type Code<const Q: u64> = Vec<Mat<Q>>;

/// Secret equivalence witness `(S,T)` with cached inverses.
#[derive(Clone)]
pub struct EquivKey<const Q: u64> {
    pub s: Mat<Q>,
    pub t: Mat<Q>,
    s_inv: Mat<Q>,
    t_inv: Mat<Q>,
}

impl<const Q: u64> EquivKey<Q> {
    pub fn new(s: Mat<Q>, t: Mat<Q>) -> Self {
        let s_inv = s.inverse().expect("S must be invertible");
        let t_inv = t.inverse().expect("T must be invertible");
        Self { s, t, s_inv, t_inv }
    }
}

impl<const Q: u64> Zeroize for EquivKey<Q> {
    fn zeroize(&mut self) {
        self.s.zeroize();
        self.t.zeroize();
        self.s_inv.zeroize();
        self.t_inv.zeroize();
    }
}

/// Sample a fresh keypair and the pushed public code `C1 = S·C0·T`.
pub fn keygen<const Q: u64>(
    c0: &Code<Q>,
    rng: &mut impl RngCore,
) -> (EquivKey<Q>, Code<Q>) {
    let mr = c0[0].nrows();
    let mc = c0[0].ncols();
    let s = Mat::random_invertible(mr, rng);
    let t = Mat::random_invertible(mc, rng);
    let c1 = c0.iter().map(|g| s.mul(g).mul(&t)).collect();
    (EquivKey::new(s, t), c1)
}

/// `H(domain ‖ index ‖ Ĉ generators)`.
fn hash_code<const Q: u64>(chat: &[Mat<Q>]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(b"/chat");
    for g in chat {
        h.update(&g.to_bytes());
    }
    *h.finalize().as_bytes()
}

/// Fiat–Shamir challenge bits, bound to both codes and all round commitments.
fn fs_bits<const Q: u64>(
    c0: &Code<Q>,
    c1: &Code<Q>,
    commits: &[[u8; 32]],
    lambda: usize,
) -> Vec<bool> {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(b"/fs");
    h.update(&(lambda as u64).to_le_bytes());
    for g in c0 {
        h.update(&g.to_bytes());
    }
    for g in c1 {
        h.update(&g.to_bytes());
    }
    for c in commits {
        h.update(c);
    }
    let mut reader = h.finalize_xof();
    let mut bits = Vec::with_capacity(lambda);
    let mut buf = [0u8; 1];
    let mut have = 0u8;
    let mut cur = 0u8;
    for _ in 0..lambda {
        if have == 0 {
            reader.fill(&mut buf);
            cur = buf[0];
            have = 8;
        }
        bits.push(cur & 1 == 1);
        cur >>= 1;
        have -= 1;
    }
    bits
}

/// A response: an equivalence pair revealed for one round.
#[derive(Clone)]
pub struct Resp<const Q: u64> {
    pub a: Mat<Q>,
    pub b: Mat<Q>,
}

/// A non-interactive code-equivalence proof.
#[derive(Clone)]
pub struct Proof<const Q: u64> {
    pub commits: Vec<[u8; 32]>,
    pub resps: Vec<Resp<Q>>,
}

/// Prove knowledge of `(S,T)` with `C1_l = S·C0_l·T`, over `lambda` rounds.
pub fn prove<const Q: u64>(
    c0: &Code<Q>,
    c1: &Code<Q>,
    key: &EquivKey<Q>,
    lambda: usize,
    rng: &mut impl RngCore,
) -> Proof<Q> {
    let mr = c0[0].nrows();
    let mc = c0[0].ncols();
    let mut eph: Vec<(Mat<Q>, Mat<Q>)> = Vec::with_capacity(lambda);
    let mut commits: Vec<[u8; 32]> = Vec::with_capacity(lambda);
    for _ in 0..lambda {
        let st = Mat::random_invertible(mr, rng);
        let tt = Mat::random_invertible(mc, rng);
        let chat: Vec<Mat<Q>> = c0.iter().map(|g| st.mul(g).mul(&tt)).collect();
        commits.push(hash_code(&chat));
        eph.push((st, tt));
    }
    let bits = fs_bits(c0, c1, &commits, lambda);
    let mut resps = Vec::with_capacity(lambda);
    for (j, (st, tt)) in eph.into_iter().enumerate() {
        if !bits[j] {
            resps.push(Resp { a: st, b: tt });
        } else {
            // (S̃·S⁻¹, T⁻¹·T̃)
            resps.push(Resp { a: st.mul(&key.s_inv), b: key.t_inv.mul(&tt) });
        }
    }
    let _ = (mr, mc);
    Proof { commits, resps }
}

/// Verify a code-equivalence proof.
pub fn verify<const Q: u64>(c0: &Code<Q>, c1: &Code<Q>, proof: &Proof<Q>) -> bool {
    let lambda = proof.commits.len();
    if proof.resps.len() != lambda {
        return false;
    }
    let bits = fs_bits(c0, c1, &proof.commits, lambda);
    for j in 0..lambda {
        let r = &proof.resps[j];
        // responses must be invertible (an honest equivalence is in GL)
        if !r.a.is_invertible() || !r.b.is_invertible() {
            return false;
        }
        let code = if bits[j] { c1 } else { c0 };
        let chat: Vec<Mat<Q>> = code.iter().map(|g| r.a.mul(g).mul(&r.b)).collect();
        if hash_code(&chat) != proof.commits[j] {
            return false;
        }
    }
    true
}

/// Special-soundness extractor: from two same-round responses produced under
/// challenge bits `0` (`resp_a`) and `1` (`resp_b`) for the SAME commitment,
/// recover `(S,T)`. (Exposed for testing/auditing the soundness argument.)
pub fn extract<const Q: u64>(resp_b0: &Resp<Q>, resp_b1: &Resp<Q>) -> (Mat<Q>, Mat<Q>) {
    // resp_b1.a = S̃·S⁻¹ , resp_b0.a = S̃  ⇒ S = resp_b1.a⁻¹ · resp_b0.a
    let s = resp_b1.a.inverse().expect("inv").mul(&resp_b0.a);
    // resp_b1.b = T⁻¹·T̃ , resp_b0.b = T̃  ⇒ T = resp_b0.b · resp_b1.b⁻¹
    let t = resp_b0.b.mul(&resp_b1.b.inverse().expect("inv"));
    (s, t)
}

/// HVZK simulator for a single round under a chosen challenge bit: sample a
/// uniform equivalence and derive the matching commitment. Verifies by
/// construction, with no witness.
pub fn simulate_round<const Q: u64>(
    c0: &Code<Q>,
    c1: &Code<Q>,
    bit: bool,
    rng: &mut impl RngCore,
) -> ([u8; 32], Resp<Q>) {
    let mr = c0[0].nrows();
    let mc = c0[0].ncols();
    let a = Mat::random_invertible(mr, rng);
    let b = Mat::random_invertible(mc, rng);
    let code = if bit { c1 } else { c0 };
    let chat: Vec<Mat<Q>> = code.iter().map(|g| a.mul(g).mul(&b)).collect();
    (hash_code(&chat), Resp { a, b })
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::{Fp2, Q_MCE};
    use rand::{rngs::StdRng, SeedableRng};

    fn random_code(mr: usize, mc: usize, k: usize, rng: &mut impl RngCore) -> Code<Q_MCE> {
        (0..k).map(|_| Mat::random(mr, mc, rng)).collect()
    }

    #[test]
    fn honest_proof_verifies() {
        let mut rng = StdRng::seed_from_u64(1);
        let c0 = random_code(5, 6, 8, &mut rng);
        let (key, c1) = keygen(&c0, &mut rng);
        let proof = prove(&c0, &c1, &key, 24, &mut rng);
        assert!(verify(&c0, &c1, &proof));
    }

    #[test]
    fn proof_for_wrong_code_rejected() {
        let mut rng = StdRng::seed_from_u64(2);
        let c0 = random_code(5, 6, 8, &mut rng);
        let (key, c1) = keygen(&c0, &mut rng);
        let proof = prove(&c0, &c1, &key, 24, &mut rng);
        // a different C1' (fresh keys) — proof must not verify against it
        let (_k2, c1b) = keygen(&c0, &mut rng);
        assert!(!verify(&c0, &c1b, &proof));
    }

    #[test]
    fn tampered_response_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let c0 = random_code(4, 5, 6, &mut rng);
        let (key, c1) = keygen(&c0, &mut rng);
        let mut proof = prove(&c0, &c1, &key, 24, &mut rng);
        // corrupt one response entry
        let cur = proof.resps[0].a.get(0, 0);
        proof.resps[0].a.set(0, 0, cur.add(Fp2::one()));
        assert!(!verify(&c0, &c1, &proof));
    }

    #[test]
    fn special_soundness_extracts_secret() {
        // Same ephemeral, two challenge bits → extractor recovers (S,T).
        let mut rng = StdRng::seed_from_u64(4);
        let c0 = random_code(5, 6, 8, &mut rng);
        let (key, c1) = keygen(&c0, &mut rng);

        let mr = 5;
        let mc = 6;
        let st = Mat::<Q_MCE>::random_invertible(mr, &mut rng);
        let tt = Mat::<Q_MCE>::random_invertible(mc, &mut rng);
        // b=0 response
        let r0 = Resp { a: st.clone(), b: tt.clone() };
        // b=1 response
        let r1 = Resp { a: st.mul(&key.s.inverse().unwrap()), b: key.t.inverse().unwrap().mul(&tt) };

        let (s_ext, t_ext) = extract(&r0, &r1);
        // verify the extracted equivalence reproduces C1
        for l in 0..c0.len() {
            assert_eq!(s_ext.mul(&c0[l]).mul(&t_ext), c1[l]);
        }
    }

    #[test]
    fn hvzk_simulated_round_verifies() {
        let mut rng = StdRng::seed_from_u64(5);
        let c0 = random_code(5, 6, 8, &mut rng);
        let (_key, c1) = keygen(&c0, &mut rng);
        for &bit in &[false, true] {
            let (cmt, resp) = simulate_round(&c0, &c1, bit, &mut rng);
            // the simulated transcript satisfies the verification relation
            let code = if bit { &c1 } else { &c0 };
            let chat: Vec<Mat<Q_MCE>> = code.iter().map(|g| resp.a.mul(g).mul(&resp.b)).collect();
            assert_eq!(hash_code(&chat), cmt);
            assert!(resp.a.is_invertible() && resp.b.is_invertible());
        }
    }

    #[test]
    fn soundness_scales_with_lambda() {
        // A prover that does NOT know the witness cannot make the FS proof verify.
        // Simulate a cheater: build commits from C0 only (knows no (S,T)); for the
        // rounds where the challenge demands b=1 it cannot answer ⇒ verify fails.
        let mut rng = StdRng::seed_from_u64(6);
        let c0 = random_code(4, 5, 6, &mut rng);
        let (_key, c1) = keygen(&c0, &mut rng);
        // forge: ephemeral commits, answer everything as if b=0
        let lambda = 32;
        let mut commits = Vec::new();
        let mut eph = Vec::new();
        for _ in 0..lambda {
            let a = Mat::<Q_MCE>::random_invertible(4, &mut rng);
            let b = Mat::<Q_MCE>::random_invertible(5, &mut rng);
            let chat: Vec<Mat<Q_MCE>> = c0.iter().map(|g| a.mul(g).mul(&b)).collect();
            commits.push(hash_code(&chat));
            eph.push((a, b));
        }
        let resps = eph.into_iter().map(|(a, b)| Resp { a, b }).collect();
        let forged = Proof { commits, resps };
        // overwhelmingly the FS bits demand at least one b=1 round the cheater can't answer
        assert!(!verify(&c0, &c1, &forged), "forged proof must fail");
    }
}
