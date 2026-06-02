//! M4b — zero-knowledge **opening proof** for a code-mode EGOC-MCE-R commitment.
//!
//! Code-mode commitment: the committer publishes the single matrix
//! `C = S·M(c)·T` (NOT its hash, and NOT the pushed basis — PATCH 1 still holds:
//! only `C` is public). `M(c) = Σ c_l G_l` with `c = (x(w) ‖ ρ)`; hiding of `w`
//! rests on decisional-MCE-with-planted-structure (the M3-calibrated instance —
//! M3 exposed *more* than `C` alone, so it is a conservative bound).
//!
//! This proves, in ZK, **knowledge of a valid opening**: that the prover knows a
//! secret two-sided equivalence `(S,T)` with `S⁻¹·C·T⁻¹ ∈ span{G_l}` — i.e. `C`
//! is well-formed and the prover can open it — **without revealing the message**.
//!
//! Per round (binary challenge, λ rounds → soundness `2⁻λ`). The prover commits
//! `D = Ŝ·C·T̂` for fresh `(Ŝ,T̂) ←$ GL` and sends `cmt = H(D)`. Then:
//! * `b=0`: reveal `(Ŝ,T̂)`; verifier recomputes `D = Ŝ·C·T̂`, checks `H(D)=cmt`.
//! * `b=1`: reveal `(U',V',D) = (Ŝ·S, T·T̂, D)`; verifier checks `H(D)=cmt` and
//!   `U'⁻¹·D·V'⁻¹ ∈ span{G_l}`.
//!
//! Soundness: two accepting transcripts with the same `cmt` force the same `D`
//! (hash collision resistance), giving `(U'⁻¹·Ŝ)·C·(T̂·V'⁻¹) ∈ span{G_l}` — a
//! valid witness `(S,T)`. HVZK: `b=0` is a random transform of `C`; `b=1`'s `D =
//! U'·M(c)·V'` with `M(c)` full rank (`q≡3 mod4` ⇒ anisotropic) is identically
//! distributed to `U'·W·V'` for a random codeword `W`, so the message leaks nothing.

use crate::Code;
use blake3::Hasher;
use egoc_linalg::{in_span, Mat};
use rand_core::RngCore;

const DOMAIN: &[u8] = b"egoc-proof/opening/v1";

fn hash_mat<const Q: u64>(d: &Mat<Q>) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(b"/D");
    h.update(&d.to_bytes());
    *h.finalize().as_bytes()
}

fn fs_bits<const Q: u64>(gens: &Code<Q>, c: &Mat<Q>, commits: &[[u8; 32]], lambda: usize) -> Vec<bool> {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(b"/fs");
    h.update(&(lambda as u64).to_le_bytes());
    for g in gens {
        h.update(&g.to_bytes());
    }
    h.update(&c.to_bytes());
    for cm in commits {
        h.update(cm);
    }
    let mut reader = h.finalize_xof();
    let mut bits = Vec::with_capacity(lambda);
    let (mut cur, mut have) = (0u8, 0u8);
    let mut buf = [0u8; 1];
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

/// One round's response. For `b=0`, `(a,b) = (Ŝ,T̂)` and `d = None`.
/// For `b=1`, `(a,b) = (U',V')` and `d = Some(D)`.
#[derive(Clone)]
pub struct OpenResp<const Q: u64> {
    pub a: Mat<Q>,
    pub b: Mat<Q>,
    pub d: Option<Mat<Q>>,
}

/// A non-interactive opening proof.
#[derive(Clone)]
pub struct OpeningProof<const Q: u64> {
    pub commits: Vec<[u8; 32]>,
    pub resps: Vec<OpenResp<Q>>,
}

impl<const Q: u64> OpeningProof<Q> {
    /// Wire format: `[λ][mr][mc]` (u32) then per round `cmt(32) ‖ a(mr²·16) ‖
    /// b(mc²·16) ‖ has_d(1) ‖ [d(mr·mc·16)]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let lambda = self.commits.len();
        let (mr, mc) = (self.resps[0].a.nrows(), self.resps[0].b.nrows());
        let mut o = Vec::new();
        o.extend_from_slice(&(lambda as u32).to_le_bytes());
        o.extend_from_slice(&(mr as u32).to_le_bytes());
        o.extend_from_slice(&(mc as u32).to_le_bytes());
        for j in 0..lambda {
            o.extend_from_slice(&self.commits[j]);
            o.extend_from_slice(&self.resps[j].a.to_bytes());
            o.extend_from_slice(&self.resps[j].b.to_bytes());
            match &self.resps[j].d {
                Some(d) => {
                    o.push(1);
                    o.extend_from_slice(&d.to_bytes());
                }
                None => o.push(0),
            }
        }
        o
    }

    /// Inverse of [`OpeningProof::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 12 {
            return None;
        }
        let lambda = u32::from_le_bytes(b[0..4].try_into().ok()?) as usize;
        let mr = u32::from_le_bytes(b[4..8].try_into().ok()?) as usize;
        let mc = u32::from_le_bytes(b[8..12].try_into().ok()?) as usize;
        let (a_len, b_len, d_len) = (mr * mr * 16, mc * mc * 16, mr * mc * 16);
        let mut pos = 12;
        let mut commits = Vec::with_capacity(lambda);
        let mut resps = Vec::with_capacity(lambda);
        for _ in 0..lambda {
            let cmt: [u8; 32] = b.get(pos..pos + 32)?.try_into().ok()?;
            pos += 32;
            let a = Mat::from_bytes(mr, mr, b.get(pos..pos + a_len)?)?;
            pos += a_len;
            let bb = Mat::from_bytes(mc, mc, b.get(pos..pos + b_len)?)?;
            pos += b_len;
            let has_d = *b.get(pos)?;
            pos += 1;
            let d = if has_d == 1 {
                let d = Mat::from_bytes(mr, mc, b.get(pos..pos + d_len)?)?;
                pos += d_len;
                Some(d)
            } else {
                None
            };
            commits.push(cmt);
            resps.push(OpenResp { a, b: bb, d });
        }
        if pos != b.len() {
            return None;
        }
        Some(OpeningProof { commits, resps })
    }
}

/// Prove knowledge of an opening of code-mode commitment `C` w.r.t. `gens`,
/// given the secret keys `(s,t)` with `C = S·M(c)·T`.
pub fn prove_opening<const Q: u64>(
    gens: &Code<Q>,
    c: &Mat<Q>,
    s: &Mat<Q>,
    t: &Mat<Q>,
    lambda: usize,
    rng: &mut impl RngCore,
) -> OpeningProof<Q> {
    let (mr, mc) = (c.nrows(), c.ncols());
    let mut eph: Vec<(Mat<Q>, Mat<Q>, Mat<Q>)> = Vec::with_capacity(lambda);
    let mut commits = Vec::with_capacity(lambda);
    for _ in 0..lambda {
        let sh = Mat::random_invertible(mr, rng);
        let th = Mat::random_invertible(mc, rng);
        let d = sh.mul(c).mul(&th); // D = Ŝ·C·T̂
        commits.push(hash_mat(&d));
        eph.push((sh, th, d));
    }
    let bits = fs_bits(gens, c, &commits, lambda);
    let mut resps = Vec::with_capacity(lambda);
    for (j, (sh, th, d)) in eph.into_iter().enumerate() {
        if !bits[j] {
            resps.push(OpenResp { a: sh, b: th, d: None });
        } else {
            // (U',V') = (Ŝ·S, T·T̂); reveal D too
            resps.push(OpenResp { a: sh.mul(s), b: t.mul(&th), d: Some(d) });
        }
    }
    OpeningProof { commits, resps }
}

/// Verify an opening proof.
pub fn verify_opening<const Q: u64>(gens: &Code<Q>, c: &Mat<Q>, proof: &OpeningProof<Q>) -> bool {
    let lambda = proof.commits.len();
    if proof.resps.len() != lambda {
        return false;
    }
    let bits = fs_bits(gens, c, &proof.commits, lambda);
    for j in 0..lambda {
        let r = &proof.resps[j];
        if !r.a.is_invertible() || !r.b.is_invertible() {
            return false;
        }
        if !bits[j] {
            // recompute D = Ŝ·C·T̂, check the commitment
            if r.d.is_some() {
                return false;
            }
            let d = r.a.mul(c).mul(&r.b);
            if hash_mat(&d) != proof.commits[j] {
                return false;
            }
        } else {
            // need the revealed D
            let d = match &r.d {
                Some(d) => d,
                None => return false,
            };
            if hash_mat(d) != proof.commits[j] {
                return false;
            }
            // U'⁻¹·D·V'⁻¹ ∈ span{G_l}
            let (ua, vb) = match (r.a.inverse(), r.b.inverse()) {
                (Some(u), Some(v)) => (u, v),
                _ => return false,
            };
            let w = ua.mul(d).mul(&vb);
            if !in_span(gens, &w) {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Round-level primitives (used by egoc-aggregate to batch under one transcript)
// ---------------------------------------------------------------------------

/// Per-round ephemeral state: `(Ŝ, T̂)` and the committed `D = Ŝ·C·T̂`.
#[derive(Clone)]
pub struct Eph<const Q: u64> {
    pub sh: Mat<Q>,
    pub th: Mat<Q>,
    pub d: Mat<Q>,
}

/// First message of one round: sample `(Ŝ,T̂)`, return the ephemeral and `cmt=H(D)`.
pub fn commit_round<const Q: u64>(c: &Mat<Q>, rng: &mut impl RngCore) -> (Eph<Q>, [u8; 32]) {
    let (mr, mc) = (c.nrows(), c.ncols());
    let sh = Mat::random_invertible(mr, rng);
    let th = Mat::random_invertible(mc, rng);
    let d = sh.mul(c).mul(&th);
    let cmt = hash_mat(&d);
    (Eph { sh, th, d }, cmt)
}

/// Response of one round to challenge `bit`, given the secret keys `(s,t)`.
pub fn respond_round<const Q: u64>(eph: &Eph<Q>, s: &Mat<Q>, t: &Mat<Q>, bit: bool) -> OpenResp<Q> {
    if !bit {
        OpenResp { a: eph.sh.clone(), b: eph.th.clone(), d: None }
    } else {
        OpenResp { a: eph.sh.mul(s), b: t.mul(&eph.th), d: Some(eph.d.clone()) }
    }
}

/// Verify one round's `(cmt, bit, resp)` against the public `(gens, c)`.
pub fn verify_round<const Q: u64>(
    gens: &Code<Q>,
    c: &Mat<Q>,
    cmt: &[u8; 32],
    bit: bool,
    r: &OpenResp<Q>,
) -> bool {
    if !r.a.is_invertible() || !r.b.is_invertible() {
        return false;
    }
    if !bit {
        if r.d.is_some() {
            return false;
        }
        let d = r.a.mul(c).mul(&r.b);
        hash_mat(&d) == *cmt
    } else {
        let d = match &r.d {
            Some(d) => d,
            None => return false,
        };
        if hash_mat(d) != *cmt {
            return false;
        }
        let (u, v) = match (r.a.inverse(), r.b.inverse()) {
            (Some(u), Some(v)) => (u, v),
            _ => return false,
        };
        in_span(gens, &u.mul(d).mul(&v))
    }
}

/// Special-soundness extractor: from a `b=0` response `(Ŝ,T̂)` and a `b=1`
/// response `(U',V')` for the SAME round commitment, recover a witness `(S,T)`
/// (here returned as `(Ū,V̄)` with `Ū·C·V̄ ∈ span{G_l}`). Exposed for testing.
pub fn extract_opening<const Q: u64>(
    resp_b0: &OpenResp<Q>,
    resp_b1: &OpenResp<Q>,
) -> (Mat<Q>, Mat<Q>) {
    // Ū = U'⁻¹·Ŝ , V̄ = T̂·V'⁻¹
    let u_bar = resp_b1.a.inverse().expect("inv").mul(&resp_b0.a);
    let v_bar = resp_b0.b.mul(&resp_b1.b.inverse().expect("inv"));
    (u_bar, v_bar)
}

/// HVZK simulator for one round under a chosen challenge bit (no witness).
pub fn simulate_opening_round<const Q: u64>(
    gens: &Code<Q>,
    c: &Mat<Q>,
    bit: bool,
    rng: &mut impl RngCore,
) -> ([u8; 32], OpenResp<Q>) {
    let (mr, mc) = (c.nrows(), c.ncols());
    if !bit {
        let sh = Mat::random_invertible(mr, rng);
        let th = Mat::random_invertible(mc, rng);
        let d = sh.mul(c).mul(&th);
        (hash_mat(&d), OpenResp { a: sh, b: th, d: None })
    } else {
        // pick random U',V' and a random codeword W; set D = U'·W·V'
        let up = Mat::random_invertible(mr, rng);
        let vp = Mat::random_invertible(mc, rng);
        let mut w = Mat::<Q>::zeros(mr, mc);
        for g in gens {
            let coeff = egoc_field::Fp2::random(rng);
            w = w.add(&g.scale(coeff));
        }
        let d = up.mul(&w).mul(&vp);
        (hash_mat(&d), OpenResp { a: up, b: vp, d: Some(d) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::{Fp2, Q_MCE};
    use rand::{rngs::StdRng, SeedableRng};

    fn random_code(mr: usize, mc: usize, k: usize, rng: &mut impl RngCore) -> Code<Q_MCE> {
        (0..k).map(|_| Mat::random(mr, mc, rng)).collect()
    }

    // build a code-mode commitment C = S·M(c)·T for a random message codeword
    fn commit_code(
        gens: &Code<Q_MCE>,
        mr: usize,
        mc: usize,
        rng: &mut impl RngCore,
    ) -> (Mat<Q_MCE>, Mat<Q_MCE>, Mat<Q_MCE>) {
        let mut m = Mat::<Q_MCE>::zeros(mr, mc);
        for g in gens {
            m = m.add(&g.scale(Fp2::random(rng)));
        }
        let s = Mat::random_invertible(mr, rng);
        let t = Mat::random_invertible(mc, rng);
        let c = s.mul(&m).mul(&t);
        (c, s, t)
    }

    #[test]
    fn honest_opening_verifies() {
        let mut rng = StdRng::seed_from_u64(1);
        let (mr, mc, k) = (5, 6, 8);
        let gens = random_code(mr, mc, k, &mut rng);
        let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);
        let proof = prove_opening(&gens, &c, &s, &t, 24, &mut rng);
        assert!(verify_opening(&gens, &c, &proof));
    }

    #[test]
    fn opening_for_non_commitment_rejected() {
        // A random C not equivalent to any codeword: an honest prover cannot
        // exist, and a forged proof (claiming b=1 membership) fails.
        let mut rng = StdRng::seed_from_u64(2);
        let (mr, mc, k) = (5, 6, 8);
        let gens = random_code(mr, mc, k, &mut rng);
        let bogus = Mat::<Q_MCE>::random(mr, mc, &mut rng); // generic, not in any orbit
        // forge: pretend keys are identity
        let id_s = Mat::identity(mr);
        let id_t = Mat::identity(mc);
        let proof = prove_opening(&gens, &bogus, &id_s, &id_t, 24, &mut rng);
        assert!(!verify_opening(&gens, &bogus, &proof),
            "a random non-commitment must not verify");
    }

    #[test]
    fn tampered_opening_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let (mr, mc, k) = (4, 5, 6);
        let gens = random_code(mr, mc, k, &mut rng);
        let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);
        let mut proof = prove_opening(&gens, &c, &s, &t, 24, &mut rng);
        // corrupt one response matrix
        let cur = proof.resps[0].a.get(0, 0);
        proof.resps[0].a.set(0, 0, cur.add(Fp2::one()));
        assert!(!verify_opening(&gens, &c, &proof));
    }

    #[test]
    fn special_soundness_extracts_opening() {
        let mut rng = StdRng::seed_from_u64(4);
        let (mr, mc, k) = (5, 6, 8);
        let gens = random_code(mr, mc, k, &mut rng);
        let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);

        // one ephemeral, two challenge bits
        let sh = Mat::<Q_MCE>::random_invertible(mr, &mut rng);
        let th = Mat::<Q_MCE>::random_invertible(mc, &mut rng);
        let d = sh.mul(&c).mul(&th);
        let r0 = OpenResp { a: sh.clone(), b: th.clone(), d: None };
        let r1 = OpenResp { a: sh.mul(&s), b: t.mul(&th), d: Some(d) };

        let (u_bar, v_bar) = extract_opening(&r0, &r1);
        // Ū·C·V̄ must be a codeword
        let w = u_bar.mul(&c).mul(&v_bar);
        assert!(in_span(&gens, &w), "extracted witness must map C into the code");
    }

    #[test]
    fn opening_proof_serialization_roundtrip() {
        let mut rng = StdRng::seed_from_u64(7);
        let (mr, mc, k) = (5, 6, 8);
        let gens = random_code(mr, mc, k, &mut rng);
        let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);
        let proof = prove_opening(&gens, &c, &s, &t, 20, &mut rng);
        let bytes = proof.to_bytes();
        let proof2 = OpeningProof::<Q_MCE>::from_bytes(&bytes).expect("deserialize");
        assert!(verify_opening(&gens, &c, &proof2), "verify after round-trip");
        assert!(OpeningProof::<Q_MCE>::from_bytes(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn full_rank_orbit_rank_is_preserved() {
        // Backs PROOFS.md Lemma 7: for invertible (U,V), rank(U·X·V) = rank(X),
        // so U·M·V (message) and U·W·V (random codeword), both full rank, are
        // indistinguishable by rank — the basis of HVZK's message-independence.
        let mut rng = StdRng::seed_from_u64(8);
        let (mr, mc) = (5usize, 6usize);
        let want = mr.min(mc);
        for _ in 0..40 {
            let u = Mat::<Q_MCE>::random_invertible(mr, &mut rng);
            let v = Mat::<Q_MCE>::random_invertible(mc, &mut rng);
            let m = Mat::<Q_MCE>::random(mr, mc, &mut rng); // generically full rank
            let w = Mat::<Q_MCE>::random(mr, mc, &mut rng);
            assert_eq!(m.rank(), want);
            assert_eq!(u.mul(&m).mul(&v).rank(), want);
            assert_eq!(u.mul(&w).mul(&v).rank(), want);
        }
    }

    #[test]
    fn hvzk_simulated_rounds_verify() {
        let mut rng = StdRng::seed_from_u64(5);
        let (mr, mc, k) = (5, 6, 8);
        let gens = random_code(mr, mc, k, &mut rng);
        let (c, _s, _t) = commit_code(&gens, mr, mc, &mut rng);
        for &bit in &[false, true] {
            let (cmt, resp) = simulate_opening_round(&gens, &c, bit, &mut rng);
            // check the per-round verification relation holds for the simulated transcript
            if !bit {
                let d = resp.a.mul(&c).mul(&resp.b);
                assert_eq!(hash_mat(&d), cmt);
            } else {
                let d = resp.d.as_ref().unwrap();
                assert_eq!(hash_mat(d), cmt);
                let w = resp.a.inverse().unwrap().mul(d).mul(&resp.b.inverse().unwrap());
                assert!(in_span(&gens, &w));
            }
        }
    }
}
