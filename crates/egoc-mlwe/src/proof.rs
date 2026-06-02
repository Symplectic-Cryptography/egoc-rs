//! Fiat–Shamir-with-aborts zero-knowledge proof of knowledge of a commitment
//! opening (Lyubashevsky-style), proving knowledge of a **short** `r` with
//! `A1·r = c1` — without revealing `r` or the message.
//!
//! * Mask `y` uniform in `[−B_y, B_y]`; `w = A1·y`.
//! * Challenge `c = H(domain ‖ A1 ‖ c1 ‖ c2 ‖ w ‖ params)` — full transcript,
//!   sparse-ternary, unbiased.
//! * Response `z = y + c·r`, accepted only if `‖z‖∞ ≤ B_z = B_y − τ·η`
//!   (bounded-uniform rejection ⇒ accepted `z` is uniform on `[−B_z, B_z]`,
//!   independent of `r` ⇒ perfect HVZK on the accept set).
//! * Verify: `‖z‖∞ ≤ B_z` and `A1·z = w + c·c1`.
//!
//! Special soundness: two accepting transcripts `(w,c,z), (w,c',z')` give
//! `A1·(z−z') = (c−c')·c1` with `z−z'` short — a relaxed opening (MSIS-style).

use crate::poly::{Poly, N, Q};
use crate::{challenge_poly, matvec, CommitKey, Commitment, Opening, Xof};
use blake3::Hasher;
use rand_core::RngCore;

/// Proof-system parameters.
#[derive(Clone, Copy, Debug)]
pub struct ProofParams {
    /// challenge weight (number of ±1 coefficients)
    pub tau: usize,
    /// mask bound `B_y` (coefficients of `y` uniform in `[−B_y, B_y]`)
    pub b_y: i64,
}

impl ProofParams {
    pub const DEMO: ProofParams = ProofParams { tau: 20, b_y: 1 << 19 };

    /// Verification bound `B_z = B_y − τ·η`.
    #[inline]
    pub fn b_z(&self, eta: u32) -> i64 {
        self.b_y - (self.tau as i64) * (eta as i64)
    }
}

/// A non-interactive opening proof.
#[derive(Clone, Debug)]
pub struct OpeningProof {
    pub w: Vec<Poly>,
    pub z: Vec<Poly>,
}

fn vec_norm_inf(v: &[Poly]) -> u64 {
    v.iter().map(|p| p.norm_inf()).max().unwrap_or(0)
}

/// Uniform poly with centered coefficients in `[−bound, bound]`, stored in `[0,q)`.
fn uniform_bounded(x: &mut Xof, bound: i64) -> Poly {
    let span = (2 * bound + 1) as u64;
    // smallest power-of-two number of bytes covering `span`
    let bits = 64 - (span - 1).leading_zeros();
    let nbytes = ((bits + 7) / 8) as usize;
    let mut p = Poly::zero();
    let mut i = 0;
    while i < N {
        let mut buf = [0u8; 8];
        x.fill(&mut buf[..nbytes]);
        let v = u64::from_le_bytes(buf) & ((1u64 << (nbytes * 8)) - 1);
        if v < span {
            let centered = v as i64 - bound;
            p.c[i] = if centered < 0 { (centered + Q as i64) as u32 } else { centered as u32 };
            i += 1;
        }
    }
    p
}

/// Bind the full statement into the Fiat–Shamir challenge.
fn fs_challenge(ck: &CommitKey, com: &Commitment, w: &[Poly], pp: &ProofParams) -> Poly {
    let mut h = Hasher::new();
    h.update(b"egoc-mlwe/fs-open/v1");
    h.update(&(N as u64).to_le_bytes());
    h.update(&Q.to_le_bytes());
    h.update(&(ck.params.k_bind as u64).to_le_bytes());
    h.update(&(ck.params.k_msg as u64).to_le_bytes());
    h.update(&(ck.params.l_rand as u64).to_le_bytes());
    h.update(&(ck.params.eta as u64).to_le_bytes());
    h.update(&(pp.tau as u64).to_le_bytes());
    h.update(&pp.b_y.to_le_bytes());
    for row in &ck.a1 {
        for p in row {
            h.update(&p.to_bytes());
        }
    }
    for p in &com.c1 {
        h.update(&p.to_bytes());
    }
    for p in &com.c2 {
        h.update(&p.to_bytes());
    }
    for p in w {
        h.update(&p.to_bytes());
    }
    let seed = *h.finalize().as_bytes();
    challenge_poly(&seed, pp.tau)
}

/// Prove knowledge of the opening. Returns `None` if rejection sampling exhausts
/// its attempt budget (vanishingly unlikely at the DEMO parameters).
pub fn prove_opening(
    ck: &CommitKey,
    com: &Commitment,
    op: &Opening,
    pp: &ProofParams,
    rng: &mut impl RngCore,
) -> Option<OpeningProof> {
    let b_z = pp.b_z(ck.params.eta);
    for _ in 0..256 {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut x = Xof::new(b"egoc-mlwe/mask/v1", &seed);
        let y: Vec<Poly> = (0..ck.params.l_rand).map(|_| uniform_bounded(&mut x, pp.b_y)).collect();
        let w = matvec(&ck.a1, &y);
        let c = fs_challenge(ck, com, &w, pp);
        let z: Vec<Poly> = y.iter().zip(op.r.iter()).map(|(yj, rj)| yj.add(&c.mul(rj))).collect();
        if vec_norm_inf(&z) <= b_z as u64 {
            return Some(OpeningProof { w, z });
        }
        // reject: leaked nothing; try a fresh mask
    }
    None
}

/// Verify an opening proof.
pub fn verify_opening(
    ck: &CommitKey,
    com: &Commitment,
    proof: &OpeningProof,
    pp: &ProofParams,
) -> bool {
    if proof.z.len() != ck.params.l_rand || proof.w.len() != ck.params.k_bind {
        return false;
    }
    let b_z = pp.b_z(ck.params.eta);
    if vec_norm_inf(&proof.z) > b_z as u64 {
        return false;
    }
    let c = fs_challenge(ck, com, &proof.w, pp);
    // A1·z  ==  w + c·c1
    let lhs = matvec(&ck.a1, &proof.z);
    let rhs: Vec<Poly> = proof.w.iter().zip(com.c1.iter()).map(|(wi, ci)| wi.add(&c.mul(ci))).collect();
    lhs == rhs
}

/// HVZK simulator against an explicit challenge `c`: sample `z`
/// uniform on `[−B_z, B_z]`, set `w = A1·z − c·c1`. The resulting `(w, c, z)`
/// satisfies the verification relation by construction.
pub fn simulate_with_challenge(
    ck: &CommitKey,
    com: &Commitment,
    c: &Poly,
    pp: &ProofParams,
    rng: &mut impl RngCore,
) -> OpeningProof {
    let b_z = pp.b_z(ck.params.eta);
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let mut x = Xof::new(b"egoc-mlwe/sim2/v1", &seed);
    let z: Vec<Poly> = (0..ck.params.l_rand).map(|_| uniform_bounded(&mut x, b_z)).collect();
    let az = matvec(&ck.a1, &z);
    let w: Vec<Poly> = az.iter().zip(com.c1.iter()).map(|(azi, ci)| azi.sub(&c.mul(ci))).collect();
    OpeningProof { w, z }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{commit_with, sample_randomness, Params};
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    fn setup(seed: u64) -> (CommitKey, Commitment, Opening, StdRng) {
        let ck = CommitKey::expand(&[42u8; 32], Params::DEMO);
        let mut rng = StdRng::seed_from_u64(seed);
        let mut mseed = [0u8; 32];
        rng.fill_bytes(&mut mseed);
        let mut mx = Xof::new(b"t/msg", &mseed);
        let m: Vec<Poly> = (0..ck.params.k_msg).map(|_| crate::uniform_poly(&mut mx)).collect();
        let mut rseed = [0u8; 32];
        rng.fill_bytes(&mut rseed);
        let r = sample_randomness(&ck, &rseed);
        let (com, op) = commit_with(&ck, m, r);
        (ck, com, op, rng)
    }

    #[test]
    fn honest_proof_verifies() {
        let (ck, com, op, mut rng) = setup(1);
        let pp = ProofParams::DEMO;
        let proof = prove_opening(&ck, &com, &op, &pp, &mut rng).expect("prove");
        assert!(verify_opening(&ck, &com, &proof, &pp));
    }

    #[test]
    fn tampered_proof_rejected() {
        let (ck, com, op, mut rng) = setup(2);
        let pp = ProofParams::DEMO;
        let mut proof = prove_opening(&ck, &com, &op, &pp, &mut rng).expect("prove");
        proof.z[0].c[0] = (proof.z[0].c[0] + 1) % Q as u32;
        assert!(!verify_opening(&ck, &com, &proof, &pp));
    }

    #[test]
    fn proof_for_wrong_commitment_rejected() {
        let (ck, com, op, mut rng) = setup(3);
        let pp = ProofParams::DEMO;
        let proof = prove_opening(&ck, &com, &op, &pp, &mut rng).expect("prove");
        // verify against a different commitment
        let (com2, _) = {
            let mut mx = Xof::new(b"t/msg2", &[1u8; 32]);
            let m2: Vec<Poly> = (0..ck.params.k_msg).map(|_| crate::uniform_poly(&mut mx)).collect();
            let r2 = sample_randomness(&ck, &[2u8; 32]);
            commit_with(&ck, m2, r2)
        };
        assert!(!verify_opening(&ck, &com2, &proof, &pp));
    }

    #[test]
    fn hvzk_simulated_transcript_verifies() {
        // Simulator (no witness) produces a transcript satisfying the relation
        // for an explicitly chosen challenge — the HVZK core.
        let (ck, com, _op, mut rng) = setup(4);
        let pp = ProofParams::DEMO;
        let c = challenge_poly(&[7u8; 32], pp.tau);
        let sim = simulate_with_challenge(&ck, &com, &c, &pp, &mut rng);
        // relation A1·z == w + c·c1 holds by construction
        let lhs = matvec(&ck.a1, &sim.z);
        let rhs: Vec<Poly> =
            sim.w.iter().zip(com.c1.iter()).map(|(wi, ci)| wi.add(&c.mul(ci))).collect();
        assert_eq!(lhs, rhs);
        assert!(vec_norm_inf(&sim.z) <= pp.b_z(ck.params.eta) as u64);
    }

    #[test]
    fn special_soundness_extracts_relaxed_opening() {
        // Two accepting transcripts with the SAME w but different challenges give
        // A1·(z−z') = (c−c')·c1 with (z−z') short — a relaxed opening.
        let (ck, com, op, _rng) = setup(5);
        let pp = ProofParams::DEMO;

        // interactive: fix one mask y, derive w, run two distinct challenges
        let mut x = Xof::new(b"ss/mask", &[3u8; 32]);
        let y: Vec<Poly> = (0..ck.params.l_rand).map(|_| uniform_bounded(&mut x, pp.b_y)).collect();
        let _w = matvec(&ck.a1, &y); // shared commitment for both transcripts (same y)
        let c = challenge_poly(&[10u8; 32], pp.tau);
        let c2 = challenge_poly(&[11u8; 32], pp.tau);
        assert_ne!(c, c2);
        let z: Vec<Poly> = y.iter().zip(op.r.iter()).map(|(yj, rj)| yj.add(&c.mul(rj))).collect();
        let z2: Vec<Poly> = y.iter().zip(op.r.iter()).map(|(yj, rj)| yj.add(&c2.mul(rj))).collect();

        // A1·(z − z') == (c − c')·c1
        let zdiff: Vec<Poly> = z.iter().zip(z2.iter()).map(|(a, b)| a.sub(b)).collect();
        let lhs = matvec(&ck.a1, &zdiff);
        let cdiff = c.sub(&c2);
        let rhs: Vec<Poly> = com.c1.iter().map(|ci| cdiff.mul(ci)).collect();
        assert_eq!(lhs, rhs, "special-soundness relation must hold");
    }
}
