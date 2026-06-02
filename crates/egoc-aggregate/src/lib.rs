//! `egoc-aggregate` — HONEST batch aggregation of code-mode opening proofs.
//!
//! Given `N` code-mode commitments `C_0,…,C_{N-1}` (sharing the public code
//! `gens`), this produces a single proof that the prover knows a valid opening
//! `(S_j,T_j)` for **every** `C_j` — under **one** Fiat–Shamir challenge derived
//! from the whole batch transcript.
//!
//! # This is NOT Nova/IVC folding, and NOT a sum.
//! The predecessor's "IVC" re-committed the *sum* of witnesses and proved only
//! knowledge of that sum — an overclaim. Here every commitment keeps its own
//! `λ`-round opening sub-proof; soundness is `2⁻λ` **per commitment**, so the
//! proof attests **each individual opening**. Insert one invalid commitment and
//! the batch fails (see the test). The aggregation win is a single transcript /
//! one challenge derivation / batched verification — **proof size is linear in
//! `N`** (genuine size reduction via seed-trees / fixed-weight challenges is
//! deferred and documented as future work, not faked).
#![forbid(unsafe_code)]

use blake3::Hasher;
use egoc_linalg::Mat;
use egoc_proof::opening::{commit_round, respond_round, verify_round, Eph, OpenResp};
use egoc_proof::Code;
use rand_core::RngCore;

const DOMAIN: &[u8] = b"egoc-aggregate/batch-open/v1";

/// A batch opening proof: per-commitment rows of `λ` round commitments/responses.
#[derive(Clone)]
pub struct AggProof<const Q: u64> {
    pub lambda: usize,
    pub commits: Vec<Vec<[u8; 32]>>, // [j][round]
    pub resps: Vec<Vec<OpenResp<Q>>>, // [j][round]
}

/// Derive `λ` challenge bits **per commitment** from one transcript hash binding
/// `gens`, all `C_j`, and all round commitments.
fn batch_bits<const Q: u64>(
    gens: &Code<Q>,
    cs: &[Mat<Q>],
    commits: &[Vec<[u8; 32]>],
    lambda: usize,
) -> Vec<Vec<bool>> {
    let mut h = Hasher::new();
    h.update(DOMAIN);
    h.update(&(lambda as u64).to_le_bytes());
    h.update(&(cs.len() as u64).to_le_bytes());
    for g in gens {
        h.update(&g.to_bytes());
    }
    for c in cs {
        h.update(&c.to_bytes());
    }
    for row in commits {
        for cm in row {
            h.update(cm);
        }
    }
    let mut reader = h.finalize_xof();
    let (mut cur, mut have) = (0u8, 0u8);
    let mut buf = [0u8; 1];
    let mut next_bit = || -> bool {
        if have == 0 {
            reader.fill(&mut buf);
            cur = buf[0];
            have = 8;
        }
        let b = cur & 1 == 1;
        cur >>= 1;
        have -= 1;
        b
    };
    (0..cs.len()).map(|_| (0..lambda).map(|_| next_bit()).collect()).collect()
}

/// Prove knowledge of an opening for every `C_j`, with keys `keys[j] = (S_j,T_j)`.
pub fn prove_batch<const Q: u64>(
    gens: &Code<Q>,
    cs: &[Mat<Q>],
    keys: &[(Mat<Q>, Mat<Q>)],
    lambda: usize,
    rng: &mut impl RngCore,
) -> AggProof<Q> {
    assert_eq!(cs.len(), keys.len(), "one keypair per commitment");
    // Phase 1: all round commitments for all commitments.
    let mut eph: Vec<Vec<Eph<Q>>> = Vec::with_capacity(cs.len());
    let mut commits: Vec<Vec<[u8; 32]>> = Vec::with_capacity(cs.len());
    for c in cs {
        let mut eph_row = Vec::with_capacity(lambda);
        let mut cmt_row = Vec::with_capacity(lambda);
        for _ in 0..lambda {
            let (e, cmt) = commit_round(c, rng);
            eph_row.push(e);
            cmt_row.push(cmt);
        }
        eph.push(eph_row);
        commits.push(cmt_row);
    }
    // One shared challenge derivation over the whole batch.
    let bits = batch_bits(gens, cs, &commits, lambda);
    // Phase 2: responses.
    let mut resps: Vec<Vec<OpenResp<Q>>> = Vec::with_capacity(cs.len());
    for j in 0..cs.len() {
        let (s, t) = &keys[j];
        let row = (0..lambda).map(|r| respond_round(&eph[j][r], s, t, bits[j][r])).collect();
        resps.push(row);
    }
    AggProof { lambda, commits, resps }
}

/// Verify the batch: every commitment's every round must check.
pub fn verify_batch<const Q: u64>(gens: &Code<Q>, cs: &[Mat<Q>], proof: &AggProof<Q>) -> bool {
    let n = cs.len();
    if proof.commits.len() != n || proof.resps.len() != n {
        return false;
    }
    for j in 0..n {
        if proof.commits[j].len() != proof.lambda || proof.resps[j].len() != proof.lambda {
            return false;
        }
    }
    let bits = batch_bits(gens, cs, &proof.commits, proof.lambda);
    for j in 0..n {
        for r in 0..proof.lambda {
            if !verify_round(gens, &cs[j], &proof.commits[j][r], bits[j][r], &proof.resps[j][r]) {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::{Fp2, Q_MCE};
    use rand::{rngs::StdRng, SeedableRng};

    fn random_code(mr: usize, mc: usize, k: usize, rng: &mut impl RngCore) -> Code<Q_MCE> {
        (0..k).map(|_| Mat::random(mr, mc, rng)).collect()
    }

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
        (s.mul(&m).mul(&t), s, t)
    }

    #[test]
    fn all_valid_batch_verifies() {
        let mut rng = StdRng::seed_from_u64(1);
        let (mr, mc, k) = (5, 6, 8);
        let gens = random_code(mr, mc, k, &mut rng);
        let n = 6;
        let mut cs = Vec::new();
        let mut keys = Vec::new();
        for _ in 0..n {
            let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);
            cs.push(c);
            keys.push((s, t));
        }
        let proof = prove_batch(&gens, &cs, &keys, 20, &mut rng);
        assert!(verify_batch(&gens, &cs, &proof));
    }

    #[test]
    fn one_invalid_commitment_fails_the_batch() {
        // Proves the batch checks EACH individual opening (no sum collapse):
        // swap one commitment for a random non-commitment but keep proving with
        // its (now wrong) keys — that index's rounds fail ⇒ whole batch fails.
        let mut rng = StdRng::seed_from_u64(2);
        let (mr, mc, k) = (5, 6, 8);
        let gens = random_code(mr, mc, k, &mut rng);
        let n = 6;
        let mut cs = Vec::new();
        let mut keys = Vec::new();
        for _ in 0..n {
            let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);
            cs.push(c);
            keys.push((s, t));
        }
        // sabotage commitment #3: replace with a random matrix (not a commitment)
        cs[3] = Mat::<Q_MCE>::random(mr, mc, &mut rng);
        let proof = prove_batch(&gens, &cs, &keys, 20, &mut rng);
        assert!(!verify_batch(&gens, &cs, &proof), "one bad opening must fail the batch");
    }

    #[test]
    fn tampered_batch_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let (mr, mc, k) = (4, 5, 6);
        let gens = random_code(mr, mc, k, &mut rng);
        let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);
        let cs = vec![c];
        let keys = vec![(s, t)];
        let mut proof = prove_batch(&gens, &cs, &keys, 20, &mut rng);
        let cur = proof.resps[0][0].a.get(0, 0);
        proof.resps[0][0].a.set(0, 0, cur.add(Fp2::one()));
        assert!(!verify_batch(&gens, &cs, &proof));
    }

    #[test]
    fn wrong_count_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let (mr, mc, k) = (4, 5, 6);
        let gens = random_code(mr, mc, k, &mut rng);
        let (c, s, t) = commit_code(&gens, mr, mc, &mut rng);
        let proof = prove_batch(&gens, &[c.clone()], &[(s, t)], 16, &mut rng);
        // verify against a different commitment set size
        assert!(!verify_batch(&gens, &[c.clone(), c], &proof));
    }
}
