//! `egoc-auction` — a sealed-bid auction on the EGOC-MCE-R code-mode commitment.
//!
//! Each bidder:
//! * encodes their bid into witness coordinate 0, masks the rest, and publishes
//!   the **code-mode commitment** `C = S·M·T` (hiding under MCE; binding via
//!   lift-injectivity + GL-invertibility — a second opening is an MCE collision);
//! * attaches a **ZK opening proof** (`egoc-proof::opening`) showing the
//!   commitment is well-formed and they can open it — **without revealing the bid**.
//!
//! At close, bidders reveal `(witness, ρ, S, T)`; the auctioneer recomputes `C`,
//! checks it matches (binding), and the highest revealed bid wins.
//!
//! Security note: this demo runs on the **MCE backend** (the elegant `sl(2)`/2T
//! construction). Its rank-based attack surfaces pass with huge margin and the
//! algebraic surface is *supportive* (msolve solving degree rises, cost OOMs at
//! tiny sizes), but a published MCE bit number still awaits the MEDS estimator —
//! see `docs/CRYPTANALYSIS.md`. The `egoc-mlwe` lattice backend is the
//! estimator-confirmed (≥2¹⁸⁶) alternative for bit-pinned deployments.
#![forbid(unsafe_code)]

use egoc_code::{CodeParams, GenSet};
use egoc_field::{Fp, Fp2, Q_MCE};
use egoc_linalg::Mat;
use egoc_proof::opening::{prove_opening, verify_opening, OpeningProof};
use egoc_sl2::{Encoder, Witness};
use rand::RngCore;

type Q = Fp<Q_MCE>;

/// Auction context: the public NUMS code + soundness parameter λ.
pub struct Auction {
    pub gens: GenSet<Q_MCE>,
    pub params: CodeParams,
    pub lambda: usize,
}

/// What a bidder publishes: the commitment matrix and a ZK opening proof.
pub struct SealedBid {
    pub commitment: Mat<Q_MCE>,
    pub proof: OpeningProof<Q_MCE>,
}

impl SealedBid {
    /// Public size in bytes (commitment matrix + proof), `Fp2 = 16 B` per entry.
    pub fn size_bytes(&self) -> usize {
        let c = self.commitment.nrows() * self.commitment.ncols() * 16;
        let mut p = self.proof.commits.len() * 32;
        for r in &self.proof.resps {
            p += r.a.nrows() * r.a.ncols() * 16 + r.b.nrows() * r.b.ncols() * 16;
            if let Some(d) = &r.d {
                p += d.nrows() * d.ncols() * 16;
            }
        }
        c + p
    }
}

/// The bidder's secret opening (kept until the reveal phase).
pub struct BidSecret {
    pub witness: Witness<Q_MCE>,
    pub rho: Vec<Fp2<Q_MCE>>,
    pub s: Mat<Q_MCE>,
    pub t: Mat<Q_MCE>,
}

impl Auction {
    /// Create an auction with a hull-generic public code (keygen reject) and λ rounds.
    pub fn new(seed: &[u8; 32], params: CodeParams, lambda: usize) -> Self {
        let (gens, _attempt) = GenSet::<Q_MCE>::expand_checked(seed, params, 0);
        Self { gens, params, lambda }
    }

    /// Commit to `bid` (a field element `< q`) and produce the ZK opening proof.
    pub fn commit_bid(&self, bid: u64, rng: &mut impl RngCore) -> (SealedBid, BidSecret) {
        let ell = self.params.ell;
        // bid in coordinate 0; the rest of the witness is fresh randomness
        let mut m: Vec<Q> = (0..ell).map(|_| Fp::random(rng)).collect();
        m[0] = Fp::new(bid % Q_MCE);
        let r: Vec<Q> = (0..ell).map(|_| Fp::random(rng)).collect();
        let witness = Witness::new(m, r);

        let x = Encoder::pack(&witness);
        let rho: Vec<Fp2<Q_MCE>> = (0..self.params.mask_len).map(|_| Fp2::random(rng)).collect();
        let mm = self.gens.embed(&x, &rho);

        let s = Mat::random_invertible(self.params.mr, rng);
        let t = Mat::random_invertible(self.params.mc, rng);
        let commitment = Mat::two_sided(&s, &mm, &t);

        let proof = prove_opening(&self.gens.gens, &commitment, &s, &t, self.lambda, rng);
        (SealedBid { commitment, proof }, BidSecret { witness, rho, s, t })
    }

    /// Verify a sealed bid's ZK opening proof (well-formedness, no bid revealed).
    pub fn verify_sealed(&self, sb: &SealedBid) -> bool {
        verify_opening(&self.gens.gens, &sb.commitment, &sb.proof)
    }

    /// Reveal: recompute `C` from the secret and check it matches the published
    /// commitment (binding). Returns the bid on success, `None` on mismatch.
    pub fn reveal(&self, sb: &SealedBid, secret: &BidSecret) -> Option<u64> {
        if secret.witness.n() != self.params.ell || secret.rho.len() != self.params.mask_len {
            return None;
        }
        let x = Encoder::pack(&secret.witness);
        let mm = self.gens.embed(&x, &secret.rho);
        let c = Mat::two_sided(&secret.s, &mm, &secret.t);
        if c == sb.commitment {
            Some(secret.witness.m[0].val())
        } else {
            None
        }
    }
}

/// Determine the winner: index and bid of the highest validly-revealed bid.
pub fn winner(reveals: &[Option<u64>]) -> Option<(usize, u64)> {
    reveals
        .iter()
        .enumerate()
        .filter_map(|(i, b)| b.map(|v| (i, v)))
        .max_by_key(|&(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    fn auction() -> Auction {
        Auction::new(&[7u8; 32], CodeParams::DEMO, 16)
    }

    #[test]
    fn commit_prove_reveal_roundtrip() {
        let a = auction();
        let mut rng = StdRng::seed_from_u64(1);
        let (sb, secret) = a.commit_bid(1234, &mut rng);
        assert!(a.verify_sealed(&sb), "ZK opening proof must verify");
        assert_eq!(a.reveal(&sb, &secret), Some(1234), "reveal returns the bid");
    }

    #[test]
    fn binding_tampered_reveal_rejected() {
        // A bidder cannot reveal a different bid for the same commitment.
        let a = auction();
        let mut rng = StdRng::seed_from_u64(2);
        let (sb, mut secret) = a.commit_bid(500, &mut rng);
        secret.witness.m[0] = Fp::new(999); // try to claim a higher bid
        assert_eq!(a.reveal(&sb, &secret), None, "tampered reveal must be rejected");
    }

    #[test]
    fn zk_opening_does_not_need_the_bid() {
        // verify_sealed checks only the proof + public commitment (no secret).
        let a = auction();
        let mut rng = StdRng::seed_from_u64(3);
        let (sb, _secret) = a.commit_bid(42, &mut rng);
        assert!(a.verify_sealed(&sb));
    }

    #[test]
    fn winner_is_the_highest_bid() {
        let a = auction();
        let mut rng = StdRng::seed_from_u64(4);
        let bids = [300u64, 1500, 700, 1500 - 1, 90];
        let mut sealed = Vec::new();
        let mut secrets = Vec::new();
        for &b in &bids {
            let (sb, sec) = a.commit_bid(b, &mut rng);
            assert!(a.verify_sealed(&sb));
            sealed.push(sb);
            secrets.push(sec);
        }
        let reveals: Vec<_> = sealed.iter().zip(&secrets).map(|(sb, s)| a.reveal(sb, s)).collect();
        let (idx, bid) = winner(&reveals).unwrap();
        assert_eq!((idx, bid), (1, 1500));
    }

    #[test]
    fn forged_commitment_proof_rejected() {
        // A "bid" whose commitment is a random matrix (not S·M·T) cannot produce
        // a verifying opening proof.
        let a = auction();
        let mut rng = StdRng::seed_from_u64(5);
        let bogus = Mat::<Q_MCE>::random(a.params.mr, a.params.mc, &mut rng);
        let id_s = Mat::identity(a.params.mr);
        let id_t = Mat::identity(a.params.mc);
        let proof = prove_opening(&a.gens.gens, &bogus, &id_s, &id_t, a.lambda, &mut rng);
        let sb = SealedBid { commitment: bogus, proof };
        assert!(!a.verify_sealed(&sb));
    }
}
