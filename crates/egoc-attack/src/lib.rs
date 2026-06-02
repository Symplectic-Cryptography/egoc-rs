//! `egoc-attack` — the adversary harness. Every test here is a **CI gate** that
//! either (a) reproduces an OLD fatal break to prove we model it faithfully, or
//! (b) runs that same break against the NEW scheme and asserts it FAILS.
//!
//! Two flagship gates (the panel's two fatal findings):
//!   * LINEAR-RECOVERY  — old: `C·g⁻¹` recovers the witness; new: no handle exists.
//!   * INVARIANT-LEAK   — old: `det(block) = m²+r²` leaks the Casimir; new: it does not.
#![forbid(unsafe_code)]

pub mod mce;

use egoc_field::{Fp, Fp2};
use egoc_linalg::Mat;

/// Flatten `m[i][j]` at flat index `p = i*ncols + j`.
fn flat<const Q: u64>(m: &Mat<Q>, p: usize) -> Fp2<Q> {
    m.get(p / m.ncols(), p % m.ncols())
}

/// Decide whether `target ∈ span_E{ gens }` by augmented-rank comparison.
/// Columns are the vectorized generators; we compare rank before/after
/// appending `vec(target)`.
pub fn in_code_span<const Q: u64>(gens: &[Mat<Q>], target: &Mat<Q>) -> bool {
    let ambient = gens[0].nrows() * gens[0].ncols();
    let k = gens.len();

    let base_rows: Vec<Vec<Fp2<Q>>> = (0..ambient)
        .map(|p| gens.iter().map(|g| flat(g, p)).collect())
        .collect();
    let base = Mat::from_rows(base_rows);

    let aug_rows: Vec<Vec<Fp2<Q>>> = (0..ambient)
        .map(|p| {
            let mut row: Vec<Fp2<Q>> = gens.iter().map(|g| flat(g, p)).collect();
            row.push(flat(target, p));
            row
        })
        .collect();
    let aug = Mat::from_rows(aug_rows);

    let _ = k;
    base.rank() == aug.rank()
}

/// Top-left `2×2` minor of a matrix over `E`: `C₀₀·C₁₁ − C₀₁·C₁₀`.
pub fn minor_2x2<const Q: u64>(c: &Mat<Q>) -> Fp2<Q> {
    c.get(0, 0).mul(c.get(1, 1)).sub(c.get(0, 1).mul(c.get(1, 0)))
}

// ---------------------------------------------------------------------------
// Faithful reconstruction of the OLD (broken) scheme over F_q.
// ---------------------------------------------------------------------------

/// Old public gauge `g = [[a,b],[c,d]] ∈ GL₂(F_q)`.
#[derive(Clone, Copy)]
pub struct OldGauge<const Q: u64> {
    pub a: Fp<Q>,
    pub b: Fp<Q>,
    pub c: Fp<Q>,
    pub d: Fp<Q>,
}

impl<const Q: u64> OldGauge<Q> {
    pub fn det(&self) -> Fp<Q> {
        self.a.mul(self.d).sub(self.b.mul(self.c))
    }
}

/// Old commitment rows: `C[2i] = [mᵢ,rᵢ]·g`, `C[2i+1] = [rᵢ,-mᵢ]·g`.
pub fn old_commit<const Q: u64>(m: &[Fp<Q>], r: &[Fp<Q>], g: &OldGauge<Q>) -> Vec<[Fp<Q>; 2]> {
    let mut rows = Vec::with_capacity(2 * m.len());
    for i in 0..m.len() {
        let (mi, ri) = (m[i], r[i]);
        rows.push([mi.mul(g.a).add(ri.mul(g.c)), mi.mul(g.b).add(ri.mul(g.d))]);
        rows.push([ri.mul(g.a).add(mi.neg().mul(g.c)), ri.mul(g.b).add(mi.neg().mul(g.d))]);
    }
    rows
}

/// THE OLD BREAK: with `g` public, recover `(mᵢ,rᵢ)` from the even row by one
/// `2×2` solve. Returns `(m̂, r̂)`.
pub fn old_linear_recovery<const Q: u64>(
    c_rows: &[[Fp<Q>; 2]],
    g: &OldGauge<Q>,
) -> (Vec<Fp<Q>>, Vec<Fp<Q>>) {
    // even row solves [[a,c],[b,d]]·[m;r] = [C0;C1]; det = ad-bc = det(g).
    let det = g.det();
    let det_inv = det.inv_public();
    let n = c_rows.len() / 2;
    let (mut mh, mut rh) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for i in 0..n {
        let [c0, c1] = c_rows[2 * i];
        // inverse of [[a,c],[b,d]] is (1/det)[[d,-c],[-b,a]]
        let m = c0.mul(g.d).sub(c1.mul(g.c)).mul(det_inv);
        let r = c0.mul(g.b).neg().add(c1.mul(g.a)).mul(det_inv);
        mh.push(m);
        rh.push(r);
    }
    (mh, rh)
}

/// Determinant of the `i`-th old `2×2` block `[C[2i]; C[2i+1]]`.
pub fn old_block_det<const Q: u64>(c_rows: &[[Fp<Q>; 2]], i: usize) -> Fp<Q> {
    let [a, b] = c_rows[2 * i];
    let [c, d] = c_rows[2 * i + 1];
    a.mul(d).sub(b.mul(c))
}

#[cfg(test)]
mod gates {
    use super::*;
    use egoc_code::{CodeParams, GenSet};
    use egoc_commit::{commit_with, recompute, Commitment};
    use egoc_field::Q_MCE;
    use egoc_sl2::{Encoder, Witness};
    use rand::{rngs::StdRng, SeedableRng};

    type Fq = Fp<Q_MCE>;

    fn hamming(a: &[u8; 32], b: &[u8; 32]) -> u32 {
        a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
    }

    // === GATE 1a — OLD LINEAR RECOVERY *SUCCEEDS* (the break is real) ========
    #[test]
    fn old_linear_recovery_succeeds() {
        let g = OldGauge::<Q_MCE> { a: Fq::new(2), b: Fq::new(1), c: Fq::new(1), d: Fq::new(1) };
        assert_eq!(g.det(), Fq::one(), "use a det=1 gauge");
        let m: Vec<Fq> = (1..=6u64).map(Fq::new).collect();
        let r: Vec<Fq> = (7..=12u64).map(Fq::new).collect();
        let c = old_commit(&m, &r, &g);
        let (mh, rh) = old_linear_recovery(&c, &g);
        assert_eq!(mh, m, "old scheme: m recovered by public-g linear solve");
        assert_eq!(rh, r, "old scheme: r recovered too — hiding fully broken");
    }

    // === GATE 1b — NEW SCHEME GIVES NO LINEAR HANDLE =========================
    #[test]
    fn new_commitment_is_only_a_hash_no_pushed_basis() {
        // The public output is 32 bytes; there is no field that holds a pushed
        // basis {S·G_l·T} (PATCH 1). Structural assertion.
        assert_eq!(core::mem::size_of::<Commitment>(), 32);
    }

    #[test]
    fn new_one_coord_flip_avalanches_the_commitment() {
        // Hold keys + ρ FIXED, flip ONE witness coordinate: a linear leak would
        // change com in a readable way; instead BLAKE3 avalanches it.
        let gens = GenSet::<Q_MCE>::expand(&[3u8; 32], CodeParams::DEMO);
        let mut rng = StdRng::seed_from_u64(1);
        let rho: Vec<_> = (0..CodeParams::DEMO.mask_len).map(|_| Fp2::random(&mut rng)).collect();
        let (sa, sb) = ([9u8; 32], [10u8; 32]);

        let w1 = Witness::<Q_MCE>::random(CodeParams::DEMO.ell, &mut rng);
        let mut m2 = w1.m.clone();
        m2[0] = m2[0].add(Fq::one()); // single-coordinate perturbation
        let w2 = Witness::new(m2, w1.r.clone());

        let (c1, _) = commit_with(&gens, w1, rho.clone(), sa, sb);
        let (c2, _) = commit_with(&gens, w2, rho, sa, sb);
        let d = hamming(&c1.com, &c2.com);
        assert!(d > 64, "expected avalanche (~128 bits), got {d}");
    }

    #[test]
    fn new_commitment_c_not_in_public_code_span() {
        // PATCH 1 core: even if C is revealed at open, C ∉ span{G_l}, so the
        // coordinate-projection recovery that broke the naive MCE proposal is
        // INCONSISTENT. The message M *is* in the span — but C is pushed out of
        // it by the secret S,T, and the pushed basis is never published.
        let gens = GenSet::<Q_MCE>::expand(&[4u8; 32], CodeParams::DEMO);
        let mut rng = StdRng::seed_from_u64(2);
        let rho: Vec<_> = (0..CodeParams::DEMO.mask_len).map(|_| Fp2::random(&mut rng)).collect();
        let w = Witness::<Q_MCE>::random(CodeParams::DEMO.ell, &mut rng);

        // The message matrix (control): in the code span by construction.
        let m_msg = gens.embed(&Encoder::pack(&w), &rho);
        assert!(in_code_span(&gens.gens, &m_msg), "M must lie in the code span");

        // The commitment matrix: pushed OUT of the span by secret S,T.
        let (_com, op) = commit_with(&gens, w, rho, [11u8; 32], [12u8; 32]);
        let c = recompute(&gens, &op).unwrap();
        assert!(
            !in_code_span(&gens.gens, &c),
            "C must NOT be in span{{G_l}} — else linear recovery would work"
        );
    }

    #[test]
    fn new_naive_one_sided_recovery_fails() {
        // Attacker ignores S,T and reads coordinates straight off C.
        let gens = GenSet::<Q_MCE>::expand(&[5u8; 32], CodeParams::DEMO);
        let mut rng = StdRng::seed_from_u64(3);
        let rho: Vec<_> = (0..CodeParams::DEMO.mask_len).map(|_| Fp2::random(&mut rng)).collect();
        let w = Witness::<Q_MCE>::random(CodeParams::DEMO.ell, &mut rng);
        let true_coords = Encoder::pack(&w);

        let (_c, op) = commit_with(&gens, w, rho, [13u8; 32], [14u8; 32]);
        let c = recompute(&gens, &op).unwrap();

        // naive guess: treat the first 2ℓ flat real-parts of C as the coords
        let guess: Vec<Fq> = (0..true_coords.len()).map(|p| flat(&c, p).c0).collect();
        assert_ne!(guess, true_coords, "naive one-sided readout must NOT recover w");
    }

    // === GATE 2a — OLD CASIMIR LEAK *PRESENT* ================================
    #[test]
    fn old_casimir_leaks_from_block_determinant() {
        let g = OldGauge::<Q_MCE> { a: Fq::new(2), b: Fq::new(1), c: Fq::new(1), d: Fq::new(1) };
        assert_eq!(g.det(), Fq::one());
        let m: Vec<Fq> = (3..=8u64).map(Fq::new).collect();
        let r: Vec<Fq> = (1..=6u64).map(Fq::new).collect();
        let c = old_commit(&m, &r, &g);
        for i in 0..m.len() {
            // block det = det(B)·det(g) = -(m²+r²)·1
            let leaked = old_block_det(&c, i);
            let casimir = m[i].mul(m[i]).add(r[i].mul(r[i])).neg();
            assert_eq!(leaked, casimir, "old scheme leaks m²+r² for block {i}");
        }
    }

    // === GATE 2b — NEW SCHEME: CASIMIR IS NOT AN INVARIANT ===================
    #[test]
    fn new_casimir_is_not_a_witness_invariant() {
        // Fix the witness; vary only the secret keys & masking. If the 2×2 minor
        // (or any spectral quantity) were a function of w it would be constant.
        // We assert it takes many distinct values ⇒ it cannot encode the Casimir.
        let gens = GenSet::<Q_MCE>::expand(&[6u8; 32], CodeParams::DEMO);
        let mut rng = StdRng::seed_from_u64(4);
        let w = Witness::<Q_MCE>::random(CodeParams::DEMO.ell, &mut rng);

        let mut minors = std::collections::HashSet::new();
        let mut ranks = std::collections::HashSet::new();
        for trial in 0..200u64 {
            let rho: Vec<_> =
                (0..CodeParams::DEMO.mask_len).map(|_| Fp2::random(&mut rng)).collect();
            let mut ss = [0u8; 32];
            let mut tt = [0u8; 32];
            ss[..8].copy_from_slice(&trial.to_le_bytes());
            tt[..8].copy_from_slice(&(trial ^ 0xABCD).to_le_bytes());
            let (_c, op) = commit_with(&gens, w.clone(), rho, ss, tt);
            let c = recompute(&gens, &op).unwrap();
            minors.insert(minor_2x2(&c).to_bytes());
            ranks.insert(c.rank());
        }
        assert!(
            minors.len() > 50,
            "2×2 minor took only {} values for a FIXED witness — possible leak",
            minors.len()
        );
        // rank is the only equivalence invariant and it is constant = min(mr,mc)
        assert_eq!(ranks.len(), 1, "rank should be constant across keys");
        assert_eq!(*ranks.iter().next().unwrap(), CodeParams::DEMO.mr.min(CodeParams::DEMO.mc));
    }

    #[test]
    fn new_rank_is_constant_across_witnesses() {
        // Vary the witness with fixed keys: rank(C) reveals nothing about w.
        let gens = GenSet::<Q_MCE>::expand(&[7u8; 32], CodeParams::DEMO);
        let mut rng = StdRng::seed_from_u64(5);
        let rho: Vec<_> = (0..CodeParams::DEMO.mask_len).map(|_| Fp2::random(&mut rng)).collect();
        let (sa, sb) = ([21u8; 32], [22u8; 32]);
        let want = CodeParams::DEMO.mr.min(CodeParams::DEMO.mc);
        for _ in 0..100 {
            let w = Witness::<Q_MCE>::random(CodeParams::DEMO.ell, &mut rng);
            let (_c, op) = commit_with(&gens, w, rho.clone(), sa, sb);
            let c = recompute(&gens, &op).unwrap();
            assert_eq!(c.rank(), want);
        }
    }
}
