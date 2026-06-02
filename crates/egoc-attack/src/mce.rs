//! M3 empirical MCE cryptanalysis harness.
//!
//! Measures the **degree-2 linearization boundary** of the MCE recovery problem
//! `C_l = S · G_l · T` (find secret `S ∈ GL_mr`, `T ∈ GL_mc` from public code
//! `{G_l}` and pushed code `{C_l}`).
//!
//! Bilinear modeling: each entry equation
//! `(S G_l T)_{ij} = Σ_{a,b} S_{ia} (G_l)_{ab} T_{bj}` is **linear** in the
//! products `P_{i,a,b,j} = S_{ia} T_{bj}`. Linearizing (one variable per product):
//! * monomials  = mr²·mc²
//! * equations  = k·mr·mc
//! The products are invariant under the scalar gauge `(λS, λ⁻¹T)`, so once the
//! linear system has full column rank the products — hence `S,T` — are pinned.
//! That happens iff `equations ≥ monomials`, i.e. **iff `k ≥ mr·mc`** — exactly
//! the easy near-full-rank regime. In the design regime `k ≪ mr·mc` the system
//! is underdetermined at degree 2, so the cheapest algebraic attack fails and the
//! real solving degree is higher.
//!
//! This is a NECESSARY indicator (degree-2 does not collapse), not a full
//! solving-degree extrapolation — that needs a real F4/F5 engine (documented in
//! `docs/CRYPTANALYSIS.md`).

use egoc_code::XofRng;
use egoc_field::Fp2;
use egoc_linalg::Mat;

/// Degree-2 monomial count `mr²·mc²`.
#[inline]
pub fn monomials(mr: usize, mc: usize) -> usize {
    mr * mr * mc * mc
}

/// Bilinear equation count `k·mr·mc`.
#[inline]
pub fn equations(mr: usize, mc: usize, k: usize) -> usize {
    k * mr * mc
}

/// Degree-2 deficiency `monomials − equations` (positive ⇒ underdetermined).
#[inline]
pub fn deficiency(mr: usize, mc: usize, k: usize) -> isize {
    monomials(mr, mc) as isize - equations(mr, mc, k) as isize
}

/// Approximate brute-force key-search exponent in bits:
/// `log2|GL_mr(E) × GL_mc(E)| ≈ (mr² + mc²)·log2|E|`.
#[inline]
pub fn brute_force_bits(mr: usize, mc: usize, log2_field: f64) -> f64 {
    (mr * mr + mc * mc) as f64 * log2_field
}

/// A small MCE instance over `E = Fp2<Q>`.
pub struct Instance<const Q: u64> {
    pub gens: Vec<Mat<Q>>,
    pub pushed: Vec<Mat<Q>>,
    pub mr: usize,
    pub mc: usize,
    pub k: usize,
}

impl<const Q: u64> Instance<Q> {
    pub fn generate(mr: usize, mc: usize, k: usize, seed: &[u8; 32]) -> Self {
        let mut rng = XofRng::new(b"m3/mce-instance/v1", seed);
        let gens: Vec<Mat<Q>> = (0..k).map(|_| Mat::random(mr, mc, &mut rng)).collect();
        let s = Mat::<Q>::random_invertible(mr, &mut rng);
        let t = Mat::<Q>::random_invertible(mc, &mut rng);
        let pushed: Vec<Mat<Q>> = gens.iter().map(|g| Mat::two_sided(&s, g, &t)).collect();
        Self { gens, pushed, mr, mc, k }
    }

    /// Build the linearized coefficient matrix (rows = equations, cols = product
    /// monomials) and return its rank over `E`. If `rank == monomials` the
    /// degree-2 linearization recovers the secret (up to the scalar gauge).
    pub fn linearization_rank(&self) -> LinResult {
        let (mr, mc, k) = (self.mr, self.mc, self.k);
        let n_mon = monomials(mr, mc);
        let n_eq = equations(mr, mc, k);

        // monomial index for product S_{ia} · T_{bj}
        let midx = |i: usize, a: usize, b: usize, j: usize| ((i * mr + a) * mc + b) * mc + j;

        let mut rows: Vec<Vec<Fp2<Q>>> = Vec::with_capacity(n_eq);
        for g in &self.gens {
            for i in 0..mr {
                for j in 0..mc {
                    let mut row = vec![Fp2::<Q>::zero(); n_mon];
                    for a in 0..mr {
                        for b in 0..mc {
                            row[midx(i, a, b, j)] = g.get(a, b);
                        }
                    }
                    rows.push(row);
                }
            }
        }
        let mat = Mat::from_rows(rows);
        let rank = mat.rank();
        LinResult { mr, mc, k, monomials: n_mon, equations: n_eq, rank, solvable: rank == n_mon }
    }
}

/// Codimension of the rank-`≤r` determinantal variety in `E^{mr×mc}`:
/// `(mr − r)·(mc − r)`. The RST/Leon birthday floor for the cheapest rank drop
/// (`r = min(mr,mc) − 1`) is `|E|^(codim/2)`.
///
/// **The square-vs-rectangular finding:** for a square code `mr = mc = m` the
/// cheapest drop has `codim = 1`, so the collision floor is only `|E|^{1/2}` —
/// silently sub-128-bit regardless of field size. A rectangular code with
/// `mc − mr ≥ 6` lifts that codim to `≥ 7`.
#[inline]
pub fn rank_drop_codim(mr: usize, mc: usize, target_rank: usize) -> usize {
    (mr - target_rank) * (mc - target_rank)
}

/// Frobenius inner product `⟨A,B⟩ = Σ_{i,j} A_{ij}·B_{ij} ∈ E`.
fn frob_inner<const Q: u64>(a: &Mat<Q>, b: &Mat<Q>) -> Fp2<Q> {
    let mut acc = Fp2::<Q>::zero();
    for i in 0..a.nrows() {
        for j in 0..a.ncols() {
            acc = acc.add(a.get(i, j).mul(b.get(i, j)));
        }
    }
    acc
}

/// Hull dimension `dim_E(C ∩ C^⊥)` under the Frobenius form, computed as
/// `k − rank(Gram)` where `Gram[i][j] = ⟨G_i, G_j⟩`. Highway-to-Hull (2025) and
/// CDG attacks exploit a non-trivial hull; a generic random code has hull 0 with
/// probability `≈ 1 − 1/q`. A keygen genericity check should reject `h > 0`.
pub fn hull_dim<const Q: u64>(gens: &[Mat<Q>]) -> usize {
    let k = gens.len();
    let rows: Vec<Vec<Fp2<Q>>> =
        (0..k).map(|i| (0..k).map(|j| frob_inner(&gens[i], &gens[j])).collect()).collect();
    let gram = Mat::from_rows(rows);
    k - gram.rank()
}

/// Exhaustive minimum matrix rank over the `F_p`-spanned sub-code (coefficients
/// in `{0,…,p−1}`, embedded into `E`). Only for tiny `pᵏ` — used to witness the
/// forced-low-rank threshold empirically. Early-exits at rank 1.
pub fn min_rank_in_code_fp<const Q: u64>(gens: &[Mat<Q>], p: u64) -> usize {
    let k = gens.len();
    let (mr, mc) = (gens[0].nrows(), gens[0].ncols());
    let mut idx = vec![0u64; k];
    let mut best = mr.min(mc);
    loop {
        if idx.iter().any(|&x| x != 0) {
            let mut m = Mat::<Q>::zeros(mr, mc);
            for l in 0..k {
                if idx[l] != 0 {
                    m = m.add(&gens[l].scale(Fp2::from_u64(idx[l], 0)));
                }
            }
            let r = m.rank();
            if r < best {
                best = r;
                if best <= 1 {
                    return 1;
                }
            }
        }
        // base-p increment
        let mut c = 0;
        loop {
            idx[c] += 1;
            if idx[c] < p {
                break;
            }
            idx[c] = 0;
            c += 1;
            if c == k {
                return best;
            }
        }
    }
}

/// Outcome of a degree-2 linearization measurement.
#[derive(Debug, Clone, Copy)]
pub struct LinResult {
    pub mr: usize,
    pub mc: usize,
    pub k: usize,
    pub monomials: usize,
    pub equations: usize,
    pub rank: usize,
    pub solvable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::Q_MCE;
    use rand::{rngs::StdRng, SeedableRng};

    // The degree-2 linearization solves MCE iff k ≥ mr·mc (the easy regime).
    // We MEASURE the rank at small sizes and confirm the threshold.
    #[test]
    fn linearization_solves_only_in_the_easy_regime() {
        for &(mr, mc) in &[(2usize, 2usize), (2, 3), (3, 3)] {
            let full = mr * mc; // threshold k
            for k in 1..=full {
                let inst = Instance::<Q_MCE>::generate(mr, mc, k, &[k as u8; 32]);
                let r = inst.linearization_rank();
                // generic rank = min(equations, monomials)
                let expected_rank = r.equations.min(r.monomials);
                assert_eq!(r.rank, expected_rank, "rank mismatch at {mr}x{mc} k={k}");
                if k < full {
                    assert!(!r.solvable, "k={k} < mr*mc={full} must be UNDERdetermined");
                } else {
                    assert!(r.solvable, "k={k} = mr*mc={full} should pin the products");
                }
            }
        }
    }

    // The design regime (k ≪ mr·mc) is firmly underdetermined at degree 2, and
    // is NOT in the easy regime — the two properties M3 must check.
    #[test]
    fn design_regime_is_underdetermined_and_not_easy() {
        // demo: mr=8, mc=9, k=16
        let (mr, mc, k) = (8usize, 9usize, 16usize);
        let def = deficiency(mr, mc, k);
        assert!(def > 0, "demo must be underdetermined at degree 2");
        assert_eq!(def, 5184 - 1152); // mr²mc² − k·mr·mc = 5184 − 1152 = 4032
        // easy-regime ratio k/(mr·mc) must be well below 1
        let ratio = k as f64 / (mr * mc) as f64;
        assert!(ratio < 0.5, "k/(mr·mc) = {ratio:.3} — too close to the easy regime");
    }

    #[test]
    fn brute_force_exponent_is_large() {
        // demo over E, |E| = q² ≈ 2^24 → log2|E| ≈ 24
        let bits = brute_force_bits(8, 9, 24.0);
        assert!(bits > 256.0, "brute-force key search exponent {bits} bits");
    }

    // THE square-vs-rectangular finding: a square code's cheapest rank drop has
    // codim 1 (collision floor |E|^{1/2}, silently weak); the rectangular
    // candidate lifts it to 7 (floor |E|^{7/2} = 2^168 at |E|≈2^48).
    #[test]
    fn rectangular_geometry_lifts_the_collision_codim() {
        // square MEDS-style 14x14: cheapest drop rank 13 → codim 1 (WEAK)
        assert_eq!(rank_drop_codim(14, 14, 13), 1);
        // candidate 22x28: cheapest drop rank 21 → codim 7 (floor 2^{7*48/2}=2^168)
        assert_eq!(rank_drop_codim(22, 28, 21), 7);
        let floor_bits = 7.0 * 48.0 / 2.0;
        assert!(floor_bits >= 128.0, "rank-collision floor {floor_bits} bits");
    }

    // Hull is generically trivial; a keygen check must reject the rare h>0 seeds.
    #[test]
    fn hull_is_generically_trivial() {
        let mut zero_hull = 0;
        for seed in 0u8..16 {
            let mut rng = StdRng::seed_from_u64(0x4855_4c4c_u64.wrapping_add(seed as u64));
            let gens: Vec<_> = (0..8).map(|_| Mat::<Q_MCE>::random(5, 6, &mut rng)).collect();
            if hull_dim(&gens) == 0 {
                zero_hull += 1;
            }
        }
        assert!(zero_hull >= 14, "hull was non-trivial too often ({zero_hull}/16 trivial)");
    }

    // Empirical forced-low-rank threshold: small k → rank-generic (PATCH-3
    // starves MinRank); growing k makes a low-rank codeword appear.
    #[test]
    fn min_rank_drops_as_k_grows() {
        let mut rng = StdRng::seed_from_u64(123);
        let pool: Vec<Mat<Q_MCE>> = (0..7).map(|_| Mat::random(3, 3, &mut rng)).collect();
        // k=1: a single generic 3×3 generator has full rank 3
        let r1 = min_rank_in_code_fp(&pool[..1], 7);
        assert_eq!(r1, 3, "single generator should be full rank");
        // k=7: a 7-dim F_7 sub-code in a 9-dim ambient must contain a low-rank word
        let r7 = min_rank_in_code_fp(&pool[..7], 7);
        assert!(r7 <= 2, "large-k code should contain a rank ≤ 2 word, got {r7}");
    }

    // The M3 candidate parameter set: confirm it is out of the easy regime,
    // underdetermined at degree 2, and meets the entropy floors.
    #[test]
    fn candidate_parameters_pass_structural_checks() {
        let (mr, mc, k, ell) = (22usize, 28usize, 40usize, 8usize);
        // fill ratio well below 1 (not the easy D≈mr·mc regime)
        let fill = k as f64 / (mr * mc) as f64;
        assert!(fill < 0.1, "fill {fill:.3} too high");
        // k = 2ℓ + mask, with mask > 0
        assert!(k > 2 * ell, "need masking coordinates");
        // degree-2 linearization vacuous
        assert!(deficiency(mr, mc, k) > 0);
        // witness Grover floor = ℓ·log2|E| = 8·48 = 384 classical / 192 quantum
        let witness_classical = ell as f64 * 48.0;
        assert!(witness_classical / 2.0 >= 128.0, "witness PQ floor too low");
        // brute force on (S,T) astronomically large
        assert!(brute_force_bits(mr, mc, 48.0) > 1000.0);
    }
}
