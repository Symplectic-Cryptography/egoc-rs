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
/// silently sub-128-bit regardless of field size. The rectangular candidate with
/// `mc − mr = 9` lifts that codim to `10` (floor `|E|^{10/2} = 2²⁴⁰`).
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

/// Basis of the right null space `{φ ∈ E^ncols : rows·φ = 0}`, via reduced row
/// echelon form. Each free column yields one basis vector. Used to build the
/// annihilator of a code (the functionals that vanish on `span{Gₗ}`).
fn right_null_space<const Q: u64>(rows: &[Vec<Fp2<Q>>], ncols: usize) -> Vec<Vec<Fp2<Q>>> {
    let nrows = rows.len();
    let mut m: Vec<Vec<Fp2<Q>>> = rows.to_vec();
    let mut pivot_col_of_row = vec![usize::MAX; nrows];
    let mut is_pivot_col = vec![false; ncols];
    let mut r = 0usize;
    for c in 0..ncols {
        if r >= nrows {
            break;
        }
        // find a pivot in column c at or below row r
        let mut piv = None;
        for (i, row) in m.iter().enumerate().take(nrows).skip(r) {
            if !bool::from(row[c].is_zero()) {
                piv = Some(i);
                break;
            }
        }
        let piv = match piv {
            Some(p) => p,
            None => continue,
        };
        m.swap(r, piv);
        // normalize pivot row so m[r][c] == 1
        let inv = m[r][c].inv_public();
        for j in 0..ncols {
            m[r][j] = m[r][j].mul(inv);
        }
        // clear column c in every other row (reduced echelon)
        for i in 0..nrows {
            if i != r && !bool::from(m[i][c].is_zero()) {
                let f = m[i][c];
                for j in 0..ncols {
                    m[i][j] = m[i][j].sub(f.mul(m[r][j]));
                }
            }
        }
        pivot_col_of_row[r] = c;
        is_pivot_col[c] = true;
        r += 1;
    }
    let mut basis = Vec::new();
    for free in 0..ncols {
        if is_pivot_col[free] {
            continue;
        }
        let mut v = vec![Fp2::<Q>::zero(); ncols];
        v[free] = Fp2::one();
        for (row, &pc) in pivot_col_of_row.iter().enumerate().take(r) {
            v[pc] = m[row][free].neg();
        }
        basis.push(v);
    }
    basis
}

/// `E`-dimension of the stabilizer Lie algebra of the code `C₀ = span{Gₗ}` under
/// the two-sided action, i.e. of
/// `{(X, Y) ∈ gl_mr(E) × gl_mc(E) : X·Gₗ + Gₗ·Y ∈ C₀ for all l}`.
///
/// The scalar gauge `{(aI, bI)}` is always a 2-dimensional solution
/// (`a·Gₗ + Gₗ·b = (a+b)·Gₗ ∈ C₀`), so the generic value is `2`. A larger value
/// signals a special-orbit symmetry of the kind the 2024/337 attack exploits;
/// [`non_scalar_excess`] reports the surplus over the scalar gauge.
///
/// Implementation: build the annihilator `{φ : ⟨φ, Gₗ⟩ = 0 ∀l}` (the right null
/// space of the vectorized generators), then require `⟨φ, X·Gₗ + Gₗ·Y⟩ = 0` for
/// every annihilator functional `φ` and every `l`, and return
/// `(mr² + mc²) − rank` of that linear system in the entries of `X, Y`.
pub fn stabilizer_lie_dim<const Q: u64>(gens: &[Mat<Q>]) -> usize {
    let k = gens.len();
    let mr = gens[0].nrows();
    let mc = gens[0].ncols();
    let n = mr * mc;
    let u = mr * mr + mc * mc;

    // annihilator basis: φ ∈ E^{mr·mc} (indexed φ[i·mc + j]) vanishing on the code
    let vec_rows: Vec<Vec<Fp2<Q>>> = gens
        .iter()
        .map(|g| {
            let mut v = Vec::with_capacity(n);
            for i in 0..mr {
                for j in 0..mc {
                    v.push(g.get(i, j));
                }
            }
            v
        })
        .collect();
    let annih = right_null_space(&vec_rows, n);
    if annih.is_empty() {
        // C₀ is the whole ambient: every (X, Y) stabilizes it.
        return u;
    }

    // unknown layout: X[i][a] at i·mr + a ; Y[b][j] at mr² + b·mc + j
    let xidx = |i: usize, a: usize| i * mr + a;
    let yidx = |b: usize, j: usize| mr * mr + b * mc + j;

    let mut eqs: Vec<Vec<Fp2<Q>>> = Vec::with_capacity(k * annih.len());
    for g in gens {
        for phi in &annih {
            let mut row = vec![Fp2::<Q>::zero(); u];
            // ⟨φ, X·Gₗ⟩ : coeff of X[i][a] is Σ_j φ[i,j]·Gₗ[a,j]
            for i in 0..mr {
                for a in 0..mr {
                    let mut acc = Fp2::<Q>::zero();
                    for j in 0..mc {
                        acc = acc.add(phi[i * mc + j].mul(g.get(a, j)));
                    }
                    row[xidx(i, a)] = acc;
                }
            }
            // ⟨φ, Gₗ·Y⟩ : coeff of Y[b][j] is Σ_i φ[i,j]·Gₗ[i,b]
            for b in 0..mc {
                for j in 0..mc {
                    let mut acc = Fp2::<Q>::zero();
                    for i in 0..mr {
                        acc = acc.add(phi[i * mc + j].mul(g.get(i, b)));
                    }
                    row[yidx(b, j)] = acc;
                }
            }
            eqs.push(row);
        }
    }
    let mat = Mat::from_rows(eqs);
    u - mat.rank()
}

/// Surplus of the stabilizer over the scalar gauge `{(aI, bI)}`. `0` means the
/// code has no special-orbit symmetry (the safe, generic case, and the property
/// PROOFS.md Lemma 9 (iii) asserts for EGOC-MCE-R).
#[inline]
pub fn non_scalar_excess<const Q: u64>(gens: &[Mat<Q>]) -> usize {
    stabilizer_lie_dim(gens).saturating_sub(2)
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
    use egoc_field::{Fp, Q_MCE};
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
    // candidate 22x31 lifts it to 10 (floor |E|^{10/2} = 2^240 at |E|≈2^48).
    #[test]
    fn rectangular_geometry_lifts_the_collision_codim() {
        // square MEDS-style 14x14: cheapest drop rank 13 → codim 1 (WEAK)
        assert_eq!(rank_drop_codim(14, 14, 13), 1);
        // candidate 22x31: cheapest drop rank 21 → codim 10 (floor 2^{10*48/2}=2^240)
        assert_eq!(rank_drop_codim(22, 31, 21), 10);
        let floor_bits = 10.0 * 48.0 / 2.0;
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
        let (mr, mc, k, ell) = (22usize, 31usize, 46usize, 8usize);
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

    // PROOFS.md Lemma 9 (iii): a generic rectangular code has stabilizer Lie
    // algebra equal to the scalar gauge {(aI,bI)} only — non-scalar excess 0.
    // This is the property whose absence breaks the 2024/337-style schemes.
    #[test]
    fn stabilizer_is_scalar_gauge_only() {
        for &(mr, mc, k, seed) in &[(6usize, 9usize, 12usize, 1u8), (8, 9, 16, 2)] {
            let mut rng = XofRng::new(b"egoc-attack/stab/v1", &[seed; 32]);
            let gens: Vec<Mat<Q_MCE>> = (0..k).map(|_| Mat::random(mr, mc, &mut rng)).collect();
            let dim = stabilizer_lie_dim(&gens);
            assert_eq!(dim, 2, "stabilizer dim at {mr}x{mc} k={k} = {dim} (expected scalar gauge 2)");
            assert_eq!(non_scalar_excess(&gens), 0);
        }
    }

    // Correctness guard for the stabilizer machinery: when the code is the WHOLE
    // ambient (k = mr·mc, generators = the standard basis), every (X,Y) stabilizes
    // it, so the dimension is exactly mr² + mc² (exercises the empty-annihilator
    // path). If this and the generic-case test both hold, a spurious "dim = 2" from
    // a construction bug is ruled out.
    #[test]
    fn stabilizer_full_ambient_code_is_everything() {
        let (mr, mc) = (2usize, 3usize);
        let mut gens = Vec::new();
        for i in 0..mr {
            for j in 0..mc {
                let mut g = Mat::<Q_MCE>::zeros(mr, mc);
                g.set(i, j, Fp2::one());
                gens.push(g);
            }
        }
        assert_eq!(stabilizer_lie_dim(&gens), mr * mr + mc * mc);
    }

    // PROOFS.md Lemma 9 (iii) at the EXACT candidate shape (22×31, k=46) over the
    // L1 field. Heavy (≈26k×1445 system); ignored by default, run with
    // `cargo test -p egoc-attack --release -- --ignored`.
    #[test]
    #[ignore]
    fn stabilizer_is_scalar_gauge_only_candidate_shape() {
        use egoc_field::Q_MCE_L1;
        let (mr, mc, k) = (22usize, 31usize, 46usize);
        let mut rng = XofRng::new(b"egoc-attack/stab-l1/v1", &[7u8; 32]);
        let gens: Vec<Mat<Q_MCE_L1>> = (0..k).map(|_| Mat::random(mr, mc, &mut rng)).collect();
        assert_eq!(stabilizer_lie_dim(&gens), 2);
    }

    // PROOFS.md Lemma 9 (iv): the commitment image M = Σ c_l G_l (first 2ℓ coords
    // on the F_q-subline, the rest uniform over E) is full rank with overwhelming
    // probability, so the opening proof's full-rank-orbit hypothesis holds.
    #[test]
    fn commitment_image_is_full_rank() {
        for &(mr, mc, k, ell, seed) in &[(6usize, 9usize, 12usize, 2usize, 3u8), (8, 9, 16, 4, 4)] {
            let mut rng = XofRng::new(b"egoc-attack/fullrank/v1", &[seed; 32]);
            let gens: Vec<Mat<Q_MCE>> = (0..k).map(|_| Mat::random(mr, mc, &mut rng)).collect();
            let trials = 200;
            let target = mr.min(mc);
            for _ in 0..trials {
                let mut m = Mat::<Q_MCE>::zeros(mr, mc);
                for (l, g) in gens.iter().enumerate() {
                    let c = if l < 2 * ell {
                        Fp2::new(Fp::random(&mut rng), Fp::zero()) // witness coord on F_q-subline
                    } else {
                        Fp2::random(&mut rng) // uniform mask over E
                    };
                    m = m.add(&g.scale(c));
                }
                assert_eq!(m.rank(), target, "commitment image not full rank at {mr}x{mc}");
            }
        }
    }

    // PROOFS.md Lemma 9 (ii): corank-1 codewords exist (the determinantal variety
    // meets the code, cod < k) but form a huge generic family, so they are not the
    // rigid anchor set the 2024/337 recovery needs.
    #[test]
    fn corank_one_codewords_exist_but_do_not_anchor() {
        let (mr, mc, k) = (22usize, 31usize, 46usize);
        let cod = rank_drop_codim(mr, mc, mr - 1);
        assert_eq!(cod, 10);
        // cod < k ⇒ {rank ≤ mr−1} variety meets the k-dim code ⇒ corank-1 words exist
        assert!(cod < k, "corank-1 variety must meet the code for existence");
        // abundance ≈ |E|^{k−1−cod}: a non-anchoring family, not a rigid point set
        let log2_e = 48.0;
        let family_bits = (k as f64 - 1.0 - cod as f64) * log2_e;
        assert!(family_bits > 1000.0, "corank-1 family {family_bits} bits — too small to be generic");
    }
}
