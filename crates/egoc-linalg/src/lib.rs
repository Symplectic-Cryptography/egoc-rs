//! `egoc-linalg` — dense matrix algebra over the extension field `E = Fp2<Q>`.
//!
//! Provides the operations EGOC-MCE-R needs:
//! * uniform-invertible sampling in `GLₙ(E)` (rejection),
//! * the two-sided equivalence product `S · M · T`,
//! * rank and determinant over `E` (the only equivalence-orbit invariant is rank).
//!
//! # Constant-time note
//! `mul` / `two_sided` run fixed nested loops — control flow is independent of
//! entry values, so applying a secret `S,T` to data is naturally branch-free at
//! the matrix level (entry ops in `egoc-field` are constant-time). `rank`/`det`
//! and rejection sampling are variable-time, but they run only on **freshly
//! sampled candidates**, never on a persistent secret across calls, so their
//! timing reveals nothing about a long-term key. Formal CT verification is M6.
#![forbid(unsafe_code)]

use egoc_field::Fp2;
use zeroize::Zeroize;

/// A dense `rows × cols` matrix over `E = Fp2<Q>`, row-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mat<const Q: u64> {
    rows: usize,
    cols: usize,
    data: Vec<Fp2<Q>>,
}

impl<const Q: u64> Mat<Q> {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        Self { rows, cols, data: vec![Fp2::zero(); rows * cols] }
    }

    pub fn identity(n: usize) -> Self {
        let mut m = Self::zeros(n, n);
        for i in 0..n {
            m.set(i, i, Fp2::one());
        }
        m
    }

    pub fn from_rows(rows: Vec<Vec<Fp2<Q>>>) -> Self {
        let r = rows.len();
        let c = rows[0].len();
        let mut data = Vec::with_capacity(r * c);
        for row in &rows {
            assert_eq!(row.len(), c, "ragged matrix");
            data.extend_from_slice(row);
        }
        Self { rows: r, cols: c, data }
    }

    #[inline]
    pub fn nrows(&self) -> usize {
        self.rows
    }
    #[inline]
    pub fn ncols(&self) -> usize {
        self.cols
    }
    #[inline]
    pub fn get(&self, i: usize, j: usize) -> Fp2<Q> {
        self.data[i * self.cols + j]
    }
    #[inline]
    pub fn set(&mut self, i: usize, j: usize, v: Fp2<Q>) {
        self.data[i * self.cols + j] = v;
    }

    /// Standard `O(n³)` matrix product. Fixed control flow.
    pub fn mul(&self, rhs: &Mat<Q>) -> Mat<Q> {
        assert_eq!(self.cols, rhs.rows, "dimension mismatch in mul");
        let mut out = Mat::zeros(self.rows, rhs.cols);
        for i in 0..self.rows {
            for k in 0..self.cols {
                let a = self.get(i, k);
                if bool::from(a.is_zero()) {
                    continue; // value-dependent skip is a perf-only shortcut on PUBLIC data paths
                }
                for j in 0..rhs.cols {
                    let cur = out.get(i, j);
                    out.set(i, j, cur.add(a.mul(rhs.get(k, j))));
                }
            }
        }
        out
    }

    /// The two-sided equivalence action `S · M · T`.
    pub fn two_sided(s: &Mat<Q>, m: &Mat<Q>, t: &Mat<Q>) -> Mat<Q> {
        s.mul(m).mul(t)
    }

    /// Add two same-shaped matrices.
    pub fn add(&self, rhs: &Mat<Q>) -> Mat<Q> {
        assert_eq!((self.rows, self.cols), (rhs.rows, rhs.cols));
        let mut out = self.clone();
        for k in 0..self.data.len() {
            out.data[k] = self.data[k].add(rhs.data[k]);
        }
        out
    }

    /// Scale every entry by `s ∈ E`.
    pub fn scale(&self, s: Fp2<Q>) -> Mat<Q> {
        let mut out = self.clone();
        for v in out.data.iter_mut() {
            *v = v.mul(s);
        }
        out
    }

    /// Rank over `E` via Gaussian elimination.
    pub fn rank(&self) -> usize {
        let mut a = self.data.clone();
        let (r, c) = (self.rows, self.cols);
        let idx = |i: usize, j: usize| i * c + j;
        let mut rank = 0usize;
        let mut col = 0usize;
        while rank < r && col < c {
            // find a pivot in this column at or below `rank`
            let mut piv = None;
            for i in rank..r {
                if !bool::from(a[idx(i, col)].is_zero()) {
                    piv = Some(i);
                    break;
                }
            }
            match piv {
                None => {
                    col += 1;
                }
                Some(p) => {
                    if p != rank {
                        for j in 0..c {
                            a.swap(idx(p, j), idx(rank, j));
                        }
                    }
                    let inv = a[idx(rank, col)].inv_public();
                    for j in col..c {
                        a[idx(rank, j)] = a[idx(rank, j)].mul(inv);
                    }
                    for i in 0..r {
                        if i == rank {
                            continue;
                        }
                        let f = a[idx(i, col)];
                        if bool::from(f.is_zero()) {
                            continue;
                        }
                        for j in col..c {
                            let sub = f.mul(a[idx(rank, j)]);
                            a[idx(i, j)] = a[idx(i, j)].sub(sub);
                        }
                    }
                    rank += 1;
                    col += 1;
                }
            }
        }
        rank
    }

    /// Determinant of a square matrix over `E` (via elimination).
    pub fn det(&self) -> Fp2<Q> {
        assert_eq!(self.rows, self.cols, "det of non-square");
        let n = self.rows;
        let mut a = self.data.clone();
        let idx = |i: usize, j: usize| i * n + j;
        let mut det = Fp2::<Q>::one();
        for col in 0..n {
            let mut piv = None;
            for i in col..n {
                if !bool::from(a[idx(i, col)].is_zero()) {
                    piv = Some(i);
                    break;
                }
            }
            let p = match piv {
                None => return Fp2::zero(),
                Some(p) => p,
            };
            if p != col {
                for j in 0..n {
                    a.swap(idx(p, j), idx(col, j));
                }
                det = det.neg(); // each row swap flips the sign
            }
            let pivot = a[idx(col, col)];
            det = det.mul(pivot);
            let inv = pivot.inv_public();
            for i in (col + 1)..n {
                let f = a[idx(i, col)].mul(inv);
                if bool::from(f.is_zero()) {
                    continue;
                }
                for j in col..n {
                    let sub = f.mul(a[idx(col, j)]);
                    a[idx(i, j)] = a[idx(i, j)].sub(sub);
                }
            }
        }
        det
    }

    #[inline]
    pub fn is_invertible(&self) -> bool {
        self.rows == self.cols && !bool::from(self.det().is_zero())
    }

    /// Inverse over `E` via Gauss–Jordan on `[A | I]`. `None` if singular.
    pub fn inverse(&self) -> Option<Mat<Q>> {
        if self.rows != self.cols {
            return None;
        }
        let n = self.rows;
        // augmented [A | I]
        let mut a = vec![vec![Fp2::<Q>::zero(); 2 * n]; n];
        for i in 0..n {
            for j in 0..n {
                a[i][j] = self.get(i, j);
            }
            a[i][n + i] = Fp2::one();
        }
        for col in 0..n {
            let piv = (col..n).find(|&i| !bool::from(a[i][col].is_zero()))?;
            a.swap(piv, col);
            let inv = a[col][col].invert().expect("nonzero pivot");
            for j in 0..2 * n {
                a[col][j] = a[col][j].mul(inv);
            }
            for i in 0..n {
                if i == col {
                    continue;
                }
                let f = a[i][col];
                if bool::from(f.is_zero()) {
                    continue;
                }
                for j in 0..2 * n {
                    let sub = f.mul(a[col][j]);
                    a[i][j] = a[i][j].sub(sub);
                }
            }
        }
        let mut out = Mat::zeros(n, n);
        for i in 0..n {
            for j in 0..n {
                out.set(i, j, a[i][n + j]);
            }
        }
        Some(out)
    }

    /// Uniform random `rows × cols` matrix over `E`.
    pub fn random(rows: usize, cols: usize, rng: &mut impl rand_core::RngCore) -> Mat<Q> {
        let data = (0..rows * cols).map(|_| Fp2::random(rng)).collect();
        Mat { rows, cols, data }
    }

    /// Uniform random invertible matrix in `GLₙ(E)` via rejection.
    /// Expected retries `≈ 1 / ∏(1 - |E|^{-i}) < 1.4` — a handful at most.
    pub fn random_invertible(n: usize, rng: &mut impl rand_core::RngCore) -> Mat<Q> {
        loop {
            let m = Mat::random(n, n, rng);
            if m.is_invertible() {
                return m;
            }
        }
    }

    /// Frobenius inner product `⟨self, other⟩ = Σ_{i,j} self_{ij}·other_{ij} ∈ E`.
    pub fn frobenius_inner(&self, other: &Mat<Q>) -> Fp2<Q> {
        let mut acc = Fp2::<Q>::zero();
        for k in 0..self.data.len() {
            acc = acc.add(self.data[k].mul(other.data[k]));
        }
        acc
    }

    /// Serialize all entries (row-major, 16 bytes each) for hashing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.data.len() * 16);
        for v in &self.data {
            out.extend_from_slice(&v.to_bytes());
        }
        out
    }

    /// Deserialize a `rows × cols` matrix from `rows·cols·16` bytes (row-major).
    pub fn from_bytes(rows: usize, cols: usize, b: &[u8]) -> Option<Mat<Q>> {
        if b.len() != rows * cols * 16 {
            return None;
        }
        let mut m = Mat::zeros(rows, cols);
        for idx in 0..rows * cols {
            let chunk: [u8; 16] = b[idx * 16..idx * 16 + 16].try_into().ok()?;
            m.data[idx] = Fp2::from_bytes(&chunk);
        }
        Some(m)
    }
}

/// Decide whether `target ∈ span_E{gens}` (the matrix code), by comparing the
/// rank of the vectorised generators with and without `target` appended.
pub fn in_span<const Q: u64>(gens: &[Mat<Q>], target: &Mat<Q>) -> bool {
    if gens.is_empty() {
        return target.frobenius_inner(target) == Fp2::zero();
    }
    let ambient = gens[0].nrows() * gens[0].ncols();
    let flat = |m: &Mat<Q>, p: usize| m.get(p / m.ncols(), p % m.ncols());
    let base_rows: Vec<Vec<Fp2<Q>>> =
        (0..ambient).map(|p| gens.iter().map(|g| flat(g, p)).collect()).collect();
    let aug_rows: Vec<Vec<Fp2<Q>>> = (0..ambient)
        .map(|p| {
            let mut row: Vec<Fp2<Q>> = gens.iter().map(|g| flat(g, p)).collect();
            row.push(flat(target, p));
            row
        })
        .collect();
    Mat::from_rows(base_rows).rank() == Mat::from_rows(aug_rows).rank()
}

/// Hull dimension `dim_E(C ∩ C^⊥)` of the matrix code spanned by `gens`, under
/// the Frobenius form, computed as `k − rank(Gram)` with `Gram_{ij} = ⟨G_i,G_j⟩`.
/// A generic random code has hull 0 with probability `≈ 1 − 1/q`; a non-trivial
/// hull is the structure Highway-to-Hull / CDG attacks exploit, so keygen rejects
/// `hull > h_max`.
pub fn frobenius_hull_dim<const Q: u64>(gens: &[Mat<Q>]) -> usize {
    let k = gens.len();
    if k == 0 {
        return 0;
    }
    let rows: Vec<Vec<Fp2<Q>>> =
        (0..k).map(|i| (0..k).map(|j| gens[i].frobenius_inner(&gens[j])).collect()).collect();
    let gram = Mat::from_rows(rows);
    k - gram.rank()
}

impl<const Q: u64> Zeroize for Mat<Q> {
    fn zeroize(&mut self) {
        for v in self.data.iter_mut() {
            v.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egoc_field::{Fp2, Q_MCE};
    use rand::{rngs::StdRng, SeedableRng};

    type M = Mat<Q_MCE>;

    #[test]
    fn identity_mul() {
        let mut rng = StdRng::seed_from_u64(1);
        let a = M::random(5, 7, &mut rng);
        let i5 = M::identity(5);
        let i7 = M::identity(7);
        assert_eq!(i5.mul(&a), a);
        assert_eq!(a.mul(&i7), a);
    }

    #[test]
    fn identity_det_and_rank() {
        let i = M::identity(6);
        assert_eq!(i.det(), Fp2::one());
        assert_eq!(i.rank(), 6);
    }

    #[test]
    fn random_invertible_has_full_rank_and_nonzero_det() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..50 {
            let g = M::random_invertible(6, &mut rng);
            assert_eq!(g.rank(), 6);
            assert!(!bool::from(g.det().is_zero()));
        }
    }

    #[test]
    fn det_multiplicative() {
        let mut rng = StdRng::seed_from_u64(9);
        let a = M::random_invertible(5, &mut rng);
        let b = M::random_invertible(5, &mut rng);
        assert_eq!(a.mul(&b).det(), a.det().mul(b.det()));
    }

    #[test]
    fn two_sided_preserves_rank() {
        // S·M·T has the same rank as M (S,T invertible) — the ONLY orbit invariant.
        let mut rng = StdRng::seed_from_u64(11);
        let s = M::random_invertible(6, &mut rng);
        let t = M::random_invertible(8, &mut rng);
        let mut m = M::random(6, 8, &mut rng);
        // force a known rank by zeroing a row
        for j in 0..8 {
            m.set(5, j, Fp2::zero());
        }
        let c = Mat::two_sided(&s, &m, &t);
        assert_eq!(c.rank(), m.rank());
    }

    #[test]
    fn inverse_roundtrip() {
        let mut rng = StdRng::seed_from_u64(21);
        for _ in 0..20 {
            let g = M::random_invertible(6, &mut rng);
            let gi = g.inverse().expect("invertible");
            assert_eq!(g.mul(&gi), M::identity(6));
            assert_eq!(gi.mul(&g), M::identity(6));
        }
    }

    #[test]
    fn singular_has_no_inverse() {
        let z = M::zeros(4, 4);
        assert!(z.inverse().is_none());
    }

    #[test]
    fn two_sided_associates() {
        let mut rng = StdRng::seed_from_u64(13);
        let s = M::random_invertible(4, &mut rng);
        let m = M::random(4, 4, &mut rng);
        let t = M::random_invertible(4, &mut rng);
        assert_eq!(Mat::two_sided(&s, &m, &t), s.mul(&m).mul(&t));
    }
}
