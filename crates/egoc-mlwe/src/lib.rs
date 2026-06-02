//! `egoc-mlwe` — SHADOW-SIS-FIX: the conservative BDLOP commitment over
//! module-LWE/MSIS. This is the **provable floor**: hiding ≤ Decision-MLWE and
//! binding = statistical/MSIS, both textbook (BDLOP18, ML-KEM/ML-DSA lineage).
//!
//! Correct BDLOP shape (the fix to the broken SHADOW-SIS):
//! ```text
//!   c1 = A1·r           (binding part)
//!   c2 = A2·r + m       (message added IN THE CLEAR, not multiplied by an inv. matrix)
//!   r short, width l_rand > k_bind + k_msg   ⇒ [A1;A2]·r is a genuine MLWE sample
//! ```
//!
//! Bit-security: the `(N,q,η,…)` set here is a STARTING POINT; a concrete number
//! is published only after a lattice-estimator run (Milestone M1 gate). We do not
//! assert a bit count we have not estimated.
#![forbid(unsafe_code)]

pub mod poly;
pub mod proof;

use blake3::Hasher;
use poly::{Poly, N, Q};

// ---------------------------------------------------------------------------
// XOF-backed deterministic sampling
// ---------------------------------------------------------------------------

struct Xof {
    r: blake3::OutputReader,
}
impl Xof {
    fn new(ctx: &[u8], seed: &[u8]) -> Self {
        let mut h = Hasher::new();
        h.update(ctx);
        h.update(&[0]);
        h.update(seed);
        Self { r: h.finalize_xof() }
    }
    fn byte(&mut self) -> u8 {
        let mut b = [0u8; 1];
        self.r.fill(&mut b);
        b[0]
    }
    pub(crate) fn fill(&mut self, b: &mut [u8]) {
        self.r.fill(b);
    }
    fn u24(&mut self) -> u32 {
        let mut b = [0u8; 3];
        self.r.fill(&mut b);
        (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
    }
}

/// Uniform poly in `R_q` via 23-bit rejection sampling.
pub(crate) fn uniform_poly(x: &mut Xof) -> Poly {
    let mut p = Poly::zero();
    let mut i = 0;
    while i < N {
        let v = x.u24() & 0x7F_FFFF; // 23 bits; q < 2^23
        if (v as u64) < Q {
            p.c[i] = v;
            i += 1;
        }
    }
    p
}

/// Short poly with coefficients uniform in `[−η, η]`, stored in `[0, q)`.
fn short_poly(x: &mut Xof, eta: u32) -> Poly {
    let span = 2 * eta + 1;
    let bound = (256 / span) * span; // largest multiple of `span` ≤ 256
    let mut p = Poly::zero();
    let mut i = 0;
    while i < N {
        let b = x.byte() as u32;
        if b < bound {
            let v = b % span; // 0..2η
            let centered = v as i64 - eta as i64; // −η..η
            p.c[i] = if centered < 0 { (centered + Q as i64) as u32 } else { centered as u32 };
            i += 1;
        }
    }
    p
}

/// Sparse challenge poly: `tau` coefficients are `±1`, the rest `0`.
pub fn challenge_poly(seed: &[u8], tau: usize) -> Poly {
    let mut x = Xof::new(b"egoc-mlwe/challenge/v1", seed);
    let mut p = Poly::zero();
    let mut placed = 0;
    while placed < tau {
        // pick a position via rejection over a power-of-two ≥ N
        let mut pos_bytes = [0u8; 2];
        x.r.fill(&mut pos_bytes);
        let pos = (u16::from_le_bytes(pos_bytes) as usize) & 0x1FF; // 0..511
        if pos >= N || p.c[pos] != 0 {
            continue;
        }
        let sign = x.byte() & 1;
        p.c[pos] = if sign == 0 { 1 } else { (Q - 1) as u32 };
        placed += 1;
    }
    p
}

// ---------------------------------------------------------------------------
// Module vectors / matrices
// ---------------------------------------------------------------------------

/// A length-`len` vector over `R_q`.
pub type Vec_ = Vec<Poly>;

fn matvec(a: &[Vec<Poly>], v: &[Poly]) -> Vec<Poly> {
    a.iter()
        .map(|row| {
            let mut acc = Poly::zero();
            for (aij, vj) in row.iter().zip(v.iter()) {
                acc = acc.add(&aij.mul(vj));
            }
            acc
        })
        .collect()
}

fn vadd(a: &[Poly], b: &[Poly]) -> Vec<Poly> {
    a.iter().zip(b.iter()).map(|(x, y)| x.add(y)).collect()
}

fn vec_eq(a: &[Poly], b: &[Poly]) -> bool {
    // Comparison is over PUBLIC commitment values, so a data-independent path is
    // not required here; the secrets (r, m) are never compared, only recomputed.
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

// ---------------------------------------------------------------------------
// BDLOP commitment
// ---------------------------------------------------------------------------

/// Scheme parameters. Invariant: `l_rand > k_bind + k_msg` (the BDLOP-shape fix).
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub k_bind: usize,
    pub k_msg: usize,
    pub l_rand: usize,
    pub eta: u32,
}

impl Params {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.l_rand <= self.k_bind + self.k_msg {
            return Err("BDLOP-shape requires l_rand > k_bind + k_msg");
        }
        if self.eta == 0 {
            return Err("eta must be > 0");
        }
        Ok(())
    }
    /// Tuned set targeting ~128–160-bit (down from the over-provisioned 2^309
    /// of the original `l_rand=8, k_bind=4`). Core-SVP ballpark (primal-uSVP):
    /// ~168-bit classical / ~152-bit quantum; binding is statistical (λ₁≈2^17 of
    /// the ker(A1) lattice ≫ the ~143 opening-difference norm, since q≈2^23).
    /// **Authoritative number pending a fresh `lattice-estimator` run** on this set
    /// (`research/run_lattice_estimator.py`). vs the old set: proof −33%,
    /// commitment −20%, randomness −37%.
    pub const DEMO: Params = Params { k_bind: 3, k_msg: 1, l_rand: 5, eta: 2 };
}

/// Public commitment key `(A1, A2)`, expanded from a published seed.
#[derive(Clone)]
pub struct CommitKey {
    pub params: Params,
    pub a1: Vec<Vec<Poly>>, // k_bind × l_rand
    pub a2: Vec<Vec<Poly>>, // k_msg  × l_rand
}

impl CommitKey {
    pub fn expand(seed: &[u8; 32], params: Params) -> Self {
        params.validate().expect("invalid params");
        let mut x = Xof::new(b"egoc-mlwe/ck/v1", seed);
        let mk = |x: &mut Xof, rows: usize, cols: usize| -> Vec<Vec<Poly>> {
            (0..rows).map(|_| (0..cols).map(|_| uniform_poly(x)).collect()).collect()
        };
        let a1 = mk(&mut x, params.k_bind, params.l_rand);
        let a2 = mk(&mut x, params.k_msg, params.l_rand);
        Self { params, a1, a2 }
    }
}

/// The public commitment `(c1, c2)`.
#[derive(Clone, Debug)]
pub struct Commitment {
    pub c1: Vec<Poly>, // length k_bind
    pub c2: Vec<Poly>, // length k_msg
}

impl Commitment {
    /// Wire format: `[k_bind: u32][k_msg: u32][c1 polys][c2 polys]`, each poly
    /// `N·4` little-endian bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(8 + (self.c1.len() + self.c2.len()) * N * 4);
        o.extend_from_slice(&(self.c1.len() as u32).to_le_bytes());
        o.extend_from_slice(&(self.c2.len() as u32).to_le_bytes());
        for p in self.c1.iter().chain(self.c2.iter()) {
            o.extend_from_slice(&p.to_bytes());
        }
        o
    }

    /// Inverse of [`Commitment::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() < 8 {
            return None;
        }
        let k1 = u32::from_le_bytes(b[0..4].try_into().ok()?) as usize;
        let k2 = u32::from_le_bytes(b[4..8].try_into().ok()?) as usize;
        if b.len() != 8 + (k1 + k2) * N * 4 {
            return None;
        }
        let mut pos = 8;
        let mut read_polys = |n: usize| -> Vec<Poly> {
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let chunk: [u8; N * 4] = b[pos..pos + N * 4].try_into().unwrap();
                v.push(Poly::from_bytes(&chunk));
                pos += N * 4;
            }
            v
        };
        let c1 = read_polys(k1);
        let c2 = read_polys(k2);
        Some(Commitment { c1, c2 })
    }
}

/// The opening: the short randomness `r` and the message `m`.
#[derive(Clone)]
pub struct Opening {
    pub r: Vec<Poly>, // length l_rand, short
    pub m: Vec<Poly>, // length k_msg
}

/// Sample a fresh short randomness vector from a 32-byte seed.
pub fn sample_randomness(ck: &CommitKey, seed: &[u8; 32]) -> Vec<Poly> {
    let mut x = Xof::new(b"egoc-mlwe/rand/v1", seed);
    (0..ck.params.l_rand).map(|_| short_poly(&mut x, ck.params.eta)).collect()
}

/// Commit to `m` with fresh short randomness drawn from `rng`.
pub fn commit(
    ck: &CommitKey,
    m: Vec<Poly>,
    rng: &mut impl rand_core::RngCore,
) -> (Commitment, Opening) {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let r = sample_randomness(ck, &seed);
    commit_with(ck, m, r)
}

/// Commit to `m` with explicit short randomness `r`.
pub fn commit_with(ck: &CommitKey, m: Vec<Poly>, r: Vec<Poly>) -> (Commitment, Opening) {
    assert_eq!(m.len(), ck.params.k_msg, "message length");
    assert_eq!(r.len(), ck.params.l_rand, "randomness length");
    let c1 = matvec(&ck.a1, &r);
    let c2 = vadd(&matvec(&ck.a2, &r), &m); // + m in the clear
    (Commitment { c1, c2 }, Opening { r, m })
}

/// Verify an opening. Checks the algebra AND that `r` is short (`‖r‖∞ ≤ η`),
/// which is what makes binding rest on MSIS (a short kernel vector is hard).
pub fn verify(ck: &CommitKey, com: &Commitment, op: &Opening) -> Result<(), &'static str> {
    if op.r.len() != ck.params.l_rand || op.m.len() != ck.params.k_msg {
        return Err("opening dimension mismatch");
    }
    for ri in &op.r {
        if ri.norm_inf() > ck.params.eta as u64 {
            return Err("opening randomness is not short — binding requires ‖r‖∞ ≤ η");
        }
    }
    let c1 = matvec(&ck.a1, &op.r);
    let c2 = vadd(&matvec(&ck.a2, &op.r), &op.m);
    if vec_eq(&c1, &com.c1) && vec_eq(&c2, &com.c2) {
        Ok(())
    } else {
        Err("commitment verification failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    fn rand_message(seed: u64, k: usize) -> Vec<Poly> {
        let mut x = Xof::new(b"test/msg", &seed.to_le_bytes());
        (0..k).map(|_| uniform_poly(&mut x)).collect()
    }

    fn fresh_seed(rng: &mut StdRng) -> [u8; 32] {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn params_enforce_bdlop_shape() {
        assert!(Params::DEMO.validate().is_ok());
        let broken = Params { k_bind: 4, k_msg: 1, l_rand: 5, eta: 2 };
        assert!(broken.validate().is_err(), "l_rand <= height must be rejected");
    }

    #[test]
    fn commit_open_roundtrip() {
        let ck = CommitKey::expand(&[1u8; 32], Params::DEMO);
        let mut rng = StdRng::seed_from_u64(1);
        let m = rand_message(7, ck.params.k_msg);
        let r = sample_randomness(&ck, &fresh_seed(&mut rng));
        let (com, op) = commit_with(&ck, m, r);
        assert!(verify(&ck, &com, &op).is_ok());
    }

    #[test]
    fn tampered_message_rejected() {
        let ck = CommitKey::expand(&[1u8; 32], Params::DEMO);
        let mut rng = StdRng::seed_from_u64(2);
        let m = rand_message(8, ck.params.k_msg);
        let r = sample_randomness(&ck, &fresh_seed(&mut rng));
        let (com, mut op) = commit_with(&ck, m, r);
        op.m[0].c[0] = (op.m[0].c[0] + 1) % Q as u32;
        assert!(verify(&ck, &com, &op).is_err());
    }

    #[test]
    fn non_short_randomness_rejected() {
        // Binding hinges on ‖r‖∞ ≤ η. A large-coefficient r must be refused.
        let ck = CommitKey::expand(&[1u8; 32], Params::DEMO);
        let mut rng = StdRng::seed_from_u64(3);
        let m = rand_message(9, ck.params.k_msg);
        let r = sample_randomness(&ck, &fresh_seed(&mut rng));
        let (com, mut op) = commit_with(&ck, m, r);
        op.r[0].c[0] = 1000; // way above eta=2
        assert!(verify(&ck, &com, &op).is_err());
    }

    // === GATE: message is added IN THE CLEAR (the broken-shape fix) ==========
    #[test]
    fn message_added_in_the_clear() {
        // Commit(m; r) − Commit(0; r) must equal (0, m): proves m is NOT mangled
        // by an invertible matrix (the exact defect that broke SHADOW-SIS).
        let ck = CommitKey::expand(&[2u8; 32], Params::DEMO);
        let mut rng = StdRng::seed_from_u64(4);
        let r = sample_randomness(&ck, &fresh_seed(&mut rng));
        let m = rand_message(11, ck.params.k_msg);
        let zero = vec![Poly::zero(); ck.params.k_msg];

        let (cm, _) = commit_with(&ck, m.clone(), r.clone());
        let (c0, _) = commit_with(&ck, zero, r);
        // c1 identical
        assert!(vec_eq(&cm.c1, &c0.c1));
        // c2 differs by exactly m
        for i in 0..ck.params.k_msg {
            assert_eq!(cm.c2[i].sub(&c0.c2[i]), m[i]);
        }
    }

    // === GATE: hiding — m is masked; c2 is not readable without short r ======
    #[test]
    fn message_is_masked_not_readable() {
        let ck = CommitKey::expand(&[3u8; 32], Params::DEMO);
        let mut rng = StdRng::seed_from_u64(5);
        let m = rand_message(13, ck.params.k_msg);

        // For a FIXED message, varying r makes c2 take many values ⇒ c2 alone
        // does not reveal m (the A2·r mask covers the space).
        let mut seen = std::collections::HashSet::new();
        let mut equals_m = 0;
        for _ in 0..200 {
            let r = sample_randomness(&ck, &fresh_seed(&mut rng));
            let (com, _) = commit_with(&ck, m.clone(), r);
            seen.insert(com.c2[0].to_bytes());
            if com.c2[0] == m[0] {
                equals_m += 1;
            }
        }
        assert!(seen.len() > 100, "c2 took only {} values — mask too weak", seen.len());
        assert_eq!(equals_m, 0, "c2 should never equal the plaintext message");
    }

    #[test]
    fn commitment_serialization_roundtrip() {
        let ck = CommitKey::expand(&[1u8; 32], Params::DEMO);
        let mut rng = StdRng::seed_from_u64(11);
        let m = rand_message(7, ck.params.k_msg);
        let r = sample_randomness(&ck, &fresh_seed(&mut rng));
        let (com, op) = commit_with(&ck, m, r);
        let bytes = com.to_bytes();
        let com2 = Commitment::from_bytes(&bytes).expect("deserialize");
        assert_eq!(com2.c1, com.c1);
        assert_eq!(com2.c2, com.c2);
        assert!(verify(&ck, &com2, &op).is_ok(), "verify after round-trip");
        // a truncated buffer must be rejected
        assert!(Commitment::from_bytes(&bytes[..bytes.len() - 1]).is_none());
    }

    #[test]
    fn challenge_is_sparse_ternary() {
        let c = challenge_poly(&[9u8; 32], 39);
        let nonzero = c.c.iter().filter(|&&x| x != 0).count();
        assert_eq!(nonzero, 39);
        for &x in &c.c {
            assert!(x == 0 || x == 1 || x == (Q - 1) as u32, "non-ternary coeff");
        }
    }
}
