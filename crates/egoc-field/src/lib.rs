//! `egoc-field` — in-house finite-field arithmetic for egoc-rs.
//!
//! Two layers, both `#![forbid(unsafe_code)]`:
//!
//! * [`Fp<Q>`] — the prime field `F_q`, `Q` a compile-time prime constant.
//! * [`Fp2<Q>`] — the quadratic extension `E = F_q[t]/(t² + 1)`.
//!
//! # Why `q ≡ 3 (mod 4)`
//! The extension polynomial `t² + 1` is irreducible over `F_q` **iff `-1` is a
//! non-residue, i.e. iff `q ≡ 3 (mod 4)`**. Then the norm form `N(a + b·t) =
//! a² + b²` is *anisotropic*: `a² + b² = 0 ⇒ a = b = 0`. This kills the
//! `q = 257 ≡ 1 (mod 4)` pathology of the predecessor, where `t² + 1` split,
//! `m² + r² = 0` had nontrivial solutions, and blocks could be singular.
//! The constraint is enforced at compile time (see [`Fp2::new`]).
//!
//! All secret-touching comparisons go through `subtle`. Modular inverse uses
//! Fermat's little theorem (`a^(q-2)`) with a fixed-iteration ladder so the
//! loop count is independent of the secret input.
#![forbid(unsafe_code)]

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Compile-time guard: F_q[t]/(t²+1) needs q ≡ 3 (mod 4).
// ---------------------------------------------------------------------------

struct Guard<const Q: u64>;
impl<const Q: u64> Guard<Q> {
    /// Forces a monomorphization-time error if `Q ≢ 3 (mod 4)`.
    const Q_IS_3_MOD_4: () =
        assert!(Q % 4 == 3, "E = F_q[t]/(t^2+1) requires a prime q ≡ 3 (mod 4)");
}

// ---------------------------------------------------------------------------
// Fp<Q> — prime field F_q
// ---------------------------------------------------------------------------

/// An element of `F_q = Z/qZ`, with `Q` a compile-time prime constant.
#[derive(Clone, Copy, Debug, Default, Zeroize)]
pub struct Fp<const Q: u64> {
    v: u64,
}

impl<const Q: u64> Fp<Q> {
    /// Reduce a raw value mod `Q`.
    #[inline]
    pub fn new(v: u64) -> Self {
        Self { v: v % Q }
    }
    #[inline]
    pub fn zero() -> Self {
        Self { v: 0 }
    }
    #[inline]
    pub fn one() -> Self {
        Self { v: 1 }
    }
    #[inline]
    pub fn val(self) -> u64 {
        self.v
    }
    #[inline]
    pub const fn modulus() -> u64 {
        Q
    }

    #[inline]
    pub fn add(self, o: Self) -> Self {
        Self { v: (self.v + o.v) % Q }
    }
    #[inline]
    pub fn sub(self, o: Self) -> Self {
        Self { v: (self.v + Q - o.v) % Q }
    }
    #[inline]
    pub fn mul(self, o: Self) -> Self {
        Self { v: ((self.v as u128 * o.v as u128) % Q as u128) as u64 }
    }
    #[inline]
    pub fn neg(self) -> Self {
        Self { v: if self.v == 0 { 0 } else { Q - self.v } }
    }

    /// `self^(q-2) mod q` — the inverse for nonzero, `none` for zero.
    /// Constant number of iterations in the secret `self`.
    pub fn invert(self) -> CtOption<Self> {
        let is_zero = self.ct_eq(&Self::zero());
        let inv = ct_pow(self.v, Q - 2, Q);
        CtOption::new(Self { v: inv }, !is_zero)
    }

    /// Inverse for a value known to be public/nonzero (panics on zero).
    #[inline]
    pub fn inv_public(self) -> Self {
        self.invert().expect("inverse of zero")
    }

    #[inline]
    pub fn is_zero(self) -> Choice {
        self.ct_eq(&Self::zero())
    }

    /// Uniform sample over `F_q` via 128-bit reduction (bias < 2^-64).
    pub fn random(rng: &mut impl rand_core::RngCore) -> Self {
        let hi = rng.next_u64() as u128;
        let lo = rng.next_u64() as u128;
        Self { v: (((hi << 64) | lo) % Q as u128) as u64 }
    }
}

impl<const Q: u64> ConstantTimeEq for Fp<Q> {
    fn ct_eq(&self, o: &Self) -> Choice {
        self.v.ct_eq(&o.v)
    }
}
impl<const Q: u64> ConditionallySelectable for Fp<Q> {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self { v: u64::conditional_select(&a.v, &b.v, c) }
    }
}
impl<const Q: u64> PartialEq for Fp<Q> {
    fn eq(&self, o: &Self) -> bool {
        bool::from(self.ct_eq(o))
    }
}
impl<const Q: u64> Eq for Fp<Q> {}

/// Constant-time `base^exp mod m`, fixed 64-iteration square-and-multiply.
/// `exp` must be public (here always `q-2`).
#[inline]
pub fn ct_pow(base: u64, exp: u64, m: u64) -> u64 {
    let mut result: u128 = 1;
    let mut b: u128 = base as u128 % m as u128;
    let mut e = exp;
    for _ in 0..64 {
        let mask = (e & 1).wrapping_neg() as u128; // 0 or all-ones (low 64 bits)
        let cand = (result * b) % m as u128;
        result = (cand & mask) | (result & !mask);
        b = (b * b) % m as u128;
        e >>= 1;
    }
    result as u64
}

// ---------------------------------------------------------------------------
// Fp2<Q> — extension E = F_q[t]/(t²+1), element  c0 + c1·t,  t² = -1
// ---------------------------------------------------------------------------

/// An element `c0 + c1·t` of `E = F_q[t]/(t² + 1)`.
#[derive(Clone, Copy, Debug, Default, Zeroize)]
pub struct Fp2<const Q: u64> {
    pub c0: Fp<Q>,
    pub c1: Fp<Q>,
}

impl<const Q: u64> Fp2<Q> {
    /// Construct `c0 + c1·t`. Touching this type forces the `q ≡ 3 (mod 4)` guard.
    #[inline]
    pub fn new(c0: Fp<Q>, c1: Fp<Q>) -> Self {
        let _ = Guard::<Q>::Q_IS_3_MOD_4;
        Self { c0, c1 }
    }
    #[inline]
    pub fn from_u64(c0: u64, c1: u64) -> Self {
        Self::new(Fp::new(c0), Fp::new(c1))
    }
    #[inline]
    pub fn zero() -> Self {
        Self::new(Fp::zero(), Fp::zero())
    }
    #[inline]
    pub fn one() -> Self {
        Self::new(Fp::one(), Fp::zero())
    }
    /// The generator `t` (a square root of `-1`).
    #[inline]
    pub fn t() -> Self {
        Self::new(Fp::zero(), Fp::one())
    }

    #[inline]
    pub fn add(self, o: Self) -> Self {
        Self::new(self.c0.add(o.c0), self.c1.add(o.c1))
    }
    #[inline]
    pub fn sub(self, o: Self) -> Self {
        Self::new(self.c0.sub(o.c0), self.c1.sub(o.c1))
    }
    #[inline]
    pub fn neg(self) -> Self {
        Self::new(self.c0.neg(), self.c1.neg())
    }

    /// `(a+bt)(c+dt) = (ac - bd) + (ad + bc)·t`  (since `t² = -1`).
    #[inline]
    pub fn mul(self, o: Self) -> Self {
        let ac = self.c0.mul(o.c0);
        let bd = self.c1.mul(o.c1);
        let ad = self.c0.mul(o.c1);
        let bc = self.c1.mul(o.c0);
        Self::new(ac.sub(bd), ad.add(bc))
    }

    /// Conjugate `a + bt ↦ a - bt`.
    #[inline]
    pub fn conj(self) -> Self {
        Self::new(self.c0, self.c1.neg())
    }

    /// Field norm `N(a+bt) = (a+bt)(a-bt) = a² + b² ∈ F_q`.
    /// Anisotropic for `q ≡ 3 (mod 4)`: zero only at the origin.
    #[inline]
    pub fn norm(self) -> Fp<Q> {
        self.c0.mul(self.c0).add(self.c1.mul(self.c1))
    }

    /// Multiplicative inverse: `conj(x) / N(x)`. `none` iff `x = 0`.
    pub fn invert(self) -> CtOption<Self> {
        let n = self.norm();
        n.invert().map(|ninv| {
            let conj = self.conj();
            Self::new(conj.c0.mul(ninv), conj.c1.mul(ninv))
        })
    }

    #[inline]
    pub fn inv_public(self) -> Self {
        self.invert().expect("inverse of zero in E")
    }

    #[inline]
    pub fn is_zero(self) -> Choice {
        self.c0.is_zero() & self.c1.is_zero()
    }

    pub fn random(rng: &mut impl rand_core::RngCore) -> Self {
        Self::new(Fp::random(rng), Fp::random(rng))
    }

    /// Encode to 16 little-endian bytes (`c0` then `c1`) for hashing/wire.
    #[inline]
    pub fn to_bytes(self) -> [u8; 16] {
        let mut o = [0u8; 16];
        o[0..8].copy_from_slice(&self.c0.val().to_le_bytes());
        o[8..16].copy_from_slice(&self.c1.val().to_le_bytes());
        o
    }

    /// Decode from 16 little-endian bytes; reduces each coordinate mod `Q`.
    #[inline]
    pub fn from_bytes(b: &[u8; 16]) -> Self {
        let c0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let c1 = u64::from_le_bytes(b[8..16].try_into().unwrap());
        Self::new(Fp::new(c0), Fp::new(c1))
    }
}

impl<const Q: u64> ConstantTimeEq for Fp2<Q> {
    fn ct_eq(&self, o: &Self) -> Choice {
        self.c0.ct_eq(&o.c0) & self.c1.ct_eq(&o.c1)
    }
}
impl<const Q: u64> ConditionallySelectable for Fp2<Q> {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self::new(
            Fp::conditional_select(&a.c0, &b.c0, c),
            Fp::conditional_select(&a.c1, &b.c1, c),
        )
    }
}
impl<const Q: u64> PartialEq for Fp2<Q> {
    fn eq(&self, o: &Self) -> bool {
        bool::from(self.ct_eq(o))
    }
}
impl<const Q: u64> Eq for Fp2<Q> {}

// ---------------------------------------------------------------------------
// Parameter constants
// ---------------------------------------------------------------------------

/// Demo/structural MCE base prime: `4099 = 2¹² + 3`, prime, `≡ 3 (mod 4)`.
/// Small enough for the exhaustive anisotropy test; NOT security-calibrated.
pub const Q_MCE: u64 = 4099;

/// M3 candidate Level-1 base prime: `16777259 = 2²⁴ + 43`, prime, `≡ 3 (mod 4)`.
/// Gives `|E| = q² ≈ 2⁴⁸`, the field size the M3 calibration selected so that
/// the rectangular-code rank-collision floors land `≥ 2¹⁶⁸`. Bit-security of the
/// MCE instance remains a TARGET pending an independent estimator run (see
/// `docs/CRYPTANALYSIS.md`); this constant only fixes the field.
pub const Q_MCE_L1: u64 = 16_777_259;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    type F = Fp<Q_MCE>;
    type E = Fp2<Q_MCE>;

    fn is_prime(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        let mut i = 2;
        while i * i <= n {
            if n % i == 0 {
                return false;
            }
            i += 1;
        }
        true
    }

    #[test]
    fn q_is_prime_and_3_mod_4() {
        assert!(is_prime(Q_MCE), "Q_MCE must be prime");
        assert_eq!(Q_MCE % 4, 3, "Q_MCE must be ≡ 3 (mod 4)");
    }

    #[test]
    fn candidate_l1_prime_is_valid() {
        assert!(is_prime(Q_MCE_L1), "Q_MCE_L1 must be prime");
        assert_eq!(Q_MCE_L1 % 4, 3, "Q_MCE_L1 must be ≡ 3 (mod 4)");
        assert!(Q_MCE_L1 >= 1 << 24, "Q_MCE_L1 must give |E| ≈ 2^48");
        // spot-check anisotropy on random nonzero pairs (full sweep is infeasible at this q)
        type E1 = Fp2<Q_MCE_L1>;
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..10_000 {
            let a = next() % Q_MCE_L1;
            let b = next() % Q_MCE_L1;
            if a == 0 && b == 0 {
                continue;
            }
            let x = E1::from_u64(a, b);
            assert!(!bool::from(x.norm().is_zero()), "norm zero off-origin at ({a},{b})");
        }
    }

    #[test]
    fn fp_inverse() {
        for a in 1..50u64 {
            let x = F::new(a);
            assert_eq!(x.mul(x.invert().unwrap()), F::one());
        }
        assert!(bool::from(F::zero().invert().is_none()));
    }

    #[test]
    fn fp_neg_add_zero() {
        let a = F::new(1234);
        assert_eq!(a.add(a.neg()), F::zero());
    }

    #[test]
    fn ext_irreducible_norm_anisotropic() {
        // For q ≡ 3 mod 4 there is NO nonzero (a,b) with a²+b² ≡ 0.
        // Exhaustive check over the whole field — cheap at q=4099.
        for a in 0..Q_MCE {
            for b in 0..Q_MCE {
                if a == 0 && b == 0 {
                    continue;
                }
                let n = F::new(a).mul(F::new(a)).add(F::new(b).mul(F::new(b)));
                assert!(
                    !bool::from(n.is_zero()),
                    "anisotropy violated at ({a},{b}) — q would be ≡ 1 mod 4"
                );
            }
        }
    }

    #[test]
    fn ext_mul_inverse_roundtrip() {
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..2000 {
            let x = E::from_u64(next() % Q_MCE, next() % Q_MCE);
            if bool::from(x.is_zero()) {
                continue;
            }
            assert_eq!(x.mul(x.invert().unwrap()), E::one());
        }
    }

    #[test]
    fn ext_t_squared_is_minus_one() {
        assert_eq!(E::t().mul(E::t()), E::one().neg());
    }

    #[test]
    fn ext_norm_multiplicative() {
        let x = E::from_u64(123, 456);
        let y = E::from_u64(789, 1011);
        assert_eq!(x.mul(y).norm(), x.norm().mul(y.norm()));
    }
}
