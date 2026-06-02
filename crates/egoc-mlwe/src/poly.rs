//! Polynomial arithmetic in `R_q = Z_q[X]/(X^256 + 1)` (negacyclic).
//!
//! `q = 8380417 = 2²³ − 2¹³ + 1` (the Dilithium prime, `< 2²³`). Multiplication
//! is schoolbook negacyclic — correctness-first; an NTT is a later perf milestone
//! (documented in docs/PERFORMANCE.md). Coefficients are kept in `[0, q)`; products use an
//! `i64` accumulator (`256·(q−1)² ≈ 1.8·10¹⁶ < 2⁶³`, no overflow).

pub const N: usize = 256;
pub const Q: u64 = 8380417;

/// An element of `R_q`, coefficients in `[0, q)`.
#[derive(Clone, Copy)]
pub struct Poly {
    pub c: [u32; N],
}

impl core::fmt::Debug for Poly {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Poly[{}..]", self.c[0])
    }
}

impl PartialEq for Poly {
    fn eq(&self, o: &Self) -> bool {
        self.c == o.c
    }
}
impl Eq for Poly {}

impl Poly {
    pub fn zero() -> Self {
        Self { c: [0; N] }
    }

    pub fn is_zero(&self) -> bool {
        self.c.iter().all(|&x| x == 0)
    }

    pub fn add(&self, o: &Poly) -> Poly {
        let mut r = Poly::zero();
        for i in 0..N {
            r.c[i] = ((self.c[i] as u64 + o.c[i] as u64) % Q) as u32;
        }
        r
    }

    pub fn sub(&self, o: &Poly) -> Poly {
        let mut r = Poly::zero();
        for i in 0..N {
            r.c[i] = ((self.c[i] as u64 + Q - o.c[i] as u64) % Q) as u32;
        }
        r
    }

    /// Negacyclic schoolbook product: `X^N ≡ −1`.
    pub fn mul(&self, o: &Poly) -> Poly {
        let mut acc = [0i64; N];
        for i in 0..N {
            let ai = self.c[i] as i64;
            if ai == 0 {
                continue;
            }
            for j in 0..N {
                let prod = ai * o.c[j] as i64;
                let d = i + j;
                if d < N {
                    acc[d] += prod;
                } else {
                    acc[d - N] -= prod; // wrap with sign flip
                }
            }
        }
        let mut r = Poly::zero();
        for i in 0..N {
            let v = acc[i] % Q as i64;
            r.c[i] = if v < 0 { (v + Q as i64) as u32 } else { v as u32 };
        }
        r
    }

    /// Infinity norm with coefficients centered to `(−q/2, q/2]`.
    pub fn norm_inf(&self) -> u64 {
        let half = Q / 2;
        self.c
            .iter()
            .map(|&x| {
                let x = x as u64;
                if x > half {
                    Q - x
                } else {
                    x
                }
            })
            .max()
            .unwrap_or(0)
    }

    pub fn to_bytes(&self) -> [u8; N * 4] {
        let mut o = [0u8; N * 4];
        for i in 0..N {
            o[4 * i..4 * i + 4].copy_from_slice(&self.c[i].to_le_bytes());
        }
        o
    }

    /// Inverse of [`Poly::to_bytes`]; reduces each coefficient mod `q`.
    pub fn from_bytes(b: &[u8; N * 4]) -> Self {
        let mut p = Poly::zero();
        for i in 0..N {
            let v = u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap());
            p.c[i] = ((v as u64) % Q) as u32;
        }
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn x_pow(k: usize) -> Poly {
        let mut p = Poly::zero();
        p.c[k] = 1;
        p
    }

    #[test]
    fn x_n_is_minus_one() {
        // X^255 · X = X^256 ≡ −1  ⇒ constant coeff = q−1, rest 0.
        let r = x_pow(255).mul(&x_pow(1));
        assert_eq!(r.c[0], (Q - 1) as u32);
        for i in 1..N {
            assert_eq!(r.c[i], 0);
        }
    }

    #[test]
    fn mul_identity() {
        let one = x_pow(0);
        let mut p = Poly::zero();
        for i in 0..N {
            p.c[i] = ((i as u64 * 7 + 3) % Q) as u32;
        }
        assert_eq!(one.mul(&p), p);
    }

    #[test]
    fn distributive() {
        let a = {
            let mut p = Poly::zero();
            for i in 0..N {
                p.c[i] = ((i * i) as u64 % Q) as u32;
            }
            p
        };
        let b = x_pow(5).add(&x_pow(200));
        let c = x_pow(3);
        assert_eq!(a.mul(&b.add(&c)), a.mul(&b).add(&a.mul(&c)));
    }

    #[test]
    fn add_sub_roundtrip() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.c[i] = (i as u64 % Q) as u32;
            b.c[i] = ((1000 + i) as u64 % Q) as u32;
        }
        assert_eq!(a.add(&b).sub(&b), a);
    }
}
