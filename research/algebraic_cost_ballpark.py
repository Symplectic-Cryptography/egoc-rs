#!/usr/bin/env python3
"""
CRUDE ballpark for the bilinear-MCE Gröbner cost, to interpret the measured
first-fall degree (~5 at small sizes) at the candidate parameters.

⚠ VERY rough: cost ≈ (Macaulay columns at degree d)^ω with columns ≈ C(N+d, d),
N = #variables after gauge fix = mr² + mc² − 1. This OVER-counts (uses all
total-degree monomials, not the smaller bilinear-restricted set) and ignores the
bilinear structure that lowers the true solving degree — so it is NOT a security
claim. It exists only to show: (a) the candidate straddles 128 depending on the
true solving degree, hence the algebraic surface is the BINDING constraint and
needs the rigorous MEDS/CryptographicEstimators number; (b) the M3 fallback bump
buys margin.
"""

from math import comb, log2

OMEGA = 2.37  # linear-algebra exponent (band 2.0 .. 2.81)


def cost_bits(mr, mc, d, omega=OMEGA):
    n = mr * mr + mc * mc - 1  # variables after the S[0][0]=1 gauge fix
    cols = comb(n + d, d)
    return n, omega * log2(cols)


def report(name, mr, mc, k):
    print(f"\n{name}: mr={mr} mc={mc} k={k}  (N = mr²+mc²−1)")
    print(f"  {'d_solve':>8} | {'cost bits (cols^ω, ω=2.37)':>28}")
    for d in (4, 5, 6, 7, 8):
        n, bits = cost_bits(mr, mc, d)
        flag = "  <128 (WEAK if true)" if bits < 128 else "  ≥128"
        print(f"  {d:>8} | {bits:>10.0f}{flag}   (N={n})")


if __name__ == "__main__":
    print("CRUDE bilinear-Gröbner ballpark (NOT a security claim — read the header).")
    print("Measured first-fall at small sizes was ≈5 and did not collapse to 2-3;")
    print("cost exploded 0.3s→20.7s→timeout over 3 tiny sizes.")
    report("CANDIDATE", 22, 28, 40)
    report("FALLBACK bump", 24, 30, 56)
    report("bigger", 28, 34, 64)
    print("\nTakeaway: if the true solving degree is ~5 the CANDIDATE may sit BELOW 128 on")
    print("the algebraic surface; d≥7 clears it. This is exactly why no MCE bit number is")
    print("claimed without the rigorous MEDS estimator, and why enlarging params is the")
    print("safe move. The lattice backend (≥2^309) is unaffected and remains primary.")
