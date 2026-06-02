#!/usr/bin/env python3
"""
APPROXIMATE core-SVP estimate for the egoc-mlwe (SHADOW-SIS-FIX) Decision-MLWE
hiding instance. Pure Python, no dependencies — runnable anywhere.

⚠ THIS IS A BALLPARK, NOT AN AUTHORITATIVE NUMBER. It implements the standard
primal-uSVP "2016 estimate" with the core-SVP cost model (classical 0.292·β,
quantum 0.265·β). The authoritative number must come from the real
`lattice-estimator` (see run_lattice_estimator.py). Use this only to sanity-check
parameters and to search for a >=128-bit set quickly.

Model: the short randomness r (dimension n = l_rand·N over Z, coeffs uniform in
[-eta,eta], std sigma) is recovered from the public [A1;A2]·r relation, giving at
most m = (k_bind+k_msg)·N Z_q samples. We optimise over the number of samples used.
"""

import math


def delta(beta):
    # root-Hermite factor of BKZ-beta (standard asymptotic)
    return ((math.pi * beta) ** (1.0 / beta) * beta / (2 * math.pi * math.e)) ** (
        1.0 / (2 * (beta - 1))
    )


def primal_beta(n, m_max, q, sigma):
    """Smallest BKZ block size beta for the primal-uSVP attack, optimising m<=m_max."""
    best = None
    for beta in range(50, 2000):
        d_factor = delta(beta)
        # try the best number of samples for this beta
        for m in range(max(1, n // 4), m_max + 1, 8):
            d = m + n + 1
            lhs = sigma * math.sqrt(beta)
            rhs = d_factor ** (2 * beta - d - 1) * (q ** (m / d))
            if lhs <= rhs:
                return beta, m
        _ = d_factor
    return None, None


def core_svp_bits(beta):
    return 0.292 * beta, 0.265 * beta  # classical (sieve), quantum


def uniform_std(eta):
    # variance of uniform on {-eta,...,eta} = eta(eta+1)/3
    return math.sqrt(eta * (eta + 1) / 3.0)


def evaluate(name, N, q, k_bind, k_msg, l_rand, eta):
    n = l_rand * N
    m_max = (k_bind + k_msg) * N
    sigma = uniform_std(eta)
    beta, m = primal_beta(n, m_max, q, sigma)
    print(f"\n=== {name} ===")
    print(f"  N={N} q={q} (~2^{math.log2(q):.1f})  k_bind={k_bind} k_msg={k_msg} "
          f"l_rand={l_rand} eta={eta}")
    print(f"  secret dim n=l_rand*N={n}   max samples m=(k_bind+k_msg)*N={m_max}   "
          f"sigma={sigma:.3f}")
    if beta is None:
        print("  primal-uSVP: no beta < 2000 succeeds — instance is (per this rough "
              "model) very hard / overkill. Use the real estimator.")
        return
    c, qb = core_svp_bits(beta)
    print(f"  primal-uSVP beta={beta} (using m={m})")
    print(f"  core-SVP bits:  classical ~{c:.0f}   quantum ~{qb:.0f}")
    print(f"  target >=128:   {'OK (ballpark)' if min(c, qb) >= 128 else 'BELOW — re-tune'}")


if __name__ == "__main__":
    print("APPROXIMATE core-SVP (ballpark only — authoritative = lattice-estimator)")
    # demo set currently in egoc-mlwe::Params::DEMO
    evaluate("egoc-mlwe DEMO", N=256, q=8380417, k_bind=4, k_msg=1, l_rand=8, eta=2)
    # a couple of alternative shapes to bracket the search
    evaluate("alt: smaller l_rand", N=256, q=8380417, k_bind=4, k_msg=1, l_rand=6, eta=2)
    evaluate("alt: eta=1 narrow", N=256, q=8380417, k_bind=4, k_msg=1, l_rand=8, eta=1)
    print("\nNOTE: a high/'no beta' result reflects the l_rand>height (secret>samples) "
          "regime, which favours hiding. The BINDING side is MSIS (separate). Confirm "
          "everything with the real lattice-estimator before any bit claim.")
