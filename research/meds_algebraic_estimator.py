#!/usr/bin/env python3
"""
Algebraic-attack cost for MCE, implementing the tri-Hilbert-series estimate from
the MEDS NIST submission (Supporting_Documentation/MEDS.pdf, §4.3.1):

  H(r,s,t) = (1-rs)^{n(mk-n)} (1-st)^{m(nk-m)} (1-tr)^{k(nm-k)} (1-rts)^{-(2nmk-n^2-m^2-k^2+1)}
             / [ (1-r)^{n^2} (1-s)^{m^2} (1-t)^{k^2} ]
  M(r,s,t) = 1 / [ (1-r)^{n^2} (1-s)^{m^2} (1-t)^{k^2} ]            (monomial count)
  cost = min over (α,β,γ) ⪯ (n,m,k) with [r^α s^β t^γ]H <= 1  of  3 · ([..]M)^2 · n m (k+1)

KEY FACT: this cost is FIELD-INDEPENDENT (Gaussian elimination over F_q; the field
size only affects the per-op cost, negligible). So MCE algebraic security depends
on (n,m,k) only.

We VALIDATE the implementation by reproducing MEDS's claimed levels for its
(n=m=k) sets, then apply it to the EGOC-MCE-R candidate (n,m,k)=(28,22,40).
Pure Python (math.comb exact big ints); no deps.
"""

from math import comb, log2

# H contributes degrees via four "diagonal" variables:
#   g_rs(j1): (rs)^j1  coeff C(A,j1)(-1)^j1 , A=n(mk-n)
#   g_st(j2): (st)^j2  coeff C(B,j2)(-1)^j2 , B=m(nk-m)
#   g_tr(j3): (tr)^j3  coeff C(C,j3)(-1)^j3 , C=k(nm-k)
#   h_rts(j4):(rts)^j4 coeff C(D+j4-1,j4)   , D=2nmk-n^2-m^2-k^2+1
# and three univariate denominators F_r,F_s,F_t with F_*[a]=C(a+v-1, v-1).

def F(a, v):
    return comb(a + v - 1, v - 1) if a >= 0 else 0

def H_coeff(al, be, ga, n, m, k):
    A = n * (m * k - n)
    B = m * (n * k - m)
    C = k * (n * m - k)
    D = 2 * n * m * k - n * n - m * m - k * k + 1
    n2, m2, k2 = n * n, m * m, k * k
    # explicit 4-fold sum (bounded; the regularity degree is small)
    total = 0
    for j1 in range(0, min(al, be, A) + 1):
        g1 = comb(A, j1) * (-1) ** j1
        for j2 in range(0, min(be, ga, B) + 1):
            g2 = comb(B, j2) * (-1) ** j2
            for j3 in range(0, min(ga, al, C) + 1):
                g3 = comb(C, j3) * (-1) ** j3
                for j4 in range(0, min(al, be, ga) + 1):
                    a_r = al - j1 - j3 - j4
                    a_s = be - j1 - j2 - j4
                    a_t = ga - j2 - j3 - j4
                    if a_r < 0 or a_s < 0 or a_t < 0:
                        continue
                    h4 = comb(D + j4 - 1, j4)
                    total += g1 * g2 * g3 * h4 * F(a_r, n2) * F(a_s, m2) * F(a_t, k2)
    return total

def M_coeff(al, be, ga, n, m, k):
    return F(al, n * n) * F(be, m * m) * F(ga, k * k)

def algebraic_cost_bits(n, m, k, dmax=20):
    best = None
    # search by increasing total degree; stop a couple levels past first hit
    found_at = None
    for d in range(2, dmax + 1):
        for al in range(0, min(n, d) + 1):
            for be in range(0, min(m, d - al) + 1):
                ga = d - al - be
                if ga < 0 or ga > k:
                    continue
                hc = H_coeff(al, be, ga, n, m, k)
                if hc <= 1:
                    mc = M_coeff(al, be, ga, n, m, k)
                    cost = 3 * mc * mc * n * m * (k + 1)
                    bits = log2(cost)
                    if best is None or bits < best[0]:
                        best = (bits, (al, be, ga), mc)
        if best is not None and found_at is None:
            found_at = d
        if found_at is not None and d >= found_at + 1:
            break
    return best

def report(name, n, m, k, claimed=None):
    res = algebraic_cost_bits(n, m, k)
    if res is None:
        print(f"  {name:<26} (n,m,k)=({n},{m},{k})  no regularity degree <= dmax")
        return
    bits, deg, mc = res
    tag = f"  [MEDS claims {claimed}]" if claimed else ""
    print(f"  {name:<26} (n,m,k)=({n},{m},{k})  d_reg={deg} "
          f"algebraic-cost ≈ 2^{bits:.0f}{tag}")

if __name__ == "__main__":
    print("MCE algebraic-attack cost (MEDS §4.3.1 tri-Hilbert-series). Field-INDEPENDENT.\n")
    print("VALIDATION on MEDS (n=m=k) sets:")
    report("MEDS-9923 (L1)", 14, 14, 14, "128")
    report("MEDS L3", 22, 22, 22, "192")
    report("MEDS L5", 30, 30, 30, "256")
    print("\nEGOC-MCE-R candidate (algebraic surface; field |E|≈2^48 irrelevant here):")
    report("EGOC cand (22x28,k40)", 28, 22, 40)
    report("EGOC fallback (24x30,k56)", 30, 24, 56)
    print("\nNote: if VALIDATION reproduces ~128/192/256, the candidate number is")
    print("credible (same methodology). Leon/MinRank surface is separately ≥2^1064.")
