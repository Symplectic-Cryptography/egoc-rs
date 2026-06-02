#!/usr/bin/env python3
"""
AUTHORITATIVE lattice cost estimate for egoc-mlwe (SHADOW-SIS-FIX), using the
real `lattice-estimator` (Albrecht et al.). REQUIRES SageMath + the estimator:

    git clone https://github.com/malb/lattice-estimator
    cd lattice-estimator
    cp /path/to/run_lattice_estimator.py .
    sage run_lattice_estimator.py

It estimates BOTH security properties of the BDLOP commitment separately:
  * HIDING  = Decision-MLWE distinguishing of [A1;A2]·r  (LWE.estimate)
  * BINDING = MSIS short collision on A1                  (SIS.estimate)

Modeling notes (adapt to taste, then defend in the writeup):
  - Flatten module to LWE/SIS: dimension multiplies by the ring degree N.
  - BDLOP hiding has no explicit error term; we model the short secret r with
    Xs = Uniform(-eta,eta) and, conservatively, Xe = Uniform(-eta,eta). If you
    prefer the exact noiseless-MLWE treatment, use the estimator's SIS view of
    the same matrix and take the min.
  - Report all costs as an omega-band (omega in {2.0, 2.37, 2.81}); the estimator
    reports the standard 0.292 beta (classical) / 0.265 beta (quantum) core-SVP.
"""

try:
    from estimator import LWE, SIS, ND
except Exception as e:  # noqa: BLE001
    raise SystemExit(
        "Could not import `estimator`. Run inside the lattice-estimator repo "
        "with SageMath. Original error: %s" % e
    )

import math

# --- egoc-mlwe::Params::DEMO (TUNED set — confirm this beats 128 both ways) --
# Old over-provisioned set was K_BIND=4, L_RAND=8 → ~2^309. Tuned down to target
# ~128-160; core-SVP ballpark says ~168 classical / ~152 quantum. CONFIRM here.
N = 256
Q = 8380417
K_BIND = 3
K_MSG = 1
L_RAND = 5
ETA = 2

n_secret = L_RAND * N
m_samples = (K_BIND + K_MSG) * N
beta_open = 2 * ETA * math.sqrt(L_RAND * N)  # crude norm of a difference of two short openings

print("== HIDING (Decision-MLWE) ==")
params_lwe = LWE.Parameters(
    n=n_secret,
    q=Q,
    Xs=ND.Uniform(-ETA, ETA),
    Xe=ND.Uniform(-ETA, ETA),
    m=m_samples,
)
print(LWE.estimate(params_lwe))

print("\n== BINDING (MSIS short collision on A1) ==")
params_sis = SIS.Parameters(
    n=K_BIND * N,
    q=Q,
    length_bound=beta_open,
    m=L_RAND * N,
)
print(SIS.estimate(params_sis))

print(
    "\nPASS criteria: every reported attack >= 128-bit classical AND >= 128-bit "
    "quantum across the omega-band. If not, raise l_rand / lower q / widen N and "
    "re-run. Record the chosen set in docs/SECURITY.md."
)
