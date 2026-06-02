#!/usr/bin/env python3
"""
MinRank / MCE cost for the EGOC-MCE-R candidate via CryptographicEstimators.

Findings on this machine's version:
  * NO MCEEstimator module (only LE/PE among equivalence problems). To get the
    authoritative MCE number, upgrade:  pip install -U cryptographic_estimators
    (MCE was added in newer releases), or use the MEDS NIST submission estimator.
  * MinRank's symbolic "Minors" algorithm blows up at our sizes → we EXCLUDE it
    and wrap every call in a hard timeout, keeping the fast formula-based
    algorithms (SupportMinors / KernelSearch / BruteForce / BigK).

    pip install -U cryptographic_estimators
    python3 research/run_mce_estimator.py
"""

import importlib
import pkgutil
import signal

# --- candidate (docs/CRYPTANALYSIS.md) --------------------------------------
Q = 16777259
E = Q * Q                    # |E| ≈ 2^48
MR, MC, K = 22, 31, 46
TIMEOUT = 90                 # seconds per estimator call


def banner(t):
    print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)


class Timeout(Exception):
    pass


def _alarm(_s, _f):
    raise Timeout()


signal.signal(signal.SIGALRM, _alarm)


def run_with_timeout(fn, secs=TIMEOUT):
    signal.alarm(secs)
    try:
        return fn()
    finally:
        signal.alarm(0)


try:
    import cryptographic_estimators as ce
except Exception as e:  # noqa: BLE001
    raise SystemExit(f"pip install cryptographic_estimators  ({e})")

banner("CryptographicEstimators — available estimators")
mods = sorted(m.name for m in pkgutil.iter_modules(ce.__path__) if m.name.endswith("Estimator"))
print("modules:", ", ".join(mods))
has_mce = any("MCE" in m for m in mods)
print("MCE estimator present:", has_mce)


def show(est):
    for method in ("table", "estimate"):
        if hasattr(est, method):
            out = run_with_timeout(getattr(est, method))
            if out is not None:
                print(out)
            return


# ---------------------------------------------------------------------------
# MinRank — exclude the slow symbolic "Minors" algorithm
# ---------------------------------------------------------------------------
try:
    from cryptographic_estimators.MREstimator import MREstimator
    excluded = []
    try:
        from cryptographic_estimators.MREstimator.MRAlgorithms.minors import Minors
        excluded = [Minors]
    except Exception:  # noqa: BLE001
        pass

    # r<=17 has NO rank-r codeword in the candidate code (absent) — not an attack.
    # The expected minimum rank is ~18; run the existing low ranks.
    for r in (18, 19, 20):
        banner(f"MinRank  q=|E|≈2^48  m={MR} n={MC} k={K}  r={r}  (Minors excluded)")
        try:
            est = MREstimator(q=E, m=MR, n=MC, k=K, r=r, excluded_algorithms=excluded)
            show(est)
        except Timeout:
            print(f"  TIMEOUT > {TIMEOUT}s — algorithm too slow at this size; "
                  "try the MEDS native estimator.")
        except Exception as e:  # noqa: BLE001
            print("  call/adapt error:", e)
except Exception as e:  # noqa: BLE001
    print("MREstimator unavailable:", e)

# ---------------------------------------------------------------------------
# MCE — only if a newer version ships it
# ---------------------------------------------------------------------------
if has_mce:
    try:
        mod = importlib.import_module("cryptographic_estimators.MCEEstimator")
        MCE = getattr(mod, "MCEEstimator")
        banner("MCE — native E (q^2)")
        show(MCE(n=MR, m=MC, k=K, q=E))
        banner("MCE — Weil restriction (dims x2, field q)")
        show(MCE(n=2 * MR, m=2 * MC, k=2 * K, q=Q))
    except Exception as e:  # noqa: BLE001
        print("MCE present but signature needs adaptation:", e)
else:
    print("\n[No MCE estimator here. Options for the authoritative MCE number:")
    print("  1) pip install -U cryptographic_estimators   (newer ships MCEEstimator)")
    print("  2) the MEDS NIST submission's own Magma/Sage estimator")
    print("  3) small-scale msolve solving-degree run (research/groebner_mce.sage) +")
    print("     the analytical Leon/RST collision floor 2^168 in docs/CRYPTANALYSIS.md.]")

print("\nPaste the MinRank numbers back; combined with the Leon floor they bound the")
print("rank-based surface. The bilinear-Gröbner surface still needs an MCE estimator or msolve.")
