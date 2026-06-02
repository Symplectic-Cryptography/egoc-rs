#!/usr/bin/env sage
# Gröbner solving-degree probe for the bilinear MCE system C_l = S·G_l·T.
#
# Each instance runs in an ISOLATED subprocess with a timeout, so a slow size is
# killed cleanly without poisoning Singular's global state (the earlier crash).
#
# GAUGE FIX: S[0][0]=1 removes the scalar gauge (λS, λ⁻¹T) → zero-dimensional.
# We estimate the first-fall degree by an increasing deg_bound sweep.
#
# WHY THIS MATTERS: research/algebraic_cost_ballpark.py shows the candidate's
# algebraic cost straddles 128 depending on the TRUE solving degree (d=5→2^106,
# d=7→2^142). Small sizes gave first-fall≈5; the question is whether it RISES
# with size (bilinear systems usually do). Push the ladder as far as patience
# allows and watch the trend. For the authoritative number use msolve -v 2 or the
# MEDS native estimator.

import os, glob, time
from multiprocessing import Process, Queue

PER_INSTANCE_TIMEOUT = 600   # seconds; raise to push larger sizes

def read_system(path):
    with open(path) as f:
        toks = f.read().split()
    it = iter(toks)
    p, mr, mc, k = (int(next(it)) for _ in range(4))
    def mat():
        return [[int(next(it)) for _ in range(mc)] for _ in range(mr)]
    G = [mat() for _ in range(k)]
    C = [mat() for _ in range(k)]
    return p, mr, mc, k, G, C

def build_ideal(path):
    p, mr, mc, k, G, C = read_system(path)
    Fp = GF(p)
    Svars = [f"s{i}_{j}" for i in range(mr) for j in range(mr)]
    Tvars = [f"t{a}_{b}" for a in range(mc) for b in range(mc)]
    R = PolynomialRing(Fp, Svars + Tvars, order="degrevlex")
    g = R.gens()
    S = [[g[i*mr + j] for j in range(mr)] for i in range(mr)]
    T = [[g[mr*mr + a*mc + b] for b in range(mc)] for a in range(mc)]
    eqs = []
    for l in range(k):
        GT = [[sum(Fp(G[l][a][b]) * T[b][j] for b in range(mc)) for j in range(mc)]
              for a in range(mr)]
        for i in range(mr):
            for j in range(mc):
                eqs.append(sum(S[i][a] * GT[a][j] for a in range(mr)) - Fp(C[l][i][j]))
    eqs.append(S[0][0] - Fp(1))     # GAUGE FIX
    return ideal(eqs), len(g), len(eqs)

def first_fall_degree(I, dmax=10):
    prev = None
    for d in range(2, dmax + 1):
        gb = I.groebner_basis(deg_bound=d)
        if any(f.is_constant() and f != 0 for f in gb):
            return d
        sig = sorted(str(f.lm()) for f in gb)
        if sig == prev:
            return d - 1
        prev = sig
    return dmax

def _worker(path, q):
    I, nv, ne = build_ideal(path)
    t0 = time.time()
    d = first_fall_degree(I)
    q.put((d, nv, ne, time.time() - t0))

def solve_one(path):
    q = Queue()
    proc = Process(target=_worker, args=(path, q))
    proc.start()
    proc.join(PER_INSTANCE_TIMEOUT)
    name = os.path.basename(path)
    if proc.is_alive():
        proc.terminate()
        proc.join()
        print(f"  {name}: TIMEOUT > {PER_INSTANCE_TIMEOUT}s (steep cost — not weak)")
        return
    if q.empty():
        print(f"  {name}: worker failed (no result)")
        return
    d, nv, ne, dt = q.get()
    print(f"  {name}: vars={nv} eqs={ne}  first-fall≈{d}  time={dt:.1f}s")

if __name__ == "__main__":
    files = sorted(glob.glob("research/mce_systems/*.txt"))
    if not files:
        raise SystemExit("No systems found. Run the Rust exporter first.")
    print(f"MCE solving-degree probe (gauge-fixed, subprocess-isolated, "
          f"{PER_INSTANCE_TIMEOUT}s/inst).")
    print("Watch whether first-fall RISES with size (≥7 at scale ⇒ candidate clears 128;")
    print("flat at ~5 ⇒ enlarge params). Authoritative: msolve -v 2 / MEDS estimator.\n")
    for f in files:
        solve_one(f)
