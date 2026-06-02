#!/usr/bin/env python3
"""
Convert the raw MCE ladder files (research/mce_systems/*.txt) into msolve's .ms
input format, so msolve can measure the bilinear solving degree.

    python3 research/export_msolve.py
    msolve -f research/mce_systems/mce_3x4_k4_p31.ms -v 2     # read the 'deg' column

The 'deg' column of msolve's F4 log is the degree of each round; its MAX is the
solving degree. Watch it RISE as the ladder grows (3x4 → 4x5 → 5x6 …): a rising/
flat-high degree supports MCE hardness; a collapse toward 2-3 would be a red flag.
(Your earlier run failed because the .txt is a matrix dump, NOT msolve syntax.)

Gauge-fixed (s0_0 = 1) → zero-dimensional, as in research/groebner_mce.sage.
"""

import glob
import os


def read_system(path):
    with open(path) as f:
        toks = iter(f.read().split())
    p, mr, mc, k = (int(next(toks)) for _ in range(4))

    def mat():
        return [[int(next(toks)) for _ in range(mc)] for _ in range(mr)]

    G = [mat() for _ in range(k)]
    C = [mat() for _ in range(k)]
    return p, mr, mc, k, G, C


def to_ms(path):
    p, mr, mc, k, G, C = read_system(path)
    svars = [f"s{i}_{a}" for i in range(mr) for a in range(mr)]
    tvars = [f"t{b}_{j}" for b in range(mc) for j in range(mc)]
    variables = ",".join(svars + tvars)

    polys = []
    for l in range(k):
        for i in range(mr):
            for j in range(mc):
                terms = []
                for a in range(mr):
                    for b in range(mc):
                        g = G[l][a][b] % p
                        if g:
                            terms.append(f"{g}*s{i}_{a}*t{b}_{j}")
                cst = (-C[l][i][j]) % p
                if cst:
                    terms.append(str(cst))
                polys.append("+".join(terms) if terms else "0")
    polys.append("s0_0-1")  # gauge fix → zero-dimensional

    body = variables + "\n" + str(p) + "\n" + ",\n".join(polys) + "\n"
    out = os.path.splitext(path)[0] + ".ms"
    with open(out, "w") as f:
        f.write(body)
    print(f"wrote {out}  ({len(svars)+len(tvars)} vars, {len(polys)} eqs, char {p})")


if __name__ == "__main__":
    files = sorted(glob.glob("research/mce_systems/*.txt"))
    if not files:
        raise SystemExit("Run `cargo run -p egoc-attack --example export_mce_system` first.")
    for f in files:
        to_ms(f)
    print("\nNow:  msolve -f research/mce_systems/<name>.ms -v 2   and read the 'deg' column.")
