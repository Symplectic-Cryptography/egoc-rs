//! Lightweight timing benchmarks (no Criterion — std::time only, stays native).
//! Run:  cargo run -p egoc-bench --release

use egoc_field::{Fp2, Q_MCE};
use egoc_linalg::Mat;
use rand::{rngs::StdRng, RngCore, SeedableRng};
use std::time::Instant;

fn bench<F: FnMut()>(name: &str, iters: u32, mut f: F) {
    // warm-up
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed = t.elapsed();
    let per = elapsed.as_nanos() as f64 / iters as f64;
    let unit = if per >= 1e6 {
        format!("{:.2} ms", per / 1e6)
    } else if per >= 1e3 {
        format!("{:.2} µs", per / 1e3)
    } else {
        format!("{:.0} ns", per)
    };
    println!("  {name:<34} {unit:>12}   ({iters} iters)");
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    println!("=== egoc-rs micro-benchmarks (release) ===\n");

    // --- field / linalg over E ---
    println!("field & linalg over E (q={}):", Q_MCE);
    let x = Fp2::<Q_MCE>::random(&mut rng);
    let y = Fp2::<Q_MCE>::random(&mut rng);
    bench("Fp2 mul", 2_000_000, || {
        std::hint::black_box(x.mul(y));
    });
    bench("Fp2 invert", 500_000, || {
        std::hint::black_box(x.invert());
    });
    let a = Mat::<Q_MCE>::random(8, 9, &mut rng);
    let g = Mat::<Q_MCE>::random_invertible(8, &mut rng);
    let h = Mat::<Q_MCE>::random_invertible(9, &mut rng);
    bench("Mat 8x9 · 9x9 (mul)", 200_000, || {
        std::hint::black_box(a.mul(&h));
    });
    bench("two_sided S·M·T (8x9)", 100_000, || {
        std::hint::black_box(Mat::two_sided(&g, &a, &h));
    });
    bench("GL_8(E) invertible sample", 50_000, || {
        std::hint::black_box(Mat::<Q_MCE>::random_invertible(8, &mut rng));
    });
    bench("Mat 8x9 rank", 100_000, || {
        std::hint::black_box(a.rank());
    });

    // --- MCE code-mode commit + opening (egoc-proof) ---
    println!("\nMCE backend (code-mode, DEMO params, λ=32):");
    use egoc_code::{CodeParams, GenSet};
    use egoc_proof::opening::{prove_opening, verify_opening};
    let p = CodeParams::DEMO;
    let (gens, _) = GenSet::<Q_MCE>::expand_checked(&[9u8; 32], p, 0);
    let lambda = 32;
    let mk_commit = |rng: &mut StdRng| {
        let mut m = Mat::<Q_MCE>::zeros(p.mr, p.mc);
        for gg in &gens.gens {
            m = m.add(&gg.scale(Fp2::random(rng)));
        }
        let s = Mat::random_invertible(p.mr, rng);
        let t = Mat::random_invertible(p.mc, rng);
        (Mat::two_sided(&s, &m, &t), s, t)
    };
    bench("commit (build C=S·M·T)", 20_000, || {
        std::hint::black_box(mk_commit(&mut rng));
    });
    let (c, s, t) = mk_commit(&mut rng);
    bench("opening prove (λ=32)", 2_000, || {
        std::hint::black_box(prove_opening(&gens.gens, &c, &s, &t, lambda, &mut rng));
    });
    let proof = prove_opening(&gens.gens, &c, &s, &t, lambda, &mut rng);
    bench("opening verify (λ=32)", 2_000, || {
        std::hint::black_box(verify_opening(&gens.gens, &c, &proof));
    });

    // --- lattice backend (egoc-mlwe) ---
    println!("\nlattice backend (SHADOW-SIS-FIX, tuned params):");
    use egoc_mlwe::proof::{prove_opening as l_prove, verify_opening as l_verify, ProofParams};
    use egoc_mlwe::{commit, sample_randomness, CommitKey, Params};
    use egoc_mlwe::poly::Poly;
    let ck = CommitKey::expand(&[3u8; 32], Params::DEMO);
    let msg: Vec<Poly> = (0..ck.params.k_msg)
        .map(|_| {
            let mut seed = [0u8; 32];
            rng.fill_bytes(&mut seed);
            // a uniform message poly via the public sampler path
            let mut p = Poly::zero();
            for coeff in p.c.iter_mut() {
                *coeff = (rng.next_u32() % egoc_mlwe::poly::Q as u32) as u32;
            }
            p
        })
        .collect();
    bench("commit (BDLOP)", 20_000, || {
        std::hint::black_box(commit(&ck, msg.clone(), &mut rng));
    });
    let (com, op) = commit(&ck, msg.clone(), &mut rng);
    let pp = ProofParams::DEMO;
    bench("opening prove (FS-abort)", 5_000, || {
        std::hint::black_box(l_prove(&ck, &com, &op, &pp, &mut rng));
    });
    if let Some(lp) = l_prove(&ck, &com, &op, &pp, &mut rng) {
        bench("opening verify", 5_000, || {
            std::hint::black_box(l_verify(&ck, &com, &lp, &pp));
        });
    }
    let _ = sample_randomness;

    println!("\n(λ=32 demo soundness; production λ=128. Sizes/security: docs/SECURITY.md)");
}
