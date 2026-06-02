//! Export bilinear MCE instances `C_l = S · G_l · T` over a small prime field
//! `F_p` at a size ladder, for an external Gröbner-basis solving-degree run
//! (msolve / Magma / Sage — see research/groebner_mce.sage).
//!
//! Run:  cargo run -p egoc-attack --example export_mce_system
//! Writes: research/mce_systems/mce_<mr>x<mc>_k<k>_p<p>.txt
//!
//! File format (all integers in [0,p)):
//!   line 1:  p mr mc k
//!   then k blocks of mr lines × mc ints  — the public generators G_0..G_{k-1}
//!   then k blocks of mr lines × mc ints  — the pushed C_l = S·G_l·T
//! The secret (S,T) is NOT written — recovering it is the solver's job.

use std::fs;
use std::io::Write;

// deterministic splitmix64 — no external rng dependency
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn elem(&mut self, p: u64) -> u64 {
        self.next() % p
    }
}

type M = Vec<Vec<u64>>;

fn rand_mat(r: usize, c: usize, p: u64, rng: &mut Rng) -> M {
    (0..r).map(|_| (0..c).map(|_| rng.elem(p)).collect()).collect()
}

fn matmul(a: &M, b: &M, p: u64) -> M {
    let (ar, ac, bc) = (a.len(), a[0].len(), b[0].len());
    let mut out = vec![vec![0u64; bc]; ar];
    for i in 0..ar {
        for k in 0..ac {
            let aik = a[i][k];
            if aik == 0 {
                continue;
            }
            for j in 0..bc {
                out[i][j] = (out[i][j] + aik * b[k][j]) % p;
            }
        }
    }
    out
}

fn rand_invertible(n: usize, p: u64, rng: &mut Rng) -> M {
    // p is small; rejection-sample until determinant != 0 (via Gaussian elimination)
    loop {
        let m = rand_mat(n, n, p, rng);
        if det_nonzero(&m, p) {
            return m;
        }
    }
}

fn det_nonzero(m: &M, p: u64) -> bool {
    let n = m.len();
    let mut a = m.clone();
    for col in 0..n {
        let piv = (col..n).find(|&i| a[i][col] != 0);
        let piv = match piv {
            Some(x) => x,
            None => return false,
        };
        a.swap(piv, col);
        let inv = modinv(a[col][col], p);
        for i in (col + 1)..n {
            let f = a[i][col] * inv % p;
            for j in col..n {
                a[i][j] = (a[i][j] + p - f * a[col][j] % p) % p;
            }
        }
    }
    true
}

fn modinv(a: u64, p: u64) -> u64 {
    // Fermat: a^(p-2) mod p
    let mut r = 1u64;
    let mut b = a % p;
    let mut e = p - 2;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % p;
        }
        b = b * b % p;
        e >>= 1;
    }
    r
}

fn export(mr: usize, mc: usize, k: usize, p: u64, seed: u64) -> String {
    let mut rng = Rng(seed);
    let gens: Vec<M> = (0..k).map(|_| rand_mat(mr, mc, p, &mut rng)).collect();
    let s = rand_invertible(mr, p, &mut rng);
    let t = rand_invertible(mc, p, &mut rng);
    let pushed: Vec<M> = gens.iter().map(|g| matmul(&matmul(&s, g, p), &t, p)).collect();

    let mut out = String::new();
    out.push_str(&format!("{p} {mr} {mc} {k}\n"));
    for blk in gens.iter().chain(pushed.iter()) {
        for row in blk {
            let line: Vec<String> = row.iter().map(|x| x.to_string()).collect();
            out.push_str(&line.join(" "));
            out.push('\n');
        }
    }
    out
}

fn main() {
    let dir = "research/mce_systems";
    fs::create_dir_all(dir).expect("mkdir");
    let p = 31u64; // small prime for fast Gröbner; the trend in (mr,mc,k) is what matters
    // a ladder of RECTANGULAR sizes mirroring the candidate geometry (mc-mr=1..2)
    let ladder = [(3usize, 4usize, 4usize), (4, 5, 6), (5, 6, 8), (6, 7, 10), (7, 8, 12)];
    for (i, &(mr, mc, k)) in ladder.iter().enumerate() {
        let body = export(mr, mc, k, p, 0xC0FFEE + i as u64);
        let path = format!("{dir}/mce_{mr}x{mc}_k{k}_p{p}.txt");
        let mut f = fs::File::create(&path).expect("create");
        f.write_all(body.as_bytes()).expect("write");
        println!("wrote {path}  (mr={mr} mc={mc} k={k}, fill={:.3})", k as f64 / (mr * mc) as f64);
    }
    println!("\nNow run:  sage research/groebner_mce.sage   (records solving degree per size)");
}
