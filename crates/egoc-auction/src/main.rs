//! End-to-end sealed-bid auction demo on the EGOC-MCE-R code-mode commitment.
//! Run:  cargo run -p egoc-auction --release

use egoc_auction::{winner, Auction};
use egoc_code::CodeParams;
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

fn main() {
    let lambda = 32; // demo soundness 2^-32; production would use 128
    let auction = Auction::new(b"egoc-auction-demo-public-seed!!!", CodeParams::DEMO, lambda);
    let p = auction.params;
    let mut rng = StdRng::seed_from_u64(0xA11CE);

    let names = ["Alice", "Bob", "Carol", "Dave", "Erin"];
    let bids: [u64; 5] = [1200, 3500, 2750, 3499, 980];

    println!("=== E-GOC sealed-bid auction (code-mode MCE commitment) ===");
    println!(
        "code: mr={} mc={} k={} ell={}  |E|=q^2 (q={})  lambda={}",
        p.mr, p.mc, p.k(), p.ell, egoc_field::Q_MCE, lambda
    );
    println!("hull-genericity keygen check: PASSED (expand_checked)\n");

    // --- bidding phase: commit + ZK opening proof -----------------------------
    let mut sealed = Vec::new();
    let mut secrets = Vec::new();
    let t0 = Instant::now();
    for (i, &b) in bids.iter().enumerate() {
        let (sb, sec) = auction.commit_bid(b, &mut rng);
        println!(
            "{:>6} commits a sealed bid  ({} bytes published, bid hidden)",
            names[i],
            sb.size_bytes()
        );
        sealed.push(sb);
        secrets.push(sec);
    }
    let commit_time = t0.elapsed();

    // --- the auctioneer verifies every ZK opening proof (no bids revealed) ----
    let t1 = Instant::now();
    let all_ok = sealed.iter().all(|sb| auction.verify_sealed(sb));
    let verify_time = t1.elapsed();
    println!(
        "\nAuctioneer verifies all {} ZK opening proofs (bids still secret): {}",
        sealed.len(),
        if all_ok { "ALL VALID ✓" } else { "FAILED ✗" }
    );

    // --- a cheater tries to verify a forged commitment ------------------------
    {
        use egoc_linalg::Mat;
        let bogus = Mat::<{ egoc_field::Q_MCE }>::random(p.mr, p.mc, &mut rng);
        let forged = egoc_proof::opening::prove_opening(
            &auction.gens.gens,
            &bogus,
            &Mat::identity(p.mr),
            &Mat::identity(p.mc),
            lambda,
            &mut rng,
        );
        let sb = egoc_auction::SealedBid { commitment: bogus, proof: forged };
        println!(
            "Forged (non-)commitment opening proof: {}",
            if auction.verify_sealed(&sb) { "accepted ✗ (BUG)" } else { "rejected ✓" }
        );
    }

    // --- reveal phase: recompute + check binding, find the winner -------------
    let reveals: Vec<Option<u64>> =
        sealed.iter().zip(&secrets).map(|(sb, s)| auction.reveal(sb, s)).collect();
    println!("\nReveal phase (binding check on each opening):");
    for (i, r) in reveals.iter().enumerate() {
        match r {
            Some(b) => println!("  {:>6}: bid = {}", names[i], b),
            None => println!("  {:>6}: INVALID opening (binding violation)", names[i]),
        }
    }

    // --- a bidder who tries to change their bid at reveal ---------------------
    {
        let (sb, mut sec) = auction.commit_bid(100, &mut rng);
        sec.witness.m[0] = egoc_field::Fp::new(9999); // claim a higher bid
        let cheated = auction.reveal(&sb, &sec);
        println!(
            "\nBidder commits 100, tries to reveal 9999: {}",
            match cheated {
                None => "REJECTED ✓ (commitment is binding)".to_string(),
                Some(b) => format!("accepted {b} ✗ (BUG)"),
            }
        );
    }

    // --- winner ----------------------------------------------------------------
    match winner(&reveals) {
        Some((idx, bid)) => println!("\n🏆 Winner: {} with bid {}", names[idx], bid),
        None => println!("\nNo valid bids."),
    }

    println!("\n--- timings ---");
    println!("commit+prove ({} bidders): {:?}", bids.len(), commit_time);
    println!("verify all proofs:          {:?}", verify_time);

    println!("\n--- honest security note ---");
    println!("This demo uses the MCE backend at DEMO sizes. At the candidate parameters");
    println!("the MCE surface estimates to ~2^208 algebraic / >=2^1064 rank (MEDS");
    println!("methodology, validated); the lattice backend is estimator-confirmed");
    println!(">=2^186 classical / ~2^146 quantum. See docs/SECURITY.md. lambda=32 here is");
    println!("demo-only (use 128 in production); the bit figures are NOT the demo sizes.");
}
