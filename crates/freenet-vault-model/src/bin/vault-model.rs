//! Run seeded schedules of the handover model and report invariant
//! violations (with shrunk traces) and coverage.
//!
//! vault-model [--seeds N] [--start S] [--queued] [--adversarial] [--stale-pointer]
//!             [--accept-query-answer] [--trace SEED] [--quiet]

use std::collections::BTreeMap;

use freenet_vault_model::cov::Cov;
use freenet_vault_model::gen::{gen_scenario, run, shrink, COVERAGE_SEEDS};
use freenet_vault_model::world::{Cfg, Delivery};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut seeds: u64 = 2000;
    let mut start: u64 = 0;
    let mut cfg = Cfg::gate();
    let mut trace: Option<u64> = None;
    let mut shrink_n = 1usize;
    let mut find: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--seeds" => {
                seeds = args[i + 1].parse().unwrap();
                i += 1;
            }
            "--start" => {
                start = args[i + 1].parse().unwrap();
                i += 1;
            }
            "--trace" => {
                trace = Some(args[i + 1].parse().unwrap());
                i += 1;
            }
            "--find" => {
                find = Some(args[i + 1].clone());
                i += 1;
            }
            "--shrink" => {
                shrink_n = args[i + 1].parse().unwrap();
                i += 1;
            }
            "--adversarial" => {
                cfg.adversarial = true;
                cfg.delivery = Delivery::Queued;
            }
            "--queued" => cfg.delivery = Delivery::Queued,
            "--stale-pointer" => cfg.stale_pointer = true,
            "--run-local-fifo" => cfg.d_global_fifo = false,
            "--no-garble" => cfg.garble_hops = false,
            "--no-withdrawals" => cfg.withdrawals = false,
            "--accept-query-answer" => cfg.params.spec.accept_query_answer = true,
            a => panic!("unknown argument {a}"),
        }
        i += 1;
    }

    if let Some(seed) = trace {
        let sc = gen_scenario(seed, &cfg);
        let o = run(&cfg, &sc);
        let inv = o.violation.as_ref().map(|v| v.inv);
        println!("seed {seed}: {:?}", o.violation);
        if let Some(inv) = inv {
            let small = shrink(&cfg, &sc, inv);
            print_trace(&cfg, &small, seed);
        }
        return;
    }

    if let Some(k) = find {
        // seeds whose run hits coverage counter `k` (for COVERAGE_SEEDS)
        for seed in start..start + seeds {
            let o = run(&cfg, &gen_scenario(seed, &cfg));
            if o.cov.get(&k) > 0 {
                println!(
                    "seed {seed} hits {k} (violation {:?})",
                    o.violation.map(|v| v.inv)
                );
            }
        }
        return;
    }

    let mut cov = Cov::default();
    let mut by_inv: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
    let mut corrupt_sealed = 0u64;
    let extra = COVERAGE_SEEDS
        .iter()
        .map(|(s, _)| *s)
        .filter(|s| !(start..start + seeds).contains(s));
    for seed in (start..start + seeds).chain(extra) {
        let sc = gen_scenario(seed, &cfg);
        let o = run(&cfg, &sc);
        cov.merge(&o.cov);
        corrupt_sealed += o.sealed_corrupt_sent;
        if let Some(v) = o.violation {
            by_inv.entry(v.inv).or_default().push(seed);
        }
    }
    println!(
        "schedules: {seeds} (seeds {start}..{}) plus {} coverage seeds, delivery {:?}, adversarial {}, stale pointer {}, global FIFO {}, accept-query-answer {}",
        start + seeds,
        COVERAGE_SEEDS.len(),
        cfg.delivery,
        cfg.adversarial,
        cfg.stale_pointer,
        cfg.d_global_fifo,
        cfg.params.spec.accept_query_answer
    );
    if by_inv.is_empty() {
        println!("violations: none");
    }
    for (inv, s) in &by_inv {
        println!(
            "violation {inv}: {} schedules, first seeds {:?}",
            s.len(),
            &s[..s.len().min(8)]
        );
    }
    println!("sealed build sent a corrupt entry: {corrupt_sealed} times");
    let missing = cov.missing();
    println!(
        "coverage: {} counters, {} required missing",
        cov.counts.len(),
        missing.len()
    );
    for m in &missing {
        println!("  MISSING {m}");
    }
    if std::env::var("COV_ALL").is_ok() {
        for (k, v) in &cov.counts {
            println!("  {k} = {v}");
        }
    }
    for (inv, s) in &by_inv {
        for seed in s.iter().take(shrink_n) {
            let sc = gen_scenario(*seed, &cfg);
            let small = shrink(&cfg, &sc, inv);
            print_trace(&cfg, &small, *seed);
        }
    }
    if !by_inv.is_empty() || !missing.is_empty() {
        std::process::exit(1);
    }
}

fn print_trace(cfg: &Cfg, sc: &freenet_vault_model::world::Scenario, seed: u64) {
    let mut c = cfg.clone();
    c.trace = true;
    let o = run(&c, sc);
    println!(
        "\n==== seed {seed}: shrunk to {} actions; ledger {:?}",
        sc.actions.len(),
        sc.ledger
    );
    println!("violation: {:?}", o.violation);
    for l in o.trace {
        println!("{l}");
    }
}
