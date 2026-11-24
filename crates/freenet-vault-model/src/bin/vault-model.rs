//! Run seeded schedules of the handover model and report invariant
//! violations (with shrunk traces) and coverage.
//!
//! vault-model [--seeds N] [--start S] [--queued] [--adversarial] [--stale-pointer]
//!             [--trace SEED] [--quiet]

use std::collections::BTreeMap;

use freenet_vault_model::cov::Cov;
use freenet_vault_model::directed::directed;
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
    let mut directed_trace = false;
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
            "--directed-trace" => directed_trace = true,
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

    if directed_trace {
        let mut c = cfg.clone();
        c.trace = true;
        for (k, sc) in directed(&cfg) {
            let o = run(&c, &sc);
            println!(
                "\n==== directed scenario for {k}: hit {} times",
                o.cov.get(k)
            );
            println!("violation: {:?}", o.violation);
            for l in o.trace {
                println!("{l}");
            }
        }
        return;
    }

    if let Some(k) = find {
        // For each counter (comma-separated; "missing" = every required
        // counter the plain range leaves at zero), the first seed whose run
        // hits it without a violation (for COVERAGE_SEEDS).
        let mut want: Vec<String> = k.split(',').map(str::to_string).collect();
        if k == "missing" {
            let mut c = Cov::default();
            for seed in 0..2000 {
                c.merge(&run(&cfg, &gen_scenario(seed, &cfg)).cov);
            }
            want = c.missing().iter().map(|m| m.to_string()).collect();
        }
        for seed in start..start + seeds {
            if want.is_empty() {
                break;
            }
            let o = run(&cfg, &gen_scenario(seed, &cfg));
            if o.violation.is_some() {
                continue;
            }
            want.retain(|k| {
                if o.cov.get(k) > 0 {
                    println!("    ({seed}, \"{k}\"),");
                    false
                } else {
                    true
                }
            });
        }
        for k in want {
            println!("    // not found: {k}");
        }
        return;
    }

    let mut cov = Cov::default();
    let mut by_inv: BTreeMap<&'static str, Vec<u64>> = BTreeMap::new();
    let mut corrupt_sealed = 0u64;
    let extra: std::collections::BTreeSet<u64> = COVERAGE_SEEDS
        .iter()
        .map(|(s, _)| *s)
        .filter(|s| !(start..start + seeds).contains(s))
        .collect();
    for seed in (start..start + seeds).chain(extra.iter().copied()) {
        let sc = gen_scenario(seed, &cfg);
        let o = run(&cfg, &sc);
        cov.merge(&o.cov);
        corrupt_sealed += o.sealed_corrupt_sent;
        if let Some(v) = o.violation {
            by_inv.entry(v.inv).or_default().push(seed);
        }
    }
    let mut directed_violations = vec![];
    let ds = directed(&cfg);
    let n_directed = ds.len();
    for (k, sc) in ds {
        let o = run(&cfg, &sc);
        cov.merge(&o.cov);
        if let Some(v) = o.violation {
            directed_violations.push((k, v));
        }
    }
    println!(
        "schedules: {seeds} (seeds {start}..{}) plus {} coverage seeds and {} directed scenarios, delivery {:?}, adversarial {}, stale pointer {}, global FIFO {} (protocol revision 8)",
        start + seeds,
        extra.len(),
        n_directed,
        cfg.delivery,
        cfg.adversarial,
        cfg.stale_pointer,
        cfg.d_global_fifo,
    );
    if by_inv.is_empty() && directed_violations.is_empty() {
        println!("violations: none");
    }
    for (k, v) in &directed_violations {
        println!(
            "violation {} in the directed scenario for {k}: {}",
            v.inv, v.msg
        );
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
    if !by_inv.is_empty() || !directed_violations.is_empty() || !missing.is_empty() {
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
