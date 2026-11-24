//! Run seeded schedules of the handover model and report invariant
//! violations (with shrunk traces) and coverage.
//!
//! vault-model [--seeds N] [--start S] [--queued] [--adversarial] [--stale-pointer]
//!             [--trace SEED] [--mutant NAME] [--mutants]
//!             [--gc-old-after-index] [--no-list-none-indexes]
//!
//! --mutants runs every mutant of `build::Mutant` over the seed range and
//! the directed scenarios, and reports for each whether it is caught: a
//! violation at a seed (or directed scenario) where the unmutated model has
//! none, or has a different one.

use std::collections::BTreeMap;

use freenet_vault_model::build::Mutant;
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
    let mut mutants = false;
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
            "--mutant" => {
                cfg.params.mutant = Some(Mutant::parse(&args[i + 1]).expect("unknown mutant"));
                i += 1;
            }
            "--mutants" => mutants = true,
            "--gc-old-after-index" => cfg.params.gc_old_before_index = false,
            "--no-list-none-indexes" => cfg.params.list_none_indexes = false,
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

    if mutants {
        run_mutants(&cfg, start, seeds, shrink_n);
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
    let mut shapes: BTreeMap<String, (u64, u64)> = BTreeMap::new();
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
            let e = shapes
                .entry(format!("{}: {}", v.inv, shape(&v.msg)))
                .or_insert((0, seed));
            e.0 += 1;
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
        "schedules: {seeds} (seeds {start}..{}) plus {} coverage seeds and {} directed scenarios, delivery {:?}, adversarial {}, stale pointer {}, global FIFO {}, gc old copy before index {}, list NONE indexes {}, mutant {:?} (protocol revision 9)",
        start + seeds,
        extra.len(),
        n_directed,
        cfg.delivery,
        cfg.adversarial,
        cfg.stale_pointer,
        cfg.d_global_fifo,
        cfg.params.gc_old_before_index,
        cfg.params.list_none_indexes,
        cfg.params.mutant,
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
    for (k, (n, first)) in &shapes {
        println!("  shape {n:>6} (first seed {first:>6}) {k}");
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

/// Labels of stated residuals and of model-scope artefacts: a mutant caught
/// only by these is not caught.
const NOT_BLOCKING: &[&str] = &[
    "I2-two-index-lost",
    "I2-direct-read-gc-lost",
    "I2-reindex-unrecoverable",
    "I8-reindex",
    "I1-two-index-lost",
    "I1-restore-unreported",
    "I5-after-restore",
    "I3-cached-never-routed",
];

/// The mutation check (15.5): each mutant must produce a violation where
/// the unmutated model produces none (or a different one).
fn run_mutants(cfg: &Cfg, start: u64, seeds: u64, shrink_n: usize) {
    let base: Vec<Option<&'static str>> = (start..start + seeds)
        .map(|s| run(cfg, &gen_scenario(s, cfg)).violation.map(|v| v.inv))
        .collect();
    let ds = directed(cfg);
    let dbase: Vec<Option<&'static str>> = ds
        .iter()
        .map(|(_, sc)| run(cfg, sc).violation.map(|v| v.inv))
        .collect();
    println!(
        "mutation check: {seeds} seeds from {start} plus {} directed scenarios, delivery {:?}",
        ds.len(),
        cfg.delivery
    );
    let mut survivors = 0;
    for m in Mutant::ALL {
        let mut c = cfg.clone();
        c.params.mutant = Some(m);
        let mut caught: BTreeMap<&'static str, (u64, String)> = BTreeMap::new();
        for (i, seed) in (start..start + seeds).enumerate() {
            let o = run(&c, &gen_scenario(seed, &c));
            if let Some(v) = o.violation {
                if base[i] != Some(v.inv) && !NOT_BLOCKING.contains(&v.inv) {
                    let e = caught.entry(v.inv).or_insert((0, format!("seed {seed}")));
                    e.0 += 1;
                }
            }
        }
        for (j, (k, sc)) in ds.iter().enumerate() {
            let o = run(&c, sc);
            if let Some(v) = o.violation {
                if dbase[j] != Some(v.inv) && !NOT_BLOCKING.contains(&v.inv) {
                    let e = caught.entry(v.inv).or_insert((0, format!("directed {k}")));
                    e.0 += 1;
                }
            }
        }
        if caught.is_empty() {
            survivors += 1;
            println!("mutant {m:?}: SURVIVED");
        } else {
            let s: Vec<String> = caught
                .iter()
                .map(|(k, (n, first))| format!("{k} x{n} (first {first})"))
                .collect();
            println!("mutant {m:?}: caught by {}", s.join(", "));
            if shrink_n > 0 {
                let (inv, (_, first)) = caught.iter().next().unwrap();
                if let Some(seed) = first.strip_prefix("seed ") {
                    let seed: u64 = seed.parse().unwrap();
                    let sc = gen_scenario(seed, &c);
                    let small = shrink(&c, &sc, inv);
                    print_trace(&c, &small, seed);
                }
            }
        }
    }
    println!("mutants surviving: {survivors}");
    if survivors > 0 {
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

/// A violation message with its numbers replaced and its oracle detail cut,
/// so that violations of the same kind count together.
fn shape(msg: &str) -> String {
    // tokens of digits, and the four-hex-digit manifest abbreviations
    let mut out = String::new();
    let mut tok = String::new();
    let flush = |tok: &mut String, out: &mut String| {
        if !tok.is_empty() {
            let hex = tok.chars().all(|c| c.is_ascii_hexdigit());
            let num = tok.chars().any(|c| c.is_ascii_digit());
            if hex && (num || tok.len() == 4) {
                out.push('#');
            } else {
                out.push_str(tok);
            }
            tok.clear();
        }
    };
    for c in msg.chars() {
        if c.is_ascii_alphanumeric() {
            tok.push(c);
        } else {
            flush(&mut tok, &mut out);
            out.push(c);
        }
    }
    flush(&mut tok, &mut out);
    let cut = out
        .find("; acknowledged")
        .or_else(|| out.find("; possible"))
        .or_else(|| out.find(": ["))
        .unwrap_or(out.len());
    out[..cut].to_string()
}
