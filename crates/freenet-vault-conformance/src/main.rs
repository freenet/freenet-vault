//! Runs the simulation model's gate, batches, directed scenarios and
//! mutation check over the freenet-vault library (protocol 15). Arguments are
//! the model runner's (`freenet_vault_model::cli`); build with
//! `--profile conformance` (simulated crashes unwind). The bridge's own
//! findings (divergences the model's invariants cannot express) are printed
//! at the end.
//!
//! `--lib-mutants SEEDS [model arguments]` runs instead the library's base
//! mutants of 15.5 that the model does not carry (each is a deliberately
//! broken guard in the library, switched on through its `trace` feature),
//! over seeds 0..SEEDS and the directed scenarios, and reports for each the
//! invariants it broke where the unmutated library broke none or a
//! different one.

use std::collections::BTreeMap;

use freenet_vault::trace::Mutant as L;
use freenet_vault_model::directed::directed;
use freenet_vault_model::gen::{gen_scenario, run};
use freenet_vault_model::world::{Cfg, Delivery};

const LIB_ONLY: [L; 10] = [
    L::UnsealOnHigherRecord,
    L::StoppedBeforeTakenOver,
    L::ClearAwaitingWithoutAnswer,
    L::CopyWhileAwaiting,
    L::GcWithoutIndexCheck,
    L::CreateWithUnansweredProbe,
    L::IgnoreQueryAnswer,
    L::QueryRetiredToOther,
    L::MissingAsAccepted,
    L::WithdrawalLiftsBar,
];

/// Seeds on which the library (not the model) reaches a coverage row that
/// ordinary runs of a few thousand consecutive seeds leave at zero. The
/// library takes other schedules than the model from the same seed (it
/// answers a caller-record submission in NONE(armed) as a read, where the
/// model creates), so the model's own seeds do not carry over. Found with
/// `--find missing` over the library; replayed on every run unless the
/// arguments name `--coverage-seeds` themselves.
const LIB_COVERAGE_SEEDS: &str =
    "2334,3362,4467,4702,5190,5378,5444,6132,13681,14728,16590,31534,39790";

fn main() {
    freenet_vault_conformance::install();
    let mut args: Vec<String> = std::env::args().collect();
    if !args.iter().any(|a| a == "--coverage-seeds") {
        args.push("--coverage-seeds".into());
        args.push(LIB_COVERAGE_SEEDS.into());
    }
    if args.get(1).map(String::as_str) == Some("--lib-mutants") {
        let seeds: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
        let mut cfg = Cfg::gate();
        if args.iter().any(|a| a == "--adversarial") {
            cfg.adversarial = true;
            cfg.delivery = Delivery::Queued;
        }
        lib_mutants(&cfg, seeds);
        return;
    }
    freenet_vault_model::cli::set_finish_hook(Some(|| {
        let r = freenet_vault_conformance::report();
        if r.is_empty() {
            println!("bridge findings: none");
        } else {
            println!("bridge findings:\n{r}");
        }
    }));
    freenet_vault_model::cli::run_cli(args);
}

fn lib_mutants(cfg: &Cfg, seeds: u64) {
    let ds = directed(cfg);
    let inv = |o: &freenet_vault_model::gen::Outcome| o.violation.as_ref().map(|v| v.inv);
    let base: Vec<_> = (0..seeds)
        .map(|s| inv(&run(cfg, &gen_scenario(s, cfg))))
        .collect();
    let dbase: Vec<_> = ds.iter().map(|(_, sc)| inv(&run(cfg, sc))).collect();
    println!(
        "library-only mutants: {seeds} seeds plus {} directed scenarios, delivery {:?}, adversarial {}",
        ds.len(),
        cfg.delivery,
        cfg.adversarial
    );
    let mut survivors = 0;
    for m in LIB_ONLY {
        freenet_vault_conformance::set_extra_mutant(Some(m));
        let mut caught: BTreeMap<&'static str, (u64, String)> = BTreeMap::new();
        for s in 0..seeds {
            let o = run(cfg, &gen_scenario(s, cfg));
            if let Some(v) = o.violation {
                if base[s as usize] != Some(v.inv) {
                    caught.entry(v.inv).or_insert((0, format!("seed {s}"))).0 += 1;
                }
            }
        }
        for (i, (k, sc)) in ds.iter().enumerate() {
            let o = run(cfg, sc);
            if let Some(v) = o.violation {
                if dbase[i] != Some(v.inv) {
                    caught
                        .entry(v.inv)
                        .or_insert((0, format!("directed {k}")))
                        .0 += 1;
                }
            }
        }
        freenet_vault_conformance::set_extra_mutant(None);
        if caught.is_empty() {
            survivors += 1;
            println!("SURVIVED {m:?}");
        } else {
            let list: Vec<String> = caught
                .iter()
                .map(|(k, (n, first))| format!("{k} x{n} (first {first})"))
                .collect();
            println!("caught {m:?}: {}", list.join("; "));
        }
    }
    println!("survivors: {survivors}");
    if survivors > 0 {
        std::process::exit(1);
    }
}
