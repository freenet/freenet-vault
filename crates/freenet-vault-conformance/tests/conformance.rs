//! The conformance gate at pull-request size: every directed scenario and a
//! band of generated schedules, run over the library and over the model.
//! The library may break an invariant only where the model breaks the same
//! one on the same schedule (the model's stated residuals), and the bridge
//! must report no divergence of its own. The full gate (2,000 seeds), the
//! 100k batches and the mutation check run from the binary; see the crate
//! documentation.

use freenet_vault_model::build::{set_build_impl, ModelBuild};
use freenet_vault_model::directed::directed;
use freenet_vault_model::gen::{gen_scenario, run};
use freenet_vault_model::world::{Cfg, Delivery, Scenario};
use std::rc::Rc;

fn invs(cfg: &Cfg, scs: &[(String, Scenario)], library: bool) -> Vec<Option<&'static str>> {
    if library {
        freenet_vault_conformance::install();
    } else {
        set_build_impl(Some(Rc::new(|| Box::new(ModelBuild) as _)));
    }
    scs.iter()
        .map(|(_, sc)| run(cfg, sc).violation.map(|v| v.inv))
        .collect()
}

/// Labels the model itself breaks under adversarial delivery, which breaks
/// assumption D (not gating; sim7 report).
const WITHOUT_D: [&str; 4] = ["I4", "I4b", "I1-restore-unreported", "I2-two-index-lost"];

fn check(cfg: Cfg, seeds: std::ops::Range<u64>) {
    let mut scs: Vec<(String, Scenario)> = directed(&cfg)
        .into_iter()
        .map(|(k, sc)| (format!("directed {k}"), sc))
        .collect();
    scs.extend(seeds.map(|s| (format!("seed {s}"), gen_scenario(s, &cfg))));
    let model = invs(&cfg, &scs, false);
    let lib = invs(&cfg, &scs, true);
    let mut bad = vec![];
    for (i, (name, _)) in scs.iter().enumerate() {
        if let Some(l) = lib[i] {
            if model[i] != Some(l) && !(cfg.adversarial && WITHOUT_D.contains(&l)) {
                bad.push(format!("{name}: library {l}, model {:?}", model[i]));
            }
        }
    }
    let r = freenet_vault_conformance::report();
    assert!(
        bad.is_empty(),
        "library violations the model does not have:\n{}",
        bad.join("\n")
    );
    assert!(r.is_empty(), "bridge findings:\n{r}");
}

#[test]
fn library_conforms_core() {
    check(Cfg::gate(), 0..300);
}

#[test]
fn library_conforms_adversarial() {
    let mut cfg = Cfg::gate();
    cfg.adversarial = true;
    cfg.delivery = Delivery::Queued;
    check(cfg, 0..100);
}
