//! Delivery modes: the queued mode reaches the F3 unseal (I4) that core's
//! delivery (hop inside the caller's run or dropped, reply in the same run)
//! cannot produce. Pins that the two modes differ where the findings say.

use crate::gen::{gen_scenario, run};
use crate::world::{Cfg, Delivery};

#[test]
fn queued_mode_reproduces_f3() {
    let mut cfg = Cfg::gate();
    cfg.delivery = Delivery::Queued;
    let o = run(&cfg, &gen_scenario(288, &cfg));
    assert_eq!(o.violation.map(|v| v.inv), Some("I4"));
}

#[test]
fn core_mode_has_no_f3_on_the_queued_mode_seeds() {
    let cfg = Cfg::gate();
    for seed in [288, 410, 564, 615, 795, 863, 1364, 1618] {
        let o = run(&cfg, &gen_scenario(seed, &cfg));
        let inv = o.violation.map(|v| v.inv);
        assert!(
            !matches!(inv, Some("I4") | Some("I4b")),
            "seed {seed}: {inv:?}"
        );
    }
}

#[test]
fn core_mode_exercises_its_delivery_paths() {
    let cfg = Cfg::gate();
    let mut cov = crate::cov::Cov::default();
    for seed in 0..300 {
        cov.merge(&run(&cfg, &gen_scenario(seed, &cfg)).cov);
    }
    for k in [
        "core/lane-call",
        "core/handed-off-unit",
        "core/forwarded-to-loop",
        "core/claim-runs-unit-first",
        "core/hop-runs-target-unit-first",
        "core/hop-dropped-target-mid-round-trip",
    ] {
        assert!(cov.get(k) > 0, "{k} never hit");
    }
}

#[test]
fn directed_scenarios_hit_their_rows() {
    let cfg = Cfg::gate();
    let ds = crate::directed::directed(&cfg);
    assert!(!ds.is_empty());
    for (k, sc) in ds {
        let o = run(&cfg, &sc);
        assert!(
            o.cov.get(k) > 0,
            "directed scenario for {k} no longer hits it"
        );
    }
}

/// Finding (revision 8): a fresh install while stopped never creates; no
/// invariant covers it (I7 is not checked while the newest record is a
/// withdrawal), so it is pinned here.
#[test]
fn fresh_install_while_stopped_never_creates() {
    let cfg = Cfg::gate();
    let o = run(&cfg, &crate::directed::fresh_install_while_stopped(&cfg));
    assert!(o.violation.is_none(), "{:?}", o.violation);
    assert_eq!(o.cov.get("5.1/created"), 0);
    assert!(o.cov.get("13.1/armed-while-stopped") > 0);
    assert!(o.cov.get("finding/creation-probe-blocked-by-withdrawal") > 0);
}

#[test]
fn coverage_seeds_still_hit_their_rows() {
    let cfg = Cfg::gate();
    for (seed, k) in crate::gen::COVERAGE_SEEDS {
        let o = run(&cfg, &gen_scenario(*seed, &cfg));
        assert!(o.cov.get(k) > 0, "coverage seed {seed} no longer hits {k}");
    }
}
