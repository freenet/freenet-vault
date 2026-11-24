//! Runs the simulation model's gate, batches, directed scenarios and
//! mutation check over the freenet-vault library (protocol 15). Arguments are
//! the model runner's (`freenet_vault_model::cli`); build with
//! `--profile conformance` (simulated crashes unwind). The bridge's own
//! findings (divergences the model's invariants cannot express) are printed
//! at the end.

fn main() {
    freenet_vault_conformance::install();
    freenet_vault_model::cli::set_finish_hook(Some(|| {
        let r = freenet_vault_conformance::report();
        if r.is_empty() {
            println!("bridge findings: none");
        } else {
            println!("bridge findings:\n{r}");
        }
    }));
    freenet_vault_model::cli::run_cli(std::env::args().collect());
}
