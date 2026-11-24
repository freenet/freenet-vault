//! Runs seeded schedules of the handover model; see `freenet_vault_model::cli`.

fn main() {
    freenet_vault_model::cli::run_cli(std::env::args().collect());
}
