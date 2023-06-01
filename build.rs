use atb_build::{generate_cargo_keys, rerun_if_git_head_changed};

fn main() {
    generate_cargo_keys();
    rerun_if_git_head_changed();

    uniffi::generate_scaffolding("./src/aethers.udl").unwrap();
}
