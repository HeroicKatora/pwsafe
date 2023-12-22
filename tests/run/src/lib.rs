mod harness;
pub use crate::harness::Harness;

pub const EXE_PREPARE_API: &str = env!("CARGO_BIN_FILE_PWSAFE_MATRIX_PREPARE_API_pwsafe-matrix-prepare-api");

#[test]
fn responds() {
    let _harness = Harness::default();
}
