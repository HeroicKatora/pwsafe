mod harness;
pub use crate::harness::{Harness, TestEnv};

pub const EXE_PREPARE_API: &str = env!("CARGO_BIN_FILE_PWSAFE_MATRIX_PREPARE_API_pwsafe-matrix-prepare-api");

/// Some functions that tests should ensure to call, to ensure errors are formatted for joy.
pub(crate) fn with_themed_errors() {
    static COLOR_EYRE_REPORT: std::sync::OnceLock<()> = std::sync::OnceLock::new();

    COLOR_EYRE_REPORT.get_or_init(|| {
        let _ = color_eyre::config::HookBuilder::blank()
            // Readability first, no color. But I get the vibe
            .theme(color_eyre::config::Theme::new())
            .install();
    });
}

#[test]
fn responds() {
    let _harness = Harness::default();
}

#[test]
fn register() {
    let harness = Harness::default();
    let env = TestEnv::new_arbitrary(&harness);
    let env_file = env.to_disk().unwrap();

    let output = std::process::Command::new(EXE_PREPARE_API)
        .env("PWSAFE_MATRIX_TESTS_PATH", env_file.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
}
