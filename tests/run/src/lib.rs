mod harness;
pub use crate::harness::{Harness, TestEnv};

pub const EXE_PREPARE_API: &str = env!("CARGO_BIN_FILE_PWSAFE_MATRIX_PREPARE_API_pwsafe-matrix-prepare-api");
pub const EXE_CREATE: &str = env!("CARGO_BIN_FILE_PWSAFE_MATRIX_TEST_CREATE_pwsafe-matrix-test-create");
pub const EXE_INVITE: &str = env!("CARGO_BIN_FILE_PWSAFE_MATRIX_TEST_INVITE_pwsafe-matrix-test-invite");
pub const EXE_JOIN: &str = env!("CARGO_BIN_FILE_PWSAFE_MATRIX_TEST_JOIN_pwsafe-matrix-test-join");

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

#[test]
fn create() {
    let harness = Harness::default();
    let env = TestEnv::new_arbitrary(&harness);
    let env_file = env.to_disk().unwrap();

    let output = std::process::Command::new(EXE_PREPARE_API)
        .env("PWSAFE_MATRIX_TESTS_PATH", env_file.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);

    let output = std::process::Command::new(EXE_CREATE)
        .env("PWSAFE_MATRIX_TESTS_PATH", env_file.path())
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output);
}

#[test]
fn join() {
    let harness0 = Harness::default();
    let env0 = TestEnv::new_arbitrary(&harness0);

    let mut env1 = env0.clone();
    let harness1 = env1.fork_harness().unwrap();

    let env_file0 = env0.to_disk().unwrap();

    let output = std::process::Command::new(EXE_PREPARE_API)
        .env("PWSAFE_MATRIX_TESTS_PATH", env_file0.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);

    let output = std::process::Command::new(EXE_CREATE)
        .env("PWSAFE_MATRIX_TESTS_PATH", env_file0.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);

    let invite = tempfile::NamedTempFile::new().unwrap();

    let output = std::process::Command::new(EXE_INVITE)
        .env("PWSAFE_MATRIX_TESTS_PATH", env_file0.path())
        .arg(invite.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
}
