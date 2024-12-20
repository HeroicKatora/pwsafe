//! Implement the synapse-based Administrator API, to prepare the Synapse homeserver for local
//! testing. All relevant configuration is passed via environment variables.
use std::{fs::File, path::Path, path::PathBuf};
use serde::Deserialize;

pub const EXE_PWSAFE_MATRIX: &str = env!("CARGO_BIN_FILE_PWSAFE_MATRIX_pwsafe-matrix");

fn main() -> Result<std::process::ExitCode, anyhow::Error> {
    let configuration_path = std::env::var_os("PWSAFE_MATRIX_TESTS_PATH")
        .map_or_else(
            || {
                let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-configuration-dummy.yaml");
                Path::new(path).to_path_buf()
            },
            |var| Path::new(&var).to_path_buf(),
        );

    let TestEnv {
        homeserver: address,
        username,
        password,
        pwsafe_db,
        pwsafe_password,
    } = {
        let path_err = configuration_path.display().to_string();

        let file = File::open(&configuration_path)
            .map_err(anyhow::Error::from)
            .map_err(|err| err.context(path_err))?;
        serde_yaml::from_reader(file)?
    };

    let pwsafe_db = configuration_path
        .parent()
        .unwrap()
        .join(&pwsafe_db);

    let cmd = std::process::Command::new(EXE_PWSAFE_MATRIX)
        .arg("create")
        .arg(pwsafe_db)
        .args(["--password", pwsafe_password.as_str()])
        .args(["--homeserver", &address.as_str()])
        .args(["--user", &username])
        .args(["--matrix-password", &password])
        .output()?;

    if !cmd.status.success() {
        eprintln!("{:?}", String::from_utf8_lossy(&cmd.stderr));
        Ok(std::process::ExitCode::FAILURE)
    } else {
        Ok(std::process::ExitCode::SUCCESS)
    }
}

#[derive(Deserialize)]
struct TestEnv {
    homeserver: url::Url,
    username: String,
    password: String,
    #[serde(rename = "pwsafe-db")]
    pwsafe_db: PathBuf,
    #[serde(rename = "pwsafe-password")]
    pwsafe_password: String,
}
