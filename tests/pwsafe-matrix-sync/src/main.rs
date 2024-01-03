//! Implement the synapse-based Administrator API, to prepare the Synapse homeserver for local
//! testing. All relevant configuration is passed via environment variables.
use std::{fs::File, io::Read as _, path::Path, path::PathBuf};
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

    let input = std::env::args_os().nth(1).unwrap();

    let TestEnv {
        pwsafe_db,
        pwsafe_password,
        server_address,
        server_token,
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

    let mut cmd = std::process::Command::new(EXE_PWSAFE_MATRIX)
        .arg("sync")
        .arg(pwsafe_db)
        .args(["--password", pwsafe_password.as_str()])
        .args(["--server-http-authorization", server_token.as_str()])
        .args(["--server-address", server_address.as_str()])
        .arg(input)
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut stdout = cmd.stdout.take().unwrap();
    stdout.read_exact(&mut [0x0])?;

    let health = format!("{server_address}/health");
    let _health = ureq::get(&health).call()?;

    let stop = format!("{server_address}/stop");
    let _stop = ureq::post(&stop).call()?;

    let cmd = cmd.wait_with_output()?;
    if !cmd.status.success() {
        eprintln!("{:?}", String::from_utf8_lossy(&cmd.stderr));
        Ok(std::process::ExitCode::FAILURE)
    } else {
        Ok(std::process::ExitCode::SUCCESS)
    }
}

#[derive(Deserialize)]
struct TestEnv {
    #[serde(rename = "pwsafe-db")]
    pwsafe_db: PathBuf,
    #[serde(rename = "pwsafe-password")]
    pwsafe_password: String,
    #[serde(rename = "pwsafe-matrix-server-http-authorization")]
    server_token: String,
    #[serde(rename = "pwsafe-matrix-server-address")]
    server_address: String,
}