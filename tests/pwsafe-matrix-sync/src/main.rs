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
        homeserver,
        username,
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
        // These would be restored from session, but the homeserver calls itself by the domain
        // configured in the file (synapse.hardmo.de) which is wrong. We want to reach it under the
        // specific one configured by the kube YAML for the host. Note how we do not pass a
        // password which might be disallowed at a later point?
        .args(["--homeserver", homeserver.as_str()])
        .args(["--user", username.as_str()])
        // The rest of the arguments are most relevant.
        .args(["--password", pwsafe_password.as_str()])
        .args(["--server-http-authorization", server_token.as_str()])
        .args(["--server-address", server_address.as_str()])
        .arg("--server-ready")
        .arg(pwsafe_db)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    let mut stdout = cmd.stdout.take().unwrap();
    stdout.read_exact(&mut [0x0])?;

    let health = format!("http://{server_address}/health");
    let _health = ureq::get(&health)
        .set("Authorization", server_token.as_str())
        .call()?;

    let stop = format!("http://{server_address}/stop");
    let _stop = ureq::post(&stop)
        .set("Authorization", server_token.as_str())
        .call()?;


    let cmd = cmd.wait()?;

    if !cmd.success() {
        // eprintln!("Not successful: {:?}\n--not successful\n", String::from_utf8_lossy(&cmd.stderr));
        Ok(std::process::ExitCode::FAILURE)
    } else {
        Ok(std::process::ExitCode::SUCCESS)
    }
}

#[derive(Deserialize)]
struct TestEnv {
    homeserver: String,
    username: String,
    #[serde(rename = "pwsafe-db")]
    pwsafe_db: PathBuf,
    #[serde(rename = "pwsafe-password")]
    pwsafe_password: String,
    #[serde(rename = "pwsafe-matrix-server-http-authorization")]
    server_token: String,
    #[serde(rename = "pwsafe-matrix-server-address")]
    server_address: String,
}
