use std::path::PathBuf;
use color_eyre::{eyre::Error, section::Section};
use serde::Serialize;
use tempfile::NamedTempFile;

/// Holds the resources we need in the test suite for the executable(s) controlling one password
/// database.
pub struct Harness {
    pub homeserver_domain: url::Url,
    pub pwsafe_user_1: NamedTempFile,
}

/// The descriptor for the executables to use.
#[derive(Serialize, Clone)]
#[serde(rename_all = "kebab-case")]
pub struct TestEnv {
    pub homeserver: url::Url,
    pub username: String,
    pub password: String,
    pub pwsafe_db: PathBuf,
    pub pwsafe_password: String,
    pub pwsafe_matrix_server_http_authorization: String,
    pub pwsafe_matrix_server_address: String,
}

impl Harness {
    fn validate(domain: String) -> Result<Self, Error> {
        const PWSAFE_TEMPLATE: &str = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../pwsafe.psafe3",
        );

        let agent = ureq::Agent::new();
        let homeserver_domain: url::Url = domain.parse()?;

        let versions_url = homeserver_domain.join("_matrix/client/versions")?;
        let versions = agent.get(versions_url.as_str()).call()?;

        if versions.status() != 200 {
            return Err(ureq::Error::Status(versions.status(), versions))?;
        }

        let mut _version_data = vec![];
        versions.into_reader().read_to_end(&mut _version_data)?;

        let pwsafe_user_1 = NamedTempFile::new()?;
        std::fs::copy(PWSAFE_TEMPLATE, pwsafe_user_1.path())?;

        Ok(Harness { homeserver_domain, pwsafe_user_1 })
    }
}

impl TestEnv {
    pub fn new_arbitrary(harness: &Harness) -> Self {
        use core::iter::repeat_with;

        let username = repeat_with(fastrand::alphanumeric).take(16).collect();
        let password = repeat_with(fastrand::alphanumeric).take(16).collect();
        let token = repeat_with(fastrand::alphanumeric).take(16).collect();

        TestEnv {
            homeserver: harness.homeserver_domain.clone(),
            username,
            password,
            pwsafe_db: harness.pwsafe_user_1.path().to_path_buf(),
            pwsafe_password: "pwsafe-matrix-test".into(),
            pwsafe_matrix_server_http_authorization: token,
            pwsafe_matrix_server_address: "127.0.0.1:8000",
        }
    }

    pub fn fork_harness(&self) -> Result<(Harness, Self), Error> {
        let pwsafe_user_1 = NamedTempFile::new()?;
        std::fs::copy(&self.pwsafe_db, pwsafe_user_1.path())?;

        let env = TestEnv {
            pwsafe_db: pwsafe_user_1.path().to_path_buf(),
            ..self.clone()
        };

        let harness = Harness {
            homeserver_domain: self.homeserver.clone(),
            pwsafe_user_1,
        };

        Ok((harness, env))
    }

    pub fn to_disk(&self) -> Result<NamedTempFile, Error> {
        let parent = 'a: {
            let fallback = std::env::temp_dir;
            let Some(own) = std::env::args_os().nth(0) else {
                break 'a fallback();
            };

            let own = std::path::PathBuf::from(own);
            let Some(exe_in) = own.parent() else {
                break 'a fallback();
            };

            exe_in.to_path_buf()
        };

        let mut file = NamedTempFile::new_in(parent)?;

        let path = file.path().display().to_string();
        serde_yaml::to_writer(&mut file, self)
            .map_err(Error::from)
            .map_err(|err| err.note(path))?;

        Ok(file)
    }
}

impl Default for Harness {
    fn default() -> Self {
        super::with_themed_errors();

        let default = std::env::var("PWSAFE_MATRIX_TEST_SERVER")
            .unwrap_or_else(|_| "http://localhost:8080".into());

        match Harness::validate(default) {
            Ok(harness) => harness,
            Err(err) => {
                let _local_path;
                let hint = format!(
                    "The test environment is defined in the configuration file `{}`",
                    {
                        const LOCAL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../local/kube.yml");
                        _local_path = std::path::Path::new(LOCAL).canonicalize().unwrap();
                        _local_path.display()
                    }
                );

                let err = err.note(hint);

                let _local_path;
                let hint = format!(
                    r#"For instance run, `pushd "{}" && podman play kube kube.yml && popd`"#,
                    {
                        const LOCAL: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../local/");
                        _local_path = std::path::Path::new(LOCAL).canonicalize().unwrap();
                        _local_path.display()
                    }
                );

                let err = err.suggestion(hint);
                panic!("{err:?}")
            }
        }
    }
}
