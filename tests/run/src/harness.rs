use color_eyre::{eyre::Error, section::Section};

pub struct Harness {
    pub domain: String,
}

impl Harness {
    fn validate(domain: String) -> Result<Self, Error> {
        let agent = ureq::Agent::new();

        let versions = agent
            .get(&format!("{domain}/_matrix/client/versions"))
            .send_bytes(b"")?;

        if versions.status() != 200 {
            return Err(ureq::Error::Status(versions.status(), versions))?;
        }

        let mut _version_data = vec![];
        versions.into_reader().read_to_end(&mut _version_data)?;

        Ok(Harness { domain })
    }
}

impl Default for Harness {
    fn default() -> Self {
        let _ = color_eyre::config::HookBuilder::blank()
            // Readability first, no color. But I get the vibe
            .theme(color_eyre::config::Theme::new())
            .install();

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

                let err = err.with_note(move || hint);

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
